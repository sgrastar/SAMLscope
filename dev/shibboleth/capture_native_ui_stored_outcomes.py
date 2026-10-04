#!/usr/bin/env python3
"""Read only the four stored UI outcomes and archive the central Evaluator derivation."""
import argparse,hashlib,json,re,shutil,subprocess,sys,tempfile
from pathlib import Path
REPO=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(REPO/'dev/reference-acceptance'))
from verify_shibboleth_native_ui_acceptance import dependency_classpath
SHA=lambda raw:hashlib.sha256(raw).hexdigest()
def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('folder',type=Path);folder=parser.parse_args().folder.resolve()
    archive=folder/'reader-v177';destination=archive/'stored-case-conclusions.json'
    if destination.exists():raise ValueError('Refusing to overwrite stored outcome original')
    run=json.loads((folder/'created.json').read_text())['run']['id'];runtime=json.loads((archive/'suite-runtime-terminal-http.json').read_text())
    jars=[archive/runtime['jars'][name]['file'] for name in ['runner','core','saml']]+[archive/'suite-store-0.1.0.jar']
    source=REPO/'dev/reference-acceptance/ReadShibbolethUiStoredConclusions.java';shutil.copy2(source,archive/'stored-readback-source.java')
    (archive/'approved-coverage-original.yaml').write_bytes((REPO/'tests/coverage.yaml').read_bytes())
    remote=None
    try:
        with tempfile.TemporaryDirectory(prefix='samlscope-ui-stored-readback-') as temporary:
            temporary=Path(temporary);classes=temporary/'classes';classes.mkdir()
            subprocess.run(['javac','-cp',':'.join(map(str,jars))+':'+dependency_classpath(archive),'-d',str(classes),str(source)],check=True,capture_output=True)
            remote=subprocess.check_output(['docker','exec','samlscope-reference-suite','mktemp','-d','/tmp/samlscope-ui-case-readback-XXXXXXXX']).decode().strip()
            if not re.fullmatch('/tmp/samlscope-ui-case-readback-[A-Za-z0-9]{8}',remote):raise ValueError('Unsafe ephemeral Suite path')
            subprocess.run(['docker','cp',str(classes)+'/.','samlscope-reference-suite:'+remote],check=True,capture_output=True)
            result=subprocess.run(['docker','exec','samlscope-reference-suite','java','-cp',remote+':/opt/samlscope/lib/*',
                'com.samlscope.runner.cases.ReadShibbolethUiStoredConclusions','capture',run],capture_output=True,check=True)
            value=json.loads(result.stdout);destination.write_bytes(result.stdout)
            (archive/'stored-readback-provenance.json').write_text(json.dumps(dict(runId=run,sourceFile='stored-readback-source.java',
                sourceSha256=SHA(source.read_bytes()),file=destination.name,sha256=SHA(result.stdout),readonly=True,
                selectedCases=list(value['cases']),caseStateExported=False,privateCredentialsExported=False,productOperations=0),indent=2)+'\n')
            print('Four stored native UI outcomes read back; central Evaluator derived verdicts')
    finally:
        if remote:subprocess.run(['docker','exec','--user','0','samlscope-reference-suite','rm','-rf','--',remote],check=True,capture_output=True)
if __name__=='__main__':main()
