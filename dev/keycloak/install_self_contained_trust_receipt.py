#!/usr/bin/env python3
"""Install public source and receipt for a recorded native trust proof; no target mutation."""
import argparse,hashlib,json,pathlib,subprocess,tempfile
p=argparse.ArgumentParser(description=__doc__);p.add_argument('folder',type=pathlib.Path);a=p.parse_args();folder=a.folder.resolve()
sha=lambda raw:hashlib.sha256(raw).hexdigest()
receipt=json.loads((folder/'trust-receipt.json').read_bytes());run=receipt['runId'];assert run.startswith('run_') and len(run)==30
remote='/data/metadata-rejection-evidence/'+run
files={folder/'trust-receipt.json':remote+'.native-trust.json',folder/'qualified-receipt.json':remote+'.keycloak-supersession.json',folder/'native-source/native-services.jar':remote+'.native-trust/native-services.jar',folder/'native-source/native-saml-core.jar':remote+'.native-trust/native-saml-core.jar'}
subprocess.run(['docker','exec','--user','0','samlscope-reference-suite','mkdir','-p',remote+'.native-trust'],check=True,capture_output=True)
rows=[]
with tempfile.TemporaryDirectory(prefix='kc-public-trust-readback-') as temporary:
 for index,(source,destination) in enumerate(files.items()):
  subprocess.run(['docker','cp',str(source),'samlscope-reference-suite:'+destination],check=True,capture_output=True)
  back=pathlib.Path(temporary)/str(index);subprocess.run(['docker','cp','samlscope-reference-suite:'+destination,str(back)],check=True,capture_output=True)
  assert back.read_bytes()==source.read_bytes(),'Receipt/public source read-back differs'
  rows.append(dict(file=str(source.relative_to(folder)),path=destination,sha256=sha(back.read_bytes()),bytes=back.stat().st_size))
(folder/'receipt-install.json').write_text(json.dumps(dict(runId=run,files=rows,productConfigurationWrites=0,samlRequests=0,privateKeyExported=False),indent=2)+'\n')
print('Native trust receipt and public source read-back verified')
