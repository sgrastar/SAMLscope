#!/usr/bin/env python3
"""Build a native event observer, run the signature batch, then remove it and restart.

The observer is enabled only in the collector's temporary realm configuration.
No dependency is downloaded: compile against the running product's own SPI jars.
"""
import argparse
import datetime
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import time
import urllib.request

CONTAINER='samlscope-reference-keycloak'
DESTINATION='/opt/keycloak/providers/samlscope-signature-observation.jar'
SHA=lambda raw:hashlib.sha256(raw).hexdigest()


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--profiles',default='browser_sso_idp,metadata_idp,ecp_idp,single_logout_idp')
    parser.add_argument('--scenario',choices=['signed-request','ec-signature','certificate-signature','metadata-key-signature'],default='signed-request')
    parser.add_argument('--playwright-modules',type=Path)
    parser.add_argument('--verify-request-signatures',action='store_true')
    args=parser.parse_args();out=args.output.resolve();out.mkdir(parents=True,exist_ok=False)
    if args.scenario!='signed-request' and (args.playwright_modules is None or not args.playwright_modules.is_dir()):
        raise ValueError('Metadata import requires an existing --playwright-modules directory')
    source=Path(__file__).resolve().parent/'signature-listener';build=out/'observer';build.mkdir()
    lib=build/'lib';lib.mkdir();classes=build/'classes';classes.mkdir();jar=build/'samlscope-signature-observation.jar'
    operations=[]
    def save():
        (out/'operations.json').write_text(json.dumps(operations,indent=2)+'\n')
    def command(arguments,timeout=60):
        return subprocess.run(arguments,check=True,capture_output=True,timeout=timeout).stdout
    def docker(*arguments):return command(['docker',*arguments])
    def absent():
        return subprocess.run(['docker','exec',CONTAINER,'test','!','-e',DESTINATION],capture_output=True,timeout=30).returncode==0
    if not absent():raise RuntimeError('Refusing existing provider replacement')
    patterns=['org.keycloak.keycloak-core-*.jar','org.keycloak.keycloak-server-spi-*.jar',
        'org.keycloak.keycloak-server-spi-private-*.jar','jakarta.ws.rs.jakarta.ws.rs-api-*.jar']
    inventory={}
    for pattern in patterns:
        paths=docker('exec',CONTAINER,'sh','-c',"printf '%s\\n' /opt/keycloak/lib/lib/main/"+pattern).decode().splitlines()
        # server-spi-* also matches the private jar; select the exact artifact prefix.
        if pattern=='org.keycloak.keycloak-server-spi-*.jar':paths=[path for path in paths if 'server-spi-private-' not in path]
        if len(paths)!=1 or '*' in paths[0]:raise RuntimeError('Ambiguous native SPI library')
        target=lib/Path(paths[0]).name;docker('cp',CONTAINER+':'+paths[0],str(target));inventory[target.name]=SHA(target.read_bytes())
    (build/'native-libraries.json').write_text(json.dumps(inventory,indent=2)+'\n')
    java=source/'src/com/samlscope/reference/SignatureEventListenerFactory.java'
    command(['javac','--release','21','-cp',str(lib/'*'),'-d',str(classes),str(java)])
    command(['jar','--create','--file',str(jar),'-C',str(classes),'.','-C',str(source/'resources'),'.'])
    digest=SHA(jar.read_bytes());installed=False;removed=False;failures=[]
    installation=dict(destination=DESTINATION,jar_sha256=digest,source_sha256=SHA(java.read_bytes()),previously_absent=True)
    (build/'installation.json').write_text(json.dumps(installation,indent=2)+'\n')
    shutil.copyfile(java,build/'SignatureEventListenerFactory.java')
    def restart(label):
        row=dict(operation='product-restart',label=label,completed=False);operations.append(row);save()
        docker('restart',CONTAINER)
        deadline=time.monotonic()+120
        while time.monotonic()<deadline:
            try:
                with urllib.request.urlopen('http://localhost:18180/realms/samlscope/protocol/saml/descriptor',timeout=3) as response:
                    if response.status==200:row['completed']=True;save();return
            except Exception:time.sleep(1)
        raise RuntimeError('Native product startup unavailable')
    try:
        installed=True;operations.append(dict(operation='provider-install',attempted=True));save()
        docker('cp',str(jar),CONTAINER+':'+DESTINATION)
        actual=docker('exec',CONTAINER,'sha256sum',DESTINATION).decode().split()[0]
        if actual!=digest:raise RuntimeError('Provider readback differs')
        installation['readback_verified']=True
        restart('observer-installed')
        collector=Path(__file__).with_name('signed_request_observation.py' if args.scenario=='signed-request' else 'ec_signature_campaign.py')
        arguments=[sys.executable,str(collector),'--output',str(out/'observations'),'--profiles',args.profiles]
        if args.scenario=='signed-request':arguments+=['--native-signature-listener']
        else:
            if args.playwright_modules is None:raise ValueError('Metadata import requires --playwright-modules')
            arguments+=['--playwright-modules',str(args.playwright_modules.resolve()),
                        '--matrix',{'certificate-signature':'certificate','metadata-key-signature':'keys','ec-signature':'ec'}[args.scenario]]
            if args.verify_request_signatures:arguments.append('--verify-request-signatures')
        subprocess.run(arguments,check=True,timeout=1200)
    finally:
        try:
            if installed:
                if not absent():
                    actual=docker('exec',CONTAINER,'sha256sum',DESTINATION).decode().split()[0]
                    if actual!=digest:raise RuntimeError('Provider changed concurrently; refusing removal')
                    docker('exec',CONTAINER,'rm',DESTINATION)
                    operations.append(dict(operation='provider-remove',completed=True));save()
                removed=absent()
                if not removed:raise RuntimeError('Provider removal incomplete')
                restart('observer-removed')
        except Exception as error:failures.append(type(error).__name__)
        batch=out/'observations';realm_restored=False
        if (batch/'operations.json').exists():
            realm_restored=json.loads((batch/'operations.json').read_text()).get('event_configuration_restored',False)
        record=dict(**installation,provider_removed=removed,realm_configuration_restored=realm_restored,
                    product_restart_verified=removed and not failures,failures=failures,
                    finished_at=datetime.datetime.now(datetime.timezone.utc).isoformat())
        (build/'restoration.json').write_text(json.dumps(record,indent=2)+'\n')
        if batch.exists():
            (batch/'native-observer.json').write_text(json.dumps(record,indent=2)+'\n')
            shutil.copyfile(java,batch/'native-observer-source.java')
        if failures or not realm_restored:raise RuntimeError('Observer or realm restoration incomplete; inspect operations')
    if args.scenario=='metadata-key-signature':
        # The receipt requires the final restoration record; never export from inside the
        # observer's live configuration window. This stage does not install or adopt it.
        subprocess.run([sys.executable,str(Path(__file__).resolve().parents[1]/'reference-acceptance/prepare_metadata_key_evidence.py'),
                        '--campaign',str(out)],check=True,timeout=900)



if __name__=='__main__':main()
