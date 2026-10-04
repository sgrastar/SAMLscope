#!/usr/bin/env python3
"""Capture native duplicate-entity conflict with exact resolver/configuration epochs.

The distinct-entity control is an already recorded two-SP campaign. This collector
performs only the fresh control and duplicate loads through the existing outbox flow.
It assigns no outcome and retains every native read-back and restoration attempt.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
from datetime import datetime, timezone
import zipfile

REPO=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('shibboleth_entityid_native_batch',REPO/'dev/shibboleth/import_metadata_batch.py')
batch=importlib.util.module_from_spec(spec);spec.loader.exec_module(batch)

NATIVE_JAR='/usr/local/tomcat/webapps/idp/WEB-INF/lib/opensaml-saml-impl-5.2.3.jar'
NATIVE_CLASS='org/opensaml/saml/metadata/resolver/impl/AbstractMetadataResolver.class'
WARN='/opt/reference-idp/logs/idp-warn.log'
SHA=lambda raw:hashlib.sha256(raw).hexdigest()
NOW=lambda:datetime.now(timezone.utc).isoformat().replace('+00:00','Z')
SAVE=lambda file,value:Path(file).write_text(json.dumps(value,sort_keys=True,indent=2)+'\n')

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',required=True,type=Path)
    args=parser.parse_args();out=args.output.resolve()
    if out.exists():raise ValueError('Refusing to replace evidence directory')
    source_holder={};epochs=[];original_reload=batch.reload;original_flow=batch.flow

    def current():
        run=json.loads((out/'created.json').read_text())['run']['id']
        return run,'/opt/reference-idp/metadata/algorithm-'+run+'.xml'

    def resolver_source():
        path=out/'native-opensaml-saml-impl.jar'
        subprocess.run(['docker','cp',batch.CONTAINER+':'+NATIVE_JAR,str(path)],check=True,capture_output=True)
        with zipfile.ZipFile(path) as jar:raw=jar.read(NATIVE_CLASS)
        (out/'native-abstract-metadata-resolver.class').write_bytes(raw)
        if b'Detected duplicate EntityDescriptor for entityID: {}' not in raw:
            raise ValueError('Unrecognized native duplicate-conflict implementation')
        source_holder.update(jar=NATIVE_JAR,jarSha256=SHA(path.read_bytes()),classFile=NATIVE_CLASS,
                             classSha256=SHA(raw),recordedAt=NOW())

    def snapshot(folder,label):
        run,path=current();at=NOW();provider=batch.docker('cat',batch.CONFIG);fixture=batch.docker('cat',path)
        (folder/(label+'-providers.xml')).write_bytes(provider)
        (folder/(label+'-fixture.xml')).write_bytes(fixture)
        return dict(recordedAt=at,providerFile=label+'-providers.xml',providerSha256=SHA(provider),
                    fixtureFile=label+'-fixture.xml',fixtureSha256=SHA(fixture),runId=run)

    def reload(folder,name):
        if name=='restore':return original_reload(folder,name)
        if not source_holder:resolver_source()
        run,_=current();before=snapshot(folder,'reload-before')
        warn_before=batch.docker('cat',WARN);start=NOW()
        original_reload(folder,name)
        finish=NOW();warn_after=batch.docker('cat',WARN)
        if not warn_after.startswith(warn_before):raise ValueError('Native warn log rotated during the captured load')
        # Export only exact resolver diagnostics; authentication identities and credentials never leave logs.
        lines=[line for line in warn_after[len(warn_before):].decode().splitlines()
               if 'AbstractMetadataResolver' in line and ('Algorithm'+run+':') in line]
        original=('\n'.join(lines)+'\n').encode();(folder/'native-resolver-warn.log').write_bytes(original)
        row=dict(phase='reload',variant=folder.name,startedAt=start,finishedAt=finish,
                 before=before,after=snapshot(folder,'reload-after'),
                 nativeLogFile='native-resolver-warn.log',nativeLogSha256=SHA(original),
                 nativeLogOffset=len(warn_before),nativeLogEnd=len(warn_after))
        epochs.append(row);SAVE(out/'native-resolver-epochs.json',epochs)

    def flow(run,file,*arguments,**keywords):
        folder=Path(file).parent;before=snapshot(folder,'flow-before');start=NOW()
        try:return original_flow(run,file,*arguments,**keywords)
        finally:
            epochs.append(dict(phase='protocol',variant=folder.name,startedAt=start,finishedAt=NOW(),
                               before=before,after=snapshot(folder,'flow-after')))
            SAVE(out/'native-resolver-epochs.json',epochs)

    batch.reload=reload;batch.flow=flow
    sys.argv=[str(REPO/'dev/shibboleth/import_metadata_batch.py'),'--output',str(out),
              '--variants','control,duplicate-entity-ids','--capture-native-originals']
    try:batch.main()
    finally:
        if out.exists() and source_holder:
            after=batch.docker('sha256sum',NATIVE_JAR).decode().split()[0]
            SAVE(out/'native-resolver-source.json',source_holder|dict(finalJarSha256=after,unchanged=after==source_holder['jarSha256']))
            if after!=source_holder['jarSha256']:raise ValueError('Native resolver binary changed')

if __name__=='__main__':main()
