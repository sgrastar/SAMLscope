#!/usr/bin/env python3
"""Remove unused native-login nonces without changing used proof or formal outcomes."""
import argparse,hashlib,json,re,subprocess,sys,tempfile
from html.parser import HTMLParser
from pathlib import Path
from export_ssp_keyvalue_runtime_receipt import export
from verify_ssp_keyvalue_runtime_acceptance import replay,sha,read,require,locate,rows

class LoginTokens(HTMLParser):
    def __init__(self):super().__init__();self.values=[];self.rawValues=[]
    def handle_starttag(self,tag,attrs):
        fields=dict(attrs)
        if tag=='input' and fields.get('name')=='AuthState' and fields.get('type','').lower()=='hidden' and fields.get('value'):
            self.values.append(fields['value'])
            match=re.search(r'\bvalue\s*=\s*(?:"([^"]*)"|\'([^\']*)\'|([^\s>]+))',self.get_starttag_text(),re.I)
            require(match is not None,'AuthState raw attribute unavailable')
            self.rawValues.append(next(value for value in match.groups() if value is not None))
def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('root',type=Path);args=parser.parse_args();folder=locate(args.root)
    projection=folder/'privacy-projection'
    if projection.exists():
        failed=read(projection/'projection.json');require(failed['oldManifestSha256']==failed['newManifestSha256'] and all(row['beforeSha256']==row['afterSha256'] for row in failed['files']),'Refusing replacement of a completed projection')
        (projection/'projection-incomplete-no-body-change.json').write_bytes((projection/'projection.json').read_bytes())
    else:projection.mkdir()
    old_manifest=read(folder/'originals/manifest.json');old_report=read(folder/'production-reader-replay.json');old_install=read(folder/'receipt-installation.json')
    for name in ['production-reader-replay.json','receipt-installation.json']:(projection/('original-'+name)).write_bytes((folder/name).read_bytes())
    (projection/'original-manifest.json').write_bytes((folder/'originals/manifest.json').read_bytes())
    decoded=[folder/row['file'] for row in read(folder/'decoded-manifest.json')]
    protected={str(p.relative_to(folder)):sha(p.read_bytes()) for p in [folder/'transcript.json',folder/'decoded-manifest.json',*decoded,*folder.glob('evaluation/*.json')]}
    old_digest=sha((folder/'originals/manifest.json').read_bytes())
    result=read(folder/'evaluation/result.json');formal=rows(result)
    require(all(old_digest not in json.dumps(row) for row in formal.values()),'Formal CaseExecution unexpectedly embeds a manifest hash')
    records=[];canonical_changed=set()
    for index in [1,2,3]:
        attempt=folder.parent/('ssp-native-keyvalue-runtime-v170-r'+str(index));http=read(attempt/'native-http-observations.json');by_id={r['request_id']:r for r in http['records']}
        for path in sorted((attempt/'native-http-originals').glob('*.html')):
            raw=path.read_bytes();page=raw.decode();tokens=LoginTokens();tokens.feed(page)
            if not tokens.values:continue
            request=by_id[path.stem];require(request['response_status']==200 and not request['saml_response_form_present'] and request['native_signature_rejection'] is None,'Nonce occurs in an evaluative native error')
            for value in tokens.rawValues+tokens.values:page=page.replace(value,'[REDACTED-AUTHSTATE]')
            projected=page.encode();require(all(value.encode() not in projected for value in tokens.rawValues+tokens.values),'Nonce projection incomplete')
            path.write_bytes(projected)
            record=dict(file=str(path.relative_to(folder.parent)),requestId=path.stem,beforeSha256=sha(raw),afterSha256=sha(projected),removedFields=['AuthState'],reason='Unused positive X509 login HTML; the Reader consumes signed final SAML Response and native error HTML only for KeyValue requests')
            if index==3 and path.name in old_manifest['files']:
                original=folder/'originals'/path.name;require(sha(original.read_bytes())==sha(raw),'Exported unused login HTML differs');original.write_bytes(projected);canonical_changed.add(path.name)
                record['exportedFile']=path.name
            records.append(record)
    require(len(canonical_changed)==2 and len(records)==9,'Unexpected login-token projection set')
    with tempfile.TemporaryDirectory(prefix='ssp-keyvalue-projected-') as name:
        regenerated=Path(name)/'originals';new_manifest=export(folder,regenerated)
        require(set(new_manifest['files'])==set(old_manifest['files']),'Projection changes original set')
        for name,digest in old_manifest['files'].items():
            require(sha((folder/'originals'/name).read_bytes())==new_manifest['files'][name],'Projected original export differs')
            require(name in canonical_changed or digest==new_manifest['files'][name],'Projection changes a used original')
        (folder/'originals/manifest.json').write_bytes((regenerated/'manifest.json').read_bytes())
    new_report=replay(folder)
    require({k:v for k,v in new_report.items() if k!='manifestSha256'}=={k:v for k,v in old_report.items() if k!='manifestSha256'},'Projected production replay outcome/controls differs')
    (folder/'production-reader-replay.json').write_text(json.dumps(new_report,indent=2)+'\n')
    target=old_install['path'];installation=[]
    for name in sorted(set(new_manifest['files'])|{'manifest.json'}):
        path=folder/'originals'/name;raw=path.read_bytes();observed=subprocess.check_output(['docker','exec','samlscope-reference-suite','cat',target+'/'+name])
        if name in canonical_changed|{'manifest.json'}:
            expected=old_digest if name=='manifest.json' else old_manifest['files'][name]
            require(sha(observed)==expected,'Runtime projection precondition differs')
            subprocess.run(['docker','exec','-i','samlscope-reference-suite','sh','-c','cat > "$1"','sh',target+'/'+name],input=raw,check=True,capture_output=True)
            observed=subprocess.check_output(['docker','exec','samlscope-reference-suite','cat',target+'/'+name])
        require(observed==raw,'Projected runtime readback differs');installation.append(dict(file=name,sha256=sha(observed)))
    (folder/'receipt-installation.json').write_text(json.dumps(dict(runId=old_install['runId'],path=target,records=installation,readBackVerified=True,reusedExact=False,privacyProjection=True),indent=2)+'\n')
    require(all(sha((folder/name).read_bytes())==digest for name,digest in protected.items()),'Privacy projection changes formal proof/result')
    report=dict(schema='samlscope-unused-login-privacy-projection-v1',runId=old_install['runId'],files=records,
        oldManifestSha256=old_digest,newManifestSha256=sha((folder/'originals/manifest.json').read_bytes()),
        changedManifestFiles=sorted(canonical_changed),formalCaseExecutionManifestHashAbsent=True,
        usedOriginalsUnchanged=True,formalOutcomeAndReferencesUnchanged=True,protectedFiles=protected,
        archivedProductionReplayIdenticalExceptManifestHash=True,runtimeProjectionWrites=3,runtimeProjectionReadBack=True,
        productConfigurationWrites=0,protocolSends=0,humanOperations=0)
    (projection/'projection.json').write_text(json.dumps(report,indent=2)+'\n')
    print('Unused native login nonces removed; original proof/results unchanged, archived production replay identical')
if __name__=='__main__':main()
