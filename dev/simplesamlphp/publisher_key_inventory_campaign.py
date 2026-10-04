#!/usr/bin/env python3
"""Record one native Browser-role publication epoch, without SAML or user authentication.

The existing Run snapshot and case slots are immutable. Native configuration bytes
exist only in memory; only public projections, source files and hashes are exported.
"""
import argparse, base64, datetime, hashlib, json, os, pathlib, re, subprocess, sys, urllib.request
import xml.etree.ElementTree as ET

REPO = pathlib.Path(__file__).resolve().parents[2]
sys.path[:0] = [str(REPO/'dev/keycloak'), str(REPO/'dev/reference-acceptance'), str(REPO/'dev/simplesamlphp')]
from import_metadata_batch import api, save, BASE
from algorithm_preference_campaign import recorded, canonical
from configuration_batch import ConfigurationBatch

CONTAINER = 'samlscope-reference-ssp'
SUITE = 'samlscope-reference-suite'
TARGET = 'http://localhost:18380/idp'
PUBLICATION = 'http://localhost:18380/simplesaml/module.php/saml/idp/metadata'
CAMPAIGN = 'native-metadata-publisher-key-inventory'
CASES = ('IIP-MD05-c1-idp-01', 'IIP-MD05-c3-idp-01')
DEFAULT_RUN = 'run_4FFJTY56TCQY9AKRA0BR0CC5K8'
CONFIG = REPO/'build/acceptance/reference-20260914/ssp-config/saml20-idp-hosted.php'
REMOTE = '/var/simplesamlphp/metadata/saml20-idp-hosted.php'
NS = {'md':'urn:oasis:names:tc:SAML:2.0:metadata','ds':'http://www.w3.org/2000/09/xmldsig#'}
SHA = lambda b: hashlib.sha256(b).hexdigest()
NOW = lambda: datetime.datetime.now(datetime.timezone.utc).isoformat().replace('+00:00','Z')
PREVIOUS = REPO/'build/acceptance/reference-20261004/publisher-cluster-preflight-r1'
SOURCES = {
 'native-idp.php': ('native-public-source-r2/ssp-source-SAML2.php','ae55fc922431d29ca6e87654ae2071500a4c3d7185ed80a6fcc5b26eed12495d'),
 'native-builder.php': ('native-public-source-r1/ssp-source-SAMLBuilder.php','b6c295c053a6b8c178899d3e35c1cf8c9752cd0442e4a45861559c7aa2107591'),
 'native-configuration.php': ('native-public-source-r2/ssp-source-Configuration.php','53837359cd60433082d3968843605a864bab97f23be482447bcfef37e7f6946e'),
 'native-crypto.php': ('native-public-source-r1/ssp-source-Crypto.php','eedf4f4d133e117235d6829c4e386570c5168ad01afe060b3a31f38d0a1db0f3'),
 'native-handler.php': ('native-public-source-r1/ssp-source-MetaDataStorageHandler.php','43a0e730d624c5a937f800c4e7e045ff3625eeb0738d81a4ab1dac96f82fe040'),
 'native-message.php': ('native-public-source-r1/ssp-source-Message.php','ab017ee6cf9fb66db1037e40ed50feff0b277b1a5d43fd8ca774a3d27ce355d2'),
 'native-controller.php': ('native-public-source-r1/ssp-source-Metadata.php','e048fb572f43168187c178e0927f9e6c885031197b8a9c8682539963dde8ec56')}

def require(value, message):
    if not value: raise ValueError(message)

def reject_sensitive(value):
    if isinstance(value,dict):
        for name,item in value.items():
            key=re.sub(r'[-_.]','',name.lower())
            require(not any(s in key for s in ('cookie','authorization','password','passwd','secret','token','privatekey'))
                and not ('credentials' in key and key!='currentcredentials'), 'Private public-projection field refused before recording')
            reject_sensitive(item)
    elif isinstance(value,list):
        for item in value: reject_sensitive(item)
    elif isinstance(value,str):
        require(re.search(r'-----BEGIN (?:RSA |EC |ENCRYPTED )?PRIVATE KEY-----',value) is None, 'Private material refused before recording')

def slots(result, run):
    require(result['run']['id']==run and result['target']['role']=='IDP', 'Foreign role/Run')
    rows={c['id']:c for req in result['requirements'] for c in req['cases']}
    require(all(c in rows and rows[c]['mode']=='CONFIG' for c in CASES), 'Both real approved CONFIG slots required before native writes')
    return {c:rows[c] for c in CASES}

def public_xml(raw, entity=TARGET):
    root=ET.fromstring(raw)
    require(root.tag=='{'+NS['md']+'}EntityDescriptor' and root.attrib['entityID']==entity, 'Foreign public metadata')
    roles=root.findall('md:IDPSSODescriptor' if entity==TARGET else 'md:SPSSODescriptor',NS)
    require(len(roles)==1, 'Ambiguous public metadata role')
    return roles[0]

def native_gaps(state):
    require(state['schema']=='samlscope-ssp-public-publisher-state-v1' and state['entityId']==TARGET, 'Unexpected native projection')
    require({x['logicalFile'] for x in state['loadedClasses']}==set(SOURCES),'Missing/duplicate native source class')
    for row in state['loadedClasses']:
        require(row['logicalFile'] in SOURCES and row['sha256']==SOURCES[row['logicalFile']][1], 'Unrecognized native producer source')
    require(len(state['loadedClasses'])==len(SOURCES), 'Incomplete native source closure')
    sources=state['metadataSources'];require(len(sources)==1 and sources[0]['type']=='flatfile', 'Additional metadata storage not qualified')
    flags=state['roleFeatureFlags'];require(all(type(flags.get(x)) is bool for x in ('saml20.ecp','saml20.hok.assertion','saml20.sendartifact','metadata.sign.enable')),'Native flags must be booleans');gaps=[]
    if any(flags[x] is True for x in ('saml20.ecp','saml20.hok.assertion','saml20.sendartifact')): gaps.append('additional-role-protocol-transport-scope-unproven')
    if flags['metadata.sign.enable'] is True: gaps.append('separate-document-signing-producer-scope-unproven')
    for row in state['currentCredentials']:
        if row['prefix'] and row['publicCertificatePresent']:gaps.append('additional-current-purpose-unproven:'+row['prefix'])
    if any(p['signatureOverridePresent'] or p['sharedEncryptionOverridePresent'] for p in state['remotePeers']):gaps.append('peer-override-current-purpose-unproven')
    for kind in ('SingleSignOnService','SingleLogoutService','ArtifactResolutionService'):
        for endpoint in state['publicNativeMetadata'].get(kind,[]):
            if not endpoint['Location'].startswith('http://'):gaps.append('endpoint-transport-authentication-scope-unproven')
            if endpoint['Binding'] not in ('urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST','urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect'):gaps.append('additional-endpoint-binding-transport-scope-unproven')
    return sorted(set(gaps))

class MountedPublisherConfigurationBatch(ConfigurationBatch):
    """Modify the existing host inode; a read-only guest mount needs no guest write."""
    def __init__(self,path,mount_reader=None,hash_reader=None):
        super().__init__(path)
        require(not any(p.is_symlink() for p in [path,*path.parents]),'Unsafe mounted host source')
        self.mount_reader=mount_reader or self._mounts
        self.hash_reader=hash_reader or self._native_hash
        self.mount=self._selected_mount();self.native_readbacks=[]
        self._verify_native(self.original,'initial')
    @staticmethod
    def _mounts():
        return json.loads(subprocess.check_output(['docker','inspect','--format','{{json .Mounts}}',CONTAINER],timeout=20))
    @staticmethod
    def _native_hash():
        raw=subprocess.check_output(['docker','exec',CONTAINER,'sha256sum',REMOTE],timeout=30).decode().split()
        require(len(raw)==2 and raw[1]==REMOTE and re.fullmatch('[0-9a-f]{64}',raw[0]),'Ambiguous native mounted readback')
        return raw[0]
    def _selected_mount(self):
        rows=[m for m in self.mount_reader() if m.get('Destination')==REMOTE]
        require(len(rows)==1,'Native file mount must be unique')
        m=rows[0]
        require(m.get('Type')=='bind' and type(m.get('RW')) is bool and m['RW'] is False
            and m.get('Source')==str(self.path.resolve()),'Native read-only mount does not bind the exact host file')
        return {k:m[k] for k in ('Type','Source','Destination','RW')}
    def _verify_native(self,payload,phase,restoring=False):
        require(self._selected_mount()==self.mount,'Native mount changed during configuration')
        started=NOW();digest=self.hash_reader();self.native_readbacks.append(dict(phase=phase,startedAt=started,finishedAt=NOW(),sha256=digest,expectedSha256=SHA(payload)))
        # A failed apply can leave the guest at the known original bytes. The
        # host's owned overlay still needs restoration; never allow unknown bytes.
        allowed={SHA(payload),SHA(self.original)} if restoring else {SHA(payload)}
        require(digest in allowed,'Host and actual native mounted bytes differ')
    def _write(self,payload):
        self._verify_native(self.expected,'before-host-write',restoring=payload==self.original and self.expected!=self.original)
        inode=self.path.stat().st_ino
        super()._write(payload)  # No container/container_path: only the existing host inode.
        require(self.path.stat().st_ino==inode,'Mounted host inode was replaced')
        self._verify_native(payload,'after-host-write')

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output',type=pathlib.Path,required=True);p.add_argument('--run',default=DEFAULT_RUN)
    p.add_argument('--browser-epoch',action='store_true',help='One explicit ECP=false epoch and exact restoration; requires serialized native lease')
    p.add_argument('--preflight-only',action='store_true',help='Read-only public preflight; do not publish Recorder records or change native settings')
    a=p.parse_args();require(re.fullmatch(r'run_[0-9A-HJKMNP-TV-Z]{26}',a.run),'Invalid Run')
    out=a.output.absolute();require(not any(x.is_symlink() for x in [out,*out.parents]),'Unsafe output path')
    out.mkdir(parents=True,exist_ok=False);receipt=out/'receipt';receipt.mkdir();(out/'collector-source.py').write_bytes(pathlib.Path(__file__).read_bytes())
    require(os.statvfs(REPO).f_bavail*os.statvfs(REPO).f_frsize>=64*1024*1024,'Insufficient disk; native operations0')
    # A real immutable Run slot is checked before any target operation or write.
    result=api('/api/runs/'+a.run+'/result.json');case_slots=slots(result,a.run);save(out/'result-before.json',result)
    created=api('/api/runs/'+a.run);run=created.get('run',created);require(run['id']==a.run,'Foreign Run document')
    plan=api('/api/plans/'+run['planId']);plan=plan.get('plan',plan);plan=plan.get('plan',plan)
    require(plan['profile']=='metadata_idp' and plan['id']==run['planId'],'Publisher proof requires real metadata_idp Run')
    created={'run':run};save(out/'created.json',created);save(receipt/'created.json',created);save(out/'plan.json',plan);save(out/'formal-slots.json',case_slots)
    old=api('/api/runs/'+a.run+'/transcript');save(out/'transcript-before-collection.json',old)
    subprocess.run(['docker','cp',SUITE+':/data/target-metadata/'+a.run+'.xml',str(receipt/'target-metadata.xml')],check=True,capture_output=True,timeout=40)
    target=(receipt/'target-metadata.xml').read_bytes();public_xml(target)
    require(result['target']['metadata_digest']=='sha256:'+SHA(target),'Initial snapshot digest differs')
    for name in ('publisher_public_readback.php','publisher_detector_control.php'):
        (receipt/('native-public-readback.php' if name.startswith('publisher_public') else 'native-publisher-control.php')).write_bytes(pathlib.Path(__file__).with_name(name).read_bytes())
    source_dir=receipt/'native-source';source_dir.mkdir()
    for name,(relative,digest) in SOURCES.items():
        data=(PREVIOUS/relative).read_bytes();require(SHA(data)==digest,'Public source archive changed');(source_dir/name).write_bytes(data)
    counts=dict(productSettings=0,configurationRestorations=0,nativePublicCalls=0,credentialPosts=0,samlSubmissions=0,personOperations=0)
    operations=[];public_reads=[];refs={};decoded={};batch=None;original_state=None;restoration={'restored':False};manifest=None
    def runtime():
        cmd=['docker','inspect','--format','{"id":{{json .Id}},"image":{{json .Image}},"running":{{json .State.Running}},"startedAt":{{json .State.StartedAt}},"mounts":{{json .Mounts}}}',CONTAINER]
        raw=subprocess.check_output(cmd,timeout=20);n=json.loads(raw);require(n['running'] is True,'Native not running');n['mounts']=sorted(n['mounts'],key=lambda x:canonical(x));return n
    def read_public(label):
        before=runtime();start=NOW();cmd=['docker','exec','-i',CONTAINER,'php','-d','display_errors=0','-d','log_errors=0'];data=(receipt/'native-public-readback.php').read_bytes()
        counts['nativePublicCalls']+=1;row=dict(operation='docker-exec-php-stdin-public-projection',command=cmd,inputSha256=SHA(data),startedAt=start);operations.append(row);save(out/'operations.json',operations)
        r=subprocess.run(cmd,input=data,capture_output=True,timeout=40);end=NOW();row.update(finishedAt=end,exitCode=r.returncode,outputSha256=SHA(r.stdout));save(out/'operations.json',operations)
        require(r.returncode==0,'Native public projection failed; stderr never persisted');n=json.loads(r.stdout);reject_sensitive(n);native_gaps(n);require(before==runtime(),'Native epoch changed during projection')
        require(SHA(base64.b64decode(n['nativeProducedMetadataXmlBase64'],validate=True))==n['nativeProducedMetadataSha256'],'Native producer bytes differ')
        d=receipt/'native-readbacks';d.mkdir(exist_ok=True);file='native-readbacks/'+label+'.json';(receipt/file).write_bytes(r.stdout)
        return n,dict(readbackFile=file,readbackSha256=SHA(r.stdout),runtime=before,invocation=row,nativeStartedAt=start,nativeFinishedAt=end)
    def record(label,kind,**fields):
        n=dict(schema='samlscope-native-publisher-original-v1',runId=a.run,campaignId=CAMPAIGN,targetMetadataSha256=SHA(target),recordedAt=NOW(),kind=kind,**fields);reject_sensitive(n)
        ref=recorded(receipt,created,n,label);ref['file']='native-originals/'+label+'.json';refs[label]=ref;decoded[ref['reference']]=canonical(n);return n
    def state(label,epoch):
        n,fields=read_public(label);record(label,'native-role-inventory',epochId=epoch,adapter='simplesamlphp-stock-publisher-inventory-v1',**fields);return n
    def publication(label):
        start=NOW();req=urllib.request.Request(PUBLICATION,headers={'Cache-Control':'no-cache'})
        row=dict(label=label,method='GET',url=PUBLICATION,startedAt=start);public_reads.append(row);save(out/'public-read-operations.json',public_reads)
        with urllib.request.urlopen(req,timeout=30) as response:raw=response.read();status=response.status
        end=NOW();row.update(finishedAt=end,responseStatus=status,responseSha256=SHA(raw));save(out/'public-read-operations.json',public_reads)
        require(status==200,'Native publication GET failed');public_xml(raw);file='native-publications/'+label+'.xml';(receipt/'native-publications').mkdir(exist_ok=True);(receipt/file).write_bytes(raw)
        return raw,dict(method='GET',url=PUBLICATION,responseStatus=status,publicationSha256=SHA(raw),nativeStartedAt=start,nativeFinishedAt=end),file
    try:
        initial,initial_fields=read_public('initial');original_state=initial
        raw,_,_=publication('initial');require(raw==target and initial['nativeProducedMetadataSha256']==SHA(raw),'Existing Run snapshot no longer matches native publication; no write')
        save(out/'native-gap-preflight.json',dict(runId=a.run,gaps=native_gaps(initial),c3Missing=['multiple-current-same-purpose'],additionalSaml=0,additionalCredentials=0))
        if a.preflight_only:return
        require(a.browser_epoch,'Explicit Browser-role epoch is required; no silent capability exemption')
        require(native_gaps(initial)==['additional-endpoint-binding-transport-scope-unproven','additional-role-protocol-transport-scope-unproven'], 'Unexpected native scope gap; no configuration write')
        require(initial['roleFeatureFlags']=={'saml20.ecp':True,'saml20.hok.assertion':False,'saml20.sendartifact':False,'metadata.sign.enable':False},'Unsupported role epoch')
        record('initial','native-role-inventory',epochId='initial',adapter='simplesamlphp-stock-publisher-inventory-v1',**initial_fields)
        # Public-only detector input. Existing server TLS certificate is a calibration
        # material, never evidence of SAML-role transport use.
        peer_url=BASE+'/p/'+run['planId']+'/metadata'
        with urllib.request.urlopen(peer_url,timeout=30) as response:peer_xml=response.read()
        peer_role=public_xml(peer_xml,BASE+'/p/'+run['planId']);certs=peer_role.findall('md:KeyDescriptor/ds:KeyInfo/ds:X509Data/ds:X509Certificate',NS);require(certs,'Public secondary detector key absent')
        current=next(x for x in initial['currentCredentials'] if x['prefix']=='')['certificateDerBase64'];other=''.join(certs[0].text.split())
        require(current!=other,'Detector requires distinct public signing keys')
        tls=json.loads((PREVIOUS/'native-transport-public-r2/public-tls-readback.json').read_bytes())['loopbackTls']['certificatePem'];tls=''.join(tls.replace('-----BEGIN CERTIFICATE-----','').replace('-----END CERTIFICATE-----','').split())
        require(tls not in (current,other),'Distinct detector transport key required')
        input_value=dict(schema='samlscope-native-publisher-detector-input-v1',purpose='oracle-calibration-only',entityId=TARGET,
            SingleSignOnService=[e for e in initial['publicNativeMetadata']['SingleSignOnService'] if e['Binding'].endswith('HTTP-Redirect')],
            SingleLogoutService=initial['publicNativeMetadata']['SingleLogoutService'],roleKeys=[dict(purpose=x,certificateDerBase64=y) for x,y in [('signing',current),('signing',other),('encryption',other),('transport-authentication',tls)]])
        input_raw=canonical(input_value);(receipt/'control-input.json').write_bytes(input_raw);invocations=[]
        program=(receipt/'native-publisher-control.php').read_bytes();code=re.sub(r'^<\?php\s*','',program.decode())
        for mode,label in [('stock-native-builder','positive'),('developer-omitted-transport-key','negative')]:
            cmd=['docker','exec','-i',CONTAINER,'php','-d','display_errors=0','-r',code,mode,SHA(program)];before=runtime();start=NOW();counts['nativePublicCalls']+=1
            row=dict(mode=mode,command=cmd,sourceSha256=SHA(program),inputSha256=SHA(input_raw),startedAt=start,runtimeBefore=before);operations.append(row);save(out/'operations.json',operations)
            r=subprocess.run(cmd,input=input_raw,capture_output=True,timeout=40);row.update(finishedAt=NOW(),exitCode=r.returncode,outputSha256=SHA(r.stdout),runtimeAfter=runtime());save(out/'operations.json',operations)
            require(r.returncode==0 and row['runtimeBefore']==row['runtimeAfter']==initial_fields['runtime'],'Native detector invocation failed or epoch changed')
            reject_sensitive(json.loads(r.stdout));(receipt/('control-'+label+'.json')).write_bytes(r.stdout);invocations.append(row)
        save(receipt/'control-invocations.json',invocations)
        record('controls','native-publisher-detector-control',purpose='oracle-calibration-only',positiveControlIds=['iip-md05-c1-idp-01-positive','iip-md05-c3-idp-01-positive'],negativeControlIds=['iip-md05-c1-idp-01-negative','iip-md05-c3-idp-01-negative'],inputSha256=SHA(input_raw),positiveOutputSha256=SHA((receipt/'control-positive.json').read_bytes()),negativeOutputSha256=SHA((receipt/'control-negative.json').read_bytes()))
        batch=MountedPublisherConfigurationBatch(CONFIG)
        require(SHA(batch.original)==next(x['sha256'] for x in initial['configurationHashes'] if x['file']==REMOTE),'Host/native configuration mismatch')
        start=NOW();batch.apply(("$metadata['"+TARGET+"']['saml20.ecp'] = false;").encode());end=NOW();counts['productSettings']=batch.write_count
        record('browser-transition','native-configuration-transition',epochId='browser-role',path=REMOTE,configurationPurpose='browser-role-no-ecp',startedAt=start,completedAt=end,beforeConfigurationSha256=SHA(batch.original),afterConfigurationSha256=SHA(batch.expected))
        configured=state('browser-before','browser-role');require(native_gaps(configured)==[],'Unexpected native role scope; restore without adoption')
        start=NOW();raw,http,file=publication('browser-role');end=NOW();require(configured['nativeProducedMetadataSha256']==SHA(raw),'Actual native publication differs from stock producer')
        record('browser-publication','native-publication',epochId='browser-role',**http)
        final=state('browser-after','browser-role');require(configured['configurationHashes']==final['configurationHashes'],'Configuration changed during publication')
        manifest=dict(schema='samlscope-native-metadata-publisher-key-inventory-v1',adapter='simplesamlphp-stock-publisher-inventory-v1',campaignId=CAMPAIGN,runId=a.run,planId=run['planId'],entityId=TARGET,targetMetadataSha256=SHA(target),recorderUrl=BASE+'/p/'+run['planId']+'/sp/paos?run='+a.run,selectedPath='stock-current-role',counterfactualCalibrationOnly=False,epochs=[dict(id='browser-role',startedAt=start,finishedAt=end,beforeOriginal='browser-before',afterOriginal='browser-after',publicationFile=file,publicationOriginal='browser-publication',transition='explicit-native-configuration',transitionOriginal='browser-transition')],controls=dict(inputFile='control-input.json',positiveOutputFile='control-positive.json',negativeOutputFile='control-negative.json',invocationsFile='control-invocations.json',original='controls'))
    finally:
        try:
            if batch is not None:
                restoration=batch.restore();save(out/'restoration-write.json',restoration)
                counts['productSettings']=batch.write_count;counts['configurationRestorations']=batch.restoration_writes
                if restoration['restored'] and manifest is not None:
                    restored=state('restored','restored');raw,http,file=publication('restored');require(raw==target,'Restored publication does not match immutable Run snapshot')
                    paths=[dict(path=x['file'],originalSha256=x['sha256'],finalSha256=next(y['sha256'] for y in restored['configurationHashes'] if y['file']==x['file'])) for x in original_state['configurationHashes']]
                    record('restoration','native-publisher-restoration',restored=True,configurationHashes=paths,restoredPublicationFile=file,restoredPublicationSha256=SHA(raw),restoredPublicationHttp=http,operationCounts=counts)
        finally:
            if batch is not None:
                counts['productSettings']=batch.write_count;counts['configurationRestorations']=batch.restoration_writes
                save(out/'native-mounted-configuration-readbacks.json',dict(mount=batch.mount,readbacks=batch.native_readbacks,guestWriteAttempts=0))
            save(out/'operation-counts.json',counts);save(out/'operations.json',operations)
            save(out/'restoration.json',restoration)
    require(manifest is not None and restoration['restored'],'Incomplete native evidence; remains unadopted')
    history=api('/api/runs/'+a.run+'/transcript');save(out/'transcript.json',history)
    require([e for e in history if e['id'] in {x['id'] for x in old}]==old,'Existing transcript entries changed')
    d=out/'decoded';d.mkdir();decoded_manifest=[]
    for id,data in decoded.items():(d/(id+'.xml')).write_bytes(data);decoded_manifest.append(dict(id=id,file='decoded/'+id+'.xml',sha256=SHA(data)))
    save(out/'decoded-manifest.json',decoded_manifest);(out/'target-metadata.xml').write_bytes(target)
    manifest['originals']=refs;manifest['files']={str(x.relative_to(receipt)):SHA(x.read_bytes()) for x in receipt.rglob('*') if x.is_file()}
    save(receipt/'manifest.json',manifest);save(out/'qualification.json',dict(runId=a.run,caseSlotsExisting=True,initialTargetSnapshotUnchanged=True,adopted=False,settingsRestored=True,newSaml=0,newCredentials=0,personOperations=0,c3MultipleCurrentMissing=True))
    print(json.dumps(dict(runId=a.run,restored=True,operationCounts=counts,caseAdopted=False)))

if __name__=='__main__':main()
