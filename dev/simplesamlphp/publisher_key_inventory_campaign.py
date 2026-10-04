#!/usr/bin/env python3
"""Record a native publisher epoch with an explicit optional per-peer signer operation.

The existing Run snapshot and case slots are immutable. Native configuration bytes
exist only in memory; only public projections, source files and hashes are exported.
"""
import argparse, base64, datetime, hashlib, importlib.util, json, os, pathlib, re, subprocess, sys, time, urllib.request, zipfile
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
PEER_CONFIG = CONFIG.with_name('saml20-sp-remote.php')
PEER_REMOTE = '/var/simplesamlphp/metadata/saml20-sp-remote.php'
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

def planned_publisher_scope(raw, plan):
    """A deployed profile proves planned scope; formal slots follow normal M0."""
    profile=json.loads(raw)
    rows={c['id']:c for c in profile['cases']}
    require(plan['profile']=='metadata_idp' and plan['target']['entityId']==TARGET
            and set(CASES)<=set(rows) and all(re.fullmatch('sha256:[0-9a-f]{64}',rows[c]['digest']) for c in CASES),
            'Both approved publisher cases must be planned before native setup')
    return dict(profile='metadata_idp',planId=plan['id'],caseDigests={c:rows[c]['digest'] for c in CASES},
                profileSha256=SHA(raw),formalSlotsConfirmed=False)

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

class MountedPeerConfigurationBatch(ConfigurationBatch):
    """Own one RW remote-peer overlay, including exact host and native restoration."""
    def __init__(self,path,mount_reader=None,hash_reader=None,guest_writer=None):
        super().__init__(path)
        require(not any(p.is_symlink() for p in [path,*path.parents]),'Unsafe remote-peer host source')
        self.mount_reader=mount_reader or MountedPublisherConfigurationBatch._mounts
        self.hash_reader=hash_reader or self._native_hash
        self.guest_writer=guest_writer or self._push_native
        self.guest_write_attempts=0;self.successful_host_writes=0;self.successful_guest_writes=0;self.native_readbacks=[]
        self.mount=self._selected_mount();self._verify_native(self.original,'initial')
    @staticmethod
    def _native_hash():
        raw=subprocess.check_output(['docker','exec',CONTAINER,'sha256sum',PEER_REMOTE],timeout=30).decode().split()
        require(len(raw)==2 and raw[1]==PEER_REMOTE and re.fullmatch('[0-9a-f]{64}',raw[0]),'Ambiguous remote-peer native hash')
        return raw[0]
    @staticmethod
    def _push_native(payload):
        subprocess.run(['docker','exec','-i',CONTAINER,'sh','-c','cat > "$1"','publisher-peer-write',PEER_REMOTE],
                       input=payload,check=True,capture_output=True,timeout=40)
    def _selected_mount(self):
        rows=[m for m in self.mount_reader() if m.get('Destination')==PEER_REMOTE]
        require(len(rows)==1,'Remote-peer native mount must be unique')
        m=rows[0]
        require(m.get('Type')=='bind' and m.get('RW') is True and m.get('Source')==str(self.path.resolve()),
                'Remote-peer mount must bind the exact writable host file')
        return {k:m[k] for k in ('Type','Source','Destination','RW')}
    def _verify_native(self,payload,phase,restoring=False):
        require(self._selected_mount()==self.mount,'Remote-peer native mount changed')
        started=NOW();digest=self.hash_reader()
        self.native_readbacks.append(dict(phase=phase,startedAt=started,finishedAt=NOW(),sha256=digest,expectedSha256=SHA(payload)))
        allowed={SHA(payload),SHA(self.original)} if restoring else {SHA(payload)}
        require(digest in allowed,'Unknown remote-peer native bytes; refusing overwrite')
    def _write(self,payload):
        self._verify_native(self.expected,'before-host-write',restoring=payload==self.original and self.expected!=self.original)
        inode=self.path.stat().st_ino
        # The base helper tracks the owned host write even if the following push fails.
        # Its container attributes remain unset so every native write is counted here.
        super()._write(payload)
        self.successful_host_writes+=1
        require(self.path.stat().st_ino==inode,'Remote-peer host inode was replaced')
        self.guest_write_attempts+=1;self.guest_writer(payload)
        self._verify_native(payload,'after-native-write')
        self.successful_guest_writes+=1

EPHEMERAL_SIGNER_CREATE = r'''<?php
$directory=$argv[1];$owner=$argv[2];
if(file_exists($directory)||is_link($directory)){throw new RuntimeException('Native ownership unavailable');}
if(!mkdir($directory,0700)){throw new RuntimeException('Native ownership creation failed');}
if(file_put_contents($directory.'/owner',$owner,LOCK_EX)!==strlen($owner)){
 @unlink($directory.'/owner');@rmdir($directory);throw new RuntimeException('Native ownership recording failed');
}
$key=openssl_pkey_new(['private_key_type'=>OPENSSL_KEYTYPE_RSA,'private_key_bits'=>2048]);
if($key===false){throw new RuntimeException('Native key generation failed');}
$csr=openssl_csr_new(['commonName'=>'SAMLscope native peer signer'],$key,['digest_alg'=>'sha256']);
if($csr===false){throw new RuntimeException('Native certificate request failed');}
$certificate=openssl_csr_sign($csr,null,$key,1,['digest_alg'=>'sha256']);
if($certificate===false||!openssl_pkey_export($key,$private)||!openssl_x509_export($certificate,$public)){
 throw new RuntimeException('Native credential generation failed');
}
if(file_put_contents($directory.'/signer.pem',$private,LOCK_EX)!==strlen($private)||!chmod($directory.'/signer.pem',0600)
 ||file_put_contents($directory.'/signer.crt',$public,LOCK_EX)!==strlen($public)||!chmod($directory.'/signer.crt',0644)){
 throw new RuntimeException('Native credential installation failed');
}
$details=openssl_pkey_get_details($key);$spki=$details['key'];
$der=base64_decode(preg_replace('/-----(?:BEGIN|END) CERTIFICATE-----|\s/','',$public),true);
unset($private,$key,$details,$certificate,$csr);
echo json_encode(['created'=>true,'certificateDerBase64'=>base64_encode($der),'certificateSha256'=>hash('sha256',$der),
 'publicSpkiPem'=>$spki,'publicSpkiPemSha256'=>hash('sha256',$spki)],JSON_THROW_ON_ERROR),"\n";
'''
EPHEMERAL_SIGNER_REMOVE = r'''<?php
$directory=$argv[1];$owner=$argv[2];
if(!file_exists($directory)&&!is_link($directory)){echo json_encode(['removed'=>false,'absent'=>true]),"\n";exit;}
if(is_link($directory)||!is_dir($directory)||is_link($directory.'/owner')
 ||!is_file($directory.'/owner')||file_get_contents($directory.'/owner')!==$owner){throw new RuntimeException('Foreign native material preserved');}
foreach(['signer.pem','signer.crt'] as $file){$path=$directory.'/'.$file;
 if(is_link($path)){throw new RuntimeException('Foreign native material preserved');}
 if(is_file($path)&&!unlink($path)){throw new RuntimeException('Native material removal failed');}
}
if(!unlink($directory.'/owner')||!rmdir($directory)){throw new RuntimeException('Native ownership removal failed');}
echo json_encode(['removed'=>true,'absent'=>!file_exists($directory)&&!is_link($directory)],JSON_THROW_ON_ERROR),"\n";
'''

class NativeEphemeralSigner:
    """Native-only credential ownership; the runner returns public projections only."""
    def __init__(self,directory,owner,runner):
        require(re.fullmatch(r'/tmp/samlscope-publisher-signers-[0-9a-f]{24}',directory),'Unsafe native material directory')
        require(re.fullmatch(r'[0-9a-f]{64}',owner),'Unsafe native material ownership')
        self.directory=directory;self.owner=owner;self.runner=runner
        self.private_path=directory+'/signer.pem';self.certificate_path=directory+'/signer.crt'
        self.creations=0;self.removals=0;self.create_attempts=0;self.remove_attempts=0;self.attempted=False
    def create(self):
        self.attempted=True;self.create_attempts+=1
        value=json.loads(self.runner(EPHEMERAL_SIGNER_CREATE,arguments=(self.directory,self.owner),operation='native-ephemeral-public-material-create'))
        reject_sensitive(value)
        require(set(value)=={'created','certificateDerBase64','certificateSha256','publicSpkiPem','publicSpkiPemSha256'}
                and value['created'] is True,'Unexpected native public material projection')
        der=base64.b64decode(value['certificateDerBase64'],validate=True)
        require(der and SHA(der)==value['certificateSha256'] and value['publicSpkiPem'].startswith('-----BEGIN PUBLIC KEY-----\n')
                and SHA(value['publicSpkiPem'].encode())==value['publicSpkiPemSha256'],'Native public material identity differs')
        self.creations+=1;return value
    def cleanup(self):
        if not self.attempted:return dict(removed=False,absent=True)
        self.remove_attempts+=1
        value=json.loads(self.runner(EPHEMERAL_SIGNER_REMOVE,arguments=(self.directory,self.owner),operation='native-ephemeral-public-material-remove'))
        reject_sensitive(value)
        require(set(value)=={'removed','absent'} and type(value['removed']) is bool and value['absent'] is True,
                'Native ephemeral material removal unproven')
        self.removals+=int(value['removed']);return value

def validate_flow_budget(counts):
    require(all(type(counts.get(k)) is int for k in ('samlSubmissions','credentialPosts','personOperations'))
            and counts.get('samlSubmissions')==3 and counts.get('credentialPosts')==1
            and counts.get('personOperations')==0,'Used signers require exactly three actual SSO submissions and one shared authentication')

def validate_used_signer_epoch(before,after,peer_rows,flow_rows,target_digest):
    require(re.fullmatch('[0-9a-f]{64}',target_digest),'Unsafe fixed target digest')
    for field in ('configurationHashes','roleFeatureFlags','loadedClasses','metadataSources',
                  'currentCredentials','remotePeers','publicNativeMetadata','publicRequestContext'):
        require(field in before and before[field]==after.get(field),'Native signer epoch changed: '+field)
    require(before.get('nativeProducedMetadataSha256')==after.get('nativeProducedMetadataSha256')==target_digest,
            'Hosted producer changed during native signer epoch')
    require(len(peer_rows)==len(flow_rows)==2 and {p['label'] for p in peer_rows}=={'primary','secondary'},
            'Two distinct actual signing peers are required')
    for field in ('runId','planId','entityId'):
        require(len({p[field] for p in peer_rows})==2,'Duplicate native signing peer '+field)
    flows={f['label']:f for f in flow_rows};require(set(flows)=={'primary','secondary'},'Duplicate or missing actual signer flow')
    rows=[];request_refs=set();response_refs=set()
    for p in peer_rows:
        require(re.fullmatch(r'run_[0-9A-HJKMNP-TV-Z]{26}',p['runId']) and re.fullmatch(r'plan_[0-9A-HJKMNP-TV-Z]{26}',p['planId'])
                and p['entityId']==BASE+'/p/'+p['planId'],'Foreign actual signing peer identity')
        f=flows[p['label']]
        require(f['runId']==p['runId'] and f['startedAt']<=f['finishedAt'],'Foreign or unordered actual signing flow')
        for field,seen in (('requestReference',request_refs),('responseReference',response_refs)):
            require(re.fullmatch(r'tx_[0-9A-HJKMNP-TV-Z]{26}',f[field]) and f[field] not in seen,'Duplicate/foreign actual signer '+field)
            seen.add(f[field])
        row={k:p[k] for k in ('label','runId','planId','entityId','fixtureFile','createdFile','planFile')}
        require(all(row[k]==p['label']+'/'+v for k,v in (('fixtureFile','fixture.xml'),('createdFile','created.json'),('planFile','plan.json'))),
                'Foreign signing peer evidence path')
        row.update(requestReference=f['requestReference'],responseReference=f['responseReference'],signerUseOriginal=p['label']+'-signer-use')
        rows.append(row)
    require(not request_refs.intersection(response_refs),'Actual signer request and response references overlap')
    return rows

def response_signer_identity(raw):
    """Identify only the direct Response signature certificate; never trust a child hint."""
    root=ET.fromstring(raw)
    require(root.tag=='{urn:oasis:names:tc:SAML:2.0:protocol}Response','Actual signer original is not a SAML Response')
    signatures=root.findall('ds:Signature',NS)
    require(len(signatures)==1,'Actual Response must have one direct signature')
    certificates=signatures[0].findall('ds:KeyInfo/ds:X509Data/ds:X509Certificate',NS)
    require(len(certificates)==1 and certificates[0].text,'Actual Response signing certificate is ambiguous')
    der=base64.b64decode(''.join(certificates[0].text.split()),validate=True)
    public=subprocess.run(['openssl','x509','-inform','DER','-pubkey','-noout'],input=der,capture_output=True,check=True,timeout=20).stdout
    require(public.startswith(b'-----BEGIN PUBLIC KEY-----\n'),'Response certificate has no public key')
    spki=base64.b64decode(re.sub(rb'-----(?:BEGIN|END) PUBLIC KEY-----|\s',b'',public),validate=True)
    return dict(certificateSha256=SHA(der),responseCertificateSpkiSha256=SHA(spki))

def collect_used_signers(args):
    """Collect actual default/peer-override signatures without changing hosted metadata."""
    # Several products have a file with this name. The authenticated client and
    # parser must be the actual SimpleSAMLphp implementation, not sys.path order.
    spec=importlib.util.spec_from_file_location('publisher_ssp_registered_signer',pathlib.Path(__file__).with_name('registered_signer_campaign.py'))
    signer=importlib.util.module_from_spec(spec);spec.loader.exec_module(signer)
    SharedClient,PARSER=signer.SharedClient,signer.PARSER
    from capture_run_originals import capture
    out=args.output.absolute();require(not any(p.is_symlink() for p in [out,*out.parents]),'Unsafe used-signer output')
    require(os.statvfs(REPO).f_bavail*os.statvfs(REPO).f_frsize>=96*1024*1024,'Insufficient disk before native setup')
    out.mkdir(parents=True,exist_ok=False);receipt=out/'receipt';receipt.mkdir()
    (out/'collector-source.py').write_bytes(pathlib.Path(__file__).read_bytes())
    (receipt/'native-public-readback.php').write_bytes(pathlib.Path(__file__).with_name('publisher_public_readback.php').read_bytes())
    (receipt/'native-publisher-control.php').write_bytes(pathlib.Path(__file__).with_name('publisher_detector_control.php').read_bytes())
    (receipt/'native-parser-command.php').write_text(PARSER)
    # These scripts contain ownership paths but never contain generated private bytes.
    (receipt/'native-material-create-command.php').write_text(EPHEMERAL_SIGNER_CREATE)
    (receipt/'native-material-remove-command.php').write_text(EPHEMERAL_SIGNER_REMOVE)
    source_dir=receipt/'native-source';source_dir.mkdir()
    for name,(relative,digest) in SOURCES.items():
        data=(PREVIOUS/relative).read_bytes();require(SHA(data)==digest,'Native source archive changed');(source_dir/name).write_bytes(data)
    peers=[];operations=[];public_reads=[];refs={};flow_rows=[];client=SharedClient()
    counts=dict(productSettings=0,configurationRestorations=0,nativePublicCalls=0,credentialPosts=0,samlSubmissions=0,
                personOperations=0,nativeEphemeralKeyCreations=0,nativeEphemeralKeyRemovals=0,
                initialBaselineSubmissions=0,selectedSignerSubmissions=0,guestWriteAttempts=0,successfulHostWrites=0,
                successfulGuestWrites=0,nativePeerApplications=0,nativePeerRestorations=0,productRestarts=0)
    batch=None;material=None;public_material=None;initial=None;target=None;created=None;manifest=None
    restoration={'restored':False};original_history=[];runtime_identity=None
    user=os.environ.get('REFERENCE_USERNAME','samlscope-m0-user');password=os.environ.get('REFERENCE_PASSWORD','samlscope-m0-password')

    def runtime():
        command=['docker','inspect','--format','{"id":{{json .Id}},"image":{{json .Image}},"running":{{json .State.Running}},"startedAt":{{json .State.StartedAt}},"mounts":{{json .Mounts}}}',CONTAINER]
        value=json.loads(subprocess.check_output(command,timeout=20));require(value['running'] is True,'Native runtime is stopped')
        value['mounts']=sorted(value['mounts'],key=lambda row:canonical(row));return value
    def native(program,arguments=(),operation='native-public-projection',worker=False):
        before=runtime();require(runtime_identity is None or before==runtime_identity,'Native runtime changed before operation')
        source=program.encode() if isinstance(program,str) else program
        if not source.lstrip().startswith(b'<?php'):source=b'<?php\n'+source
        command=['docker','exec','-i']+(['--user','www-data'] if worker else [])+[CONTAINER,'php','-d','display_errors=0','-d','log_errors=0']
        if arguments or worker:command+=['/dev/stdin',*arguments]
        row=dict(operation=operation,inputSha256=SHA(source),startedAt=NOW(),runtimeBefore=before)
        if not arguments and not worker:row['command']=command
        counts['nativePublicCalls']+=1;operations.append(row);save(out/'operations.json',operations)
        result=subprocess.run(command,input=source,capture_output=True,timeout=40)
        row.update(finishedAt=NOW(),exitCode=result.returncode,outputSha256=SHA(result.stdout),runtimeAfter=runtime());save(out/'operations.json',operations)
        require(row['runtimeAfter']==before,'Native runtime changed during operation')
        require(result.returncode==0,'Native operation failed; stderr and credentials are never persisted')
        return result.stdout
    def record(label,kind,**fields):
        value=dict(schema='samlscope-native-publisher-original-v1',runId=created['run']['id'],campaignId=CAMPAIGN,
                   targetMetadataSha256=SHA(target),recordedAt=NOW(),kind=kind,**fields)
        reject_sensitive(value);ref=recorded(receipt,created,value,label);ref['file']='native-originals/'+label+'.json';refs[label]=ref
        return value
    def read_public(label):
        start=NOW();raw=native((receipt/'native-public-readback.php').read_bytes(),operation='docker-exec-php-stdin-public-projection');end=NOW()
        value=json.loads(raw);reject_sensitive(value);native_gaps(value)
        produced=base64.b64decode(value['nativeProducedMetadataXmlBase64'],validate=True)
        require(SHA(produced)==value['nativeProducedMetadataSha256']==SHA(target),'Hosted publication changed from immutable target snapshot')
        folder=receipt/'native-readbacks';folder.mkdir(exist_ok=True);file='native-readbacks/'+label+'.json';(receipt/file).write_bytes(raw)
        return value,dict(readbackFile=file,readbackSha256=SHA(raw),runtime=runtime(),invocation=operations[-1],nativeStartedAt=start,nativeFinishedAt=end)
    def state(label,epoch):
        value,fields=read_public(label);record(label,'native-role-inventory',epochId=epoch,adapter='simplesamlphp-stock-publisher-inventory-v1',**fields);return value
    def publication(label):
        row=dict(label=label,method='GET',url=PUBLICATION,startedAt=NOW());public_reads.append(row);save(out/'public-read-operations.json',public_reads)
        with urllib.request.urlopen(urllib.request.Request(PUBLICATION,headers={'Cache-Control':'no-cache'}),timeout=30) as response:
            status=response.status;raw=response.read(1024*1024+1)
        row.update(finishedAt=NOW(),responseStatus=status,responseSha256=SHA(raw));save(out/'public-read-operations.json',public_reads)
        require(status==200 and len(raw)<=1024*1024 and raw==target,'Actual hosted publication differs from fixed target original')
        public_xml(raw);folder=receipt/'native-publications';folder.mkdir(exist_ok=True);file='native-publications/'+label+'.xml';(receipt/file).write_bytes(raw)
        return raw,dict(method='GET',url=PUBLICATION,responseStatus=status,publicationSha256=SHA(raw),nativeStartedAt=row['startedAt'],nativeFinishedAt=row['finishedAt']),file
    def history(peer):
        entries=api('/api/runs/'+peer['runId']+'/transcript');seen=set()
        require(isinstance(entries,list),'Actual signing history is not a list')
        for entry in entries:
            require(isinstance(entry,dict) and entry.get('runId')==peer['runId']
                    and re.fullmatch(r'tx_[0-9A-HJKMNP-TV-Z]{26}',entry.get('id','')) and entry['id'] not in seen,
                    'Foreign or duplicate actual signing history')
            seen.add(entry['id'])
        return entries
    def original(peer,entry):
        require(re.fullmatch(r'run_[0-9A-HJKMNP-TV-Z]{26}',peer['runId'])
                and re.fullmatch(r'tx_[0-9A-HJKMNP-TV-Z]{26}',entry['id']) and entry.get('runId')==peer['runId'],
                'Unsafe actual signer content identity')
        reference=entry.get('decodedSamlRef');expected='transcripts/'+peer['runId']+'/'+entry['id']+'.saml.xml'
        require(reference==expected and entry.get('decodedSamlBytes',0)>0,'Actual signer decoded original is missing')
        folder=receipt/peer['label']/'decoded';folder.mkdir(exist_ok=True);destination=folder/(entry['id']+'.xml')
        subprocess.run(['docker','cp',SUITE+':/data/'+reference,str(destination)],check=True,capture_output=True,timeout=30)
        raw=destination.read_bytes();require(len(raw)==entry['decodedSamlBytes'],'Actual signer original byte length differs');return raw
    def real_flow(peer,baseline=False):
        old_ids={e['id'] for e in history(peer)};before=client.native_post_attempts+client.native_redirect_attempts;start=NOW()
        result=client.flow(peer['entityId']+'/start/m0-roundtrip?run='+peer['runId'],None,user,password);end=NOW()
        attempts=client.native_post_attempts+client.native_redirect_attempts-before
        counts['samlSubmissions']=client.native_post_attempts+client.native_redirect_attempts;counts['credentialPosts']=client.credential_posts
        require(result=='recorded' and attempts==1,'One correlated actual signer SSO was not recorded')
        entries=history(peer);requests=[e for e in entries if e['id'] not in old_ids and e.get('direction')=='OUTBOUND'
                    and e.get('samlSummary',{}).get('type')=='AuthnRequest']
        require(len(requests)==1,'Actual signer AuthnRequest is ambiguous');request=requests[0];request_raw=original(peer,request)
        request_id=ET.fromstring(request_raw).get('ID');responses=[e for e in entries if e['id'] not in old_ids and e.get('direction')=='INBOUND'
                    and e.get('samlSummary',{}).get('type')=='Response' and e['samlSummary'].get('inResponseTo')==request_id]
        require(len(responses)==1,'Actual signer Response is ambiguous');response=responses[0];response_raw=original(peer,response)
        identity=response_signer_identity(response_raw)
        row=dict(label=peer['label'],runId=peer['runId'],requestReference=request['id'],responseReference=response['id'],
                 requestSha256=SHA(request_raw),responseSha256=SHA(response_raw),fixtureSha256=SHA((receipt/peer['fixtureFile']).read_bytes()),
                 startedAt=start,finishedAt=end,**identity)
        if baseline:counts['initialBaselineSubmissions']+=1;save(receipt/'baseline.json',row|dict(credentialPosts=client.credential_posts))
        else:counts['selectedSignerSubmissions']+=1
        save(out/'operation-counts.json',counts);return row
    def controls():
        current=next(r for r in initial['currentCredentials'] if r['prefix']=='')['certificateDerBase64']
        peer_role=public_xml((receipt/peers[0]['fixtureFile']).read_bytes(),peers[0]['entityId'])
        certificates=peer_role.findall('md:KeyDescriptor/ds:KeyInfo/ds:X509Data/ds:X509Certificate',NS);require(certificates,'Native detector secondary public key is missing')
        other=''.join(certificates[0].text.split());tls=json.loads((PREVIOUS/'native-transport-public-r2/public-tls-readback.json').read_bytes())['loopbackTls']['certificatePem']
        tls=''.join(tls.replace('-----BEGIN CERTIFICATE-----','').replace('-----END CERTIFICATE-----','').split());require(len({current,other,tls})==3,'Native detector public keys must be distinct')
        value=dict(schema='samlscope-native-publisher-detector-input-v1',purpose='oracle-calibration-only',entityId=TARGET,
                   SingleSignOnService=[e for e in initial['publicNativeMetadata']['SingleSignOnService'] if e['Binding'].endswith('HTTP-Redirect')],
                   SingleLogoutService=initial['publicNativeMetadata']['SingleLogoutService'],roleKeys=[dict(purpose=p,certificateDerBase64=c)
                       for p,c in [('signing',current),('signing',other),('encryption',other),('transport-authentication',tls)]])
        input_raw=canonical(value);(receipt/'control-input.json').write_bytes(input_raw);invocations=[]
        program=(receipt/'native-publisher-control.php').read_bytes();code=re.sub(r'^<\?php\s*','',program.decode())
        for mode,label in [('stock-native-builder','positive'),('developer-omitted-transport-key','negative')]:
            before=runtime();row=dict(mode=mode,sourceSha256=SHA(program),inputSha256=SHA(input_raw),startedAt=NOW(),runtimeBefore=before)
            command=['docker','exec','-i',CONTAINER,'php','-d','display_errors=0','-r',code,mode,SHA(program)]
            row['command']=command
            counts['nativePublicCalls']+=1;operations.append(row);save(out/'operations.json',operations)
            result=subprocess.run(command,input=input_raw,capture_output=True,timeout=40)
            row.update(finishedAt=NOW(),exitCode=result.returncode,outputSha256=SHA(result.stdout),runtimeAfter=runtime());save(out/'operations.json',operations)
            require(result.returncode==0 and before==row['runtimeAfter']==runtime_identity,'Native detector invocation is incomplete')
            reject_sensitive(json.loads(result.stdout));(receipt/('control-'+label+'.json')).write_bytes(result.stdout);invocations.append(row)
        save(receipt/'control-invocations.json',invocations)
        record('controls','native-publisher-detector-control',purpose='oracle-calibration-only',
               positiveControlIds=['iip-md05-c1-idp-01-positive','iip-md05-c3-idp-01-positive'],
               negativeControlIds=['iip-md05-c1-idp-01-negative','iip-md05-c3-idp-01-negative'],inputSha256=SHA(input_raw),
               positiveOutputSha256=SHA((receipt/'control-positive.json').read_bytes()),negativeOutputSha256=SHA((receipt/'control-negative.json').read_bytes()))

    try:
        for label,profile in [('primary','metadata_idp'),('secondary','browser_sso_idp')]:
            folder=receipt/label;folder.mkdir()
            response=api('/api/plans',dict(name='SimpleSAMLphp actual publisher signer '+label,profile=profile,targetKind='IDP',targetEntityId=TARGET,
                metadataSourceKind='URL',metadataSourceLocation='http://samlscope-reference-ssp/simplesaml/module.php/saml/idp/metadata',
                suiteMetadataDelivery='HTTP_URL',declaredFeatures={},parameters=dict(clockSkewToleranceSeconds=180,metadataRefreshWaitSeconds=300,
                testUserHint='Shared native signer observation',requestSigningMode='REQUIRED'),interaction=dict(allowBrowserSteps=True,allowAttestation=False,preset='quick'),authorizedTarget=True))
            plan=response['plan']['plan'];plan_id=plan['id']
            require(re.fullmatch(r'plan_[0-9A-HJKMNP-TV-Z]{26}',plan_id) and plan['profile']==profile
                    and plan['target']['entityId']==TARGET,'Foreign fresh signing Plan')
            peer_created=api('/api/plans/'+plan_id+'/runs',{});peer_run=peer_created['run']
            require(re.fullmatch(r'run_[0-9A-HJKMNP-TV-Z]{26}',peer_run['id']) and peer_run['planId']==plan_id,
                    'Foreign fresh signing Run')
            save(folder/'plan.json',plan);save(folder/'created.json',peer_created);save(folder/'preflight.json',api('/api/runs/'+peer_run['id']+'/preflight',{}))
            peer=dict(label=label,runId=peer_run['id'],planId=plan_id,entityId=BASE+'/p/'+plan_id,
                      fixtureFile=label+'/fixture.xml',createdFile=label+'/created.json',planFile=label+'/plan.json')
            peers.append(peer)
            subprocess.run(['docker','cp',SUITE+':/data/target-metadata/'+peer_run['id']+'.xml',str(folder/'target-metadata.xml')],check=True,capture_output=True,timeout=30)
            peer_target=(folder/'target-metadata.xml').read_bytes()
            if label=='primary':
                created=peer_created;target=peer_target;save(out/'created.json',created);save(receipt/'created.json',created);save(out/'plan.json',plan)
                (receipt/'target-metadata.xml').write_bytes(target);(out/'target-metadata.xml').write_bytes(target)
                archive=REPO/'build/acceptance/reference-20261004/deployment-v229/runtime-built/api-0.1.0.jar'
                actual=subprocess.check_output(['docker','exec',SUITE,'sha256sum','/opt/samlscope/lib/api-0.1.0.jar'],timeout=30).decode().split()[0]
                require(SHA(archive.read_bytes())==actual,'Planned scope must come from the actual deployed API')
                with zipfile.ZipFile(archive) as jar:profile_raw=jar.read('profiles/metadata_idp.json')
                (receipt/'planned-profile.json').write_bytes(profile_raw)
                save(out/'planned-case-preflight.json',planned_publisher_scope(profile_raw,plan)|dict(runId=peer['runId'],
                     targetMetadataSha256=SHA(target),deployedApiSha256=actual))
                original_history=history(peer);save(out/'transcript-before-collection.json',original_history)
            else:require(peer_target==target,'Actual signing peers have different fixed target metadata')
            with urllib.request.urlopen(peer['entityId']+'/metadata',timeout=30) as response:(folder/'fixture.xml').write_bytes(response.read())
            public_xml((folder/'fixture.xml').read_bytes(),peer['entityId'])
        public_xml(target);runtime_identity=runtime();initial,initial_fields=read_public('initial');raw,_,_=publication('initial')
        require(raw==target and not initial['remotePeers'],'Native peer baseline must be empty and publication unchanged')
        require(initial['roleFeatureFlags']=={'saml20.ecp':True,'saml20.hok.assertion':False,'saml20.sendartifact':False,'metadata.sign.enable':False},'Unexpected unchanged hosted role configuration')
        record('initial','native-role-inventory',epochId='initial',adapter='simplesamlphp-stock-publisher-inventory-v1',**initial_fields)
        batch=MountedPeerConfigurationBatch(PEER_CONFIG)
        require(SHA(batch.original)==next(x['sha256'] for x in initial['configurationHashes'] if x['file']==PEER_REMOTE),
                'Original native peer configuration differs from owned host bytes')
        require(b'?>' not in batch.original and all(p['entityId'].encode() not in batch.original for p in peers),'Refusing existing native peer ownership')
        overlays=[]
        for peer in peers:
            fixture=(receipt/peer['fixtureFile']).read_bytes()
            # The native parser command receives only public fixture XML on STDIN.
            command=['docker','exec','-i',CONTAINER,'php','-d','display_errors=0','-d','log_errors=0','-r',PARSER,peer['entityId']]
            before_runtime=runtime();require(before_runtime==runtime_identity,'Native runtime changed before peer parser')
            row=dict(operation='native-original-peer-parser',inputSha256=SHA(fixture),sourceSha256=SHA(PARSER.encode()),startedAt=NOW(),runtimeBefore=before_runtime);operations.append(row);counts['nativePublicCalls']+=1;save(out/'operations.json',operations)
            result=subprocess.run(command,input=fixture,capture_output=True,timeout=40);row.update(finishedAt=NOW(),exitCode=result.returncode,outputSha256=SHA(result.stdout),runtimeAfter=runtime());save(out/'operations.json',operations)
            require(row['runtimeAfter']==before_runtime,'Native runtime changed during peer parser')
            require(result.returncode==0,'Native peer parser failed; stderr never persisted');parsed=json.loads(result.stdout);reject_sensitive(parsed)
            require(parsed['entityId']==peer['entityId'] and parsed['validateAuthnRequest'] is True,'Native parser selected a different signed peer')
            (receipt/peer['label']/'parser-output.json').write_bytes(result.stdout);overlays.append(parsed['php'].encode())
        owner=SHA(str(out).encode()+created['run']['id'].encode());material=NativeEphemeralSigner('/tmp/samlscope-publisher-signers-'+owner[:24],owner,
                    lambda program,arguments=(),operation='':native(program,arguments,operation,worker=True))
        start=NOW();public_material=material.create();end=NOW();counts['nativeEphemeralKeyCreations']=material.creations
        public_file='ephemeral-public-certificate.der';(receipt/public_file).write_bytes(base64.b64decode(public_material['certificateDerBase64'],validate=True))
        save(receipt/'ephemeral-public-material.json',public_material)
        record('ephemeral-material','native-public-signing-material',certificateSha256=public_material['certificateSha256'],
               publicCertificateFile=public_file,nativeStartedAt=start,nativeFinishedAt=end)
        secondary=peers[1]
        # Only references enter remote native configuration. Bytes remain in memory and are never archived.
        overrides=("\n$metadata["+json.dumps(secondary['entityId'])+"][\"signature.privatekey\"]="+json.dumps(material.private_path)+";\n"
                   +"$metadata["+json.dumps(secondary['entityId'])+"][\"signature.certificate\"]="+json.dumps(material.certificate_path)+";\n").encode()
        start=NOW();batch.apply(b'\n'.join(overlays)+overrides);end=NOW();counts['productSettings']=batch.write_count
        record('signers-transition','native-configuration-transition',epochId='peer-signers',path=PEER_REMOTE,
               configurationPurpose='per-peer-current-signers',startedAt=start,completedAt=end,
               beforeConfigurationSha256=SHA(batch.original),afterConfigurationSha256=SHA(batch.expected))
        time.sleep(3)  # Installed OPcache revalidation; this is not proof of native application.
        baseline=real_flow(peers[0],baseline=True)
        require(baseline['certificateSha256']==next(r['certificateSha256'] for r in initial['currentCredentials'] if r['prefix']==''),
                'Primary M0 did not use the original native signer')
        require(api('/api/runs/'+peers[0]['runId'])['status']=='COMPLETED','Initial normal M0 must complete before formal publisher slots')
        save(out/'tests-start.json',api('/api/runs/'+peers[0]['runId']+'/tests/start',{}))
        result=api('/api/runs/'+peers[0]['runId']+'/result.json');formal_slots=slots(result,peers[0]['runId']);save(out/'result-before.json',result);save(out/'formal-slots.json',formal_slots)
        require(result['target']['metadata_digest']=='sha256:'+SHA(target),'Formal slots changed the immutable target snapshot')
        controls();before=state('signers-before','peer-signers')
        native_peers={p['entityId']:p for p in before['remotePeers']}
        require(len(before['remotePeers'])==2 and set(native_peers)=={p['entityId'] for p in peers},'Native parser peer application is incomplete')
        for peer in peers:
            observed=native_peers[peer['entityId']]
            require(observed['signatureOverridePresent'] is (peer['label']=='secondary')
                    and observed['sharedEncryptionOverridePresent'] is False,'Native peer signer purpose differs')
        require(SHA(base64.b64decode(native_peers[secondary['entityId']]['signatureOverrideCertificateDerBase64'],validate=True))
                ==public_material['certificateSha256'],'Native peer application selected another public signer')
        counts['nativePeerApplications']=1;epoch_start=NOW()
        flow_rows=[real_flow(peer) for peer in peers]
        require(flow_rows[0]['certificateSha256']==baseline['certificateSha256'] and flow_rows[1]['certificateSha256']==public_material['certificateSha256']
                and flow_rows[0]['responseCertificateSpkiSha256']!=flow_rows[1]['responseCertificateSpkiSha256'],'Actual SSO signers were not the distinct configured keys')
        raw,http,publication_file=publication('peer-signers');record('signers-publication','native-publication',epochId='peer-signers',**http)
        epoch_end=NOW();after=state('signers-after','peer-signers');used_peers=validate_used_signer_epoch(before,after,peers,flow_rows,SHA(target));validate_flow_budget(counts)
        for flow in flow_rows:
            record(flow['label']+'-signer-use','native-signer-use',observedRunId=flow['runId'],requestReference=flow['requestReference'],
                   responseReference=flow['responseReference'],requestSha256=flow['requestSha256'],responseSha256=flow['responseSha256'],
                   fixtureSha256=flow['fixtureSha256'],responseCertificateSpkiSha256=flow['responseCertificateSpkiSha256'],
                   nativeStartedAt=flow['startedAt'],nativeFinishedAt=flow['finishedAt'])
        manifest=dict(schema='samlscope-native-metadata-publisher-key-inventory-v1',adapter='simplesamlphp-stock-publisher-inventory-v1',
            campaignId=CAMPAIGN,runId=created['run']['id'],planId=created['run']['planId'],entityId=TARGET,targetMetadataSha256=SHA(target),
            recorderUrl=BASE+'/p/'+created['run']['planId']+'/sp/paos?run='+created['run']['id'],selectedPath='stock-current-role',counterfactualCalibrationOnly=False,
            usedSigningPeers=used_peers,epochs=[dict(id='peer-signers',startedAt=epoch_start,finishedAt=epoch_end,beforeOriginal='signers-before',
                afterOriginal='signers-after',publicationFile=publication_file,publicationOriginal='signers-publication',
                transition='explicit-native-peer-signers',transitionOriginal='signers-transition')],controls=dict(inputFile='control-input.json',
                positiveOutputFile='control-positive.json',negativeOutputFile='control-negative.json',invocationsFile='control-invocations.json',original='controls'))
    finally:
        errors=[]
        if batch is not None:
            try:restoration=batch.restore()
            except Exception as failure:errors.append(dict(operation='remote-configuration-restoration',exceptionClass=type(failure).__name__))
            counts['productSettings']=batch.write_count;counts['configurationRestorations']=batch.restoration_writes;counts['guestWriteAttempts']=batch.guest_write_attempts
            counts['successfulHostWrites']=batch.successful_host_writes;counts['successfulGuestWrites']=batch.successful_guest_writes
            save(out/'native-mounted-configuration-readbacks.json',dict(mount=batch.mount,readbacks=batch.native_readbacks,
                guestWriteAttempts=batch.guest_write_attempts,successfulHostWrites=batch.successful_host_writes,successfulGuestWrites=batch.successful_guest_writes))
        if material is not None:
            try:
                start=NOW();removed=material.cleanup();end=NOW();counts['nativeEphemeralKeyCreations']=material.creations;counts['nativeEphemeralKeyRemovals']=material.removals
                save(out/'ephemeral-removal.json',removed|dict(createAttempts=material.create_attempts,removeAttempts=material.remove_attempts))
                if public_material is not None:
                    record('ephemeral-removal','native-public-signing-material-removal',certificateSha256=public_material['certificateSha256'],absent=removed['absent'],nativeStartedAt=start,nativeFinishedAt=end)
            except Exception as failure:errors.append(dict(operation='native-material-removal',exceptionClass=type(failure).__name__))
        if initial is not None and batch is not None and restoration.get('restored') and not errors:
            try:
                restored=state('restored','restored');raw,http,file=publication('restored')
                require(all(restored[k]==initial[k] for k in ('currentCredentials','remotePeers','roleFeatureFlags','configurationHashes','metadataSources','loadedClasses')),
                        'Native restored public configuration differs from captured original')
                counts['nativePeerRestorations']=int(batch.restoration_writes>0)
                paths=[dict(path=r['file'],originalSha256=r['sha256'],finalSha256=next(f['sha256'] for f in restored['configurationHashes'] if f['file']==r['file'])) for r in initial['configurationHashes']]
                record('restoration','native-publisher-restoration',restored=True,configurationHashes=paths,restoredPublicationFile=file,
                       restoredPublicationSha256=SHA(raw),restoredPublicationHttp=http,operationCounts=counts)
            except Exception as failure:errors.append(dict(operation='native-restoration-readback',exceptionClass=type(failure).__name__))
        counts['credentialPosts']=client.credential_posts;counts['samlSubmissions']=client.native_post_attempts+client.native_redirect_attempts
        restoration['restored']=restoration.get('restored') is True and not errors;restoration['errors']=errors
        save(out/'restoration-write.json',restoration);save(out/'restoration.json',restoration);save(out/'operation-counts.json',counts);save(out/'operations.json',operations)
        for peer in peers:
            entries=history(peer);save(receipt/peer['label']/'transcript.json',entries);capture(receipt/peer['label'],peer['runId'],entries)
            require((receipt/peer['label']/'target-metadata.xml').read_bytes()==target,'Actual peer target snapshot changed during collection')
            if peer['label']=='primary':
                require([e for e in entries if e['id'] in {x['id'] for x in original_history}]==original_history,'Existing primary history changed')
                save(out/'transcript.json',entries);capture(out,peer['runId'],entries)
                require((out/'target-metadata.xml').read_bytes()==target,'Primary target snapshot changed during collection')
        if errors:raise ValueError('Native used-signer restoration is incomplete; public error classes recorded')
    require(manifest is not None and restoration.get('restored') and material.creations==material.removals==1,'Incomplete used-signer evidence remains unadopted')
    validate_flow_budget(counts);manifest['originals']=refs;manifest['files']={str(p.relative_to(receipt)):SHA(p.read_bytes()) for p in receipt.rglob('*') if p.is_file()}
    save(receipt/'manifest.json',manifest);save(out/'qualification.json',dict(runId=created['run']['id'],caseSlotsExisting=True,
        initialTargetSnapshotUnchanged=True,adopted=False,settingsRestored=True,newSaml=3,newCredentials=1,personOperations=0,c3MultipleCurrentMissing=False))
    print(json.dumps(dict(runId=created['run']['id'],restored=True,operationCounts=counts,caseAdopted=False)))

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output',type=pathlib.Path,required=True);p.add_argument('--run',default=DEFAULT_RUN)
    p.add_argument('--browser-epoch',action='store_true',help='One explicit ECP=false epoch and exact restoration; requires serialized native lease')
    p.add_argument('--preflight-only',action='store_true',help='Read-only public preflight; do not publish Recorder records or change native settings')
    p.add_argument('--per-peer-signers',action='store_true',help='Three actual SSO submissions with one shared login; native peer signer key is removed and remote configuration restored')
    a=p.parse_args()
    if a.per_peer_signers:
        require(not a.browser_epoch and not a.preflight_only,'Per-peer signers require their own explicit native operation mode')
        return collect_used_signers(a)
    require(re.fullmatch(r'run_[0-9A-HJKMNP-TV-Z]{26}',a.run),'Invalid Run')
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
