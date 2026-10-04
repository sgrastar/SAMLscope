#!/usr/bin/env python3
"""Native two-peer SLO signer campaign with one memory login and exact remote metadata restoration."""
import argparse
import base64
import json
import importlib.util
from pathlib import Path
import re
import sys
import time
import urllib.request
import urllib.error
import urllib.parse
import xml.etree.ElementTree as ET

REPO=Path(__file__).resolve().parents[2]
sys.path[:0]=[str(REPO/'dev/slo'),str(REPO/'dev/simplesamlphp')]
from registered_signer_common import collect,docker,runtime,SHA,NOW,require,public_json,save,MD,mounted_hashes,SharedSloClient,local_url,endpoint
from configuration_batch import ConfigurationBatch
_spec=importlib.util.spec_from_file_location('ssp_slo_native_import',Path(__file__).with_name('registered_signer_campaign.py'))
_native=importlib.util.module_from_spec(_spec);_spec.loader.exec_module(_native)
PARSER,SOURCES=_native.PARSER,_native.SOURCES

CONTAINER='samlscope-reference-ssp'
REMOTE='/var/simplesamlphp/metadata/saml20-sp-remote.php'
HOSTED='/var/simplesamlphp/metadata/saml20-idp-hosted.php'
CONFIG=REPO/'build/acceptance/reference-20260914/ssp-config/saml20-sp-remote.php'
MOUNTS={remote:dict(source=CONFIG.parent/name,rw=rw) for remote,name,rw in [('/var/simplesamlphp/cert/server.pem','server.pem',False),('/var/simplesamlphp/config/authsources.php','authsources.php',False),('/var/simplesamlphp/config/config-override.php','config-override.php',False),('/var/simplesamlphp/metadata/saml20-idp-hosted.php','saml20-idp-hosted.php',False),('/var/simplesamlphp/metadata/saml20-sp-remote.php','saml20-sp-remote.php',True),('/etc/apache2/sites-enabled/000-default.conf','http-reference.conf',False),('/var/simplesamlphp/cert/server.crt','server.crt',False)]}
CLASSES={'native-idp.php':'SimpleSAML\\Module\\saml\\IdP\\SAML2','native-message.php':'SimpleSAML\\Module\\saml\\Message','native-configuration.php':'SimpleSAML\\Configuration','native-handler.php':'SimpleSAML\\Metadata\\MetaDataStorageHandler','native-source.php':'SimpleSAML\\Metadata\\MetaDataStorageSource','native-signed-helper.php':'SAML2\\SignedElementHelper','native-metadata-controller.php':'SimpleSAML\\Module\\saml\\Controller\\Metadata','native-saml-builder.php':'SimpleSAML\\Metadata\\SAMLBuilder'}
SOURCE_NAMES=tuple(CLASSES)
SOURCES=dict(SOURCES,**{'native-metadata-controller.php':'/var/simplesamlphp/modules/saml/src/Controller/Metadata.php','native-saml-builder.php':'/var/simplesamlphp/src/SimpleSAML/Metadata/SAMLBuilder.php'})
HOSTED_ORIGINAL_SHA='559eeba5e28f145f0b0bd9ee8c1c147b155babe73d7c19809affdd2147ce8e49'
POST_BINDING_OVERLAY=b'\n$metadata["http://localhost:18380/idp"]["SingleLogoutServiceBinding"] = ["urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect","urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"];\n'
CONTINUATION_SOURCE={
 'native-core-idp.php':('/var/simplesamlphp/src/SimpleSAML/IdP.php','313760d280f557ffbba61fd4622fbf7e9892b21425d8d24d26d9f08eb9312888','SimpleSAML\\IdP'),
 'native-core-logout-controller.php':('/var/simplesamlphp/modules/core/src/Controller/Logout.php','414577028f93afb1dff21577b69d3f3f2c5f7ad80d7bb163e3d03a533ba272e6','SimpleSAML\\Module\\core\\Controller\\Logout'),
 'native-auth-state.php':('/var/simplesamlphp/src/SimpleSAML/Auth/State.php','59576819feb0d08c19ff34bdee6f239b8edc94e1806fc056ff83b69e6b39ec8a','SimpleSAML\\Auth\\State')}
READBACK=r'''
require '/var/simplesamlphp/lib/_autoload.php';
$input=json_decode(stream_get_contents(STDIN),true,512,JSON_THROW_ON_ERROR);
$metadata=[];require '/var/simplesamlphp/metadata/saml20-sp-remote.php';
$handler=\SimpleSAML\Metadata\MetaDataStorageHandler::getMetadataHandler();$rows=[];
$idp=$handler->getMetaDataConfig($input['target'],'saml20-idp-hosted');
foreach($input['entities'] as $entity){
 $present=isset($metadata[$entity]);$config=null;$keys=[];$responseSigning=null;
 if($present){$native=$handler->getMetaDataConfig($entity,'saml20-sp-remote');$config=$native->toArray();$keys=$native->getPublicKeys('signing');
  $logout=\SimpleSAML\Module\saml\Message::buildLogoutResponse($idp,$native);$certificates=[];
  foreach($logout->getCertificates() as $certificate){$fingerprint=openssl_x509_fingerprint($certificate,'sha256');if($fingerprint===false){throw new \RuntimeException('Native outgoing signing certificate unavailable');}$certificates[]=$fingerprint;}
  $responseSigning=['selectedSigningKeyAvailable'=>$logout->getSignatureKey()!==null,'certificateSha256'=>$certificates];
 }
 $rows[]=['entity'=>$entity,'present'=>$present,'resolvedMetadata'=>$config,'signingKeys'=>$keys,'logoutResponseSigning'=>$responseSigning];
}
$source=[];
$reflection=[];foreach($input['sources'] as $label=>$file){$source[$label]=hash_file('sha256',$file);$class=new \ReflectionClass($input['classes'][$label]);$actual=$class->getFileName();if($actual!==$file){throw new \RuntimeException('Native source class selection mismatch');}$reflection[$label]=['class'=>$input['classes'][$label],'sourceFile'=>$actual,'sha256'=>hash_file('sha256',$actual)];}
$bindings=$handler->getGenerated('SingleLogoutServiceBinding','saml20-idp-hosted',null,$input['target']);
echo json_encode(['peers'=>$rows,'hostedEntityId'=>$idp->getString('entityid'),
 'hostedIdp'=>['authproc'=>$idp->getOptionalArray('authproc',[]),'singleLogoutServiceBindings'=>is_array($bindings)?$bindings:[$bindings]],
 'configurationSha256'=>hash_file('sha256','/var/simplesamlphp/metadata/saml20-sp-remote.php'),
 'hostedConfigurationSha256'=>hash_file('sha256','/var/simplesamlphp/metadata/saml20-idp-hosted.php'),
 'sourceHashes'=>$source,'selectedClasses'=>$reflection],JSON_THROW_ON_ERROR);
'''


def require_response_signing(observed,hosted_metadata):
    """Qualify stock Message::buildLogoutResponse before the first authentication; export no key material."""
    resolved=observed['resolvedMetadata'];selection=observed['logoutResponseSigning']
    require(resolved.get('sign.logout') is True and isinstance(selection,dict)
            and selection.get('selectedSigningKeyAvailable') is True,
            'Native outgoing LogoutResponse signature is not selected; stop before login')
    root=ET.fromstring(hosted_metadata);roles=root.findall('{'+MD+'}IDPSSODescriptor')
    require(len(roles)==1,'Native hosted IdP signing role is ambiguous')
    certificates=set()
    for key in roles[0].findall('{'+MD+'}KeyDescriptor'):
        if key.get('use','') not in ('','signing'):continue
        for certificate in key.iter('{http://www.w3.org/2000/09/xmldsig#}X509Certificate'):
            certificates.add(SHA(base64.b64decode(''.join(certificate.text.split()),validate=True)))
    selected=selection.get('certificateSha256')
    require(certificates and isinstance(selected,list) and selected and len(set(selected))==len(selected)
            and set(selected).issubset(certificates),
            'Native outgoing LogoutResponse key differs from the published IdP signing key; stop before login')


class SimpleSamlPhpSloClient(SharedSloClient):
    """Only the stock logout-resume/id continuation; the state value never leaves memory."""
    def __init__(self,origin,directory):
        super().__init__(origin,directory);self.completions=[]

    def complete_native_redirect(self,final,body,code,location,request_id):
        if code not in (301,302,303) or location is None:return final,body,code,location,{}
        following=urllib.parse.urljoin(final,location);p=local_url(following)
        if p.path!='/simplesaml/module.php/core/logout-resume':return final,body,code,location,{}
        require(p.scheme+'://'+p.netloc==self.target_origin and p.fragment=='','Foreign native logout continuation refused')
        query=urllib.parse.parse_qs(p.query,strict_parsing=True)
        require(set(query)=={'id'} and len(query['id'])==1 and re.fullmatch(r'_[0-9a-f]{1,256}',query['id'][0]) is not None,
                'Unexpected native logout state/return URL refused')
        row=dict(operation='stock-native-logout-resume',method='GET',requestId=request_id,path=p.path,
                 urlSha256=SHA(following.encode()),issuedLocationSha256=SHA(location.encode()),
                 issuedPageSha256=SHA(body),startedAt=NOW(),completed=False,executionValueExported=False)
        self.completions.append(row);ledger=self.directory.parent/'native-logout-completion-attempts.json';save(ledger,self.completions)
        response=None
        try:
            try:response=self.slo_op.open(urllib.request.Request(following,method='GET'),timeout=40)
            except urllib.error.HTTPError as error:response=error
            result=response.read(1024*1024+1);status=response.status;actual=response.geturl();next_location=response.headers.get('Location')
            require(actual==following,'Native continuation returned a different HTTP URL')
            require(len(result)<=1024*1024,'Oversize native continuation response')
            if next_location is not None:
                following_path=local_url(urllib.parse.urljoin(actual,next_location)).path
                require(following_path!='/simplesaml/module.php/core/logout-resume','Repeated native logout continuation refused')
            row.update(completed=True,completedAt=NOW(),responseStatus=status,responseBodySha256=SHA(result))
            # The effective endpoint is public; the actual capability-bearing URL has only a digest.
            public=endpoint(actual)
            return public,result,status,next_location,dict(nativeInitialResponseBodySha256=SHA(body),nativeFlowCompletions=[row],
                nativeResponseUrlOriginalSha256=SHA(actual.encode()),responseUrlQueryRedacted=True)
        except Exception as failure:
            row.update(completedAt=NOW(),exceptionClass=type(failure).__name__);raise
        finally:
            if response is not None:response.close()
            save(ledger,self.completions)


class SimpleSamlPhpProduct:
    name='SimpleSAMLphp';adapter='simplesamlphp-native-slo-issuer-key-v1'
    origin='http://localhost:18380';target=origin+'/idp'
    metadata_url=origin+'/simplesaml/module.php/saml/idp/metadata'
    metadata_source='http://samlscope-reference-ssp/simplesaml/module.php/saml/idp/metadata'

    def create_client(self,receipt):self.client=SimpleSamlPhpSloClient(self.origin,receipt);return self.client

    def bind(self,out,receipt):
        self.out,self.receipt=out,receipt;self.commands=[];self.batch=None;self.hosted_batch=None

    def command(self,*argv,data=None):
        row=dict(executable=argv[0],startedAt=NOW(),completed=False);self.commands.append(row);save(self.out/'native-command-counts.json',self.commands)
        raw=docker('exec','-i',CONTAINER,*argv,data=data,timeout=60)
        row.update(finishedAt=NOW(),completed=True,exitCode=0);save(self.out/'native-command-counts.json',self.commands)
        return raw

    def preflight(self):
        require(runtime(CONTAINER,MOUNTS)['image']=='sha256:9ae050473c68ce13c5451839cb64257eaa17be3a4d2c9a3f87996bbe0cebb0aa','Unqualified SSP native image')
        self.batch=ConfigurationBatch(CONFIG);self.batch.container,self.batch.container_path=CONTAINER,REMOTE
        require(self.command('cat',REMOTE)==self.batch.original and b'?>' not in self.batch.original,'Host/native metadata baseline mismatch')
        require(re.search(rb'(?i)private[._-]?key|password|passwd|authorization|cookie|client[._-]?secret',self.batch.original) is None,'Credential-bearing native configuration refused')
        self.hosted_batch=ConfigurationBatch(CONFIG.parent/'saml20-idp-hosted.php')
        require(SHA(self.hosted_batch.original)==HOSTED_ORIGINAL_SHA and self.command('cat',HOSTED)==self.hosted_batch.original,
                'Hosted configuration does not match the fixed public stock source')
        sources=self.receipt/'native-source';sources.mkdir()
        for name in SOURCE_NAMES:
            (sources/name).write_bytes(self.command('cat',SOURCES[name]))
        (self.receipt/'native-parser-command.php').write_text(PARSER)
        (self.receipt/'native-readback-command.php').write_text(READBACK)
        original=self.receipt/'original-configuration';original.mkdir();(original/'saml20-sp-remote.php').write_bytes(self.batch.original)
        (original/'saml20-idp-hosted.php').write_bytes(self.hosted_batch.original)
        # All native converter inputs are prepared before the single shared authentication.
        self.command('php','-v')
        self.continuation_preflight()

    def continuation_preflight(self):
        folder=self.out/'native-continuation-source';folder.mkdir()
        expected={}
        for name,(path,digest,cls) in CONTINUATION_SOURCE.items():
            raw=self.command('cat',path);require(SHA(raw)==digest,'Stock native logout continuation source changed before setup/login')
            (folder/name).write_bytes(raw);expected[cls]=dict(sourceFile=path,sha256=digest)
        php=r"require '/var/simplesamlphp/lib/_autoload.php';$in=json_decode(stream_get_contents(STDIN),true,512,JSON_THROW_ON_ERROR);$out=[];foreach($in as $class){$r=new \ReflectionClass($class);$file=$r->getFileName();$out[$class]=['sourceFile'=>$file,'sha256'=>hash_file('sha256',$file)];}echo json_encode($out,JSON_THROW_ON_ERROR);"
        raw=self.command('php','-r',php,data=json.dumps(list(expected)).encode());actual=json.loads(raw)
        require(actual==expected,'Native logout continuation class selection differs before setup/login')
        (folder/'native-reflection-output.json').write_bytes(raw)
        save(folder/'qualification.json',dict(selectedClasses=expected,nativeOutputSha256=SHA(raw),
            driverContinuationOnly=True,nativeSessionEvidence=False,capabilityExported=False))

    def configure_publisher(self):
        require(self.hosted_batch is not None,'Publisher prerequisite is not captured')
        # Read-only container bind: host in-place writes retain the actual shared inode.
        self.hosted_batch.apply(POST_BINDING_OVERLAY.strip(b'\n'))
        expected=self.hosted_batch.original+POST_BINDING_OVERLAY
        require(self.hosted_batch.expected==expected,'Hosted overlay changed unrelated configuration')
        self.wait_hosted(expected)
        time.sleep(3)
        directory=self.receipt/'configured-configuration';directory.mkdir()
        (directory/'saml20-idp-hosted.php').write_bytes(expected)
        with urllib.request.urlopen(self.metadata_url,timeout=40) as response:raw=response.read(1024*1024+1)
        root=ET.fromstring(raw);roles=root.findall('{'+MD+'}IDPSSODescriptor')
        require(root.get('entityID')==self.target and len(roles)==1 and len([e for e in roles[0].findall('{'+MD+'}SingleLogoutService') if e.get('Binding')=='urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST'])==1,
                'Native exporter did not advertise the configured POST SLO binding; stop before preflight/login')
        (directory/'hosted-metadata.xml').write_bytes(raw)

    def wait_hosted(self,expected):
        for _ in range(6):
            if self.command('cat',HOSTED)==expected:return
            time.sleep(1)
        raise ValueError('Native hosted configuration did not converge to the exact owned bytes')

    def state(self,label,peers):
        inputs=dict(entities=[p['entity'] for p in peers],target=self.target,sources={k:SOURCES[k] for k in SOURCE_NAMES},classes=CLASSES)
        raw=self.command('php','-r',READBACK,data=json.dumps(inputs).encode());value=json.loads(raw);public_json(value)
        require(value['hostedEntityId']==self.target,'Native hosted IdP belongs to a different target')
        directory=self.receipt/'native-readbacks';directory.mkdir(exist_ok=True)
        rawfile=directory/(label+'-native-output.json');rawfile.write_bytes(raw)
        hosted_file='native-readbacks/'+label+'-hosted-metadata.xml'
        with urllib.request.urlopen(self.metadata_url,timeout=40) as response:
            require(response.status==200,'Hosted metadata readback failed');metadata=response.read(1024*1024+1)
        xml=ET.fromstring(metadata);require(xml.tag=='{'+MD+'}EntityDescriptor' and xml.get('entityID')==value['hostedEntityId'],'Hosted metadata and native configuration identity differ')
        (self.receipt/hosted_file).write_bytes(metadata)
        rows=[]
        for observed,peer in zip(value['peers'],peers):
            require(observed['entity']==peer['entity'],'Native metadata handler lookup differs from expected Issuer')
            row=dict(entity=observed['entity'],present=observed['present'])
            if observed['present']:
                resolved=observed['resolvedMetadata'];require(resolved.get('validate.logout') is True,'Native SLO signature enforcement is disabled')
                require_response_signing(observed,metadata)
                file='native-readbacks/registered-'+peer['label']+'-metadata.json';bytes_=(json.dumps(resolved,sort_keys=True,separators=(',',':'))+'\n').encode();path=self.receipt/file
                if path.exists():require(path.read_bytes()==bytes_,'Effective native registered peer changed during controls')
                else:path.write_bytes(bytes_)
                certs=[]
                for key in observed['signingKeys']:
                    require(key.get('type')=='X509Certificate','Native signing key has an unsupported representation')
                    certs.append(base64.b64encode(base64.b64decode(''.join(key['X509Certificate'].split()),validate=True)).decode())
                require(certs,'Native consumer has no peer signing key');row.update(signingCertificates=certs,nativeMetadataFile=file,
                    logoutResponseSigning=observed['logoutResponseSigning'])
            rows.append(row)
        if label=='restoration':
            final=self.receipt/'final-configuration';final.mkdir();(final/'saml20-sp-remote.php').write_bytes(self.command('cat',REMOTE));(final/'saml20-idp-hosted.php').write_bytes(self.command('cat',HOSTED))
        observed_runtime=runtime(CONTAINER,MOUNTS)
        return dict(runtime=observed_runtime,mountedFileHashes=mounted_hashes(CONTAINER,observed_runtime),hostedEntityId=value['hostedEntityId'],hostedMetadataFile=hosted_file,
            hostedIdp=value['hostedIdp'],peers=rows,nativeOutputFile=str(rawfile.relative_to(self.receipt)),nativeOutputSha256=SHA(raw),
            configurationFiles={'saml20-sp-remote.php':value['configurationSha256'],'saml20-idp-hosted.php':value['hostedConfigurationSha256']},sourceHashes=value['sourceHashes'],selectedClasses=value['selectedClasses'],
            operativeConsumer={'class':'SimpleSAML\\Module\\saml\\IdP\\SAML2','method':'receiveLogoutMessage'})

    def prepare(self,peers):
        overlays=[]
        for peer in peers:
            require(peer['entity'].encode() not in self.batch.original,'Fresh native entity already existed before this campaign')
            fixture=(self.receipt/peer['label']/'fixture.xml').read_bytes()
            raw=self.command('php','-r',PARSER,peer['entity'],data=fixture);value=json.loads(raw);public_json(value)
            require(value['entityId']==peer['entity'] and value['validateAuthnRequest'] is True,'Native XML parser did not select expected signed peer')
            (self.receipt/peer['label']/'parser-output.json').write_bytes(raw)
            # SLO enforcement is a documented native setting, applied explicitly and read back before any fixture.
            suffix=("\n$metadata["+json.dumps(peer['entity'])+"]['validate.logout'] = true;\n"
                    +"$metadata["+json.dumps(peer['entity'])+"]['sign.logout'] = true;\n").encode()
            overlays.append(value['php'].encode()+suffix)
        self.batch.apply(b'\n'.join(overlays))
        require(self.command('cat',REMOTE)==self.batch.expected,'Native batch overlay readback mismatch')
        # Reference PHP's installed OPcache revalidation interval. This wait is operational only.
        time.sleep(3)
        save(self.out/'native-prepared.json',dict(nativeSignatureEnforcementSetting='validate.logout',nativeOutgoingSignatureSetting='sign.logout',nativeReadbackRequired=True,fixtureCount=2))

    def before_http(self):return None
    def after_http(self,before):return {}

    def restore(self,peers):
        errors=[];restored={'restored':False}
        try:restored=self.batch.restore()
        except Exception as failure:errors.append({'configuration':'remote-metadata','exceptionClass':type(failure).__name__})
        if self.hosted_batch is not None:
            try:
                hosted=self.hosted_batch.restore();self.wait_hosted(self.hosted_batch.original)
                restored.update(hostedOriginalSha256=hosted['original_sha256'],hostedFinalSha256=hosted['final_sha256'],hostedRestored=hosted['restored'])
                restored['restored']=restored['restored'] and hosted['restored']
            except Exception as failure:errors.append({'configuration':'hosted-metadata','exceptionClass':type(failure).__name__})
        restored['errors']=errors
        save(self.out/'native-restoration.json',restored)
        require(not errors,'Native configuration restoration failed; both owned files were independently checked')
        require(self.command('cat',REMOTE)==self.batch.original,'Native restoration differs from original bytes')
        return restored['restored']

    def counts(self):
        return dict(nativeConfigurationWrites=sum(b.write_count for b in (self.batch,self.hosted_batch) if b is not None),
            restorationWrites=sum(b.restoration_writes for b in (self.batch,self.hosted_batch) if b is not None),
            productRestarts=0,nativeCliExecutions=len(self.commands),nativeLogoutCompletionGets=len(self.client.completions) if hasattr(self,'client') else 0)


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--min-free-mib',type=int,default=96);args=parser.parse_args()
    collect(SimpleSamlPhpProduct(),args.output,min_free_mib=args.min_free_mib)
