#!/usr/bin/env python3
"""Native consent UI consumers, exact fixture imports and public state originals; restore all settings."""
import argparse,base64,hashlib,html,json,os,re,subprocess,sys,time,urllib.parse,urllib.request
from datetime import datetime,timezone
from pathlib import Path
from persistent_nameid_normal_campaign import REPO,CONTAINER,IDP,PREFIX,api,save,BASE,native,batch,raw,settled,ConfigurationBatch
from metadata_replacement_campaign import arm,READBACK
from keyvalue_runtime_campaign import KeyValueClient,inspect_identity
from import_metadata_batch import flow
sys.path.insert(0,str(REPO/'dev/keycloak'));from reference_flow import parse_forms
DISPLAY=['ui-consumer-display-all','ui-consumer-display-service','ui-consumer-display-entity']
LOGO=['ui-consumer-logo-localized','ui-consumer-logo-fallback']
URLS=['ui-url-'+kind+'-'+scheme for kind in ['logo','information','privacy'] for scheme in ['http','https','data','javascript','file']]
VARIANTS=['control']+DISPLAY+LOGO+URLS
SOURCES={'consent-controller':'modules/consent/src/Controller/ConsentController.php','consent-filter':'modules/consent/src/Auth/Process/Consent.php',
    'consent-template':'modules/consent/templates/consentform.twig','noconsent-template':'modules/consent/templates/noconsent.twig',
    'template':'src/SimpleSAML/XHTML/Template.php','parser':'src/SimpleSAML/Metadata/SAMLParser.php',
    'idp-saml2':'modules/saml/src/IdP/SAML2.php','auth-state':'src/SimpleSAML/Auth/State.php',
    'base-template':'templates/base.twig','header-template':'templates/_header.twig'}
STATE=r'''
require '/var/simplesamlphp/lib/_autoload.php';
$input=json_decode(stream_get_contents(STDIN),true,512,JSON_THROW_ON_ERROR);
$_COOKIE=$input['cookies'];
$state=\SimpleSAML\Auth\State::loadState($input['stateId'],'consent:request');
echo json_encode(['requestId'=>$state['saml:RequestId'],'sourceEntityId'=>$state['Source']['entityid'],
 'destination'=>$state['Destination'],'stateIdSha256'=>hash('sha256',$input['stateId'])],JSON_THROW_ON_ERROR);
'''
POLICY=r'''
require '/var/simplesamlphp/lib/_autoload.php';
$c=\SimpleSAML\Configuration::getInstance();$m=\SimpleSAML\Metadata\MetaDataStorageHandler::getMetadataHandler()->getMetaData($argv[1],'saml20-idp-hosted');
echo json_encode(['entityId'=>$argv[1],'authproc'=>$m['authproc']??null,'auth'=>$m['auth']??null,
 'consentEnabled'=>\SimpleSAML\Module::isModuleEnabled('consent'),'theme'=>$c->getOptionalString('theme.use','default'),
 'language'=>$c->getArray('language.available',[]),'defaultLanguage'=>$c->getOptionalString('language.default','en')],JSON_THROW_ON_ERROR);
'''
def sha(raw):return hashlib.sha256(raw).hexdigest()
def now():return datetime.now(timezone.utc).isoformat()
def sanitized(page,stateId):
    if stateId:page=page.replace(stateId,'[REDACTED-STATE]')
    from html.parser import HTMLParser
    class Hidden(HTMLParser):
        def __init__(self):super().__init__();self.values=[]
        def handle_starttag(self,tag,attrs):
            d=dict(attrs)
            if tag=='input' and d.get('type','').lower()=='hidden' and d.get('value'):self.values.append(d['value'])
    parser=Hidden();parser.feed(page)
    for value in parser.values:page=page.replace(value,'[REDACTED]')
    def redact(match):
        tag=match.group(0)
        if re.search(r'\btype\s*=\s*[\"\']?hidden',tag,re.I):
            tag=re.sub(r'\bvalue\s*=\s*(?:\"[^\"]*\"|\'[^\']*\'|[^\s>]+)','value="[REDACTED]"',tag,flags=re.I)
        return tag
    return re.sub(r'<input\b[^>]*>',redact,page,flags=re.I)
class ConsentClient(KeyValueClient):
    def __init__(self,records,response_originals,request_originals,folder,observations):
        super().__init__(records,response_originals,request_originals);self.folder=folder;self.observations=observations;self.request_id=None
        self.op.addheaders=[('Accept-Language','en-US')]
    def request(self,url,fields=None):
        if fields and 'SAMLRequest' in fields and urllib.parse.urlparse(url).port==18380:
            import xml.etree.ElementTree as ET
            self.request_id=ET.fromstring(base64.b64decode(fields['SAMLRequest'])).get('ID')
        final,page,status=super().request(url,fields)
        if 'id="consent-yes"' not in page:return final,page,status
        forms=parse_forms(page);yes=[f for f in forms if 'StateId' in f.fields and '/consent/getconsent' in f.action]
        if len(yes)!=1:raise ValueError('Ambiguous native consent form')
        stateId=yes[0].fields['StateId'];cookies={c.name:c.value for c in self.jar if c.domain in ['localhost.local','localhost','127.0.0.1']}
        observed=now();payload=json.dumps(dict(cookies=cookies,stateId=stateId)).encode()
        result=subprocess.run(['docker','exec','-i',CONTAINER,'php','-r',STATE],input=payload,capture_output=True,timeout=30)
        if result.returncode:raise ValueError('Native public consent state unavailable')
        public=json.loads(result.stdout)
        if public['requestId']!=self.request_id:raise ValueError('Native consent state request differs')
        browser_input=json.dumps(dict(url=final,cookies=[dict(name=k,value=v) for k,v in cookies.items()],tokens=[stateId,*cookies.values()])).encode()
        browser=subprocess.run(['node',str(Path(__file__).with_name('consent_browser.mjs'))],input=browser_input,capture_output=True,timeout=40)
        if browser.returncode:
            save(self.folder/'browser-failure.json',json.loads(browser.stderr))
            raise ValueError('Real native consent browser observation unavailable')
        ident=self.request_id;safe=sanitized(page,stateId).encode();(self.folder/(ident+'.html')).write_bytes(safe)
        (self.folder/(ident+'.state.json')).write_bytes(result.stdout)
        (self.folder/(ident+'.browser.json')).write_bytes(browser.stdout)
        self.observations.append(dict(requestId=ident,recordedAt=observed,status=status,url=urllib.parse.urlunsplit(urllib.parse.urlsplit(final)._replace(query='')),
            bodySha256=sha(safe),bodySanitized=True,stateSha256=sha(result.stdout),browserSha256=sha(browser.stdout),stateIdSha256=sha(stateId.encode()),preferredLanguage='en-US'))
        # Native form is GET: submit the real StateId only in memory, never persist it.
        target=urllib.parse.urljoin(final,yes[0].action)+'?'+urllib.parse.urlencode(dict(yes='yes',StateId=stateId))
        return super().request(target,None)
def readback(out,label,configs,entity):
    folder=out/label;folder.mkdir();stamp=now()
    for key,config in configs.items():(folder/(key+'.php')).write_bytes(settled(config.container_path,config.expected))
    (folder/'policy.json').write_bytes(subprocess.check_output(['docker','exec',CONTAINER,'php','-r',POLICY,IDP],timeout=30))
    if entity:(folder/'metadata.json').write_bytes(subprocess.check_output(['docker','exec',CONTAINER,'php','-r',READBACK,entity],timeout=30))
    save(folder/'observed.json',dict(recordedAt=stamp))
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True);p.add_argument('--display-only',action='store_true');a=p.parse_args();out=a.output.resolve();out.mkdir(parents=True,exist_ok=False)
    variants=['control']+DISPLAY if a.display_only else VARIANTS
    remote=batch('saml20-sp-remote.php');hosted=batch('saml20-idp-hosted.php');override=ConfigurationBatch(PREFIX/'config-override.php');override.container_path='/var/simplesamlphp/config/config-override.php'
    configs=dict(remote=remote,hosted=hosted,override=override)
    for label,c in configs.items():
        if raw(c.container_path)!=c.original:raise ValueError('Native baseline differs')
        (out/(label+'-original.php')).write_bytes(c.original)
    for name,path in SOURCES.items():(out/('native-'+name+'.txt')).write_bytes(raw('/var/simplesamlphp/'+path))
    (out/'native-state-command.php').write_text(STATE);(out/'native-policy-command.php').write_text(POLICY);(out/'native-parser-command.php').write_text(native.PHP)
    (out/'native-readback-command.php').write_text(READBACK);(out/'collector.py').write_bytes(Path(__file__).read_bytes())
    (out/'browser.mjs').write_bytes(Path(__file__).with_name('consent_browser.mjs').read_bytes())
    save(out/'identity-before.json',inspect_identity());run=None;operations=[];records=[];originals={};submitted={};observations=[];parsers=attempts=0
    credentials=(os.environ.get('REFERENCE_USERNAME','samlscope-m0-user'),os.environ.get('REFERENCE_PASSWORD','samlscope-m0-password'))
    try:
        override.apply(b"$config['module.enable']['consent'] = true;\n$config['language.default']='en';\n")
        hosted.apply(("$metadata['"+IDP+"']['authproc']=[90=>['class'=>'consent:Consent','includeValues'=>false,'checked'=>false,'identifyingAttribute'=>'uid']];").encode());time.sleep(3)
        readback(out,'prepared',configs,None)
        created=api('/api/plans',dict(name='SimpleSAMLphp native consent UI consumption',profile='metadata_idp',targetKind='IDP',targetEntityId=IDP,metadataSourceKind='URL',
            metadataSourceLocation='http://samlscope-reference-ssp/simplesaml/module.php/saml/idp/metadata',suiteMetadataDelivery='HTTP_URL',declaredFeatures={},parameters=dict(clockSkewToleranceSeconds=180,metadataRefreshWaitSeconds=300,testUserHint=credentials[0],requestSigningMode='REQUIRED'),interaction=dict(allowBrowserSteps=True,allowAttestation=False,preset='quick'),authorizedTarget=True))
        save(out/'plan.json',created);plan=created['plan']['plan']['id'];entity=BASE+'/p/'+plan
        created=api('/api/plans/'+plan+'/runs',{});save(out/'created.json',created);run=created['run']['id'];save(out/'preflight.json',api('/api/runs/'+run+'/preflight',{}))
        save(out/'campaign.json',api('/api/runs/'+run+'/metadata-lab/automatic-polling',dict(variants=variants,pollingDelaySeconds=0)))
        for variant in variants:
            folder=out/variant;folder.mkdir();row=dict(variant=variant,startedAt=now(),status='incomplete');operations.append(row);save(out/'operations.json',operations)
            state,fixture=arm(run,folder,variant);parsers+=1
            parsed=subprocess.run(['docker','exec','-i',CONTAINER,'php','-r',native.PHP,entity,'default'],input=fixture,capture_output=True,timeout=30)
            (folder/'parser.stdout').write_bytes(parsed.stdout);(folder/'parser.stderr').write_bytes(parsed.stderr);row['nativeParserReturncode']=parsed.returncode
            if parsed.returncode:raise ValueError('Native metadata parser did not accept UI fixture')
            remote.apply(json.loads(parsed.stdout)['php'].encode());time.sleep(3);readback(folder,'before',configs,entity)
            ui=folder/'ui';ui.mkdir();attempts+=2
            flow(run,folder/'flow.json',suite_signature_control=True,login_inputs=credentials,client_factory=lambda **kw:ConsentClient(records,originals,submitted,ui,observations))
            readback(folder,'after',configs,entity);row.update(status='correlated-success',completedAt=now());save(out/'operations.json',operations)
            if variant=='control':save(out/'tests-start.json',api('/api/runs/'+run+'/tests/start',{}))
    finally:
        restoration={}
        for label,c in configs.items():
            restoration[label]=c.restore();(out/(label+'-final.php')).write_bytes(settled(c.container_path,c.original))
        save(out/'restoration.json',restoration);save(out/'identity-after.json',inspect_identity());save(out/'native-ui-observations.json',dict(runId=run,observations=observations,productVerdictAssigned=False))
        http_folder=out/'native-http-originals';http_folder.mkdir()
        for record in records:
            ident=record['request_id'];body=sanitized(originals[ident].decode(),None).encode();(http_folder/(ident+'.html')).write_bytes(body)
            record['persisted_body_sha256']=sha(body);record['body_sanitized']=body!=originals[ident]
            request_xml,body=submitted[ident];(http_folder/(ident+'.request.xml')).write_bytes(request_xml);(http_folder/(ident+'.request.body')).write_bytes(body)
        save(out/'native-http-observations.json',dict(runId=run,records=records,productVerdictAssigned=False))
        save(out/'operation-counts.json',dict(productConfigurationWriteAttempts=sum(c.write_count for c in configs.values()),configurationApplyWrites=sum(c.applied_count for c in configs.values()),restorationWrites=sum(c.restoration_writes for c in configs.values()),nativeParserInvocations=parsers,protocolOperationsAttempted=attempts,runCreations=int(run is not None),productRestarts=0,humanOperations=0,restored=all(r['restored'] for r in restoration.values())))
        if run:
            sys.path.insert(0,str(REPO/'dev/reference-acceptance'));from capture_run_originals import capture
            entries=api('/api/runs/'+run+'/transcript');save(out/'transcript.json',entries);capture(out,run,entries)
            try:save(out/'result-before.json',api('/api/runs/'+run+'/result.json'))
            except RuntimeError:save(out/'result-artifact-unavailable.json',dict(available=False))
            save(out/'protocol-evidence-before.json',api('/api/runs/'+run+'/protocol-evidence'))
        if not all(r['restored'] for r in restoration.values()):raise ValueError('Native consent settings not restored')
    print(run,'native UI originals collected, all settings restored; no adoption')
if __name__=='__main__':main()
