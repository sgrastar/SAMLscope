#!/usr/bin/env python3
"""Adopt original Shibboleth signed normal and POST NoPassive error without new logins."""
import hashlib,importlib.util,json,pathlib,shutil,sys,subprocess,datetime,xml.etree.ElementTree as ET
from verify_terminal_http_acceptance import find_case
from verify_shibboleth_authentication_identity_acceptance import native_runtime
from capture_terminal_http_runtime import capture_suite,api
from verify_post_error_binding_acceptance import capture_history,verify_history
REPO=pathlib.Path(__file__).resolve().parents[2]
FOLDER='shibboleth-post-error-binding-v179';SOURCE='reference-20260930/shibboleth-identity-v170-r3';RUN='run_B7216J6NG10P449KERTB9WWV2T';CASE='IIP-SSO03-b-idp-01'
CASE_DIGEST='sha256:fbfce2000bd2c63133890b630547c6efb0fec385ea297c2adf068656dd232391'
JAR_PINS={'runner':'b3a7c7850cbcaa429a3aa054d39060375a5dc846870e5e5a73259cde9511bef0','core':'1d6e0020c915f50e78902554c06b61916a3f49e50de78d3bc23c6089d312babe',
 'saml':'20981403f9b5125ea5ca5bc25e2a464e37918b88870d930561d69c9d4d71df1c','store':'c4482cd06f9290a3592f0fceac2c9ec2d7603ea0557d1edc885e1c3d51bd8ece'}
HELPER_PIN='25e67709aa297362795208ca87091198ca474b6ba64127851ad88177bf91d55f'
HISTORY_HELPER_PIN='b77e5e97be48324bfe535c863b64a0d99608142e233622af0f511f95ee18f74a'
spec=importlib.util.spec_from_file_location('shibboleth_post_error_archived_runtime',REPO/'dev/reference-acceptance/verify_ssp_intersection_capability_acceptance.py')
runtime=importlib.util.module_from_spec(spec);spec.loader.exec_module(runtime);runtime.HELPER='VerifyPostErrorBindingEvidence';runtime.CLASSES=('com/samlscope/runner/cases/NormalFlowBrowserObservation.class','com/samlscope/runner/cases/AutoBrowserEvidenceTestCase.class')
SHA=lambda b:hashlib.sha256(b).hexdigest();READ=lambda p:json.loads(pathlib.Path(p).read_bytes())
def require(value,message):
 if not value:raise ValueError(message)
def capture(root):
 root=pathlib.Path(root);folder=root/FOLDER;folder.mkdir(exist_ok=False);source=REPO/'build/acceptance'/SOURCE;browser=source/'browser';originals={}
 for name in ['created.json','transcript.json','decoded-manifest.json','target-metadata.xml']:
  shutil.copy2(browser/name,folder/name);originals[name]=SHA((folder/name).read_bytes())
 shutil.copytree(browser/'decoded',folder/'decoded')
 for name in ['restoration.json','operations.json','operation-counts.json','original-providers','final-providers']:
  shutil.copy2(source/name,folder/name);originals[name]=SHA((folder/name).read_bytes())
 # Capture the complete original restoration/configuration proof, including all native
 # credential/challenge checks, through the already adopted ae verifier, without rerunning it.
 (folder/'source.json').write_text(json.dumps(dict(source=SOURCE,runId=RUN,files=originals,caseDigest=CASE_DIGEST),indent=2)+'\n')
 runtime.capture_runtime(folder);replayed=runtime.replay(folder);(folder/'native-reader-replay.json').write_text(json.dumps(replayed,indent=2)+'\n');capture_history(folder)
 started=datetime.datetime.now(datetime.timezone.utc).isoformat();capture_suite(folder)
 case=find_case(READ(folder/'evaluation-terminal-http-v1/result.json'),CASE)
 (folder/'formal.json').write_text(json.dumps(dict(runId=RUN,startedAt=started,transcriptUnchanged=True,productWrites=0,productRestarts=0,protocolSends=0,humanOperations=0,newRuns=0,case=case),indent=2)+'\n')
 return folder

def verify(root):
 root=pathlib.Path(root);folder=root if root.name==FOLDER else root/FOLDER;source=READ(folder/'source.json');require(source['source']==SOURCE and source['runId']==RUN and source['caseDigest']==CASE_DIGEST,'Wrong source/case scope')
 for file,digest in source['files'].items():require(pathlib.Path(file).name==file and SHA((folder/file).read_bytes())==digest,'Original changed')
 for where,helper_pin in [(folder,HELPER_PIN),(folder/'history-v175',HISTORY_HELPER_PIN)]:
  pins=READ(where/'runtime/pins.json');require(pins['jars']==JAR_PINS and pins['helperSha256']==helper_pin,'Actual deployed runtime/helper pin differs')
 native=REPO/'build/acceptance'/SOURCE
 require(READ(native/'restoration.json')==READ(folder/'restoration.json') and READ(folder/'restoration.json')['restored'] is True
  and (folder/'original-providers').read_bytes()==(folder/'final-providers').read_bytes(),'Original setup not restored')
 restoration=READ(folder/'restoration.json');require(restoration['originalSha256']==restoration['finalSha256'] and not restoration['failures'],'Original native configuration differs')
 original_manifest=READ(native/'receipt/manifest.json')
 for row in original_manifest['configurationFiles']:
  original=(native/'receipt'/row['originalFile']).read_bytes();final=(native/'receipt'/row['finalFile']).read_bytes()
  require(SHA(original)==row['originalSha256'] and SHA(final)==row['finalSha256'] and original==final,'Configuration restoration bytes differ')
 entries=READ(folder/'transcript.json');byid={e['id']:e for e in entries};require(len(byid)==len(entries) and all(e['runId']==RUN for e in entries),'Mixed Recorder history')
 native_runtime(native,byid,READ(folder/'operations.json'))
 originals={}
 for row in READ(folder/'decoded-manifest.json'):
  path=folder/row['file'];raw=path.read_bytes();e=byid[row['id']]
  require(path.resolve().parent==(folder/'decoded').resolve() and e['decodedSamlRef']=='transcripts/'+RUN+'/'+e['id']+'.saml.xml'
   and e['decodedSamlBytes']==len(raw) and SHA(raw)==row['sha256'],'Recorder original changed');originals[row['id']]=raw
 replayed=runtime.replay(folder);require(replayed==READ(folder/'native-reader-replay.json'),'Archived production Reader changed')
 require(replayed['runId']==RUN and replayed['outcome']=='SATISFIED' and replayed['reasonCode']=='browser.normal-flow.error-responses-use-post'
  and replayed['configurationWrites']==0 and replayed['privateKeyExported'] is False,'Replay scope/outcome differs')
 require(replayed['checks']=={'native-normal-and-post-error':'SATISFIED','get-error-mutant':'VIOLATED','error-only':'NOT_VERIFIED','success-only':'NOT_VERIFIED','uncorrelated-error':'NOT_VERIFIED','missing-error-status':'NOT_VERIFIED'},'Control matrix failed')
 verify_history(folder,replayed)
 p='{urn:oasis:names:tc:SAML:2.0:protocol}';requests={ET.fromstring(raw).get('ID'):(e,ET.fromstring(raw)) for id,raw in originals.items() if (e:=byid[id])['direction']=='OUTBOUND' and ET.fromstring(raw).tag==p+'AuthnRequest'}
 normal=error=0
 for id,digest in replayed['verifiedNativeResponses'].items():
  require(SHA(originals[id])==digest,'Signed original changed');xml=ET.fromstring(originals[id]);request=requests.get(xml.get('InResponseTo'));e=byid[id]
  require(request and e['direction']=='INBOUND' and e['method']=='POST' and request[0]['timestamp']<e['timestamp'] and request[1].get('AssertionConsumerServiceURL')==xml.get('Destination'),'Wrong protocol correlation/binding')
  status=xml.find(p+'Status/'+p+'StatusCode');require(status is not None,'Status absent')
  if status.get('Value')=='urn:oasis:names:tc:SAML:2.0:status:Success':normal+=1
  else:require(request[1].get('IsPassive')=='true' and status.get('Value') in {'urn:oasis:names:tc:SAML:2.0:status:Requester','urn:oasis:names:tc:SAML:2.0:status:Responder'} and xml.find(p+'Status/'+p+'StatusCode/'+p+'StatusCode').get('Value')=='urn:oasis:names:tc:SAML:2.0:status:NoPassive','Wrong native error trigger');error+=1
 require(normal==1 and error>=1 and replayed['details']['error_kinds']==['is_passive'],'Control closure missing')
 formal=READ(folder/'formal.json');require(formal['runId']==RUN and formal['transcriptUnchanged'] is True and all(formal[k]==0 for k in ['productWrites','productRestarts','protocolSends','humanOperations','newRuns']),'Formal performed new product work')
 result_path=folder/'evaluation-terminal-http-v1/result.json';result=READ(result_path);case=find_case(result,CASE)
 require(case==formal['case'] and (case['outcome'],case['verdict'],case['reason_code'],case['attested'])==('SATISFIED','PASS',replayed['reasonCode'],False)
  and case['evidence']==replayed['evidence'],'Formal and replay differ')
 require(result['run']['id']==RUN and result['target']['metadata_digest']=='sha256:'+SHA((folder/'target-metadata.xml').read_bytes()),'Fixed Run/metadata differs')
 require(READ(folder/'evaluation-terminal-http-v1/transcript-before.json')==READ(folder/'evaluation-terminal-http-v1/transcript.json')==entries,'Formal changed transcript')
 return result_path,{CASE:case}
if __name__=='__main__':
 import argparse
 parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('root',type=pathlib.Path);parser.add_argument('--capture',action='store_true');args=parser.parse_args()
 if args.capture:capture(args.root)
 path,cases=verify(args.root);print(path,{id:case['verdict'] for id,case in cases.items()})
