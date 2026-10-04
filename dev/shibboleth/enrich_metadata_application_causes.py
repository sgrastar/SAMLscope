#!/usr/bin/env python3
"""Read-only public native cause projection for already recorded metadata PAOS controls.

The complete process log stays in memory. Only the selected peer's audit and its
literal signature-validation/error events enter the artifact. No settings, SAML,
credentials, transcript entries or original campaign files are changed.
"""
import argparse, datetime, hashlib, json, re, subprocess
from pathlib import Path

CONTAINER='samlscope-reference-shibboleth'
LOG='/opt/reference-idp/logs/idp-process.log'
SHA=lambda value:hashlib.sha256(value).hexdigest()
NOW=lambda:datetime.datetime.now(datetime.timezone.utc).isoformat().replace('+00:00','Z')

def native(*command):
 return subprocess.run(['docker','exec',CONTAINER,*command],capture_output=True,check=True,timeout=40).stdout

def export(folder,output):
 folder=folder.resolve();output=output.absolute()
 if output.exists() or output.is_symlink():raise ValueError('Fresh qualification output required')
 manifest=json.loads((folder/'receipt/manifest.json').read_bytes());run=manifest['runId'];entity=manifest['entityId']
 if not re.fullmatch(r'run_[0-9A-HJKMNP-TV-Z]{26}',run) or not entity.endswith('/p/'+manifest['planId']):raise ValueError('Invalid original Run/Plan')
 entries={row['id']:row for row in json.loads((folder/'transcript.json').read_bytes())}
 decoded={row['id']:row['file'] for row in json.loads((folder/'decoded-manifest.json').read_bytes())}
 windows=[];bindings=[]
 for row in manifest['probes']:
  if row.get('browser'):continue
  before=json.loads((folder/decoded[row['beforeEpoch']['reference']]).read_bytes());after=json.loads((folder/decoded[row['afterEpoch']['reference']]).read_bytes())
  root=folder/'receipt'/row.get('nativeRoot','native')
  clock_before=json.loads((root/before['clockAfterFile']).read_bytes());clock_after=json.loads((root/after['clockBeforeFile']).read_bytes())
  windows.append((clock_before['stdout'],clock_after['stdout']))
  request=entries[row['requestReference']];responses=[entries[value] for value in row['responseReferences']]
  if request['runId']!=run or len(responses)!=1 or responses[0]['runId']!=run:raise ValueError('Foreign/ambiguous original operation')
  bindings.append(dict(fixture=row['fixture'],requestReference=request['id'],responseReference=responses[0]['id'],
   actionId=row['actionId'],requestSha256=SHA((folder/decoded[request['id']]).read_bytes()),
   responseSha256=SHA((folder/decoded[responses[0]['id']]).read_bytes()),nativeClockBefore=clock_before,nativeClockAfter=clock_after))
 started=NOW();size=int(native('stat','-c','%s',LOG).strip())
 raw=native('head','-c',str(size),LOG)
 actual=native('sh','-c','head -c '+str(size)+' '+LOG+' | sha256sum').decode().split()[0]
 if len(raw)!=size or SHA(raw)!=actual:raise ValueError('Native immutable log prefix changed during read')
 lines=[]
 for number,line in enumerate(raw.decode('utf-8').splitlines(),1):
  prefix=re.match(r'^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d,\d{3}) - [0-9a-fA-F:.]+ - (?:INFO|WARN) \[([^\]]+)\] - (.*)$',line)
  if not prefix:continue
  at=datetime.datetime.strptime(prefix[1],'%Y-%m-%d %H:%M:%S,%f').replace(tzinfo=datetime.timezone.utc).isoformat().replace('+00:00','Z')
  if not any(begin<=at<end for begin,end in windows):continue
  logger,message=prefix[2],prefix[3]
  own_audit=message.startswith('SAMLscope-application-v1|') and len(message.split('|'))==12 and message.split('|')[4]==entity
  failure=logger.startswith('org.opensaml.saml.common.binding.security.impl.SAMLProtocolMessageXMLSignatureSecurityHandler:') and message=="Message Handler: Validation of protocol message signature failed for context issuer '"+entity+"', message type: {urn:oasis:names:tc:SAML:2.0:protocol}AuthnRequest"
  event=logger.startswith('org.opensaml.profile.action.impl.LogEvent:') and message=='A non-proceed event occurred while processing the request: MessageAuthenticationError'
  if own_audit or failure or event:
   lines.append(dict(lineNumber=number,nativeLoggedAt=at,kind='native-peer-audit' if own_audit else 'native-signature-validation-failure' if failure else 'native-message-authentication-error',raw=line,lineSha256=SHA(line.encode())))
 # Missing or unrelated failures do not become signature rejections merely
 # because the transport happened to return HTTP 500.
 by_request={}
 for index,row in enumerate(lines):
  if row['kind']!='native-peer-audit':continue
  fields=row['raw'].split(' - ',3)[3].split('|');request=fields[1]
  lower=max((i for i in range(index) if lines[i]['kind']=='native-peer-audit'),default=-1)
  segment=lines[lower+1:index]
  validations=[value for value in segment if value['kind']=='native-signature-validation-failure']
  errors=[value for value in segment if value['kind']=='native-message-authentication-error']
  by_request[request]=dict(auditLineNumber=row['lineNumber'],validationLineNumbers=[v['lineNumber'] for v in validations],errorLineNumbers=[v['lineNumber'] for v in errors])
 for binding in bindings:
  request_id='_'+binding['actionId'];binding['nativeEventSequence']=by_request.get(request_id)
  if any(word in binding['fixture'] for word in ('unadvertised','invalid-signature','old-key')):
   sequence=binding['nativeEventSequence']
   if sequence is None or len(sequence['validationLineNumbers'])!=1 or len(sequence['errorLineNumbers'])!=1:raise ValueError('Native signature refusal sequence is not uniquely request-bound')
 value=dict(schema='samlscope-shibboleth-metadata-application-public-causes-v1',runId=run,entityId=entity,
  originalManifestSha256=SHA((folder/'receipt/manifest.json').read_bytes()),sourcePath=LOG,sourcePrefixBytes=size,
  sourcePrefixSha256=SHA(raw),sourcePrefixRecheckedSha256=actual,startedAt=started,completedAt=NOW(),
  sourceLineNumbersPreserved=True,privateLogPersisted=False,publicCandidateLines=lines,operations=bindings,
  costs=dict(productSettings=0,protocolSubmissions=0,credentialPosts=0,personOperations=0,nativeReadCommands=3))
 output.parent.mkdir(parents=True,exist_ok=True);output.write_text(json.dumps(value,sort_keys=True,indent=2)+'\n')
 print(run,'public native cause projection qualified; new SAML/login/settings 0')

if __name__=='__main__':
 parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('folder',type=Path);parser.add_argument('output',type=Path);args=parser.parse_args();export(args.folder,args.output)
