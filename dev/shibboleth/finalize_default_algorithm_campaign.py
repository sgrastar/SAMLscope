#!/usr/bin/env python3
"""Close public ALG08 native originals after exact restore; no SAML, login, or settings.

The two ciphertext mathematics calls read the native private key only inside the target JVM.
Their output proves input validity, never target algorithm-policy acceptance. Public JSON
originals are recorded separately from SAML. Existing collection files are immutable.
"""
import argparse,base64,datetime,hashlib,importlib.util,json,pathlib,re,subprocess,sys,urllib.request
REPO=pathlib.Path(__file__).resolve().parents[2];sys.path[:0]=[str(REPO/'dev/reference-acceptance')]
sys.path[:0]=[str(REPO/'dev/shibboleth')]
from capture_run_originals import capture
from capture_stock_unmarshaller import capture as capture_stock_decoder
spec=importlib.util.spec_from_file_location('default_finalizer_api',REPO/'dev/keycloak/import_metadata_batch.py');module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
api,BASE=module.api,module.BASE
NATIVE='samlscope-reference-shibboleth';SUITE='samlscope-reference-suite'
SOURCE=REPO/'dev/reference-acceptance/ShibbolethDefaultCipherInputValidation.java'
SOURCE_SHA='c6a0511b0b481621239f5bb04fb11f6ca951cd1b9f66c74fae93ee53bb53e8c3'
SHA=lambda b:hashlib.sha256(b).hexdigest();NOW=lambda:datetime.datetime.now(datetime.timezone.utc).isoformat().replace('+00:00','Z')
def require(value,reason):
 if not value:raise ValueError(reason)
def read(path):return json.loads(path.read_bytes())
def original(path,raw):
 require(not path.exists() and not path.is_symlink(),'Immutable finalizer output already exists');path.write_bytes(raw)
def save(path,value):original(path,(json.dumps(value,sort_keys=True,indent=2)+'\n').encode())
def command(argv,timeout=30,check=True):
 r=subprocess.run(argv,capture_output=True,timeout=timeout)
 if check:require(r.returncode==0,'Public diagnostic command failed: '+str(r.returncode))
 return r
def runtime():
 n=json.loads(command(['docker','inspect',NATIVE]).stdout)[0]
 value=dict(containerId=n['Id'],image=n['Image'],running=n['State']['Running'],mounts=n['Mounts'])
 require(value['running'] is True and value['mounts']==[],'Unknown mutable native diagnostic runtime');return value
def record(run,plan,raw):
 before={e['id'] for e in api('/api/runs/'+run+'/transcript')};request=urllib.request.Request(BASE+'/p/'+plan+'/sp/paos?run='+run,data=raw,method='POST',headers={'Content-Type':'application/json'})
 with urllib.request.urlopen(request,timeout=30) as response:require(response.status==204,'Public-original Recorder did not complete')
 added=[e for e in api('/api/runs/'+run+'/transcript') if e['id'] not in before and e.get('decodedSamlRef')]
 require(len(added)==1 and added[0]['runId']==run and added[0]['decodedSamlBytes']==len(raw),'Ambiguous public-original Recorder binding')
 return dict(reference=added[0]['id'],sha256=SHA(raw))
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--folder',required=True,type=pathlib.Path);a=p.parse_args();out=a.folder.resolve();folder=out/'receipt'
 m=read(out/'manifest-pending.json');run=m['runId'];plan=read(out/'created.json')['run']['planId'];require(re.fullmatch(r'run_[0-9A-HJKMNP-TV-Z]{26}',run) and re.fullmatch(r'plan_[0-9A-HJKMNP-TV-Z]{26}',plan),'Unsafe Run/Plan')
 require(read(out/'restoration.json')['restored'] is True and not (folder/'manifest.json').exists(),'Exact restore must precede finalization')
 require(SHA(SOURCE.read_bytes())==SOURCE_SHA,'Native input-only producer source changed');original(folder/'cipher-input-producer.java',SOURCE.read_bytes())
 rows=api('/api/runs/'+run+'/transcript');save(out/'transcript-before-finalization.json',rows);decoded={r['id']:out/r['file'] for r in read(out/'decoded-manifest.json')}
 epochs=m['observations'];require(len(epochs)==6 and len({r['requestReference'] for r in epochs})==6,'Six native originals required')
 decoder_calls=0
 early=[row for row in epochs if row['nativeUsePending'].get('auditMode')=='pre-audit-decoder-rejection']
 if early:
  require(len(early)==1 and early[0]['fixtureId']=='rsa-md5','Pre-audit evidence belongs only to RSA-MD5')
  output=capture_stock_decoder(out,m,epochs);ref=record(run,plan,output);m['nativeOriginals'].append(ref)
  early[0]['nativeUsePending'].update(unmarshallerOutputReference=ref['reference'],unmarshallerOutputSha256=ref['sha256'],unmarshallerInvocationFile='stock-unmarshaller-invocation.json');decoder_calls=1
 temporary='/tmp/samlscope-default-cipher-'+run;ledger=dict(schema='samlscope-default-cipher-diagnostics-ledger-v1',runId=run,nativeCompilerCalls=0,nativeJavaCalls=0,productSettings=0,protocolSubmissions=0,credentialPosts=0,personOperations=0,attempts=[],temporaryRemoved=False)
 require(command(['docker','exec',NATIVE,'sh','-c','test -e '+temporary+' && echo exists || true']).stdout.strip()==b'','Fresh diagnostic directory already exists')
 command(['docker','exec',NATIVE,'mkdir','-p',temporary+'/classes']);before=runtime();save(folder/'cipher-native-before.json',before)
 try:
  command(['docker','cp',str(SOURCE),NATIVE+':'+temporary+'/ShibbolethDefaultCipherInputValidation.java'])
  require(command(['docker','exec',NATIVE,'cat',temporary+'/ShibbolethDefaultCipherInputValidation.java']).stdout==SOURCE.read_bytes(),'Native producer source readback mismatch')
  compile_args=['javac','-d',temporary+'/classes',temporary+'/ShibbolethDefaultCipherInputValidation.java'];start=NOW();compiled=command(['docker','exec',NATIVE,*compile_args],timeout=45,check=False);ledger['nativeCompilerCalls']+=1
  save(folder/'cipher-compile-invocation.json',dict(command=compile_args,sourceSha256=SOURCE_SHA,startedAt=start,completedAt=NOW(),exitCode=compiled.returncode,stdoutSha256=SHA(compiled.stdout),stderrSha256=SHA(compiled.stderr)))
  original(folder/'cipher-compile.stdout',compiled.stdout);original(folder/'cipher-compile.stderr',compiled.stderr);require(compiled.returncode==0,'Input-only native compilation failed')
  for row in epochs:
   fixture=row['fixtureId']
   if fixture not in {'rsa15-encrypted-id','oaep-encrypted-id-control'}:continue
   require(row['requestReference'] in decoded,'Original ciphertext request unavailable');raw=decoded[row['requestReference']].read_bytes();require(SHA(raw)==row['requestSha256'],'Original ciphertext request changed')
   name=fixture+'.request.xml';original(folder/name,raw);command(['docker','cp',str(folder/name),NATIVE+':'+temporary+'/'+name]);require(command(['docker','exec',NATIVE,'cat',temporary+'/'+name]).stdout==raw,'Native public input readback mismatch')
   argv=['java','-cp',temporary+'/classes','ShibbolethDefaultCipherInputValidation',run,temporary+'/'+name,temporary+'/ShibbolethDefaultCipherInputValidation.java']
   start=NOW();result=command(['docker','exec',NATIVE,*argv],timeout=30,check=False);ledger['nativeJavaCalls']+=1;call=dict(schema='samlscope-shibboleth-cipher-input-invocation-v1',runId=run,fixtureId=fixture,command=argv,startedAt=start,completedAt=NOW(),exitCode=result.returncode,sourceFile='cipher-input-producer.java',sourceSha256=SOURCE_SHA,inputFile=name,stdoutFile=fixture+'-cipher-input.stdout.json',stdoutSha256=SHA(result.stdout),stderrSha256=SHA(result.stderr),nativeBeforeFile='cipher-native-before.json',nativeAfterFile='cipher-native-after.json')
   ledger['attempts'].append(call);original(folder/call['stdoutFile'],result.stdout);original(folder/(fixture+'-cipher-input.stderr'),result.stderr);save(folder/(fixture+'-cipher-input-invocation.json'),call)
   require(result.returncode==0 and result.stderr==b'','Native input-only validation failed; do not substitute product rejection');value=json.loads(result.stdout)
   require(value['runId']==run and value['requestSha256']==SHA(raw) and value['producerSourceSha256']==SOURCE_SHA and value['authenticatedGcm'] is True and value['inputValidationOnly'] is True and value['productAlgorithmPolicyEvaluated'] is False and value['privateKeyExported'] is False,'Native ciphertext math output not bound')
   plaintext=base64.b64decode(value['decryptedNameIdBase64'],validate=True);require(SHA(plaintext)==value['decryptedNameIdSha256'],'Native ciphertext plaintext hash mismatch')
   ref=record(run,plan,result.stdout);use=row['nativeUsePending'];use.update(cipherInputReference=ref['reference'],cipherInputSha256=ref['sha256'],cipherInvocationFile=fixture+'-cipher-input-invocation.json');m['nativeOriginals'].append(ref)
  after=runtime();require(before==after,'Native runtime changed during input-only mathematics');save(folder/'cipher-native-after.json',after)
 finally:
  command(['docker','exec',NATIVE,'rm','-rf','--',temporary]);ledger['temporaryRemoved']=True;save(out/'cipher-diagnostic-operations.json',ledger);save(folder/'cipher-diagnostic-operations.json',ledger)
 # Only genuine native use/audit files select decisions. Input-only math cannot declare acceptance.
 observations=[]
 for row in epochs:
  use=row.pop('nativeUsePending');raw=(json.dumps(use,sort_keys=True,separators=(',',':'))+'\n').encode();original(folder/(row['fixtureId']+'-native-use.json'),raw);ref=record(run,plan,raw)
  row.update(nativeUseReference=ref['reference'],nativeUseSha256=ref['sha256']);m['nativeOriginals'].append(ref);observations.append(row)
 m.update(schema='samlscope-default-algorithm-prevention-v1',observations=observations,restorationFile='restoration.json',restoredReadinessFile='restored-native-readiness.json',operationCountsFile='operation-counts.json')
 m['files']={f.name:SHA(f.read_bytes()) for f in folder.iterdir() if f.is_file() and f.stat().st_size>0 and f.name!='manifest.json'}
 save(folder/'manifest.json',m);save(out/'finalized-manifest-binding.json',dict(runId=run,manifestSha256=SHA((folder/'manifest.json').read_bytes()),counterfactualCalibrationOnly=False,settings=0,protocolSubmissions=0,credentialPosts=0,nativeCompilerCalls=1+decoder_calls,nativeJavaCalls=2+decoder_calls,cipherInputCompilerCalls=1,cipherInputJavaCalls=2,stockDecoderCompilerCalls=decoder_calls,stockDecoderJavaCalls=decoder_calls))
 final=api('/api/runs/'+run+'/transcript');save(out/'transcript-after-finalization.json',final);before_ids={e['id'] for e in rows};require([e for e in final if e['id'] in before_ids]==rows,'Collection originals changed during finalization')
 snapshot=out/'finalized-originals';snapshot.mkdir();save(snapshot/'transcript.json',final);capture(snapshot,run,final)
 print(run,'input-only mathematics 2 calls; native policy observations unchanged; final public originals closed',flush=True)
if __name__=='__main__':main()
