#!/usr/bin/env python3
"""Record already collected public direct-HTTP control originals; no product operations."""
import argparse,base64,hashlib,json,sys
from datetime import datetime,timezone
from pathlib import Path
from persistent_nameid_normal_campaign import REPO,api,save,raw
sys.path.insert(0,str(REPO/'dev/keycloak'))
from algorithm_preference_campaign import recorded
sys.path.insert(0,str(REPO/'dev/reference-acceptance'))
from capture_run_originals import capture
def sha(raw):return hashlib.sha256(raw).hexdigest()
def encoded(raw):return dict(base64=base64.b64encode(raw).decode(),sha256=sha(raw))
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('folder',type=Path);a=p.parse_args();out=a.folder.resolve();load=lambda n:json.loads((out/n).read_bytes());created=load('created.json');run=created['run']['id']
 receipt=load('qualified-receipt.json')
 if 'baselineProtocolControl' in receipt:raise ValueError('Native baseline control already recorded')
 observations=load('native-http-observations.json');records=observations['records'];rejects=[r for r in records if r['native_signature_rejection']=='signature-value-invalid']
 if len(records)!=2 or len(rejects)!=1:raise ValueError('Ambiguous actual transport control')
 reject=rejects[0];ident=reject['request_id'];originals={suffix:encoded((out/'native-http-originals'/(ident+'.'+suffix)).read_bytes()) for suffix in ['html','request.xml','request.body']}
 value=dict(schema='samlscope-ssp-mdiop-native-original-v1',runId=run,targetEntityId=receipt['targetEntityId'],targetMetadataSha256=receipt['targetMetadataSha256'],kind='baseline-protocol-control',recordedAt=datetime.now(timezone.utc).isoformat(),variant='control',nativeTransport=reject,originals=originals,nativeMessageSource=encoded(raw('/var/simplesamlphp/modules/saml/src/Message.php')),collector=encoded(Path(__file__).read_bytes()))
 for name in ['qualified-receipt.json','transcript.json','decoded-manifest.json','operation-counts.json']:
  copy=out/(name.removesuffix('.json')+'-initial.json')
  if copy.exists():raise ValueError('Immutable pre-augmentation history exists')
  copy.write_bytes((out/name).read_bytes())
 reference=recorded(out,created,value,'baseline-protocol-control');receipt['baselineProtocolControl']=reference;save(out/'qualified-receipt.json',receipt)
 entries=api('/api/runs/'+run+'/transcript');save(out/'transcript.json',entries);capture(out,run,entries)
 counts=load('operation-counts.json');counts['nativeOriginalRecorderWrites']+=1;counts['publicOriginalAugmentationAttempts']=1;save(out/'operation-counts.json',counts)
 save(out/'augmentation-history.json',dict(schema='samlscope-public-original-augmentation-v1',productConfigurationWrites=0,productProtocolOperations=0,humanOperations=0,originalTranscriptEntryIds=[e['id'] for e in load('transcript-initial.json')],addedOriginal=reference,collectorSha256=sha(Path(__file__).read_bytes())))
 print(run,'actual baseline HTTP control appended, product untouched')
if __name__=='__main__':main()
