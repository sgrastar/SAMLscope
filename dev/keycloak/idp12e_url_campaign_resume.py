#!/usr/bin/env python3
"""Resumable, bounded local driver for the Keycloak IIP-IDP12.e URL campaign.

Each subcommand has a small bounded operation budget so an interrupted terminal
cannot strand a temporary client. `finish` restores the native-imported state,
deletes the temporary client, and exports Suite originals.
"""
import argparse, copy, hashlib, json, os, re, shutil, subprocess, sys
import urllib.error, urllib.parse as urls, urllib.request as http
from pathlib import Path
REPO=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(REPO/'dev/keycloak'));sys.path.insert(0,str(REPO/'dev/reference-acceptance'))
from import_metadata_batch import api,save,BASE
from reference_flow import Client
CASE='IIP-IDP12-e-idp-01'; ADMIN='http://localhost:18180/admin/realms/samlscope';TOKEN_URL='http://localhost:18180/realms/master/protocol/openid-connect/token'
USER=os.environ.get('REFERENCE_USERNAME','samlscope-m0-user');PASSWORD=os.environ.get('REFERENCE_PASSWORD','samlscope-m0-password')
def canonical(x):return json.dumps(x,ensure_ascii=False,sort_keys=True,separators=(',',':')).encode()
def sha(x):return hashlib.sha256(x).hexdigest()
def tok():
 b=urls.urlencode(dict(client_id='admin-cli',username=os.environ.get('KEYCLOAK_ADMIN_USERNAME','admin'),password=os.environ.get('KEYCLOAK_ADMIN_PASSWORD','admin'),grant_type='password')).encode()
 with http.urlopen(http.Request(TOKEN_URL,data=b),timeout=30) as r:return json.load(r)['access_token']
def admin(access,ops):
 def call(path,body=None,method='GET'):
  encoded=None if body is None else canonical(body)
  q=http.Request(ADMIN+path,data=encoded,method=method,headers={'Authorization':'Bearer '+access,'Content-Type':'application/json'})
  rec={'method':method,'path':path.split('?',1)[0]};ops.append(rec)
  if encoded is not None:rec['request_json_sha256']=sha(encoded)
  try:
   with http.urlopen(q,timeout=30) as r:
    rec['status']=r.status;raw=r.read()
    if not raw:return None
    value=json.loads(raw);rec['response_json_sha256']=sha(canonical(value));return value
  except urllib.error.HTTPError as e:rec['status']=e.code;raise RuntimeError(f'admin {method} {rec["path"]} {e.code}') from None
 return call
def find(call,entity):
 rows=call('/clients?clientId='+urls.quote(entity,safe=''))
 if len(rows)>1:raise ValueError('ambiguous client')
 if not rows:return None
 ident=rows[0].get('id','')
 if not re.fullmatch(r'[a-f0-9-]{36}',ident):raise ValueError('invalid client id')
 x=call('/clients/'+ident)
 if x.get('id')!=ident or x.get('clientId')!=entity:raise ValueError('client identity mismatch')
 return x
def info(out):
 p=json.loads((out/'plan.json').read_text());c=json.loads((out/'created.json').read_text())['run'];return p['plan']['plan']['id'],c['id'],BASE+'/p/'+p['plan']['plan']['id']
def cap(out,action):subprocess.run([sys.executable,str(REPO/'dev/reference-acceptance/capture_keycloak_default_acs_runtime.py'),str(out),action],check=True,timeout=120)
def write_ops(out,ops):
 p=out/'admin-operations.json'; old=json.loads(p.read_text()) if p.exists() else []
 old.extend(ops);save(p,old)
def setup(out,mods):
 if out.exists() and any(out.iterdir()):raise ValueError('empty output required')
 out.mkdir(parents=True);ops=[];call=admin(tok(),ops)
 p=api('/api/plans',dict(name='Keycloak ACS URL selection native import',profile='browser_sso_idp',targetKind='IDP',targetEntityId='http://localhost:18180/realms/samlscope',metadataSourceKind='URL',metadataSourceLocation='http://samlscope-reference-keycloak:8080/realms/samlscope/protocol/saml/descriptor',suiteMetadataDelivery='HTTP_URL',declaredFeatures={},parameters=dict(clockSkewToleranceSeconds=180,metadataRefreshWaitSeconds=300,testUserHint=USER,requestSigningMode='REQUIRED'),interaction=dict(allowBrowserSteps=True,allowAttestation=False,preset='quick'),authorizedTarget=True));save(out/'plan.json',p);plan=p['plan']['plan']['id']
 c=api('/api/plans/'+plan+'/runs',{});save(out/'created.json',c);run=c['run']['id'];save(out/'preflight.json',api('/api/runs/'+run+'/preflight',{}));entity=BASE+'/p/'+plan
 with http.urlopen(entity+'/metadata',timeout=60) as r: fixture=r.read()
 (out/'suite-sp-metadata.xml').write_bytes(fixture)
 if find(call,entity):raise ValueError('existing client')
 stage=out/'driver';stage.mkdir();shutil.copyfile(REPO/'dev/keycloak/console_import.mjs',stage/'console_import.mjs');(stage/'node_modules').symlink_to(mods.resolve(),target_is_directory=True)
 cap(out,'target-start')
 r=subprocess.run(['node',str(stage/'console_import.mjs'),'--fixture',str(out/'suite-sp-metadata.xml'),'--record',str(out/'import.json'),'--entity-id',entity],capture_output=True,text=True,timeout=180)
 (out/'console-import.log').write_text(r.stdout+r.stderr)
 if r.returncode:raise RuntimeError('native console import failed')
 original=find(call,entity)
 if not original:raise RuntimeError('console client absent')
 (out/'client-original.json').write_bytes(canonical(original));updated=copy.deepcopy(original);primary=entity+'/sp/acs/0';secondary=entity+'/sp/acs/1'
 if primary not in updated.get('redirectUris',[]):raise RuntimeError('primary ACS absent after import')
 if secondary in updated.get('redirectUris',[]):raise RuntimeError('secondary ACS already accepted after import')
 updated['redirectUris']=sorted(set(updated['redirectUris'])|{secondary});call('/clients/'+original['id'],updated,'PUT');readback=find(call,entity)
 # Preserve the product's API read-back as an immutable original before driving a request.
 # The verifier binds this response to the immediately preceding PUT in admin-operations.
 if not readback:raise RuntimeError('temporary client read-back missing')
 (out/'client-configured-readback.json').write_bytes(canonical(readback))
 if set(readback.get('redirectUris',[]))!=set(updated['redirectUris']) or readback.get('attributes')!=original.get('attributes'):raise RuntimeError('secondary ACS read-back mismatch')
 save(out/'client-configuration.json',{'entity_id':entity,'client_database_id':original['id'],'original_sha256':sha(canonical(original)),'original_redirect_uris':original.get('redirectUris'),'configured_redirect_uris':readback.get('redirectUris'),'configured_readback_sha256':sha(canonical(readback)),'added_redirect_uri':secondary,'configuration_scope':'temporary existing console-imported client redirectUris only'})
 initial=Client().flow(entity+'/start/m0-roundtrip?run='+run,None,USER,PASSWORD);save(out/'initial-login.json',{'receipt':initial})
 if initial!='recorded':raise RuntimeError('baseline login did not record')
 save(out/'tests-start.json',api('/api/runs/'+run+'/tests/start',{}));write_ops(out,ops)
def drive(out,limit):
 plan,run,entity=info(out);rows=json.loads((out/'steps.json').read_text()) if (out/'steps.json').exists() else [];ops=[];call=admin(tok(),ops);current=find(call,entity)
 expected=json.loads((out/'client-configuration.json').read_text())
 if not current or expected['added_redirect_uri'] not in current.get('redirectUris',[]):raise RuntimeError('temporary ACS configuration missing')
 seen=any(x.get('caseId')==CASE for x in rows)
 for n in range(limit):
  status=api('/api/runs/'+run+'/active-probe');case=status.get('caseId')
  if seen and case!=CASE:
   rows.append({'caseId':CASE,'action':'target-complete','nextCaseId':case,'state':status.get('state')});save(out/'steps.json',rows);break
  if case==CASE:seen=True
  if status.get('state')=='AWAITING_RESPONSE':
   api('/api/runs/'+run+'/active-probe/abort',{});rows.append({'caseId':case,'actionId':status.get('actionId'),'action':'abort'});save(out/'steps.json',rows);continue
  if status.get('state')!='READY':raise RuntimeError('unexpected probe state '+str(status.get('state')))
  result=Client().flow(status['startUrl'],None,USER,PASSWORD);after=api('/api/runs/'+run+'/active-probe')
  row={'caseId':case,'actionId':status.get('actionId'),'receipt':result,'nextState':after.get('state'),'nextCaseId':after.get('caseId'),'nextActionId':after.get('actionId')};rows.append(row)
  if after.get('state')=='AWAITING_RESPONSE' and after.get('actionId')==status.get('actionId'):
   api('/api/runs/'+run+'/active-probe/abort',{});row['abort_after_unrecorded_terminal']=True
  save(out/'steps.json',rows)
 save(out/'steps.json',rows);write_ops(out,ops);save(out/'drive-state.json',{'run':run,'target_seen':seen,'target_completed':seen and api('/api/runs/'+run+'/active-probe').get('caseId')!=CASE,'steps':len(rows)})
def finish(out):
 plan,run,entity=info(out);ops=[];call=admin(tok(),ops);cfg=json.loads((out/'client-configuration.json').read_text());original=json.loads((out/'client-original.json').read_text());cleanup={'restore_attempted':False,'delete_attempted':False}
 try:
  current=find(call,entity)
  if current:
   if current['id']!=cfg['client_database_id']:raise RuntimeError('cleanup identity mismatch')
   cleanup['restore_attempted']=True;call('/clients/'+current['id'],original,'PUT');restored=find(call,entity)
   cleanup['redirect_uris_restored']=restored.get('redirectUris')==original.get('redirectUris');cleanup['attributes_restored']=restored.get('attributes')==original.get('attributes')
   if not cleanup['redirect_uris_restored'] or not cleanup['attributes_restored']:raise RuntimeError('restore mismatch')
   save(out/'client-restoration.json',{'original_sha256':sha(canonical(original)),'restored_sha256':sha(canonical(restored)),'redirect_uris_restored':cleanup['redirect_uris_restored'],'attributes_restored':cleanup['attributes_restored'],'restored':True})
   cleanup['delete_attempted']=True;call('/clients/'+current['id'],method='DELETE')
  cleanup['read_back_absent']=find(call,entity) is None;cleanup['restored']=cleanup['read_back_absent']
 finally:
  write_ops(out,ops);save(out/'cleanup.json',cleanup)
 if not cleanup.get('restored'):raise RuntimeError('cleanup unproven')
 # Export active evidence before formal reevaluation; capture helper proves re-evaluation immutability.
 entries=api('/api/runs/'+run+'/transcript');save(out/'transcript.json',entries)
 for name in ['result.json','protocol-evidence']:
  with http.urlopen(BASE+'/api/runs/'+run+'/'+name,timeout=60) as r:(out/name).write_bytes(r.read())
 cap(out,'target-end');cap(out,'suite')
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);p.add_argument('mode',choices=['setup','drive','finish']);p.add_argument('--playwright-modules',type=Path);p.add_argument('--limit',type=int,default=15);a=p.parse_args();out=a.output.resolve()
 if a.mode=='setup':
  if not a.playwright_modules:p.error('--playwright-modules required for setup')
  setup(out,a.playwright_modules)
 elif a.mode=='drive':drive(out,a.limit)
 else:finish(out)
