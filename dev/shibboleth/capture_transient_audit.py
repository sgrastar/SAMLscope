#!/usr/bin/env python3
"""Capture request-bound native audit facts with opaque names/session handles hashed.

Only lines for this Suite SP are selected. Field 9 (NameID) and field 19
(native login session identifier) are irreversibly transformed in memory before
any bytes reach the output folder. The reader matches the signed/decrypted
Assertion ID and NameID digest to these public audit originals.
"""
import argparse,datetime,hashlib,json,pathlib,subprocess
SHA=lambda b:hashlib.sha256(b).hexdigest()
def main():
 p=argparse.ArgumentParser();p.add_argument('root',type=pathlib.Path);a=p.parse_args();root=a.root.resolve();out=root/'native-audit-public';out.mkdir(exist_ok=False);created=json.loads((root/'browser/created.json').read_bytes());run=created['run']['id'];entity='http://localhost:18080/p/'+created['run']['planId'];before=subprocess.check_output(['docker','exec','samlscope-reference-shibboleth','sha256sum','/opt/reference-idp/conf/audit.xml']).decode().split()[0]
 raw=subprocess.check_output(['docker','exec','samlscope-reference-shibboleth','cat','/opt/reference-idp/logs/idp-audit.log']).decode();rows=[]
 for line in raw.splitlines():
  fields=line.split('|')
  if len(fields)!=21 or fields[4]!=entity or not fields[3] or not fields[5]:continue
  if not fields[9] or not fields[19]:raise ValueError('Native NameID/session audit unavailable; no identity guessed')
  fields[9]='sha256:'+SHA(fields[9].encode());fields[19]='sha256:'+SHA(fields[19].encode());rows.append('|'.join(fields))
 if len(rows)!=7:raise ValueError('Expected normal control plus six distinct native audit records')
 original=('\n'.join(rows)+'\n').encode();(out/'audit-public.log').write_bytes(original);after=subprocess.check_output(['docker','exec','samlscope-reference-shibboleth','sha256sum','/opt/reference-idp/conf/audit.xml']).decode().split()[0];assert before==after
 (out/'collector.py').write_bytes(pathlib.Path(__file__).read_bytes());(out/'observed.json').write_text(json.dumps(dict(runId=run,entityId=entity,recordedAt=datetime.datetime.now(datetime.timezone.utc).isoformat(),auditConfigurationSha256=before,publicOriginalSha256=SHA(original),sourceSha256=SHA(pathlib.Path(__file__).read_bytes()),rowCount=len(rows),nameIdFieldHashed=True,nativeLoginSessionFieldHashed=True,privateCredentialsExported=False,productConfigurationWrites=0,protocolOperations=0),sort_keys=True,indent=2)+'\n');print(run,'native audit public originals',len(rows))
if __name__=='__main__':main()
