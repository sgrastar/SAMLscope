#!/usr/bin/env python3
"""Install public native UI proof and source binaries with exact read-back; no target mutation."""
import argparse,hashlib,json,pathlib,re,subprocess,tempfile
p=argparse.ArgumentParser(description=__doc__);p.add_argument('folder',type=pathlib.Path);a=p.parse_args();folder=a.folder.resolve()
receipt=json.loads((folder/'qualified-receipt.json').read_bytes());run=receipt['runId']
if not re.fullmatch(r'run_[0-9A-HJKMNP-TV-Z]{26}',run):raise ValueError('Original Run required')
remote='/data/ui-native-feature-absence/'+run+'.keycloak-ui-consumer'
files={folder/'qualified-receipt.json':remote+'.json',folder/'native-source/before-services.jar':remote+'/native-services.jar',folder/'native-source/before-themes.jar':remote+'/native-themes.jar'}
subprocess.run(['docker','exec','--user','0','samlscope-reference-suite','mkdir','-p',remote],check=True,capture_output=True)
rows=[]
with tempfile.TemporaryDirectory(prefix='kc-public-ui-readback-') as temporary:
 for i,(source,destination) in enumerate(files.items()):
  subprocess.run(['docker','cp',str(source),'samlscope-reference-suite:'+destination],check=True,capture_output=True)
  back=pathlib.Path(temporary)/str(i);subprocess.run(['docker','cp','samlscope-reference-suite:'+destination,str(back)],check=True,capture_output=True)
  if back.read_bytes()!=source.read_bytes():raise ValueError('Public receipt/source read-back differs')
  rows.append(dict(file=str(source.relative_to(folder)),path=destination,sha256=hashlib.sha256(back.read_bytes()).hexdigest(),bytes=back.stat().st_size))
(folder/'receipt-install.json').write_text(json.dumps(dict(runId=run,files=rows,productConfigurationWrites=0,samlRequests=0,credentialsPersisted=False),indent=2)+'\n')
print('Public native UI receipt and source installation verified')
