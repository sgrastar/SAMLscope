#!/usr/bin/env python3
"""Read current native log ranges. This is explicitly not a historical offset capture."""
import argparse,datetime,hashlib,json,pathlib,subprocess
CONTAINER='samlscope-reference-shibboleth';LOG='/opt/reference-idp/logs/idp-process.log'
SHA=lambda b:hashlib.sha256(b).hexdigest()
NOW=lambda:datetime.datetime.now(datetime.timezone.utc).isoformat().replace('+00:00','Z')
def docker(*args):return subprocess.run(['docker','exec',CONTAINER,*args],capture_output=True,check=True,timeout=30).stdout
def save(p,value):p.write_text(json.dumps(value,indent=2)+'\n')
def capture(folder):
 folder=pathlib.Path(folder);out=folder/'receipt';created=json.loads((folder/'created.json').read_bytes())['run'];run=created['id'];entity='http://localhost:18080/p/'+created['planId'];provider='Validity'+run
 target=out/'retrospective-log-range.json'
 if target.exists():raise ValueError('Retrospective original already exists')
 started=NOW();before=docker('stat','-c','%i %s %Y',LOG).decode().strip();raw=docker('cat',LOG);after=docker('stat','-c','%i %s %Y',LOG).decode().strip();finished=NOW()
 if before!=after:raise ValueError('Native log changed during range read; retry without persisting raw log')
 inode,size,mtime=before.split();assert int(size)==len(raw)
 runtime=json.loads(subprocess.run(['docker','inspect','--format','{"id":{{json .Id}},"image":{{json .Image}},"gateway":{{range .NetworkSettings.Networks}}{{json .Gateway}}{{end}}}',CONTAINER],capture_output=True,check=True,timeout=30).stdout)
 rows=[];offset=0
 for number,line in enumerate(raw.splitlines(keepends=True),1):
  if ('FilesystemMetadataResolver '+provider+':').encode() in line and ('EntityDescriptor with the ID: '+entity+',').encode() in line and b'but it was no longer valid' in line:
   text=line.decode();timestamp=datetime.datetime.strptime(text[:23],'%Y-%m-%d %H:%M:%S,%f').replace(tzinfo=datetime.timezone.utc)
   for observation in json.loads((folder/'observations.json').read_bytes()):
    http=observation['after']['nativeHttp'][0];begin=datetime.datetime.fromisoformat(http['startedAt']);end=datetime.datetime.fromisoformat(http['completedAt'])
    if begin.replace(microsecond=begin.microsecond//1000*1000)<=timestamp<=end:
     name=observation['variant']+'-retrospective-native-log-line.txt';path=out/name
     if path.exists():raise ValueError('Ambiguous or repeated matching native expiry event')
     path.write_bytes(line);assert line.strip()==(out/(observation['variant']+'-after-probe-process.log')).read_bytes().strip()
     rows.append(dict(variant=observation['variant'],file=name,sha256=SHA(line),offsetStart=offset,offsetEnd=offset+len(line),lineNumber=number,nativeInstant=timestamp.isoformat().replace('+00:00','Z')))
  offset+=len(line)
 assert len(rows)==3 and len({r['variant'] for r in rows})==3
 save(target,dict(schema='samlscope-retrospective-native-log-range-v1',evidenceKind='retrospective-physical-range-readback',historicalBeforeOffsetCaptured=False,hostStartedAt=started,hostCompletedAt=finished,logPath=LOG,inode=int(inode),size=int(size),mtimeEpochSeconds=int(mtime),nativeLogSha256=SHA(raw),readBackUnchanged=True,targetRuntime=runtime,ranges=rows,privateLogContentsPersisted=False,productConfigurationWrites=0,protocolOperations=0))
 return len(rows)
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('folder',type=pathlib.Path);a=p.parse_args();print(capture(a.folder),'public native log ranges captured, no historical offsets asserted')
