#!/usr/bin/env python3
"""Complete a CONFIG source Run's initial round trip and start its full profile.

Profile start is not a selected-case API. Record its actual message and outbox
changes instead of claiming zero dispatches. Credentials and cookies remain in
memory. The previous native key epoch and its originals remain unchanged.
"""
import argparse,hashlib,json,os,re,subprocess,sys,time
from datetime import datetime,timezone
from pathlib import Path
sys.dont_write_bytecode=True
from transient_allow_create_campaign import REPO,CONTAINER,IDP,BASE,api,save,batch,settled,raw
sys.path.insert(0,str(REPO/'dev/keycloak'))
from reference_flow import Client
from initial_roundtrip_accounting import OperationSnapshots, difference

def require(value,reason):
    if not value:raise ValueError(reason)
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--folder',type=Path,required=True);a=p.parse_args();folder=a.folder.resolve()
    require(folder.is_relative_to(REPO/'build/acceptance') and folder.is_dir(),'Owned ignored capture required')
    require(not any(p.is_symlink() for p in [folder,*folder.parents]),'Unsafe capture path')
    created=json.loads((folder/'created.json').read_bytes());run=created['run']['id'];plan=created['run']['planId']
    require(re.fullmatch(r'run_[0-9A-HJKMNP-TV-Z]{26}',run) and re.fullmatch(r'plan_[0-9A-HJKMNP-TV-Z]{26}',plan),'Invalid actual scope')
    current=api('/api/runs/'+run);model=api('/api/plans/'+plan)['plan']
    require(current['planId']==plan and model['profile']=='single_logout_idp' and model['target']['entityId']==IDP,'Foreign actual target/profile')
    user=os.environ.get('REFERENCE_USERNAME');password=os.environ.get('REFERENCE_PASSWORD')
    require(user is not None and password is not None,'In-memory owned reference credentials required')
    out=folder/'initial-roundtrip';out.mkdir()
    operations=[];original_run=subprocess.run
    def native_run(command,*args,**options):
        if not isinstance(command,(list,tuple)) or command[0]!='docker':return original_run(command,*args,**options)
        row=dict(index=len(operations),command=list(command),startedAt=datetime.now(timezone.utc).isoformat(),stdinSha256=hashlib.sha256(options.get('input') or b'').hexdigest());operations.append(row)
        try:
            if not any(k in options for k in ('stdout','stderr','capture_output')):options['capture_output']=True
            result=original_run(command,*args,**options)
            row.update(exitCode=result.returncode,stdoutSha256=hashlib.sha256(result.stdout or b'').hexdigest(),stderrSha256=hashlib.sha256(result.stderr or b'').hexdigest())
            if result.stdout is not None:(out/(str(row['index'])+'.stdout')).write_bytes(result.stdout)
            if result.stderr is not None:(out/(str(row['index'])+'.stderr')).write_bytes(result.stderr)
            return result
        except subprocess.CalledProcessError as error:
            row.update(exitCode=error.returncode,stdoutSha256=hashlib.sha256(error.stdout or b'').hexdigest(),stderrSha256=hashlib.sha256(error.stderr or b'').hexdigest());raise
        finally:row['finishedAt']=datetime.now(timezone.utc).isoformat();save(out/'operations.json',operations)
    subprocess.run=native_run
    remote=batch('saml20-sp-remote.php')
    require(settled(remote.container_path,remote.original)==(folder/'remote-original.php').read_bytes()
        and raw('/var/simplesamlphp/metadata/saml20-idp-hosted.php')==(folder/'hosted-original.php').read_bytes(),'Previous epoch not restored')
    (out/'remote-original.php').write_bytes(remote.original)
    parser=json.loads((folder/'native-peer-parser.stdout').read_bytes());entity=BASE+'/p/'+plan;require(parser['entity_id']==entity,'Foreign native peer')
    class CountingClient(Client):
        def __init__(self):super().__init__();self.credentialPosts=0
        def request(self,url,fields=None):
            if fields and any('password' in str(k).lower() for k in fields):
                require(self.credentialPosts==0,'No repeated credential submission');self.credentialPosts+=1
            return super().request(url,fields)
    client=CountingClient();attempted=0;profile_counts=None;initial_counts=None
    try:
        with OperationSnapshots(REPO,out,run) as counters:
            before=counters.capture('before-initial')
            require(not before['caseExecutions'] and not before['outboxActions'],
                'This source prerequisite helper requires an unstarted profile')
            remote.apply(parser['php'].encode());(out/'remote-configured.php').write_bytes(settled(remote.container_path,remote.expected));time.sleep(3)
            attempted=1
            receipt=client.flow(entity+'/start/m0-roundtrip?run='+run,None,user,password)
            save(out/'flow.json',dict(runId=run,receipt=receipt));current=api('/api/runs/'+run);save(out/'run-after.json',current)
            require(current['status']=='COMPLETED','Initial normal round trip did not complete; no retry')
            ready=counters.capture('before-profile-start');initial_counts=difference(before,ready)
            save(out/'tests-start.json',api('/api/runs/'+run+'/tests/start',{}))
            started=counters.capture('after-profile-start');profile_counts=difference(ready,started)
            save(out/'recorded-operation-differences.json',dict(initial=initial_counts,fullProfileStart=profile_counts))
            save(out/'result.json',api('/api/runs/'+run+'/result.json'))
    finally:
        try:
            restoration=remote.restore();(out/'remote-final.php').write_bytes(settled(remote.container_path,remote.original));save(out/'restoration.json',restoration)
            require(raw('/var/simplesamlphp/metadata/saml20-idp-hosted.php')==(folder/'hosted-original.php').read_bytes(),'Unrelated native hosted config changed')
            save(out/'operation-counts.json',dict(productConfigurationWriteAttempts=remote.write_count,successfulHostWrites=remote.write_count,nativeApplications=remote.applied_count,
                restorationWrites=remote.restoration_writes,initialNormalProtocolOperationsAttempted=attempted,credentialPosts=client.credentialPosts,
                dockerCommandsAttempted=len(operations),failedDockerCommands=sum(x.get('exitCode',-1)!=0 for x in operations),
                schema='samlscope-initial-roundtrip-operation-counts-v2',
                initialRecordedOperations=initial_counts,fullProfileStartRecordedOperations=profile_counts,
                networkAttemptCount=None,networkAttemptCountBasis='Recorded messages/outbox states only; unrecorded network retries are not inferred.',
                humanOperations=0,restored=restoration['restored']))
            require(restoration['restored'],'Native remote peer restoration failed')
        finally:subprocess.run=original_run
    print(run,'actual initial round trip completed; full-profile operation changes recorded; native peer restored')
if __name__=='__main__':main()
