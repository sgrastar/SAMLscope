"""Keep historical runtime-epoch proof intact after a separately recorded daemon recovery."""
import hashlib,json,pathlib,subprocess
from keycloak_registered_signer_stored_outcome import _instant_seconds
NAME='/samlscope-reference-keycloak'
NAMES={NAME,'/samlscope-reference-suite','/samlscope-reference-ssp','/samlscope-reference-shibboleth','/samlscope-reference-local-forward-v116'}
sha=lambda raw:hashlib.sha256(raw).hexdigest()
def mounts(rows):
    require(isinstance(rows,list) and all(isinstance(r,dict) and isinstance(r.get('Destination'),str) for r in rows),'Invalid native mount inventory')
    require(len({r['Destination'] for r in rows})==len(rows),'Ambiguous native mount inventory')
    return sorted(rows,key=lambda r:r['Destination'])
def require(value,message):
    if not value:raise ValueError(message)
def runtime_recovery_proof(folder,expected,actual,current_inspect=None):
    if actual==expected:return None
    require(set(actual)==set(expected) and all(actual[k]==expected[k] for k in expected if k!='startedAt'),'Post-recovery native runtime changed beyond its epoch')
    directory=pathlib.Path(folder).parent/'docker-maintenance';records={}
    for name in ['pre-recovery-containers.json','post-recovery-containers.json','desktop-recovery.json']:
        path=directory/name
        require(path.is_file() and not any(p.is_symlink() for p in [path,*path.parents]),'Unsafe daemon recovery original')
        raw=path.read_bytes();records[name]={'sha256':sha(raw),'value':json.loads(raw)}
    pre=records['pre-recovery-containers.json']['value'];post=records['post-recovery-containers.json']['value'];recovery=records['desktop-recovery.json']['value']
    require(len(pre)==len(post)==5 and {r['Name'] for r in pre}=={r['Name'] for r in post}==NAMES,'Recovery scope is not the same five reference containers')
    pre={r['Name']:r for r in pre};post={r['Name']:r for r in post}
    require(len({r['Id'] for r in pre.values()})==len({r['Id'] for r in post.values()})==5,'Ambiguous recovery container identities')
    for name in NAMES:
        require(pre[name]['Id']==post[name]['Id'] and pre[name]['Image']==post[name]['Image'] and mounts(pre[name]['Mounts'])==mounts(post[name]['Mounts']) and pre[name]['Running'] is post[name]['Running'] is True,'Recovery changed a container/image/mount or did not restart the same process')
        require(_instant_seconds(pre[name]['StartedAt'])<_instant_seconds(post[name]['StartedAt']),'Recovery epoch did not advance')
    require(recovery['ioRecovered'] is True and recovery['runtimeMatches'] is True and recovery['runtimeFiles']==125 and recovery['settingsWrites']==recovery['protocolSubmissions']==recovery['personOperations']==recovery['volumeDeletion']==0 and recovery['daemonRestarts']==1 and recovery['productContainerStarts']==3 and recovery['suiteContainerStarts']==recovery['forwarderContainerStarts']==1,'Recovery actions or deployed-runtime verification differ')
    before=pre[NAME];after=post[NAME]
    require((expected['containerId'],expected['image'],expected['startedAt'])==(before['Id'],before['Image'],before['StartedAt']) and (actual['containerId'],actual['image'],actual['startedAt'])==(after['Id'],after['Image'],after['StartedAt']),'Native historical/current epochs do not bind to the recorded recovery')
    recorded=recovery['recordedAt'];recorded=recorded[:-6]+'Z' if recorded.endswith('+00:00') else recorded
    require(_instant_seconds(after['StartedAt'])<_instant_seconds(recorded),'Recovery completion precedes its native restart')
    if current_inspect is None:
        rows=json.loads(subprocess.check_output(['docker','inspect','samlscope-reference-keycloak'],timeout=40))
        require(len(rows)==1,'Ambiguous live native runtime');row=rows[0]
        current_inspect={'Id':row['Id'],'Name':row['Name'],'Image':row['Image'],'Running':row['State']['Running'],'StartedAt':row['State']['StartedAt'],'Mounts':row['Mounts']}
    require(current_inspect==after,'Current native runtime/mounts do not match the post-recovery original')
    return {'purpose':'post-campaign restoration read-back following separately recorded daemon recovery; historical campaign epochs are not rewritten','historicalRuntime':expected,'postRecoveryRuntime':actual,'recordedCurrentNativeInspect':current_inspect,'recoveryOriginalSha256':{k:v['sha256'] for k,v in records.items()},'globalRecoveryCosts':{'daemonRestarts':recovery['daemonRestarts'],'productContainerStarts':recovery['productContainerStarts'],'suiteContainerStarts':recovery['suiteContainerStarts'],'forwarderContainerStarts':recovery['forwarderContainerStarts'],'shibbolethServiceStarts':recovery['shibbolethServiceStarts'],'settingsWrites':0,'protocolSubmissions':0,'personOperations':0,'volumeDeletion':0},'originalCampaignProofUnchanged':True}
