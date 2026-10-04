#!/usr/bin/env python3
"""PROVISIONAL / NON-ADOPTABLE: IDP21 selector controls and recipient original are unfinished."""
import argparse,hashlib,importlib.util,json,pathlib,secrets,shutil,subprocess,tempfile,zipfile
REPO=pathlib.Path(__file__).resolve().parents[2]
SUITE='samlscope-reference-suite'
RUN='run_MZ1VKMF44GK8TD3H67V3D7YM5S'
SOURCE='run_5PVJ1E05DBMMMASJ9QTS45T3TM'
CASE='IIP-IDP21-a-idp-01'
DIGEST='sha256:a7252257701b0427cd6bb9eea917624135a3344042e2135501cfb4f4a41b23f8'
RESOURCE='com/samlscope/runner/cases/native-uuid-canonical-formatter-contract.json'
SHA=lambda b:hashlib.sha256(b).hexdigest()
READ=lambda p:json.loads(pathlib.Path(p).read_bytes())
COUNTS=[]
PROVISIONAL_REASON="IDP21 is unregistered and NOT_VERIFIED: the same-policy different-subject negative control and genuine recipient transcript are unqualified. No installation, evaluation, or infrastructure commands are enabled."
def require(v,why):
    if not v:raise ValueError(why)
def save(p,v):pathlib.Path(p).write_text(json.dumps(v,indent=2)+'\n')
def command(args,timeout=300):
    raise RuntimeError(PROVISIONAL_REASON)
    r=subprocess.run(list(map(str,args)),capture_output=True,timeout=timeout)
    COUNTS.append(dict(command=list(map(str,args)),exitCode=r.returncode,stdoutSha256=SHA(r.stdout),stderrSha256=SHA(r.stderr)))
    if r.returncode:raise RuntimeError('Public capability infrastructure command failed: '+str(args[0])+', exit '+str(r.returncode)+'; '+r.stderr.decode(errors='replace')[:3000])
    return r

def archive(folder):
    raise RuntimeError(PROVISIONAL_REASON)
    spec=importlib.util.spec_from_file_location('persistent_adoption',REPO/'dev/reference-acceptance/verify_keycloak_persistent_identifier_acceptance.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
    m.HELPER='VerifyKeycloakCaseCollisionCapability';m.PRODUCTION+=['NativeUuidFormatterDerivation','KeycloakCaseCollisionCapabilityEvidence','NativeCaseCollisionCapabilityTestCase']
    generation=folder/("reader-generation-"+secrets.token_hex(6));generation.mkdir();target=m.archive(generation)
    resource=(REPO/'runner/src/main/resources'/RESOURCE).read_bytes();jar=target/'runner.jar';parent=target/'runner-persistent-candidate.jar';jar.rename(parent)
    with zipfile.ZipFile(parent) as old,zipfile.ZipFile(jar,'w',zipfile.ZIP_DEFLATED) as new:
        for entry in old.infolist():
            if entry.filename!=RESOURCE:new.writestr(entry,old.read(entry.filename))
        new.writestr(RESOURCE,resource)
    with zipfile.ZipFile(parent) as old,zipfile.ZipFile(jar) as new:require(set(new.namelist())==set(old.namelist())|{RESOURCE} and all(old.read(n)==new.read(n) for n in old.namelist() if n!=RESOURCE),'Unrelated candidate bytes changed')
    pins=READ(target/'pins.json');pins['projects']['runner']=SHA(jar.read_bytes());pins['casePolicyResourceSha256']=SHA(resource);save(target/'pins.json',pins)
    pointer=folder/'active-candidate.json'
    if pointer.exists():shutil.copyfile(pointer,folder/('candidate-selection-'+secrets.token_hex(6)+'.json'))
    save(pointer,dict(directory=str(target.relative_to(folder)),pinsSha256=SHA((target/'pins.json').read_bytes())))
    return target

def remote(folder,mode,output):
    raise RuntimeError(PROVISIONAL_REASON)
    pointer=READ(folder/'active-candidate.json');archive=folder/pointer['directory'];pins=READ(archive/'pins.json');require(SHA((archive/'pins.json').read_bytes())==pointer['pinsSha256'],'Candidate changed')
    target='/tmp/kc-case-policy-'+secrets.token_hex(8)
    command(['docker','exec','-u','0',SUITE,'mkdir',target])
    try:
        for name,digest in pins['projects'].items():
            p=archive/(name+'.jar');require(p.stat().st_nlink==1 and SHA(p.read_bytes())==digest,'Independent candidate bytes changed');command(['docker','cp',p,SUITE+':'+target+'/'+name+'.jar'])
        command(['docker','cp',archive/'classes',SUITE+':'+target+'/classes'])
        if mode!='preflight':
            command(['docker','cp',folder/'receipt',SUITE+':'+target+'/receipt'])
            command(['docker','cp',folder/'source-native',SUITE+':'+target+'/source-native'])
        uid=command(['docker','exec',SUITE,'id','-u']).stdout.decode().strip();require(uid.isdecimal(),'Unsafe Suite uid');command(['docker','exec','-u','0',SUITE,'chown','-R',uid+':'+uid,target]);command(['docker','exec','-u','0',SUITE,'chmod','-R','a+rX',target])
        cp=':'.join(target+'/'+n+'.jar' for n in ['runner','core','saml','store','api','peer'])+':'+target+'/classes:'+':'.join('/opt/samlscope/lib/'+r['name'] for r in pins['dependencies'])
        command(['docker','exec',SUITE,'java','-Xmx768m','-cp',cp,'com.samlscope.runner.cases.VerifyKeycloakCaseCollisionCapability',mode,'/data',RUN,SOURCE if mode=='preflight' else target+'/receipt',target+'/proof.json'],600)
        command(['docker','cp',SUITE+':'+target+'/proof.json',output])
        if mode=='snapshot':
            for name in ['destination-store.json','destination-history.json','source-stores.json','source-history.json']:command(['docker','cp',SUITE+':'+target+'/receipt/'+name,folder/'receipt'/name])
    finally:
        command(['docker','exec','-u','0',SUITE,'rm','-rf','--',target]);command(['docker','exec',SUITE,'test','!','-e',target])
    return READ(output)

def prepare(folder):
    raise RuntimeError(PROVISIONAL_REASON)
    source=REPO/'build/acceptance/reference-20261004/keycloak-persistent-opaque-r1/receipt';require(source.is_dir(),'Qualified persistent receipt unavailable')
    require(not (folder/'receipt').exists() and not (folder/'source-native').exists(),'Refusing original overwrite')
    archive(folder);scope=remote(folder,'preflight',folder/'membership-preflight.json');require(scope['runId']==RUN and scope['sourceRunId']==SOURCE and scope['caseDigest']==DIGEST,'Wrong approved scope')
    receipt=folder/'receipt';receipt.mkdir()
    for p in folder.glob('*.stdout.txt'):shutil.copyfile(p,receipt/p.name)
    for p in folder.glob('*.stderr.txt'):shutil.copyfile(p,receipt/p.name)
    for name in ['native-formatter-helper.java','native-formatter-process.json']:shutil.copyfile(folder/name,receipt/name)
    shutil.copytree(folder/'native-jre-classes',receipt/'native-jre-classes')
    slo=REPO/'build/acceptance/reference-20261004/keycloak-slo-registered-signer-r5/receipt'
    shutil.copyfile(slo/'native-readbacks/initial.json',receipt/'recipient-native-epoch.json');shutil.copyfile(slo/'native-originals/initial.json',receipt/'recipient-native-epoch-record.json')
    companion=folder/'source-native';companion.mkdir();shutil.copytree(source,companion/(SOURCE+'.keycloak-native-identifier'))
    manifest=dict(schema='samlscope-keycloak-case-collision-capability-v1',scope='selectable-native-persistent-canonical-construction-only',runId=RUN,planId=scope['planId'],caseId=CASE,caseDigest=DIGEST,sourceRunId=SOURCE,sourcePlanId=scope['sourcePlanId'],targetEntityId=scope['targetEntityId'],targetMetadataSha256=scope['targetMetadataSha256'],sourceManifestSha256=SHA((source/'manifest.json').read_bytes()),files={})
    save(receipt/'manifest.json',manifest);remote(folder,'snapshot',folder/'binding-snapshot.json')
    manifest['files']={str(p.relative_to(receipt)):SHA(p.read_bytes()) for p in receipt.rglob('*') if p.is_file() and p.name!='manifest.json'};save(receipt/'manifest.json',manifest)
    baseline=remote(folder,'replay',folder/'candidate-reader-replay.json');require(baseline['productionOutcome']['outcome']=='SATISFIED' and len(baseline['negativeControls'])==13 and set(baseline['negativeControls'].values())=={'NOT_VERIFIED'},'Native capability not qualified')
    remote(folder,'state',folder/'state-before.json')
    return baseline

def main():
    p=argparse.ArgumentParser();p.add_argument('mode',choices=['prepare','replay','state']);p.add_argument('folder',type=pathlib.Path);a=p.parse_args();p.error(PROVISIONAL_REASON);folder=a.folder.resolve();root=(REPO/'build/acceptance').resolve();require(folder.is_relative_to(root) and folder!=root and not folder.is_symlink(),'Only owned acceptance folders permitted')
    try:
        if a.mode=='prepare':result=prepare(folder)
        else:result=remote(folder,a.mode,folder/('candidate-'+a.mode+'.json'))
        print(json.dumps(dict(runId=RUN,sourceRunId=SOURCE,caseId=CASE,qualified=result.get('productionOutcome',{}).get('outcome'),productOperations=0)))
    finally:save(folder/'suite-helper-operations.json',dict(operations=COUNTS,productSettingsWrites=0,productHttpRequests=0,protocolSubmissions=0,credentialPosts=0,scope='Suite-only isolated candidate infrastructure; product formatter operations counted separately'))
if __name__=='__main__':main()
