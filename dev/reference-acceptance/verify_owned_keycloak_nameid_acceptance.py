#!/usr/bin/env python3
"""Independently adopt ONE new v2 native Keycloak NameID observation.

No HTTP, Docker, product credentials, source Run writes, or Verdict assignment.
The old literal-equality baseline is preserved; this source Run owns its v2 digest.
"""
from __future__ import annotations
import argparse,base64,copy,hashlib,json,os,pathlib,subprocess,tempfile,xml.etree.ElementTree as ET,zipfile
import export_owned_keycloak_nameid_originals as original
import owned_keycloak_public_ci as owned
REPO=pathlib.Path(__file__).resolve().parents[2]
RUN='run_BPEHJD546WG5YJTCRD8F7JRQ1E';PLAN='plan_X6K5P280D25MDRAT2FC73EG1PC';GENERATION='20261008-nameid-r1'
CASE=owned.CASE;CASE_DIGEST=owned.CASE_DIGEST
IDENTITY={'profile':'browser_sso_idp','version':'functional-case-v2-nameid','digest':'sha256:05558838bf997f81d5be63d423df254b547ffe7c0600683157b6dadd566b7448'}
LEGACY_CASE_DIGEST='sha256:eac0ed91cf492475301d9a3ea651749ad9cf0228a240fb918497b170e6ba4fca'
SOURCE_C='69a53c8b837fad1578298f7077662369a3b137bd';APPROVAL_A='a5eb099ea3e2f70e4820a3ca7ea990e851e43ea7'
SUITE_IMAGE='sha256:1b8b993c333933d2ba55669c697ecc11be898d7f0fbd3c250265b92929af6fa6'
SUITE_CONTAINER='5b8e2ef2c997eed6aeaa9e5fd22f6aa9147acf31cde2490df9b5caa95d255373'
CLIENT='f91db372-27e6-4f09-a292-f741980cba43';CONTAINER='874d42235c6f59f89753021c959fc0a9a9a2f090930db069681da87567819f9b'
STATE='319f312d0fddf8b7e8a41bc9008717f34eb7dc5b4615d942e3e3bbed9997eaa8'
ROOT_NAME='reference-20261008';FOLDER='owned-keycloak-nameid-adoption-r1'
PROJECT_PINS={'api-0.1.0.jar':'ef101a7020263c41ab003cb942a6c922a1222bfc543b1fbbd4115b2ce63c655c','core-0.1.0.jar':'11da00390d12026cd50b47cd05b285b9628b25708ea35d140298425e2fa0d1fa','peer-0.1.0.jar':'bcba2760509dbfbd10c04bb539225a8c126940b6c3ceaca4e7b87cd0ed852940','runner-0.1.0.jar':'0905d71db838645285e2a734e5a54cffd60400279fe211055517907b22e761a2','saml-0.1.0.jar':'0077f8e61bcdb0867bc7d06919f4bcfdb19594a9fd1dc1f224d5a5cbdb84ec1f','store-0.1.0.jar':'1f66fea444ea5e47afeda097803f2d7f42c585abeb45728afa7dec2afdb49036'}
# Pins were established from independent deployment/campaign qualification, not supplied by a Run.
PINS={
 'deployment-v238-r1/runtime-live-verification.json':'f19e388b6b6de68330e5d0fc26a108b54883067312dc6be02dcce381a8feb979',
 'deployment-v238-r1/qualification.json':'45ea8583919beda2b5790f38e8b52e6fc061bf4706ac6e410a946d7bb4231a56',
 'deployment-v238-r1/release-approval/release-check-report.json':'6563f35c556fa2fe7f3ae9159ab80e29f5270923742ec16d1f393c463d0ed461',
 'owned-keycloak-nameid-closure-r1/closure.json':'8ce1fdc0a12668bdda68d4a57f6791243da2890cb4fcfce5f472a77306a7be5b',
 'owned-keycloak-public-ci-setup-r4/setup.json':'81fff4aa2964473849c472328883ab2aebdcb45f1e9b46b08e9f5485458ef784',
 'owned-keycloak-public-ci-setup-r4/browser-setup.json':'d5440c69cb8fbb8585115681bf70aaceeea5d1fca6d2d48ce6cbfe8722ca198d',
 'owned-keycloak-public-ci-restoration-r1/restoration.json':'15e89e52e3678419da2c367422f08b5c56e6007be0585c6f33a278d531bbc878',
 'owned-keycloak-public-ci-cleanup-r1/cleanup.json':'cb72e4c49e057942704d5d6ed3c0ed2a403c338d1cd8d101dc45dfc65ef133a7',
 'owned-keycloak-nameid-native-r1/runtime.json':'4b163356b89185ffce4ce32a9e16508d2d406ca4af4346494f4a1f5660d29829',
 'owned-keycloak-nameid-browser-r2/result.json':'9862f3674d66c506115fb60d58229796e5128c167f1209f34c9a1cd6e382ea06',
 'owned-keycloak-nameid-native-r1/session-reuse-proof.json':'f4ce3f77c503ae16445446154fbf936598ca4fce791b3372c6ffd405478b4ce4'}
REPLAY_SOURCE_PINS={'ReplayOwnedKeycloakNameIdAcceptance.java':'00df8c65cc51c4ca1dc2de81407843e62b2507cca80b1b8a69fa4ac7e6bf9ee4','OwnedKeycloakNameIdReplayControls.java':'a4a7f6829d7abcecf5784dc98a5ebcdf37d5763e44d784a831453e57ded0a770'}
sha=owned.digest;require=owned.require

def file(path,limit=32*1024*1024):
    path=pathlib.Path(path).absolute();owned.reject_symlinks(path)
    require(path.is_file() and path.stat().st_size<=limit,'Missing, unsafe, or oversized acceptance original')
    return path.read_bytes()
def load(path):return original.strict_json(file(path))
def read_pins(root):
    documents={}
    for name,digest in PINS.items():
        raw=file(root/name);require(sha(raw)==digest,'Pinned acceptance input changed: '+name);documents[name]=original.strict_json(raw)
    return documents

def campaign_documents(root,documents):
    start=load(root/'owned-keycloak-public-ci-start-r1/owned-start.json');setup=documents['owned-keycloak-public-ci-setup-r4/setup.json']
    native=documents['owned-keycloak-nameid-native-r1/runtime.json'];result=documents['owned-keycloak-nameid-browser-r2/result.json']
    restored=documents['owned-keycloak-public-ci-restoration-r1/restoration.json'];cleanup=documents['owned-keycloak-public-ci-cleanup-r1/cleanup.json']
    counts=load(root/'owned-keycloak-nameid-browser-r2/owned-login-counts.json');operations=load(root/'owned-keycloak-nameid-browser-r2/operation-counts.json')
    require((setup['runId'],setup['planId'],setup['generation'],setup['caseId'],setup['caseDigest'],setup['definitionIdentity'])==(RUN,PLAN,GENERATION,CASE,CASE_DIGEST,IDENTITY),'Owned new source Run identity changed')
    require(setup['clientDbId']==CLIENT and setup['ownedContainerId']==CONTAINER and setup['ownedContainerName']==owned.name(GENERATION)
        and setup['originalClientStateSha256']==STATE and setup['imageReference']==owned.IMAGE
        and setup['ownedLabels']==owned.labels(GENERATION),'Native setup/runtime/ownership changed')
    projection=setup['nativeClientReadback'];require(projection['id']==CLIENT and projection['clientId']==owned.SUITE+'/p/'+PLAN
        and projection['name']=='SAMLscope Owned CI NameID '+GENERATION and projection['protocol']=='saml'
        and projection['enabled'] is True and projection['attributes']=={**owned.ATTRIBUTES,'samlscope.owned.generation':GENERATION}
        and owned.SUITE+'/p/'+PLAN+'/sp/acs/0' in projection['redirectUris']
        and projection['configurationSha256']=='64abb18db082e6c9270189e1d62fa571432f9343da94ca13339d9303caed9152','Native public configuration read-back changed')
    require(start['id']==CONTAINER and start['imageReference']==owned.IMAGE and start['image']=='sha256:'+owned.IMAGE.rsplit('sha256:',1)[1]
        and start['version']=='26.7.2' and start['generation']==GENERATION and start['name']=='/'+owned.name(GENERATION)
        and start['publicRealmSha256']==owned.SEED_SHA and start['publicRealmGitBlob']==owned.SEED_BLOB
        and start['startedAt']=='2026-10-08T06:03:18.781606257Z'
        and start['ports']=={'8080/tcp':[{'HostIp':'127.0.0.1','HostPort':'28080'}]}
        and all(start['labels'].get(k)==v for k,v in owned.labels(GENERATION).items()),'Stock owned native product identity changed')
    require(restored['restored'] is True and restored['nativeClientDeleteAttempts']==restored['nativeClientDeletes']==1
        and restored['readbackStatus']==404 and restored['originalClientStateSha256']==STATE
        and cleanup['ownedContainerId']==CONTAINER and cleanup['ownedContainerRemoved'] is True
        and cleanup['imageAndOtherContainersRetained'] is True,'Native original state restoration or ownership cleanup incomplete')
    require(counts['observedLoginPostRequests']==counts['loginFillAttempts']==counts['loginClickAttempts']==1
        and counts['primaryContextsCreated']==1 and counts['formalContextReuses']==3
        and counts['credentialValuesPersisted']==0 and counts['cookiesOrStorageStateExported'] is False
        and operations['selectedTargetActions']==operations['selectedBrowserDispatchAttempts']==3
        and operations['initialNormalFlowSubmissions']==operations['fullProfileStartCalls']==1
        and operations['freshEmptyContexts']==0 and operations['skippedBeforeTargetSubmission']==89,'Actual public-demo login/context/operation scope changed')
    raw_suite=file(root/'owned-keycloak-public-ci-setup-r4/suite-public-metadata.xml',1024*1024)
    raw_target=file(root/'owned-keycloak-public-ci-start-r1/keycloak-public-metadata.xml',1024*1024)
    require(sha(raw_suite)==setup['suitePublicMetadataSha256']==native['suitePublicMetadataSha256']
        and sha(raw_target)==setup['targetMetadataSha256']==start['targetMetadataSha256']==native['runMetadataSnapshotSha256'],'Actual trusted metadata original binding changed')
    require(native['selectedCaseOutcome']=='SATISFIED' and result['suite']['image_digest']==SUITE_IMAGE,'Actual outcome or Suite runtime changed')
    rows=[c for r in result['requirements'] for c in r['cases'] if c['id']==CASE]
    require(len(rows)==1 and (rows[0]['outcome'],rows[0]['verdict'],rows[0]['reason_code'],rows[0]['attested'],rows[0]['evidence_class'])==('SATISFIED','PASS','idp.nameid-policy.satisfied',False,'PROTOCOL_OBSERVED'),'Actual formal case result changed')
    owned.source_seed();actor=json.loads(file(REPO/owned.SEED,1024*1024))['users'][0]
    originals,case=original.check(setup,native,result,actor['username'],actor['credentials'][0]['value'])
    portable=load(root/'owned-keycloak-nameid-native-r1/portable/manifest.json')
    require(portable['runId']==RUN and portable['planId']==PLAN and portable['caseDigest']==CASE_DIGEST and portable['selectedOriginalCount']==8
        and portable['browserOriginalsAvailable'] is False and portable['browserByteEqualityClaimed'] is False
        and portable['canonicalAdoption'] is False,'Native-only physical export scope changed')
    require(len(portable['originals'])==8 and [o['reference'] for o in portable['originals']]==native['portableEvidenceReferences'],'Native physical reference set changed')
    for native_row,(entry,body,xml,query) in zip(portable['originals'],originals,strict=True):
        require(native_row['runId']==RUN and native_row['nativeBodyReference']==entry['bodyRef'] and native_row['nativeDecodedReference']==entry['decodedSamlRef'],'Native physical identity changed')
        expected={'body':('.body',body),'decoded':('.saml.xml',xml)}
        if query is not None:expected['query']=('.query.txt',query)
        require(set(native_row['physical'])==set(expected),'Native physical body/query inventory changed')
        for kind,(suffix,bytes_) in expected.items():
            row=native_row['physical'][kind];require(row['file']==entry['id']+suffix,'Unsafe exported native filename')
            actual=file(root/'owned-keycloak-nameid-native-r1/portable'/row['file'],4*1024*1024)
            require(actual==bytes_ and len(actual)==row['bytes'] and sha(actual)==row['sha256'],'Native physical original changed')
    session=documents['owned-keycloak-nameid-native-r1/session-reuse-proof.json'];A='{urn:oasis:names:tc:SAML:2.0:assertion}'
    responses=[(e,ET.fromstring(xml)) for e,body,xml,query in originals if e['direction']=='INBOUND']
    statements=[doc.findall('.//'+A+'AuthnStatement') for e,doc in responses]
    require(all(len(v)==1 and v[0].get('SessionIndex') for v in statements) and len({v[0].get('SessionIndex') for v in statements})==1
        and session['runId']==RUN and session['sourceNativeRuntimeSha256']==PINS['owned-keycloak-nameid-native-r1/runtime.json']
        and session['allSignedNativeSessionIndexesSameAndPresent'] is True and session['cookieValuesReadOrExported'] is False
        and session['sourceReferences']==[e['id'] for e,doc in responses],'Actual signed native session proof changed')
    return native,result,case

def runtime_classpath(root,documents):
    live=documents['deployment-v238-r1/runtime-live-verification.json'];qualification=documents['deployment-v238-r1/qualification.json'];release=documents['deployment-v238-r1/release-approval/release-check-report.json']
    require(live['approvedCommit']==qualification['approvedCommit']==SOURCE_C and live['approvalCommit']==qualification['approvalCommit']==APPROVAL_A
        and live['imageId']==SUITE_IMAGE and live['suiteContainerId']==SUITE_CONTAINER and live['healthStatus']==200
        and live['projectJars']==qualification['projectJars']==PROJECT_PINS and release['complete'] is True,'Signed approved v238 deployment authority changed')
    # Use actual signed source authorities, not a sourceRoot reported by a Run.
    for commit in [SOURCE_C,APPROVAL_A]:
        proof=subprocess.run(['git','verify-commit',commit],cwd=REPO,capture_output=True)
        require(proof.returncode==0,'Signed public source/approval commit verification failed')
    require(sha(file(root/'deployment-v238-r1/approved-source-target.tar.gz',64*1024*1024))==qualification['sourceArchiveSha256']=='ce0ece0fbd2ed70485273e45db824e66511af16d69f15c1cc89d8a3059d9c2c2','Signed source archive changed')
    protected=qualification['protectedSourceSha256'];require(len(protected)==87,'Protected source inventory differs')
    for path,digest in protected.items():
        raw=subprocess.run(['git','show',SOURCE_C+':'+path],cwd=REPO,capture_output=True,check=True).stdout
        require(sha(raw)==digest,'Approved protected source differs from signed source authority')
    jars=[]
    for name,digest in sorted(PROJECT_PINS.items()):
        path=root/'deployment-v238-r1/runtime-built'/name;require(sha(file(path,32*1024*1024))==digest,'Frozen v238 project JAR changed');jars.append(path)
    external=live['runtimeDependencySha256'];require(len(external)==102 and external==qualification['runtimeDependencySha256'] and not set(external)&set(PROJECT_PINS),'Dependency closure changed')
    for name,digest in sorted(external.items()):
        require(pathlib.Path(name).name==name and name.endswith('.jar'),'Unsafe dependency path')
        path=REPO/'api/build/install/samlscope/lib'/name;require(sha(file(path,32*1024*1024))==digest,'Qualified external dependency changed');jars.append(path)
    with zipfile.ZipFile(root/'deployment-v238-r1/runtime-built/api-0.1.0.jar') as jar:
        require(sha(jar.read('profiles/browser_sso_idp.json'))==IDENTITY['digest'].split(':')[1],'Runtime approved profile bytes changed')
    return jars

def replay(root,documents):
    jars=runtime_classpath(root,documents)
    def snapshot():
        return [(str(p),p.stat().st_dev,p.stat().st_ino,p.stat().st_size,p.stat().st_mtime_ns,p.stat().st_ctime_ns,sha(file(p))) for p in jars]
    before=snapshot()
    closure=documents['owned-keycloak-nameid-closure-r1/closure.json'];archive=root/FOLDER/'frozen-helper-sources'
    pins={pathlib.Path(p['path']).name:p['sha256'] for p in closure['sourceFreeze']}
    for name,digest in pins.items():require(sha(file(archive/name,1024*1024))==digest,'Frozen native helper source changed')
    sources=[archive/n for n in ['ReadOwnedKeycloakNameIdRuntime.java','OwnedKeycloakNameIdReaderControls.java']]
    artifact=REPO/'dev/reference-acceptance/ReadSyntheticArtifactRuntime.java';require(sha(file(artifact,1024*1024))=='ae38aeb1eeb931a093de6ab8ef1bf10230d53ce087d18a53a12228163f36f726','Shared original guard changed');sources.append(artifact)
    for name,digest in REPLAY_SOURCE_PINS.items():
        path=REPO/'dev/reference-acceptance'/name;require(sha(file(path,1024*1024))==digest,'Independent replay source changed');sources.append(path)
    cp=os.pathsep.join(map(str,jars));env={k:v for k,v in os.environ.items() if k not in ['JAVA_TOOL_OPTIONS','JDK_JAVA_OPTIONS','JDK_JAVAC_OPTIONS','JAVA_OPTS','CLASSPATH']}
    with tempfile.TemporaryDirectory(prefix='owned-nameid-acceptance-') as temporary:
        classes=pathlib.Path(temporary)/'classes'
        compiled=subprocess.run(['javac','--release','21','-cp',cp,'-d',str(classes),*map(str,sources)],env=env,capture_output=True)
        require(compiled.returncode==0,'Exact frozen native proof compilation failed; compiler diagnostics omitted')
        def run(main,*args):
            proc=subprocess.run(['java','-Xmx512m','-cp',str(classes)+os.pathsep+cp,'com.samlscope.api.'+main,*map(str,args)],env=env,capture_output=True,timeout=180)
            require(proc.returncode==0,'Native offline replay failed; raw diagnostics omitted')
            return original.strict_json(proc.stdout)
        controls=run('OwnedKeycloakNameIdReaderControls');require(controls['checksPassed']==142 and len(controls['checks'])==142 and all(c['passed'] is True for c in controls['checks']),'Native cryptographic/input controls incomplete')
        loader=run('OwnedKeycloakNameIdReplayControls',root/'owned-keycloak-nameid-native-r1/runtime.json',root/'owned-keycloak-nameid-native-r1/portable/manifest.json')
        require(loader['checksPassed']==25 and all(c['passed'] is True for c in loader['checks']),'Native original loader controls incomplete')
        result=run('ReplayOwnedKeycloakNameIdAcceptance',root/'owned-keycloak-nameid-native-r1/runtime.json',root/'owned-keycloak-nameid-native-r1/portable/manifest.json',root/'owned-keycloak-public-ci-setup-r4/suite-public-metadata.xml',root/'owned-keycloak-public-ci-start-r1/keycloak-public-metadata.xml')
    require(before==snapshot(),'Qualified dependency changed during replay generation')
    require(result['schema']=='owned-keycloak-nameid-offline-replay-v1' and result['qualificationOutcome']=='VERIFIED'
        and result['replayedCaseOutcome']=='SATISFIED' and result['replayedReasonCode']=='idp.nameid-policy.satisfied'
        and result['canonicalAdoption'] is False,'Actual native case replay did not establish the stored outcome')
    require(result['controlsPassed']==23 and len(result['controls'])==23 and all(c['passed'] is True for c in result['controls'])
        and result['authenticatedOriginalCount']==8 and result['physicalFileCount']==17
        and result['approvedBaselineFixture']=='idp-core-no-ecp' and result['approvedMutantFixture']=='mut-iip-idp10-d-idp'
        and result['mutantsAreNotProductProtocolObservations'] is True,'Actual approved case controls/native crypto proof incomplete')
    return result,controls

def actual_native_tamper_controls(root,documents):
    setup=documents['owned-keycloak-public-ci-setup-r4/setup.json'];native=documents['owned-keycloak-nameid-native-r1/runtime.json'];result=documents['owned-keycloak-nameid-browser-r2/result.json']
    actor=json.loads(file(REPO/owned.SEED,1024*1024))['users'][0]
    mutations=[('foreign-run',lambda d:d.update(runId='run_FOREIGN')),('foreign-plan',lambda d:d.update(planId='plan_FOREIGN')),
        ('old-case',lambda d:d.update(caseDigest=LEGACY_CASE_DIGEST)),('old-definition',lambda d:d['definitionIdentity'].update(version='functional-case-v1')),
        ('missing-response-ref',lambda d:d['selectedCaseEvidence'].pop()),('duplicate-response',lambda d:d['selectedCaseEvidence'].__setitem__(2,d['selectedCaseEvidence'][1])),
        ('missing-original',lambda d:d['transcriptOriginals'].pop()),('foreign-body-path',lambda d:d['transcriptOriginals'][3].update(bodyRef='private/foreign')),
        ('bad-body-hash',lambda d:d['transcriptOriginals'][3].update(computedBodySha256='a'*64)),('bad-xml-hash',lambda d:d['transcriptOriginals'][3].update(computedDecodedSha256='a'*64)),
        ('wrong-action',lambda d:d['transcriptOriginals'][3].update(correlationId='foreign')),('wrong-endpoint',lambda d:d['transcriptOriginals'][3].update(url='http://foreign.example/acs')),
        ('claim-adoption',lambda d:d.update(canonicalAdoption=True))]
    for name,mutate in mutations:
        changed=copy.deepcopy(native);mutate(changed)
        try:original.check(setup,changed,result,actor['username'],actor['credentials'][0]['value'])
        except (ValueError,KeyError,IndexError):continue
        raise ValueError('Actual native tamper control accepted: '+name)
    return len(mutations)

def source_provenance(root):
    return {'scope':'owned-public-ci-Keycloak-native-NameID-v2','sourceRunId':RUN,'sourcePlanId':PLAN,
        'adoptedDefinitionIdentity':dict(IDENTITY),'adoptedCaseDigest':CASE_DIGEST,'legacyLiteralEqualityCaseDigest':LEGACY_CASE_DIGEST,
        'legacyRunReinterpreted':False,'suiteApprovedCommit':SOURCE_C,'suiteApprovalCommit':APPROVAL_A,'suiteImageDigest':SUITE_IMAGE,
        'nativeProductImageReference':owned.IMAGE,'publicRealmGitBlob':owned.SEED_BLOB,'publicRealmSha256':owned.SEED_SHA,
        'nativeOriginalScope':'normal2-and-selectedNameID6','browserOriginalsAvailable':False,'newLoginOperationsForAdoption':0,
        'newProtocolOperationsForAdoption':0,'metadataInterpretationConformanceClaimed':False}

def source_result_path(input_root):
    return pathlib.Path(input_root)/'owned-keycloak-nameid-browser-r2/result.json'

def verify_adoption(root,live=False):
    require(not live,'This acceptance verifier is offline only')
    input_root=pathlib.Path(root);root=input_root.resolve();require(root.name==ROOT_NAME,'Unexpected acceptance generation')
    documents=read_pins(root);native,result,case=campaign_documents(root,documents)
    require(actual_native_tamper_controls(root,documents)==13,'Actual native tamper controls incomplete')
    replayed,controls=replay(root,documents)
    require(replayed['runId']==RUN and replayed['planId']==PLAN and replayed['caseDigest']==CASE_DIGEST
        and replayed['definitionIdentity']==IDENTITY and replayed['replayedEvidenceReferences']==native['selectedCaseEvidence'],'Offline case/source evidence binding changed')
    # Keep the ACTUAL public result and case object byte-for-byte; provenance is ledger-only.
    return source_result_path(input_root),{CASE:case}

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('root',type=pathlib.Path);args=parser.parse_args()
    verify_adoption(args.root);print('Owned public-CI Keycloak NameID acceptance verified; exactly one new v2 observation')
