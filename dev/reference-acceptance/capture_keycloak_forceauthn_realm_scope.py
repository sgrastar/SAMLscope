#!/usr/bin/env python3
"""Read-only later native supplementation, explicitly bound to unchanged restored source originals."""
import argparse,base64,datetime,hashlib,json,pathlib,subprocess,sys,urllib.parse,urllib.request
REPO=pathlib.Path(__file__).resolve().parents[2];sys.path.insert(0,str(REPO/'dev/keycloak'))
from attribute_policy_capability_absence import product_token
from mdiop_representation_campaign import runtime
SHA=lambda raw:hashlib.sha256(raw).hexdigest();READ=lambda p:json.loads(p.read_bytes())
FIELDS=['id','realm','attributes','eventsEnabled','bruteForceProtected','internationalizationEnabled','accessCodeLifespanLogin','accessCodeLifespanUserAction','browserFlow','eventsListeners']
ATTRIBUTES={'cibaAuthRequestedUserHint','cibaBackchannelTokenDeliveryMode','cibaExpiresIn','cibaInterval','oauth2DeviceCodeLifespan','oauth2DevicePollingInterval','parRequestUriLifespan','realmReusableOtpCode'}
def require(value,why):
    if not value:raise ValueError(why)
def capture(folder,phase):
    token=product_token();created=READ(folder/'created.json')['run'];source=READ(folder/'manifest.json');peer='http://localhost:18080/p/'+created['planId'];ops=[]
    def native(path,realm=False):
        url='http://localhost:18180/admin/realms/samlscope'+path;request=urllib.request.Request(url,headers={'Authorization':'Bearer '+token})
        with urllib.request.urlopen(request,timeout=40) as response:raw=response.read();value=json.loads(raw);status=response.status
        require(status==200,'Native administrative read failed');original=raw
        projection={}
        if realm:
            require(set(value.get('attributes',{}))==ATTRIBUTES and all(k in value for k in FIELDS),'Opaque native authentication attributes')
            raw=json.dumps({k:value[k] for k in FIELDS},sort_keys=True,separators=(',',':')).encode();value=json.loads(raw)
            projection=dict(response_projection='native-realm-public-authentication-view-v1',projected_fields=FIELDS,unprojected_response_sha256=SHA(original))
        record=dict(method='GET',url=url,status=status,response_base64=base64.b64encode(raw).decode(),response_sha256=SHA(raw),recordedAt=datetime.datetime.now(datetime.timezone.utc).isoformat().replace('+00:00','Z'),**projection)
        ops.append(dict(method='GET',url=url,status=status,productSettingWrite=False));return value,record
    realm,realm_record=native('',True);clients,client_record=native('/clients?clientId='+urllib.parse.quote(peer,safe=''));flows,flow_record=native('/authentication/flows')
    require(clients==[],'Source temporary client remains')
    original_flows=json.loads(base64.b64decode(READ(folder/'originals/flow-inventory-before.json')['response_base64']))
    require(flows==original_flows and READ(folder/'restoration.json')['restored'],'Source native flow restoration differs')
    initial=READ(folder/'originals/native-realm-before.json');require(realm==json.loads(base64.b64decode(initial['response_base64'])),'Supplemental realm attributes differ from native replay input')
    before=READ(folder/'originals/before.environment.json');current=runtime();require(current==before['runtime'],'Native source runtime changed')
    inventory=subprocess.check_output(['docker','exec','samlscope-reference-keycloak','sh','-c','find /opt/keycloak/lib /opt/keycloak/providers -type f -name "*.jar" | sort | while IFS= read -r p; do sha256sum "$p"; done'])
    require(inventory==(folder/'originals/before.native-classpath.txt').read_bytes(),'Native source classpath changed')
    record=dict(schema='samlscope-keycloak-forceauthn-later-native-scope-v1',scope='later-read-only-native-replay-supplement',runId=created['id'],planId=created['planId'],targetEntityId=source['targetEntityId'],sourceManifestSha256=SHA((folder/'manifest.json').read_bytes()),sourceStoreSnapshotSha256=SHA((folder/'receipt/source-store-snapshot.json').read_bytes()),sourceHistorySha256=SHA((folder/'receipt/source-history.json').read_bytes()),nativeClasspathSha256=SHA(inventory),runtime=current,realmRecord=realm_record,restoredClientAbsenceRecord=client_record,restoredFlowInventoryRecord=flow_record,operations=ops,productSettingWrites=0,protocolSubmissions=0,credentialPosts=0,managementTokenAcquisitions=1)
    path=folder/('native-scope-'+phase+'.json');require(not path.exists(),'Native readback original is immutable');path.write_text(json.dumps(record,sort_keys=True,indent=2)+'\n');return record
if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('folder',type=pathlib.Path);p.add_argument('phase',choices=['before','after']);args=p.parse_args();capture(args.folder.resolve(),args.phase);print('Read-only restored native source scope captured')
