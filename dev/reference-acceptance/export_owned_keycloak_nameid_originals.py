#!/usr/bin/env python3
"""Offline physical copy of qualified native originals; no browser-byte or adoption claim."""
import argparse,base64,copy,hashlib,json,pathlib,re,urllib.parse,xml.etree.ElementTree as ET,zlib
import owned_keycloak_public_ci as owned
A='urn:oasis:names:tc:SAML:2.0:assertion'
P='urn:oasis:names:tc:SAML:2.0:protocol'
FIXTURES=['format-transient','format-persistent','sp-name-qualifier']
sha=lambda b:hashlib.sha256(b).hexdigest()
require=owned.require

def strict_json(raw):
    require(len(raw)<=32*1024*1024,'Oversized public document')
    def pairs(items):
        result={}
        for key,value in items:require(key not in result,'Duplicate JSON key');result[key]=value
        return result
    return owned.public(json.loads(raw.decode('utf8'),object_pairs_hook=pairs))

def checked_xml(raw,username,password):
    require(len(raw)<=4*1024*1024 and b'<!DOCTYPE' not in raw.upper() and b'<!ENTITY' not in raw.upper(),'Unsafe XML')
    text=raw.decode('utf8');require(password not in text and '/login-actions/' not in text,'Private auth material')
    doc=ET.fromstring(raw);require(doc.tag in ['{'+P+'}AuthnRequest','{'+P+'}Response'],'Not protocol original')
    # Only exact public fixture identity text in genuine assertion data is allowed.
    projected=copy.deepcopy(doc)
    for element in projected.iter():
        local=element.tag.rsplit('}',1)[-1].replace('-','').replace('_','').lower()
        require(local not in owned.PRIVATE_KEYS,'Private XML field')
        require(element.attrib.get('Name','').rsplit(':',1)[-1].replace('-','').replace('_','').lower() not in owned.PRIVATE_KEYS,'Private attribute field')
        if username in (element.text or ''):
            require(element.tag in ['{'+A+'}NameID','{'+A+'}AttributeValue'] and element.text==username and not list(element),'Identity outside typed assertion data')
            element.text='PUBLIC_OWNED_PROTOCOL_IDENTITY'
    require(username not in ET.tostring(projected,encoding='unicode'),'Identity outside typed assertion text')
    return raw

def decoded(value,size,digest):
    require(isinstance(value,str) and isinstance(size,int) and 0<=size<=4*1024*1024 and bool(re.fullmatch('[a-f0-9]{64}',digest or '')),'Bad original declaration')
    raw=base64.b64decode(value,validate=True);require(base64.b64encode(raw).decode()==value and len(raw)==size and sha(raw)==digest,'Original size/hash mismatch');return raw

def checked_wire(original,body,xml):
    field='SAMLRequest' if original['direction']=='OUTBOUND' else 'SAMLResponse'
    if original['method']=='GET':
        require(not body,'Redirect body must be empty');text=original['rawQuery']
        allowed={field,'RelayState','SigAlg','Signature'}
    else:
        require(original['method']=='POST' and original['rawQuery'] is None and re.match(r'application/x-www-form-urlencoded(?:;|$)',original['contentType'] or '',re.I),'Unknown POST wire')
        text=body.decode('utf8');allowed={field,'RelayState'}
    pairs=urllib.parse.parse_qsl(text,keep_blank_values=True,strict_parsing=True)
    require(len({k for k,v in pairs})==len(pairs) and {k for k,v in pairs}==allowed,'Private or duplicate wire fields')
    values=dict(pairs);encoded=values[field];raw=base64.b64decode(encoded,validate=True)
    require(base64.b64encode(raw).decode()==encoded,'Noncanonical wire base64')
    if original['method']=='GET':
        raw=zlib.decompress(raw,-15);require(len(raw)<=4*1024*1024,'Oversized Redirect XML')
    require(raw==xml,'Wire body differs from decoded original')

def check(setup,runtime,result,username,password):
    identity={'profile':'browser_sso_idp','version':'functional-case-v2-nameid','digest':'sha256:05558838bf997f81d5be63d423df254b547ffe7c0600683157b6dadd566b7448'}
    require(runtime.get('schema')=='owned-keycloak-nameid-native-v1' and runtime.get('qualificationOutcome')=='VERIFIED'
        and runtime.get('definitionIdentity')==identity==setup['definitionIdentity'] and runtime.get('runId')==setup['runId']
        and runtime.get('planId')==setup['planId'] and runtime.get('generation')==setup['generation']
        and runtime.get('caseId')==owned.CASE and runtime.get('caseDigest')==owned.CASE_DIGEST
        and runtime.get('targetEntityId')==owned.ORIGIN+'/realms/samlscope' and runtime.get('canonicalAdoption') is False
        and runtime.get('selectedRegisteredScenarioProven') is True and runtime.get('nativeRequiredRequestShapesProven') is True
        and runtime.get('approvedControlReplayRequiredForAdoption') is True,'Native owning scope incomplete')
    rows=[c for r in result['requirements'] for c in r.get('cases',[]) if c['id']==owned.CASE]
    require(result['run']['id']==setup['runId'] and result['run']['completeness']=='INCOMPLETE' and len(rows)==1
        and rows[0]['outcome']==runtime['selectedCaseOutcome'],'Central result mismatch')
    pairs=runtime['selectedActionPairs'];require(len(pairs)==3 and [p['fixtureId'] for p in pairs]==FIXTURES
        and len({p['actionId'] for p in pairs})==3,'Selected action scope mismatch')
    selected=[p['responseReference'] for p in pairs];evidence=rows[0]['evidence']
    require(len(evidence)==3 and all(e['kind']=='transcript' for e in evidence) and {e['reference'] for e in evidence}==set(selected)
        and len(set(selected))==3 and runtime['selectedCaseEvidence']==selected,'Stored three response refs mismatch')
    refs=[runtime['normalRequestReference'],runtime['normalResponseReference']]+[r for p in pairs for r in [p['requestReference'],p['responseReference']]]
    require(len(set(refs))==8 and runtime['portableEvidenceReferences']==refs and len(runtime['transcriptOriginals'])==8
        and [o['id'] for o in runtime['transcriptOriginals']]==refs,'Native eight refs mismatch')
    out=[];total=0
    for o in runtime['transcriptOriginals']:
        require(o['runId']==setup['runId'] and re.fullmatch('tx_[0-9A-HJKMNP-TV-Z]{26}',o['id']),'Foreign original')
        prefix='transcripts/'+setup['runId']+'/'+o['id'];require(o['decodedSamlRef']==prefix+'.saml.xml'
            and (o['bodyRef']==prefix+'.body' or o['bodyRef'] is None and o['bodyBytes']==0),'Foreign physical ref')
        body=decoded(o['bodyBase64'],o['bodyBytes'],o['computedBodySha256']);xml=checked_xml(decoded(o['decodedSamlBase64'],o['decodedSamlBytes'],o['computedDecodedSha256']),username,password)
        require(o['storedBodySha256'] is None or o['storedBodySha256']==sha(body),'Stored body mismatch');total+=len(body)+len(xml);require(total<=16*1024*1024,'Too many bytes')
        uri=urllib.parse.urlsplit(o['url']);require(not uri.username and not uri.password and not uri.fragment,'Private URL')
        endpoint=uri.scheme+'://'+uri.netloc+uri.path
        require(endpoint==(owned.ORIGIN+'/realms/samlscope/protocol/saml' if o['direction']=='OUTBOUND' else owned.SUITE+'/p/'+setup['planId']+'/sp/acs/0'),'Foreign endpoint')
        pair=next((p for p in pairs if o['id'] in [p['requestReference'],p['responseReference']]),None)
        if pair:
            require(o['method']=='POST' and o['correlationId']==('' if o['direction']=='OUTBOUND' else '_')+pair['actionId'],'Foreign action')
            if o['direction']=='OUTBOUND':require(o['summary'].get('fixture_id')==pair['fixtureId'] and o['summary'].get('scenario_case_id')==owned.CASE,'Fixture mismatch')
        query=None
        if o['method']=='GET':
            require(o['id']==runtime['normalRequestReference'] and o['rawQuery']==uri.query and not body,'Foreign Redirect')
            query=o['rawQuery'].encode();require(password.encode() not in query and username.encode() not in query,'Private query')
        else:require(o['method']=='POST' and not uri.query and o['rawQuery'] is None,'Unknown wire')
        checked_wire(o,body,xml)
        out.append((o,body,xml,query))
    return out,rows[0]

def export(setup,runtime,result,output,username,password):
    originals,row=check(setup,runtime,result,username,password);output=owned.owned_path(output);output.mkdir()
    manifest=[]
    for o,body,xml,query in originals:
        files={}
        for kind,suffix,raw in [('body','.body',body),('decoded','.saml.xml',xml),('query','.query.txt',query)]:
            if raw is None:continue
            path=output/(o['id']+suffix)
            with path.open('xb') as f:f.write(raw)
            saved=path.read_bytes();require(saved==raw and len(saved)==len(raw),'Physical retention mismatch')
            files[kind]={'file':path.name,'bytes':len(saved),'sha256':sha(saved)}
        manifest.append({'reference':o['id'],'runId':setup['runId'],'nativeBodyReference':o['bodyRef'],'nativeDecodedReference':o['decodedSamlRef'],'physical':files})
    doc={'schema':'owned-keycloak-nameid-native-portable-v1','runId':setup['runId'],'planId':setup['planId'],'caseId':owned.CASE,'caseDigest':owned.CASE_DIGEST,
        'actualSuiteOutcome':row['outcome'],'centralVerdict':row['verdict'],'originals':manifest,'selectedOriginalCount':8,'source':'actual-read-only-native-Recorder-files',
        'browserOriginalsAvailable':False,'browserByteEqualityClaimed':False,'publicSeedIdentityIsBoundProtocolData':True,
        'approvedControlReplayRequiredForAdoption':True,'nativeReaderQualificationRequired':True,'canonicalAdoption':False,'wholeRunConformance':'NOT_QUALIFIED'}
    owned.write(output,'manifest.json',doc);return doc

def main():
    a=argparse.ArgumentParser();a.add_argument('--setup',required=True);a.add_argument('--runtime',required=True);a.add_argument('--result',required=True);a.add_argument('--output',required=True);args=a.parse_args()
    owned.source_seed();realm=json.loads((owned.ROOT/owned.SEED).read_bytes());actor=realm['users'][0]
    read=lambda p:strict_json(owned.owned_path(p).read_bytes())
    export(read(args.setup),read(args.runtime),read(args.result),args.output,actor['username'],actor['credentials'][0]['value'])
if __name__=='__main__':
    try:main()
    except Exception:raise SystemExit('Owned native original export incomplete; private diagnostics omitted')
