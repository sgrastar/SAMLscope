#!/usr/bin/env python3
"""Same-Run native SLO issuer/key controls; one memory login, exact restoration."""
import argparse
import base64
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
import urllib.parse
import urllib.request
import urllib.error
import xml.etree.ElementTree as ET
import zipfile

REPO=Path(__file__).resolve().parents[2]
sys.path[:0]=[str(REPO/'dev/slo'),str(REPO/'dev/shibboleth')]
from registered_signer_common import collect,docker,runtime,SHA,NOW,require,save,MD,public_json,SharedSloClient,local_url,parse_forms
from default_algorithm_logout_continuation import continuation,public_response_identity
from signature_audit_format import FORMAT

def isolated(name,path):
    spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module

SIGNER=isolated('slo_shib_provider_configuration',REPO/'dev/shibboleth/registered_signer_campaign.py')
TRUST=isolated('slo_shib_selected_trust_scope',REPO/'dev/shibboleth/metadata_certificate_trust_scope.py')
CONTAINER='samlscope-reference-shibboleth'
ROOT='/opt/reference-idp'
PROVIDERS=ROOT+'/conf/metadata-providers.xml'
AUDIT=ROOT+'/conf/audit.xml'
PROFILE='http://shibboleth.net/ns/profiles/saml2/logout'
FLOW_ENTRIES={
 'slo-front-abstract-flow.xml':'net/shibboleth/idp/flows/saml/saml2/slo-front-abstract-flow.xml',
 'saml-abstract-flow.xml':'net/shibboleth/idp/flows/saml/saml-abstract-flow.xml',
 'slo-front-abstract-beans.xml':'net/shibboleth/idp/flows/saml/saml2/slo-front-abstract-beans.xml',
 'mdquery-view.vm':'net/shibboleth/idp/views/admin/mdquery.vm',
 'mdquery-flow.xml':'net/shibboleth/idp/flows/admin/mdquery-flow.xml'}

def public_configuration(raw):
    require(len(raw)<=1024*1024,'Oversize public native configuration')
    root=ET.fromstring(raw);sensitive={'password','passwd','secret','privatekey','authorization','cookie','token','clientsecret','proxypassword'}
    for node in root.iter():
        require(node.tag.split('}')[-1].lower() not in sensitive,'Credential-valued native configuration refused before export')
        for name,value in node.attrib.items():
            require(name.split('}')[-1].lower() not in sensitive,'Credential-valued native attribute refused before export')
            if name=='name':require(value.lower() not in sensitive,'Credential property refused before export')
            if value.startswith(('http://','https://')):
                url=urllib.parse.urlsplit(value);require(url.username is None and url.password is None,'Credential-bearing metadata URL refused')
                require(not(set(k.lower() for k,_ in urllib.parse.parse_qsl(url.query))&sensitive),'Capability-bearing metadata URL refused')
    return raw

class ShibSloClient(SharedSloClient):
    def __init__(self,origin,directory):
        super().__init__(origin,directory);self.completions=[];self._used_executions=set()

    def _execution_redirect(self,final,location):
        """Stock Webflow redirect-on-pause only; never export its execution capability."""
        current=local_url(final);following=urllib.parse.urljoin(final,location);chosen=local_url(following)
        require((current.scheme+'://'+current.netloc, current.path)==(self.target_origin,'/idp/profile/SAML2/POST/SLO'),
                'Native logout navigation began outside the selected SLO endpoint')
        require((chosen.scheme,chosen.netloc,chosen.path)==(current.scheme,current.netloc,current.path) and not chosen.fragment,
                'Native logout execution redirect escaped the selected endpoint')
        fields=urllib.parse.parse_qsl(chosen.query,keep_blank_values=True,strict_parsing=True)
        require(len(fields)==1 and fields[0][0]=='execution' and re.fullmatch(r'e[1-9][0-9]*s[1-9][0-9]*',fields[0][1]) is not None,
                'Unexpected native logout execution redirect fields')
        active=[value for key,value in urllib.parse.parse_qsl(current.query,keep_blank_values=True) if key=='execution']
        require(not active or active==[fields[0][1]],'Native logout redirect belongs to a different active execution')
        require(fields[0][1] not in self._used_executions,'Old native logout execution refused')
        self._used_executions.add(fields[0][1]);return following

    def _navigation_get(self,following,body,request_id,operation,location=None):
        row=dict(operation=operation,requestId=request_id,method='GET',path='/idp/profile/SAML2/POST/SLO',
            urlSha256=SHA(following.encode()),issuedPageSha256=SHA(body),startedAt=NOW(),executionValueExported=False,completed=False)
        if location is not None:row['issuedLocationSha256']=SHA(location.encode())
        self.completions.append(row);ledger=self.directory.parent/'native-logout-completion-attempts.json';save(ledger,self.completions)
        response=None
        try:
            try:response=self.slo_op.open(urllib.request.Request(following,method='GET'),timeout=40)
            except urllib.error.HTTPError as error:response=error
            result=response.read(1024*1024+1);status=response.status;actual=response.geturl();next_location=response.headers.get('Location')
            require(actual==following and len(result)<=1024*1024,'Native completion returned a different URL or oversized page')
            row.update(completedAt=NOW(),completed=True,responseStatus=status,responseBodySha256=SHA(result))
            return actual,result,status,next_location,row
        except Exception as failure:
            row.update(completedAt=NOW(),exceptionClass=type(failure).__name__);raise
        finally:
            if response is not None:response.close()
            save(ledger,self.completions)

    def complete_native_redirect(self,final,body,code,location,request_id):
        initial_sha=SHA(body);navigations=[]
        # NoRedirect keeps native intermediate Locations private and the final signed
        # SAML Location byte-for-byte intact. The ordinary driver would hide both.
        if code in (301,302,303) and location is not None:
            chosen=urllib.parse.urlsplit(urllib.parse.urljoin(final,location))
            if any(key=='execution' for key,_ in urllib.parse.parse_qsl(chosen.query,keep_blank_values=True)):
                following=self._execution_redirect(final,location)
                final,body,code,location,row=self._navigation_get(following,body,request_id,'stock-native-slo-execution-navigation',location)
                navigations.append(row)
        for _ in range(2):
            following=continuation(final,body.decode('utf-8'),code)
            if following is None:break
            final,body,code,location,row=self._navigation_get(following,body,request_id,'same-native-slo-flow-completion')
            navigations.append(row)
        else:raise ValueError('Native SLO completion hop limit')
        if not navigations:return final,body,code,location,{}
        # A login page, repeated execution redirect or an unfinished/logout-only page
        # is never recorded as a terminal native protocol response.
        terminal_forms=[f for f in parse_forms(body.decode('utf-8')) if 'SAMLResponse' in f.fields]
        terminal_redirect=False
        if code in (301,302,303) and location is not None:
            destination=local_url(urllib.parse.urljoin(final,location))
            values=urllib.parse.parse_qs(destination.query,strict_parsing=True)
            terminal_redirect=(not destination.fragment and set(values).issubset({'SAMLResponse','RelayState','SigAlg','Signature'})
                and 'SAMLResponse' in values and all(len(value)==1 for value in values.values()))
        require((code==200 and len(terminal_forms)==1 and set(terminal_forms[0].fields).issubset({'SAMLResponse','RelayState'}))
                or terminal_redirect,'Native SLO navigation has no terminal SAML response; no retry')
        require(re.search(rb'(?i)[?&](?:amp;)?execution=|AuthState|session_code|csrf|auth_session_id',body) is None,
                'Native terminal page still contains a private authentication/navigation capability')
        public=public_response_identity(final)
        return public['responseUrl'],body,code,location,dict(nativeInitialResponseBodySha256=initial_sha,
            nativeFlowCompletions=navigations,**public)

class ShibbolethProduct:
    name='Shibboleth';adapter='shibboleth-native-slo-issuer-key-v1'
    origin='http://localhost:18280';target=origin+'/idp/shibboleth'
    metadata_source='http://samlscope-reference-shibboleth:8080/idp/shibboleth'
    def create_client(self,receipt):self.client=ShibSloClient(self.origin,receipt);return self.client
    def bind(self,out,receipt):
        self.out,self.receipt=out,receipt;self.commands=[];self.operations=[];self.original={};self.expected={};self.owned_sources={};self.audit_changed=False;self.activation_attempted=False
    def command(self,*argv,data=None,allow_failure=False):
        row=dict(executable=argv[0],startedAt=NOW(),completed=False);self.commands.append(row);save(self.out/'native-command-counts.json',self.commands)
        r=subprocess.run(['docker','exec','-i',CONTAINER,*argv],input=data,capture_output=True,timeout=60)
        row.update(completedAt=NOW(),completed=True,exitCode=r.returncode);save(self.out/'native-command-counts.json',self.commands)
        require(allow_failure or r.returncode==0,'Native command failed; private stderr not exported')
        return r if allow_failure else r.stdout
    def preflight(self):
        require(runtime(CONTAINER)['image']=='sha256:3c1b1fa64c58258aefc9e38d4ae60e9f0340731318a472110ea56ce88c18a11a','Unqualified Shib image')
        folder=self.receipt/'original-configuration';folder.mkdir()
        for path in (PROVIDERS,AUDIT):
            raw=public_configuration(self.command('cat',path));self.original[path]=self.expected[path]=raw;(folder/Path(path).name).write_bytes(raw)
        self.audit_configured=SIGNER.audit_configuration(self.original[AUDIT]);self.audit_changed=self.audit_configured!=self.original[AUDIT]
        self.command('curl','--version')
        # Stock JAR closure is verified before any write or login, then reused by inode only
        # among immutable archives. The source path itself is never a mutable build output.
        sources=self.receipt/'native-source';sources.mkdir()
        for name,digest in dict(TRUST.JARS,**{'opensaml-saml-api':SIGNER.API_JAR_SHA}).items():
            native='/usr/local/tomcat/webapps/idp/WEB-INF/lib/'+name+'-5.2.3.jar'
            require(self.command('sha256sum',native).decode().split()[0]==digest,'Native source JAR changed')
            archive=SIGNER.API_JAR if name=='opensaml-saml-api' else TRUST.XMLSEC if name=='opensaml-xmlsec-impl' else TRUST.OLD/(name+'.jar')
            require(SHA(archive.read_bytes())==digest,'Immutable native JAR differs');os.link(archive,sources/(name+'.jar'))
        with zipfile.ZipFile(sources/'idp-conf-impl.jar') as jar:
            for label,entry in FLOW_ENTRIES.items():(sources/label).write_bytes(jar.read(entry))
    def write(self,path,raw,label):
        if path in self.expected:require(self.command('cat',path)==self.expected[path],'External native configuration changed; no overwrite')
        row=dict(operation='write',path=path,label=label,sha256=SHA(raw),startedAt=NOW(),completed=False);self.operations.append(row);save(self.out/'operations.json',self.operations)
        self.expected[path]=raw
        self.command('sh','-c','cat > '+path,data=raw);require(self.command('cat',path)==raw,'Native write/readback differs')
        row.update(completedAt=NOW(),completed=True);save(self.out/'operations.json',self.operations)
    def activate(self,label):
        if label=='prepare':self.activation_attempted=True
        operation='restart' if self.audit_changed else 'reload';row=dict(operation=operation,label=label,startedAt=NOW(),completed=False);self.operations.append(row);save(self.out/'operations.json',self.operations)
        if self.audit_changed:
            subprocess.run(['docker','restart',CONTAINER],check=True,capture_output=True,timeout=60);self.command('/usr/local/tomcat/bin/catalina.sh','start')
            limit=time.monotonic()+90
            while True:
                try:
                    with urllib.request.urlopen(self.target,timeout=3) as r:
                        if r.status==200:break
                except Exception:pass
                require(time.monotonic()<limit,'Native readiness not observed after restart');time.sleep(1)
        else:
            raw=self.command(ROOT+'/bin/reload-service.sh','-id','shibboleth.MetadataResolverService','-u','http://localhost:8080/idp');(self.receipt/(label+'-reload.txt')).write_bytes(raw)
        row.update(completedAt=NOW(),completed=True);save(self.out/'operations.json',self.operations)
    def prepare(self,peers):
        registration=[]
        for peer in peers:
            path=ROOT+'/metadata/registered-signer-'+peer['runId']+'.xml'
            require(re.fullmatch(r'/opt/reference-idp/metadata/registered-signer-run_[0-9A-HJKMNP-TV-Z]{26}\.xml',path),'Unsafe owned provider source')
            require(self.command('test','-e',path,allow_failure=True).returncode==1,'Fresh native source already exists')
            raw=(self.receipt/peer['label']/'fixture.xml').read_bytes();SIGNER.public_fixture(raw,peer['entity'])
            self.owned_sources[path]=raw;registration.append(dict(peer,sourcePath=path))
        provider=SIGNER.provider_configuration(self.original[PROVIDERS],registration)
        for path,raw in self.owned_sources.items():self.write(path,raw,'register-source')
        self.write(PROVIDERS,provider,'register-providers')
        if self.audit_changed:self.write(AUDIT,self.audit_configured,'register-audit')
        folder=self.receipt/'configured-configuration';folder.mkdir()
        for path in (PROVIDERS,AUDIT):(folder/Path(path).name).write_bytes(self.expected[path])
        self.activate('prepare')
    def scope(self,label,entity):
        folder=self.receipt/'native-source';command=[ROOT+'/bin/dumpconfig.sh','-u','http://localhost:8080/idp','--saml2','-r',entity,'-P',PROFILE]
        profile=json.loads(self.command(*command));public_json(profile)
        require(set(profile)=={'RelyingPartyConfiguration','ProfileConfiguration'} and profile['ProfileConfiguration'].get('id')==PROFILE,
            'Native SLO profile was not selected')
        require(all(isinstance(v,(str,bool,int)) for group in profile.values() for v in group.values()),'Unexpected native public profile schema')
        # An isolated copy of the existing source/config closure targets the real SLO profile.
        previous=TRUST.docker;TRUST.docker=self.command;TRUST.PROFILE=PROFILE;TRUST.PROFILE_KEYS=set(profile['ProfileConfiguration'])
        try:TRUST.capture(folder,label,entity)
        finally:TRUST.docker=previous
        selected=json.loads((folder/('trust-'+label+'-selected-properties.json')).read_bytes())
        require(selected.get('idp.trust.signatures')=='shibboleth.ExplicitKeySignatureTrustEngine','Selected native signature trust engine is not closed')
        return dict(profileId=PROFILE,signatureTrustEngine=selected['idp.trust.signatures'],credentialResolver='shibboleth.MetadataCredentialResolver',
            effectiveProfileFile='native-source/trust-probes-before-primary-native-effective-profile.json',overrideSourceInventoryFile='native-source/trust-probes-before-primary-override-source-inventory.json')
    def state(self,label,peers):
        rows=[];consumer={};queries=[];sources=self.receipt/'native-source'
        for peer in peers:
            url='http://localhost:8080/idp/profile/admin/mdquery?entityID='+urllib.parse.quote(peer['entity'],safe='')
            cmd=['curl','--silent','--show-error','--max-time','20','--write-out','\n%{http_code}',url]
            started=NOW();result=self.command(*cmd,allow_failure=True);finished=NOW()
            require(result.returncode==0,'Native metadata query transport failed; absence is not established')
            body,separator,status=result.stdout.rpartition(b'\n');require(separator and status in (b'200',b'404'),'Native metadata query did not return a qualified status')
            present=status==b'200'
            if present:require(ET.fromstring(body).tag=='{'+MD+'}EntityDescriptor' and ET.fromstring(body).get('entityID')==peer['entity'],'Native metadata query returned another object')
            else:require(body.strip()==b'Not Found','Native metadata query 404 is not the stock explicit no-entity result')
            prefix='native-readbacks/'+label+'-'+peer['label'];directory=self.receipt/'native-readbacks';directory.mkdir(exist_ok=True)
            rawfile=prefix+'-query.stdout';bodyfile=prefix+'-query.body';(self.receipt/rawfile).write_bytes(result.stdout);(self.receipt/bodyfile).write_bytes(body)
            query=dict(command=cmd,entity=peer['entity'],url=url,method='GET',exitCode=result.returncode,startedAt=started,finishedAt=finished,responseStatus=int(status),
                stdoutFile=rawfile,stdoutSha256=SHA(result.stdout),responseBodyFile=bodyfile,responseBodySha256=SHA(body),responseBodyBytes=len(body));queryfile=prefix+'-query.json';save(self.receipt/queryfile,query);queries.append(queryfile)
            record=dict(entity=peer['entity'],present=present)
            if record['present']:
                root=ET.fromstring(body);file='native-readbacks/registered-'+peer['label']+'-metadata.xml';path=self.receipt/file
                if path.exists():require(path.read_bytes()==body,'Effective native peer metadata changed during controls')
                else:path.write_bytes(body)
                certs=[c.text for role in root.findall('{'+MD+'}SPSSODescriptor') for kd in role.findall('{'+MD+'}KeyDescriptor') if kd.get('use') in (None,'signing') for c in kd.findall('.//{http://www.w3.org/2000/09/xmldsig#}X509Certificate')]
                require(certs,'Native SP-role signing certificates absent');record.update(signingCertificates=[''.join(c.split()) for c in certs],nativeMetadataFile=file)
                if label in ('probes-before','probes-after'):
                    actual=self.scope(label+'-'+peer['label'],peer['entity'])
                    if peer['label']=='primary':consumer=actual
            rows.append(record)
        directories=[ROOT+'/views',ROOT+'/flows',ROOT+'/edit-webapp/WEB-INF/lib',ROOT+'/dist/plugin-webapp/WEB-INF/lib','/usr/local/tomcat/webapps/idp/WEB-INF/classes']
        command='for d in '+' '.join(directories)+'; do if test -d "$d"; then find "$d" -type f; fi; done'
        inventory=self.command('sh','-c',command)
        for path in inventory.decode().splitlines():
            require(path.startswith(ROOT+'/') and not path.endswith(('/admin/mdquery.vm','.jar','.class','/slo-front-abstract-flow.xml','/slo-front-abstract-beans.xml','/saml-abstract-flow.xml')) and '/flows/admin/mdquery' not in path,
                'Native SLO/metadata-query override requires another source qualification')
        inventory_file='native-source/'+label+'-flow-view-overrides.txt';(self.receipt/inventory_file).write_bytes(inventory)
        native=runtime(CONTAINER);files={}
        for path in (PROVIDERS,AUDIT):
            raw=self.command('cat',path);require(raw==self.expected[path],'Native configuration changed during campaign');files[Path(path).name]=SHA(raw)
            if label=='restoration':
                folder=self.receipt/'final-configuration';folder.mkdir(exist_ok=True);(folder/Path(path).name).write_bytes(raw)
        with urllib.request.urlopen(self.target,timeout=40) as response:
            require(response.status==200,'Native hosted metadata readback failed');raw=response.read(1024*1024+1)
        root=ET.fromstring(raw);require(root.get('entityID')==self.target,'Hosted metadata identity differs');file='native-readbacks/'+label+'-hosted-metadata.xml';(self.receipt/file).parent.mkdir(exist_ok=True);(self.receipt/file).write_bytes(raw)
        return dict(runtime=native,configurationFiles=files,peers=rows,metadataQueries=queries,hostedEntityId=self.target,hostedMetadataFile=file,
            flowViewOverrideInventoryFile=inventory_file,flowViewOverrideInventorySha256=SHA(inventory),
            sourceHashes={p.name:SHA(p.read_bytes()) for p in sources.iterdir() if p.name.endswith('.jar') or p.name in FLOW_ENTRIES},operativeConsumer=consumer)
    def before_http(self):
        raw=self.command('date','-u','+%Y-%m-%dT%H:%M:%S.%NZ');return raw.decode().strip()
    def after_http(self,before):
        after=self.command('date','-u','+%Y-%m-%dT%H:%M:%S.%NZ').decode().strip();request_id=self.client.records[-1]['requestId'];rows=[]
        for _ in range(5):
            rows=[]
            for line in self.command('cat',ROOT+'/logs/idp-audit.log').decode().splitlines():
                if 'SAMLscope-signature-v1|' not in line:continue
                public='SAMLscope-signature-v1|'+line.split('SAMLscope-signature-v1|',1)[1];fields=public.split('|')
                if len(fields)==9 and fields[1]==request_id:rows.append(public)
            if rows:break
            time.sleep(.2)
        require(len(rows)==1,'Native operation has no unique request-bound audit; no retry')
        file='native-audit-'+request_id+'.log';(self.receipt/file).write_text(rows[0]+'\n')
        return dict(nativeClockBefore=before,nativeClockAfter=after,nativeAuditFile=file)
    def restore(self,peers):
        errors=[]
        for path,original in self.original.items():
            try:
                current=self.command('cat',path);require(current in (original,self.expected[path]),'External native configuration changed during restoration')
                if current!=original:self.write(path,original,'restore-configuration')
            except Exception as failure:errors.append(dict(path=path,exceptionClass=type(failure).__name__))
        for path,raw in self.owned_sources.items():
            try:
                check=self.command('test','-e',path,allow_failure=True)
                if check.returncode==0:
                    require(self.command('cat',path)==raw,'Owned source changed outside campaign; do not remove');self.command('rm',path)
                require(self.command('test','-e',path,allow_failure=True).returncode==1,'Owned source remains')
            except Exception as failure:errors.append(dict(path=path,exceptionClass=type(failure).__name__))
        try:
            if self.activation_attempted:self.activate('restore')
        except Exception as failure:errors.append(dict(path='activation',exceptionClass=type(failure).__name__))
        restored=not errors and all(self.command('cat',p)==raw for p,raw in self.original.items())
        save(self.out/'native-restoration.json',dict(restored=restored,errors=errors,original={p:SHA(b) for p,b in self.original.items()},final={p:SHA(self.command('cat',p)) for p in self.original},temporarySourcesAbsent=not errors))
        return restored
    def counts(self):
        return dict(nativeConfigurationWrites=sum(o['operation']=='write' for o in self.operations),restorationWrites=sum(o['operation']=='write' and o['label'].startswith('restore') for o in self.operations),
            productRestarts=sum(o['operation']=='restart' for o in self.operations),metadataReloads=sum(o['operation']=='reload' for o in self.operations),nativeCliExecutions=len(self.commands),nativeLogoutCompletionGets=len(self.client.completions))

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output',type=Path,required=True);parser.add_argument('--min-free-mib',type=int,default=96);args=parser.parse_args()
    collect(ShibbolethProduct(),args.output,min_free_mib=args.min_free_mib)
