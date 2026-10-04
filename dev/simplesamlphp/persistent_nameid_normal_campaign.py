#!/usr/bin/env python3
"""Observe native persistent NameIDs with normal Suite requests and exact restoration.

This campaign never submits an operator verdict. The product-native filter and
default format are temporary settings; the original Suite metadata is consumed
by the installed product parser without Suite XML-to-attribute conversion.
"""
import argparse
import importlib.util
import json
import os
import hashlib
import secrets
from pathlib import Path
import subprocess
import sys
import time
import urllib.request

REPO=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(REPO/"dev/keycloak"))
from import_metadata_batch import api,save,BASE
from reference_flow import Client
sys.path.insert(0,str(Path(__file__).resolve().parent))
from configuration_batch import ConfigurationBatch
spec=importlib.util.spec_from_file_location("ssp_native",Path(__file__).with_name("import_metadata_batch.py"))
native=importlib.util.module_from_spec(spec);spec.loader.exec_module(native)
CONTAINER="samlscope-reference-ssp"
PREFIX=REPO/"build/acceptance/reference-20260914/ssp-config"
IDP="http://localhost:18380/idp"
FORMAT="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
READBACK=r'''
$metadata=[];require '/var/simplesamlphp/metadata/saml20-idp-hosted.php';
$m=$metadata[$argv[1]];
echo json_encode(['entity_id'=>$argv[1],'NameIDFormat'=>$m['NameIDFormat']??null,
 'authproc'=>$m['authproc']??null],JSON_THROW_ON_ERROR);
'''

READBACK_ATTEMPTS={}
def raw(path):
    READBACK_ATTEMPTS[path]=READBACK_ATTEMPTS.get(path,0)+1
    return subprocess.check_output(["docker","exec",CONTAINER,"cat",path],timeout=30)

def settled(path,expected):
    for attempt in range(8):
        observed=raw(path)
        if observed==expected:return observed
        if attempt<7:time.sleep(1)
    raise ValueError("Native bind-mount read-back differs after configuration settle")

def batch(name):
    result=ConfigurationBatch(PREFIX/name)
    result.container_path="/var/simplesamlphp/metadata/"+name
    # Hosted metadata is intentionally a read-only bind mount in the reference
    # container. Its host file remains writable and is updated in place; never
    # attempt a container push to that mount.
    if name=="saml20-sp-remote.php":result.container=CONTAINER
    if raw(result.container_path)!=result.original or b"?>" in result.original:
        raise ValueError("Native metadata initial read-back differs")
    return result

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument("--output",type=Path,required=True)
    p.add_argument("--profiles",default="browser_sso_idp,ecp_idp")
    p.add_argument("--length-mutant",action="store_true",help="Native AttributeNameID emits 257 characters; diagnostic control, never adopted")
    args=p.parse_args();profiles=args.profiles.split(",")
    if len(set(profiles))!=len(profiles) or not set(profiles)<={"browser_sso_idp","ecp_idp"}:
        raise ValueError("Invalid profiles")
    out=args.output.resolve();out.mkdir(parents=True,exist_ok=False)
    save(out/"campaign.json",dict(case="IIP-SSO05-a2-idp-01",native_length_mutant=args.length_mutant,verdict_adopted=False))
    hosted,remote=batch("saml20-idp-hosted.php"),batch("saml20-sp-remote.php")
    salt=ConfigurationBatch(PREFIX/"config-override.php")
    salt.container_path="/var/simplesamlphp/config/config-override.php"
    if b"secretsalt" in salt.original or b"?>" in salt.original or raw(salt.container_path)!=salt.original:
        raise ValueError("Unexpected native salt override baseline")
    (out/"salt-override-original.php").write_bytes(salt.original)
    (out/"hosted-original.php").write_bytes(hosted.original)
    (out/"remote-original.php").write_bytes(remote.original)
    for name,path in [("persistent-filter","/var/simplesamlphp/modules/saml/src/Auth/Process/PersistentNameID.php"),
                      ("nameid-generator","/var/simplesamlphp/modules/saml/src/IdP/SAML2.php"),
                      ("attribute-nameid","/var/simplesamlphp/modules/saml/src/Auth/Process/AttributeNameID.php"),
                      ("attribute-add","/var/simplesamlphp/modules/core/src/Auth/Process/AttributeAdd.php")]:
        (out/("native-"+name+".php")).write_bytes(raw(path))
    operations=[];save(out/"operations.json",operations)
    credentials=(os.environ.get("REFERENCE_USERNAME","samlscope-m0-user"),
                 os.environ.get("REFERENCE_PASSWORD","samlscope-m0-password"))
    salt_value=secrets.token_hex(32)
    try:
        salt.apply(("$config['secretsalt'] = "+repr(salt_value)+";").encode())
        settled(salt.container_path,salt.expected)
        native_salt=subprocess.check_output(["docker","exec",CONTAINER,"php","-r",
            "require '/var/simplesamlphp/lib/_autoload.php'; $salt=(new \\SimpleSAML\\Utils\\Config())->getSecretSalt(); "
            "echo json_encode(['saltSha256'=>hash('sha256',$salt)]);"],timeout=30)
        salt_hash=hashlib.sha256(salt_value.encode()).hexdigest()
        if json.loads(native_salt)!={"saltSha256":salt_hash}:raise ValueError("Native salt setting unavailable")
        save(out/"salt-native-readback.json",dict(salt_sha256=salt_hash,
            configured_file_sha256=hashlib.sha256(salt.expected).hexdigest(),secret_persisted=False))
        overlay=("$metadata["+repr(IDP)+"][\"authproc\"] = [20 => [\"class\" => \"saml:PersistentNameID\", "
                 "\"identifyingAttribute\" => \"uid\"]];\n"
                 "$metadata["+repr(IDP)+"][\"NameIDFormat\"] = ["+repr(FORMAT)+"];\n").encode()
        expected_authproc={"20":{"class":"saml:PersistentNameID","identifyingAttribute":"uid"}}
        if args.length_mutant:
            value="x"*257
            overlay=("$metadata["+repr(IDP)+"][\"authproc\"] = [20 => [\"class\" => \"core:AttributeAdd\", "
                "\"samlscopePersistentLengthControl\" => ["+repr(value)+"]], 30 => [\"class\" => \"saml:AttributeNameID\", "
                "\"identifyingAttribute\" => \"samlscopePersistentLengthControl\", \"Format\" => "+repr(FORMAT)+"]];\n"
                "$metadata["+repr(IDP)+"][\"NameIDFormat\"] = ["+repr(FORMAT)+"];\n").encode()
            expected_authproc={"20":{"class":"core:AttributeAdd","samlscopePersistentLengthControl":[value]},
                "30":{"class":"saml:AttributeNameID","identifyingAttribute":"samlscopePersistentLengthControl","Format":FORMAT}}
        hosted.apply(overlay)
        configured=settled(hosted.container_path,hosted.expected)
        if configured!=hosted.expected:raise ValueError("Native hosted read-back mismatch")
        (out/"hosted-configured.php").write_bytes(configured)
        check=subprocess.check_output(["docker","exec",CONTAINER,"php","-r",READBACK,IDP],timeout=30)
        (out/"hosted-native-readback.json").write_bytes(check)
        if json.loads(check)!=dict(entity_id=IDP,NameIDFormat=[FORMAT],authproc=expected_authproc):
            raise ValueError("Native PersistentNameID setting differs")
        time.sleep(3)
        for profile in profiles:
            folder=out/profile;folder.mkdir()
            row=dict(profile=profile,status="incomplete",normal_flows_attempted=0,ecp_probe_attempted=False)
            operations.append(row);save(out/"operations.json",operations)
            created=api("/api/plans",dict(name="SimpleSAMLphp native persistent NameID",profile=profile,
                targetKind="IDP",targetEntityId=IDP,metadataSourceKind="URL",
                metadataSourceLocation="http://samlscope-reference-ssp/simplesaml/module.php/saml/idp/metadata",
                suiteMetadataDelivery="HTTP_URL",declaredFeatures={},parameters=dict(clockSkewToleranceSeconds=180,
                metadataRefreshWaitSeconds=300,testUserHint=credentials[0],requestSigningMode="REQUIRED"),
                interaction=dict(allowBrowserSteps=True,allowAttestation=False,preset="quick"),authorizedTarget=True))
            save(folder/"plan.json",created);plan=created["plan"]["plan"]["id"];entity=BASE+"/p/"+plan
            if entity.encode() in remote.original:raise ValueError("Unexpected existing peer")
            created=api("/api/plans/"+plan+"/runs",{});save(folder/"created.json",created)
            run=created["run"]["id"];row["run"]=run
            save(folder/"preflight.json",api("/api/runs/"+run+"/preflight",{}))
            with urllib.request.urlopen(entity+"/metadata",timeout=30) as response:fixture=response.read()
            (folder/"fixture.xml").write_bytes(fixture)
            parsed=subprocess.run(["docker","exec","-i",CONTAINER,"php","-r",native.PHP,entity,"default"],
                input=fixture,capture_output=True,timeout=40)
            (folder/"parser.stdout").write_bytes(parsed.stdout);(folder/"parser.stderr").write_bytes(parsed.stderr)
            row["native_parser_returncode"]=parsed.returncode
            if parsed.returncode:raise ValueError("Native SP metadata parser failed")
            data=json.loads(parsed.stdout)
            if data["entity_id"]!=entity or data["validate_authnrequest"] is not True:
                raise ValueError("Native SP scope/signature setting differs")
            remote.apply(data["php"].encode());configured=settled(remote.container_path,remote.expected)
            (folder/"remote-configured.php").write_bytes(configured)
            if configured!=remote.expected:raise ValueError("Native remote read-back mismatch")
            time.sleep(3)
            flows=[]
            for _ in range(2):
                row["normal_flows_attempted"]+=1;save(out/"operations.json",operations)
                receipt=Client().flow(entity+"/start/m0-roundtrip?run="+run,None,*credentials)
                flows.append(receipt);save(folder/"flows.json",flows)
                if receipt!="recorded":raise ValueError("Normal native persistent SSO not recorded")
            if profile=="ecp_idp":
                row["ecp_probe_attempted"]=True;save(out/"operations.json",operations)
                save(folder/"ecp-probe.json",api("/api/runs/"+run+"/ecp-probe",dict(username=credentials[0],password=credentials[1])))
            save(folder/"tests-start.json",api("/api/runs/"+run+"/tests/start",{}))
            save(folder/"evaluation.json",api("/api/runs/"+run+"/protocol-evidence/evaluate",{}))
            row["status"]="recorded";save(out/"operations.json",operations)
    finally:
        restoration={}
        for label,configuration in [("remote",remote),("hosted",hosted),("salt-override",salt)]:
            restoration[label]=configuration.restore();final=settled(configuration.container_path,configuration.original)
            (out/(label+"-final.php")).write_bytes(final)
            if final!=configuration.original:restoration[label]["restored"]=False
        save(out/"restoration.json",restoration);save(out/"operations.json",operations)
        save(out/"operation-counts.json",dict(product_configuration_write_attempts=remote.write_count+hosted.write_count+salt.write_count,
            configuration_apply_writes=remote.applied_count+hosted.applied_count+salt.applied_count,
            restoration_writes=remote.restoration_writes+hosted.restoration_writes+salt.restoration_writes,
            native_parser_invocations=sum("native_parser_returncode" in row for row in operations),
            normal_flows_attempted=sum(row["normal_flows_attempted"] for row in operations),
            ecp_probe_invocations=sum(row["ecp_probe_attempted"] for row in operations),
            native_file_readbacks=READBACK_ATTEMPTS,
            product_restarts=0,human_operations=0,restored=all(value["restored"] for value in restoration.values())))
        sys.path.insert(0,str(REPO/"dev/reference-acceptance"))
        from capture_run_originals import capture
        for row in operations:
            if "run" not in row:continue
            folder=out/row["profile"];run=row["run"]
            for suffix in ["transcript","result.json","protocol-evidence"]:
                try:save(folder/(suffix if "." in suffix else suffix+".json"),api("/api/runs/"+run+"/"+suffix))
                except Exception as error:save(folder/(suffix.replace(".","-")+"-error.json"),dict(error=str(error)))
            entries=api("/api/runs/"+run+"/transcript");capture(folder,run,entries)
            subprocess.run(["docker","cp","samlscope-reference-suite:/data/target-metadata/"+run+".xml",
                str(folder/"target-metadata.xml")],check=True,capture_output=True,timeout=30)
        if not all(value["restored"] for value in restoration.values()):raise ValueError("Native restore failed")
        if any(salt_value.encode() in path.read_bytes() for path in out.rglob("*") if path.is_file()):
            raise ValueError("Native salt leaked into evidence")
    print("Native persistent campaign recorded; both metadata files restored")

if __name__=="__main__":main()
