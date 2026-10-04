#!/usr/bin/env python3
"""Adopt native SSP intersection evidence after signed capability controls and replay.

HTTP silence is never a rejection conclusion. The conclusion comes from verified
target signatures, matching-key decryption, the complete original matrix and
independently observed native signing capability in the same Run.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
import zipfile

REPO=Path(__file__).resolve().parents[2]
FOLDER="ssp-intersection-capability-v165-r1"
CASE="IIP-MD05-e8-idp-01"
SUITE="samlscope-reference-suite"
HELPER="VerifyMetadataIntersectionCapabilityEvidence"
JARS=("runner","core","saml","store")
CLASSES=("com/samlscope/runner/cases/MetadataIntersectionEvidence.class",
         "com/samlscope/runner/cases/MetadataAlgorithmEvidence.class",
         "com/samlscope/runner/cases/MetadataEncryptionProof.class",
         "com/samlscope/runner/cases/MetadataAlgorithmConfigurationTestCase.class",
         "com/samlscope/runner/cases/MetadataFixtureObservationTestCase.class")
P="{urn:oasis:names:tc:SAML:2.0:protocol}"
S="{urn:oasis:names:tc:SAML:2.0:assertion}"
DS="{http://www.w3.org/2000/09/xmldsig#}"
sys.path.insert(0,str(REPO/"dev/reference-acceptance"))
from verify_metadata_intersection import REQUIRED
from native_algorithm_preparation import verify as verify_preparation


def sha(raw):return hashlib.sha256(raw).hexdigest()
def load(path):return json.loads(path.read_bytes())
def require(value,message):
    if not value:raise ValueError(message)
def rows(result):return {case["id"]:case for requirement in result["requirements"] for case in requirement["cases"]}


def capture_runtime(folder):
    runtime=folder/"runtime";runtime.mkdir(exist_ok=False)
    pins={"jars":{},"classes":{}}
    for name in JARS:
        path=runtime/(name+".jar")
        subprocess.run(["docker","cp",SUITE+":/opt/samlscope/lib/"+name+"-0.1.0.jar",str(path)],check=True,capture_output=True)
        pins["jars"][name]=sha(path.read_bytes())
    helper=(REPO/("dev/reference-acceptance/"+HELPER+".java")).read_bytes()
    (runtime/(HELPER+".java")).write_bytes(helper)
    pins["helperSha256"]=sha(helper)
    with zipfile.ZipFile(runtime/"runner.jar") as jar:
        pins["classes"]={name:sha(jar.read(name)) for name in CLASSES}
    (runtime/"pins.json").write_text(json.dumps(pins,indent=2)+"\n")


def replay(folder):
    pins=load(folder/"runtime/pins.json")
    require(set(pins["jars"])==set(JARS),"runtime JAR set differs")
    for name in JARS:require(sha((folder/("runtime/"+name+".jar")).read_bytes())==pins["jars"][name],"archived runtime changed")
    require(sha((folder/("runtime/"+HELPER+".java")).read_bytes())==pins["helperSha256"],"archived verifier changed")
    with zipfile.ZipFile(folder/"runtime/runner.jar") as jar:
        require(pins["classes"]=={name:sha(jar.read(name)) for name in CLASSES},"production reader class changed")
    classpath_file=Path("/private/tmp/samlscope-runner-runtime-classpath.txt")
    require(classpath_file.is_file(),"existing runtime dependency classpath unavailable")
    with tempfile.TemporaryDirectory(prefix="ssp-intersection-capability-") as temp:
        temp=Path(temp)
        local_cp=":".join(str(folder/("runtime/"+name+".jar")) for name in JARS)+":"+classpath_file.read_text().strip()
        subprocess.run(["javac","-cp",local_cp,"-d",str(temp/"classes"),str(folder/("runtime/"+HELPER+".java"))],check=True,capture_output=True)
        remote="/tmp/intersection-capability-"+sha(folder.as_posix().encode())[:20]
        subprocess.run(["docker","exec",SUITE,"mkdir","-p",remote],check=True,capture_output=True)
        try:
            subprocess.run(["docker","cp",str(folder),SUITE+":"+remote+"/campaign"],check=True,capture_output=True)
            subprocess.run(["docker","cp",str(temp/"classes"),SUITE+":"+remote+"/classes"],check=True,capture_output=True)
            runtime_cp=":".join(remote+"/campaign/runtime/"+name+".jar" for name in JARS)
            result=subprocess.run(["docker","exec",SUITE,"java","-cp",runtime_cp+":"+remote+"/classes:/opt/samlscope/lib/*",
                "com.samlscope.runner.cases."+HELPER,remote+"/campaign","/data",remote+"/replay.json"],capture_output=True,text=True,timeout=120)
            if result.returncode:raise ValueError("Production replay failed: "+result.stderr[-2500:])
            subprocess.run(["docker","cp",SUITE+":"+remote+"/replay.json",str(temp/"replay.json")],check=True,capture_output=True)
            return load(temp/"replay.json")
        finally:
            subprocess.run(["docker","exec","--user","0",SUITE,"rm","-rf",remote],check=True,capture_output=True)


def verify(root,formal=True,live=False):
    folder=Path(root).resolve()
    if folder.name!=FOLDER:folder=folder/FOLDER
    source=folder/"source"
    created=load(folder/"created.json")["run"];run=created["id"];entity="http://localhost:18080/p/"+created["planId"]
    require(load(source/"created.json")["run"]==created,"original Run identity differs")
    require(load(folder/"plan.json")==load(source/"plan.json"),"original Plan changed")
    before=load(folder/"transcript-before.json");transcript_list=load(folder/"transcript.json")
    require(before==load(source/"transcript.json") and transcript_list[:len(before)]==before,"original complete matrix transcript changed")
    require(len(transcript_list)-len(before)==10,"capability operation transcript count differs")
    transcript={row["id"]:row for row in transcript_list}
    require(len(transcript)==len(transcript_list) and all(row["runId"]==run for row in transcript_list),"foreign/ambiguous transcript")
    originals={}
    for row in load(folder/"decoded-manifest.json"):
        path=(folder/row["file"]).resolve()
        require(path.parent==(folder/"decoded").resolve() and row["id"] not in originals,"unsafe original")
        raw=path.read_bytes()
        require(sha(raw)==row["sha256"] and len(raw)==transcript[row["id"]]["decodedSamlBytes"],"original hash/length differs")
        originals[row["id"]]=raw
    for row in load(source/"decoded-manifest.json"):
        raw=(source/row["file"]).read_bytes()
        require(sha(raw)==row["sha256"] and originals[row["id"]]==raw,"old matrix original changed")
    operations=load(source/"operations.json")
    require({row["variant"] for row in operations}==REQUIRED and len(operations)==len(REQUIRED),"original matrix is partial")
    restoration=load(source/"restoration.json")
    original=(folder/"original-sp-config.php").read_bytes()
    require(restoration["restored"] and restoration["original_sha256"]==restoration["final_sha256"]==sha(original),"original matrix native baseline differs")
    for variant in REQUIRED:
        verify_preparation(source,variant)
        native=load(source/variant/"parser-output.json")
        require(native["entity_id"]==entity and native["validate_authnrequest"] is True
                and native["assertion_encryption"] is True,"original native parser output scope differs")
    matrix=folder/"native-matrix-readback"
    audit=load(matrix/"verification.json")
    require(audit["runId"]==run and audit["native_parser_invocations"]==len(REQUIRED)
        and audit["product_configuration_writes"]==audit["product_restarts"]==audit["human_operations"]==0,
        "native parser read-only audit scope differs")
    require(len(audit["records"])==len(REQUIRED) and {row["variant"] for row in audit["records"]}==REQUIRED,
        "native parser read-only audit matrix is partial")
    for row in audit["records"]:
        variant=row["variant"];raw=(matrix/(variant+".stdout")).read_bytes()
        require(row["returncode"]==0 and row["matches_original"] is True
            and row["fixture_sha256"]==sha((source/variant/"fixture.xml").read_bytes())
            and row["parser_output_sha256"]==sha(raw)
            and json.loads(raw)==load(source/variant/"parser-output.json"),
            "native parser original matrix mapping differs")
    require((folder/"target-metadata.xml").read_bytes()==(source/"target-metadata.xml").read_bytes(),"target trust snapshot changed")
    current=load(folder/"restoration.json");counts=load(folder/"operation-counts.json")
    require((folder/"final-sp-config.php").read_bytes()==original and current["restored"]
        and current["original_sha256"]==current["final_sha256"]==sha(original),"capability configuration not restored")
    require(counts==dict(run=run,configuration_apply_writes=2,restoration_writes=1,product_configuration_write_attempts=3,
        native_parser_invocations=2,protocol_operation_pairs_attempted=2,product_restarts=0,human_operations=0,restored=True,verdict_adopted=False),"operation counts differ")
    for label,algorithm in [("sha256","http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"),
                           ("sha384","http://www.w3.org/2001/04/xmldsig-more#rsa-sha384")]:
        member=folder/("capability-"+label);native=json.loads((member/"parser.stdout").read_bytes())
        overlay=native["php"]+"\n$metadata["+repr(entity)+"][\"signature.algorithm\"] = "+repr(algorithm)+";"
        require((member/"overlay.php").read_text()==overlay+"\n"
            and (member/"configuration-readback.php").read_bytes()==original+b"\n"+overlay.encode()+b"\n","native capability configuration derivation differs")
        require(load(member/"native-readback.json")==dict(entity_id=entity,signature_algorithm=algorithm,
            assertion_encryption=True,validate_authnrequest=True),"native capability setting differs")
        flow=load(member/"flow.json")
        require(flow["run"]==run and flow["variant"]=="control" and flow["correlated_success"] is True,"native signing capability Success absent")
        positive=flow["positive_exchange"];request,response=[transcript[ref] for ref in positive["transcript_ids"]]
        request_xml,response_xml=[ET.fromstring(originals[row["id"]]) for row in (request,response)]
        require(request_xml.tag==P+"AuthnRequest" and response_xml.tag==P+"Response"
            and response_xml.get("InResponseTo")==request_xml.get("ID")
            and response_xml.find(P+"Status/"+P+"StatusCode").get("Value")=="urn:oasis:names:tc:SAML:2.0:status:Success"
            and response_xml.find(DS+"Signature/"+DS+"SignedInfo/"+DS+"SignatureMethod").get("Algorithm")==algorithm
            and len(response_xml.findall(S+"EncryptedAssertion"))>0,"native signed encrypted capability output differs")
        prepared=[row for row in transcript_list if row["direction"]=="OUTBOUND"
            and row["samlSummary"].get("type")=="MetadataPrepared"
            and originals.get(row["id"])==(member/"fixture.xml").read_bytes()
            and row["timestamp"]<request["timestamp"] and row not in before]
        require(prepared,"capability fixture original missing")
        # Record corrupted-input non-success diagnostically; it is not a rejection oracle.
        negative=flow["negative_control"]
        require(negative["source"]=="suite" and negative["correlated_success"] is False,"corrupted input contradicted by Success")
    recorded=load(folder/"native-reader-replay.json")
    require(replay(folder)==recorded,"archived production replay differs")
    require(recorded["runId"]==run and recorded["outcome"]=="VIOLATED"
        and recorded["reasonCode"]=="metadata.algorithms.intersection-violated"
        and recorded["privateKeyExported"] is False and recorded["plaintextPersisted"] is False
        and len(recorded["checks"])==12 and all(value=="NOT_VERIFIED" for name,value in recorded["checks"].items()
            if name!="complete-native-campaign"),"negative controls not complete")
    require(set(recorded["details"]["observed_variants"])==REQUIRED and not recorded["details"]["missing_variants"]
        and not recorded["details"]["evidence_issues"] and recorded["details"]["signature_capability_controls_verified"],"full matrix not qualified")
    if live:
        require(subprocess.check_output(["docker","exec","samlscope-reference-ssp","cat","/var/simplesamlphp/metadata/saml20-sp-remote.php"])
            ==original,"live restoration differs")
    if not formal:return recorded
    result=load(folder/"evaluation/result.json");case=rows(result)[CASE]
    require(result["run"]["id"]==run and result["target"]["metadata_digest"]=="sha256:"+sha((folder/"target-metadata.xml").read_bytes()),"formal result Run/target differs")
    require((case["outcome"],case["verdict"],case["reason_code"],case["attested"])==
        ("VIOLATED","FAIL","metadata.algorithms.intersection-violated",False),"formal intersection conclusion differs")
    require(load(folder/"evaluation/transcript-before.json")==load(folder/"evaluation/transcript.json")==transcript_list,"formal reevaluation changed transcript")
    expected={row["reference"] for row in recorded["evidence"]}
    execution=load(folder/"evaluation/case-execution.json")
    require(execution["runId"]==run and execution["caseId"]==CASE and execution["status"]=="FINISHED",
        "formal stored case identity differs")
    details=execution["outcome"]["details"]
    require(execution["outcome"]["outcome"]==case["outcome"] and execution["outcome"]["reasonCode"]==case["reason_code"]
        and details.get("configuration_confirmed") is True
        and all(details.get(name)==value for name,value in recorded["details"].items()),"formal stored preparation/reader details differ")
    require(expected<={row["reference"] for row in case["evidence"]},"formal evidence/preparation binding differs")
    return folder/"evaluation/result.json",{CASE:case}


if __name__=="__main__":
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument("root",type=Path)
    parser.add_argument("--prepare-runtime",action="store_true");parser.add_argument("--record-replay",action="store_true")
    parser.add_argument("--diagnostic-only",action="store_true");parser.add_argument("--live",action="store_true")
    args=parser.parse_args();folder=args.root.resolve()
    if folder.name!=FOLDER:folder=folder/FOLDER
    if args.prepare_runtime:capture_runtime(folder)
    if args.record_replay:
        path=folder/"native-reader-replay.json";require(not path.exists(),"immutable replay exists")
        path.write_text(json.dumps(replay(folder),indent=2)+"\n")
    result=verify(folder,formal=not args.diagnostic_only,live=args.live)
    print("Verified SSP native intersection", result["outcome"] if args.diagnostic_only else result[1][CASE]["verdict"])
