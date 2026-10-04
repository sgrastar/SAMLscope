#!/usr/bin/env python3
"""Verify native persistent length originals, producer mutant, restoration, and pinned replay."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import urllib.request
import zipfile

REPO=Path(__file__).resolve().parents[2]
FOLDER="ssp-native-persistent-normal-v165-r6"
MUTANT="ssp-native-persistent-length-mutant-v165-r1"
CASE="IIP-SSO05-a2-idp-01"
SUITE="samlscope-reference-suite"
TARGET="http://localhost:18380/idp"
FORMAT="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
JARS=("runner","core","saml","store")
CLASSES=("com/samlscope/runner/cases/NormalFlowBrowserObservation.class",
         "com/samlscope/runner/cases/AutoBrowserEvidenceTestCase.class",
         "com/samlscope/runner/cases/MetadataAlgorithmEvidence.class")
HELPER="VerifySspPersistentLengthOriginals"
JAVA=r'''
package com.samlscope.runner.cases;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.*;
import com.samlscope.store.JsonCodec;
import com.samlscope.saml.normal.SecureXml;
import com.samlscope.saml.crypto.VerifiedSignatureAlgorithms;
import com.samlscope.core.evaluation.CaseOutcome;
import org.w3c.dom.Element;
public final class VerifySspPersistentLengthOriginals {
 static final String CASE="IIP-SSO05-a2-idp-01", TARGET="http://localhost:18380/idp";
 static final String P="urn:oasis:names:tc:SAML:2.0:protocol", S="urn:oasis:names:tc:SAML:2.0:assertion";
 static final String DS="http://www.w3.org/2000/09/xmldsig#", MD="urn:oasis:names:tc:SAML:2.0:metadata";
 static JsonCodec codec=new JsonCodec();
 static void require(boolean condition) {if(!condition)throw new IllegalArgumentException("Unproven native original");}
 static String hash(byte[] b)throws Exception{return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(b));}
 static Instant time(com.fasterxml.jackson.databind.JsonNode node) {
  if(!node.isNumber())return Instant.parse(node.asText());
  var value=node.decimalValue();long seconds=value.longValue();
  return Instant.ofEpochSecond(seconds,value.subtract(java.math.BigDecimal.valueOf(seconds)).movePointRight(9).longValue());
 }
 static List<Element> children(Element root,String ns,String name){return MetadataAlgorithmEvidence.children(root,ns,name);}
 static Optional<CaseOutcome> observe(Path folder,String mutation)throws Exception {
  try {
   var created=codec.mapper().readTree(Files.readAllBytes(folder.resolve("created.json"))).path("run");
   var run=created.path("id").asText();var entity="http://localhost:18080/p/"+created.path("planId").asText();
   var target=SecureXml.parse(Files.readAllBytes(folder.resolve("target-metadata.xml"))).getDocumentElement();
   require(TARGET.equals(target.getAttribute("entityID"))&&!mutation.equals("foreign-target"));
   var keys=MetadataAlgorithmEvidence.signingKeys(target);require(!keys.isEmpty());
   var prepared=SecureXml.parse(Files.readAllBytes(folder.resolve("fixture.xml"))).getDocumentElement();
   require(MD.equals(prepared.getNamespaceURI())&&entity.equals(prepared.getAttribute("entityID")));
   var entries=codec.mapper().readTree(Files.readAllBytes(folder.resolve("transcript.json")));
   require(entries.isArray()&&entries.size()==4);
   var originals=new HashMap<String,byte[]>();
   for(var record:codec.mapper().readTree(Files.readAllBytes(folder.resolve("decoded-manifest.json")))) {
    var path=folder.resolve(record.path("file").asText()).normalize();
    require(path.getParent().equals(folder.resolve("decoded")));
    var raw=Files.readAllBytes(path);if(mutation.equals("changed-original"))raw[raw.length-1]^=1;
    require(hash(raw).equals(record.path("sha256").asText())&&originals.put(record.path("id").asText(),raw)==null);
   }
   var requests=new HashMap<String,com.fasterxml.jackson.databind.JsonNode>();
   var messages=new ArrayList<NormalFlowBrowserObservation.Message>();
   for(var entry:entries) {
    require(run.equals(entry.path("runId").asText())&&!mutation.equals("foreign-run"));
    var raw=originals.get(entry.path("id").asText());require(raw!=null&&raw.length==entry.path("decodedSamlBytes").asInt());
    if(!entry.path("direction").asText().equals("OUTBOUND"))continue;
    var root=SecureXml.parse(raw).getDocumentElement();
    require(P.equals(root.getNamespaceURI())&&"AuthnRequest".equals(root.getLocalName()));
    var issuer=children(root,S,"Issuer");
    require(issuer.size()==1&&entity.equals(issuer.getFirst().getTextContent())&&!mutation.equals("foreign-issuer"));
    require(requests.put(root.getAttribute("ID"),entry)==null);
    messages.add(new NormalFlowBrowserObservation.Message("transcript:"+entry.path("id").asText(),
      entry.path("method").asText(),entry.path("url").asText(),time(entry.path("timestamp")),raw,false));
   }
   require(requests.size()==2);
   var seen=new HashSet<String>();
   for(var entry:entries) {
    if(!entry.path("direction").asText().equals("INBOUND"))continue;
    if(mutation.equals("missing-responses"))continue;
    var raw=originals.get(entry.path("id").asText());var root=SecureXml.parse(raw).getDocumentElement();
    if(mutation.equals("corrupt-signature")) {
     var sig=root.getElementsByTagNameNS(DS,"SignatureValue").item(0);
     var signature=Base64.getMimeDecoder().decode(sig.getTextContent());signature[0]^=1;
     sig.setTextContent(Base64.getEncoder().encodeToString(signature));raw=SecureXml.serialize(root.getOwnerDocument());
    }
    require(entry.path("samlSummary").path("normalFlowAccepted").asBoolean());
    var request=requests.get(root.getAttribute("InResponseTo"));require(request!=null&&seen.add(request.path("id").asText()));
    require(!time(request.path("timestamp")).isAfter(time(entry.path("timestamp"))));
    var requestXml=SecureXml.parse(originals.get(request.path("id").asText())).getDocumentElement();
    var recipient=requestXml.getAttribute("AssertionConsumerServiceURL");
    require(!recipient.isBlank()&&!mutation.equals("foreign-recipient"));
    var assertions=children(root,S,"Assertion");require(assertions.size()==1&&children(root,S,"EncryptedAssertion").isEmpty());
    var assertion=VerifiedResponseAssertion.read(root,TARGET,keys,prepared,Optional.empty(),requestXml.getAttribute("ID"),recipient);
    var names=assertion.getElementsByTagNameNS(S,"NameID");require(names.getLength()==1);
    require("urn:oasis:names:tc:SAML:2.0:nameid-format:persistent".equals(((Element)names.item(0)).getAttribute("Format")));
    messages.add(new NormalFlowBrowserObservation.Message("transcript:"+entry.path("id").asText(),
      entry.path("method").asText(),entry.path("url").asText(),time(entry.path("timestamp")),raw,true));
   }
   return NormalFlowBrowserObservation.evaluate(CASE,messages,TARGET,keys);
  } catch(Exception unavailable) {if(mutation.equals("none"))unavailable.printStackTrace();return Optional.empty();}
 }
 public static void main(String[] args)throws Exception {
  var folder=Path.of(args[0]).toAbsolutePath().normalize();var mutant=Path.of(args[1]).toAbsolutePath().normalize();
  var positive=observe(folder,"none").orElseThrow();var negative=observe(mutant,"none").orElseThrow();
  require(positive.outcome().name().equals("SATISFIED")&&negative.outcome().name().equals("VIOLATED"));
  require(positive.details().get("longest_code_points").equals(40)&&negative.details().get("longest_code_points").equals(257));
  var checks=new TreeMap<String,String>();checks.put("native-positive",positive.outcome().name());checks.put("native-length-mutant",negative.outcome().name());
  for(var mutation:List.of("foreign-run","foreign-issuer","foreign-recipient","missing-responses","corrupt-signature","foreign-target","changed-original")) {
   var result=observe(folder,mutation);require(result.isEmpty());checks.put(mutation,"NOT_VERIFIED");
  }
  var report=new TreeMap<String,Object>();report.put("checks",checks);report.put("outcome",positive.outcome().name());
  report.put("reasonCode",positive.reasonCode());report.put("details",positive.details());report.put("evidence",positive.evidence());
  report.put("nativeMutantOutcome",negative.outcome().name());report.put("nativeMutantDetails",negative.details());
  report.put("privateKeyExported",false);report.put("plaintextNewlyPersisted",false);
  Files.writeString(Path.of(args[2]),codec.mapper().writerWithDefaultPrettyPrinter().writeValueAsString(report)+"\n");
 }
}
'''

def sha(raw):return hashlib.sha256(raw).hexdigest()
def load(path):return json.loads(path.read_bytes())
def require(value,message):
    if not value:raise ValueError(message)
def case(result):return next(c for req in result["requirements"] for c in req["cases"] if c["id"]==CASE)

def capture_runtime(folder):
    runtime=folder/"runtime";runtime.mkdir(exist_ok=False);pins={"jars":{},"classes":{}}
    for name in JARS:
        path=runtime/(name+".jar")
        subprocess.run(["docker","cp",SUITE+":/opt/samlscope/lib/"+name+"-0.1.0.jar",str(path)],check=True,capture_output=True)
        pins["jars"][name]=sha(path.read_bytes())
    (runtime/(HELPER+".java")).write_text(JAVA);pins["helperSha256"]=sha(JAVA.encode())
    with zipfile.ZipFile(runtime/"runner.jar") as jar:pins["classes"]={name:sha(jar.read(name)) for name in CLASSES}
    (runtime/"pins.json").write_text(json.dumps(pins,indent=2)+"\n")

def replay(folder,mutant):
    pins=load(folder/"runtime/pins.json")
    require(set(pins["jars"])==set(JARS),"runtime JAR set differs")
    for name in JARS:require(sha((folder/("runtime/"+name+".jar")).read_bytes())==pins["jars"][name],"runtime JAR changed")
    require(sha((folder/("runtime/"+HELPER+".java")).read_bytes())==pins["helperSha256"],"archived helper changed")
    with zipfile.ZipFile(folder/"runtime/runner.jar") as jar:
        require(pins["classes"]=={name:sha(jar.read(name)) for name in CLASSES},"production reader class changed")
    cpfile=Path("/private/tmp/samlscope-runner-runtime-classpath.txt")
    require(cpfile.is_file(),"runtime dependencies unavailable")
    classpath=":".join(str(folder/("runtime/"+name+".jar")) for name in JARS)+":"+cpfile.read_text().strip()
    with tempfile.TemporaryDirectory(prefix="ssp-persistent-length-") as temporary:
        temporary=Path(temporary)
        subprocess.run(["javac","-cp",classpath,"-d",str(temporary/"classes"),str(folder/("runtime/"+HELPER+".java"))],check=True,capture_output=True)
        process=subprocess.run(["java","-cp",str(temporary/"classes")+":"+classpath,"com.samlscope.runner.cases."+HELPER,
            str(folder/"browser_sso_idp"),str(mutant/"browser_sso_idp"),str(temporary/"replay.json")],capture_output=True,text=True,timeout=60)
        require(process.returncode==0,"Production replay failed: "+process.stderr[-1600:])
        return load(temporary/"replay.json")

def verify(folder,live=False):
    folder=Path(folder).resolve()
    if folder.name!=FOLDER:folder=folder/FOLDER
    mutant=folder.parent/MUTANT
    for campaign,is_mutant in [(folder,False),(mutant,True)]:
        restoration=load(campaign/"restoration.json")
        for label in ["hosted","remote","salt-override"]:
            original=(campaign/(label+"-original.php")).read_bytes();final=(campaign/(label+"-final.php")).read_bytes()
            require(original==final and restoration[label]["restored"] is True
                and restoration[label]["original_sha256"]==restoration[label]["final_sha256"]==sha(original),"native restoration differs")
        configured=(campaign/"hosted-configured.php").read_bytes();native=load(campaign/"hosted-native-readback.json")
        require(native["entity_id"]==TARGET and native["NameIDFormat"]==[FORMAT],"native persistent default differs")
        if is_mutant:
            require(load(campaign/"campaign.json")["native_length_mutant"] is True,"producer control not marked diagnostic")
            value="x"*257
            expected={"20":{"class":"core:AttributeAdd","samlscopePersistentLengthControl":[value]},
                "30":{"class":"saml:AttributeNameID","identifyingAttribute":"samlscopePersistentLengthControl","Format":FORMAT}}
        else:expected={"20":{"class":"saml:PersistentNameID","identifyingAttribute":"uid"}}
        require(native["authproc"]==expected and all(row["status"]=="recorded" for row in load(campaign/"operations.json")),"native filter campaign incomplete")
        require(configured.startswith((campaign/"hosted-original.php").read_bytes()+b"\n")
            and ("saml:AttributeNameID" if is_mutant else "saml:PersistentNameID").encode() in configured,"native configured original absent")
        salt=load(campaign/"salt-native-readback.json")
        require(salt["secret_persisted"] is False and len(salt["salt_sha256"])==len(salt["configured_file_sha256"])==64,"native salt receipt differs")
        counts=load(campaign/"operation-counts.json")
        expected_counts=dict(product_configuration_write_attempts=5 if is_mutant else 7,
            configuration_apply_writes=3 if is_mutant else 4,restoration_writes=2 if is_mutant else 3,
            native_parser_invocations=1 if is_mutant else 2,normal_flows_attempted=2 if is_mutant else 4,
            ecp_probe_invocations=0 if is_mutant else 1,product_restarts=0,human_operations=0,restored=True)
        # All three files are changed/restored in either campaign.
        if is_mutant:expected_counts.update(product_configuration_write_attempts=6,restoration_writes=3)
        require(all(counts[name]==value for name,value in expected_counts.items()),"operation counts differ")
        for row in load(campaign/"operations.json"):
            member=campaign/row["profile"];created=load(member/"created.json")["run"];entity="http://localhost:18080/p/"+created["planId"]
            native=json.loads((member/"parser.stdout").read_bytes())
            require(native["entity_id"]==entity and native["validate_authnrequest"] is True
                and (member/"remote-configured.php").read_bytes()==(campaign/"remote-original.php").read_bytes()+b"\n"+native["php"].encode()+b"\n",
                "native parser configuration derivation differs")
            result=load(member/"result.json")
            require(result["run"]["id"]==created["id"] and result["target"]["metadata_digest"]=="sha256:"+sha((member/"target-metadata.xml").read_bytes()),"result Run/target differs")
    recorded=load(folder/"native-reader-replay.json")
    require(replay(folder,mutant)==recorded,"archived production replay differs")
    require(recorded["outcome"]=="SATISFIED" and recorded["nativeMutantOutcome"]=="VIOLATED"
        and len(recorded["checks"])==9 and all(value=="NOT_VERIFIED" for name,value in recorded["checks"].items() if not name.startswith("native-")),
        "native positive/mutant or archive mutation controls failed")
    row=case(load(folder/"browser_sso_idp/result.json"));negative=case(load(mutant/"browser_sso_idp/result.json"))
    require((row["outcome"],row["verdict"],row["reason_code"],row["attested"])==
        ("SATISFIED","PASS","browser.normal-flow.persistent-nameid-length",False),"formal positive differs")
    require((negative["outcome"],negative["verdict"],negative["reason_code"],negative["attested"])==
        ("VIOLATED","FAIL","browser.normal-flow.persistent-nameid-too-long",False),"formal diagnostic mutant differs")
    require({r["reference"] for r in row["evidence"]}=={r["reference"] for r in recorded["evidence"]},"formal evidence differs")
    if live:
        for name,label,prefix in [("saml20-idp-hosted.php","hosted","metadata"),("saml20-sp-remote.php","remote","metadata"),
                                  ("config-override.php","salt-override","config")]:
            require(subprocess.check_output(["docker","exec","samlscope-reference-ssp","cat","/var/simplesamlphp/"+prefix+"/"+name])
                ==(folder/(label+"-original.php")).read_bytes(),"live native restoration differs")
        for campaign in [folder,mutant]:
            member=campaign/"browser_sso_idp";run=load(member/"created.json")["run"]["id"]
            for suffix in ["transcript","result.json"]:
                with urllib.request.urlopen("http://localhost:18080/api/runs/"+run+"/"+suffix,timeout=40) as response:
                    current=json.load(response)
                saved=load(member/(suffix if "." in suffix else suffix+".json"))
                require(current==saved if suffix=="transcript" else case(current)==case(saved),"live formal original/conclusion changed")
    return folder/"browser_sso_idp/result.json",{CASE:row}

if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__);p.add_argument("root",type=Path)
    p.add_argument("--prepare-runtime",action="store_true");p.add_argument("--record-replay",action="store_true");p.add_argument("--live",action="store_true")
    args=p.parse_args();folder=args.root.resolve()
    if folder.name!=FOLDER:folder=folder/FOLDER
    if args.prepare_runtime:capture_runtime(folder)
    if args.record_replay:
        path=folder/"native-reader-replay.json";require(not path.exists(),"immutable replay exists")
        path.write_text(json.dumps(replay(folder,folder.parent/MUTANT),indent=2)+"\n")
    print("Verified SSP persistent length",verify(folder,args.live)[1][CASE]["verdict"])
