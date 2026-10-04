package com.samlscope.runner.cases;

import com.samlscope.core.caseexec.ActionIds;
import com.samlscope.saml.normal.SecureXml;
import com.samlscope.saml.crypto.XmlSignatureVerifier;
import com.samlscope.store.JsonCodec;
import java.net.URI;
import java.nio.file.*;
import java.time.*;
import java.util.*;

/** Generates public candidate bytes only, using an existing Run primary key in memory. */
public final class PreflightVersionMismatchFixtures {
    public static void main(String[] args)throws Exception{
        if(args.length!=3||!args[1].matches("run_[0-9A-HJKMNP-TV-Z]{26}"))throw new IllegalArgumentException("data, Run, public Suite metadata required");
        var bridge=new KeycloakNativeRunEvidenceBridge(Path.of(args[0]));var key=bridge.key(args[1],"primary").orElseThrow();
        var target=SecureXml.parse(bridge.targetMetadata(args[1])).getDocumentElement();
        var peer=SecureXml.parse(Files.readAllBytes(Path.of(args[2]))).getDocumentElement();
        var roles=MetadataAlgorithmEvidence.children(peer,IdpVersionMismatchScenarioTestCase.MD,"SPSSODescriptor");
        if(roles.size()!=1)throw new IllegalArgumentException("Suite SP role ambiguous");
        boolean advertised=false;
        for(var descriptor:MetadataAlgorithmEvidence.children(roles.getFirst(),IdpVersionMismatchScenarioTestCase.MD,"KeyDescriptor")){
            if(!descriptor.getAttribute("use").isBlank()&&!"signing".equals(descriptor.getAttribute("use")))continue;
            for(var info:MetadataAlgorithmEvidence.children(descriptor,"http://www.w3.org/2000/09/xmldsig#","KeyInfo"))
                for(var data:MetadataAlgorithmEvidence.children(info,"http://www.w3.org/2000/09/xmldsig#","X509Data"))
                    for(var node:MetadataAlgorithmEvidence.children(data,"http://www.w3.org/2000/09/xmldsig#","X509Certificate")){
                        var certificate=(java.security.cert.X509Certificate)java.security.cert.CertificateFactory.getInstance("X.509").generateCertificate(new java.io.ByteArrayInputStream(Base64.getMimeDecoder().decode(node.getTextContent())));
                        advertised|=Arrays.equals(certificate.getPublicKey().getEncoded(),key.certificate().getPublicKey().getEncoded());
                    }
        }
        if(!advertised)throw new IllegalArgumentException("Existing Run signing key is not advertised by the actual Suite SP metadata");
        var acss=MetadataAlgorithmEvidence.children(roles.getFirst(),IdpVersionMismatchScenarioTestCase.MD,"AssertionConsumerService").stream().filter(e->"0".equals(e.getAttribute("index"))).toList();
        if(acss.size()!=1)throw new IllegalArgumentException("Actual Suite ACS0 missing");
        var targetRoles=MetadataAlgorithmEvidence.children(target,IdpVersionMismatchScenarioTestCase.MD,"IDPSSODescriptor");
        var ssos=new ArrayList<org.w3c.dom.Element>();for(var role:targetRoles)for(var endpoint:MetadataAlgorithmEvidence.children(role,IdpVersionMismatchScenarioTestCase.MD,"SingleSignOnService"))
            if("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST".equals(endpoint.getAttribute("Binding")))ssos.add(endpoint);
        if(ssos.size()!=1)throw new IllegalArgumentException("Actual target POST SSO missing/ambiguous");
        var config=new IdpErrorProbeConfiguration(URI.create(ssos.getFirst().getAttribute("Location")),peer.getAttribute("entityID"),URI.create(acss.getFirst().getAttribute("Location")),Duration.ofHours(2),true,true,false);
        var records=new ArrayList<Map<String,Object>>();var at=Instant.parse("2026-10-03T00:00:00Z");
        for(String fixture:IdpVersionMismatchScenarioTestCase.REQUIRED){
            String action=ActionIds.derive(args[1],IdpVersionMismatchScenarioTestCase.CASE_ID,"await-fixture-"+fixture,0);
            byte[] raw=IdpVersionMismatchScenarioTestCase.fixture(fixture,"_"+action,config,at,key);
            if(!new XmlSignatureVerifier().hasValidEnvelopedSignature(SecureXml.parse(raw).getDocumentElement(),key.certificate()))throw new IllegalArgumentException("Fixture signature invalid");
            records.add(Map.of("fixtureId",fixture,"actionId",action,"requestId","_"+action,"sha256",VersionMismatchTerminalEvidence.hash(raw),"requestBase64",Base64.getEncoder().encodeToString(raw),"signatureValid",true));
        }
        System.out.println(new JsonCodec().write(Map.of("schema","samlscope-version-fixture-preflight-v1","runId",args[1],"caseId",IdpVersionMismatchScenarioTestCase.CASE_ID,"fixtures",records,"privateKeyExported",false,"protocolSubmissions",0)));
    }
}
