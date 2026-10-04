package com.samlscope.runner.cases;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.*;
import com.samlscope.core.evaluation.Outcome;
import com.samlscope.store.JsonCodec;
import java.security.*;
import java.util.*;
import org.junit.jupiter.api.*;
import static org.junit.jupiter.api.Assertions.*;

class SimpleSamlPhpMultipleDecryptionKeysEvidenceTest {
    private static final com.fasterxml.jackson.databind.ObjectMapper JSON=new JsonCodec().mapper();
    private static List<KeyPair> keys;
    @BeforeAll static void keys()throws Exception {
        var generator=KeyPairGenerator.getInstance("RSA");generator.initialize(2048);
        keys=List.of(generator.generateKeyPair(),generator.generateKeyPair());
    }
    private static String hash(byte[] bytes)throws Exception{return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));}
    private static ObjectNode report()throws Exception {
        var report=JSON.createObjectNode();var rows=report.putArray("baselineKeys");
        for(var key:keys)rows.addObject().put("spkiSha256",hash(key.getPublic().getEncoded()));
        report.putObject("control").put("usableKeys",1);report.putObject("settings").put("source","native");
        report.putArray("decrypt").add(true);report.putArray("classes").add("native.Message");return report;
    }
    private static ArrayNode sign(byte[] raw)throws Exception {
        var rows=JSON.createArrayNode();for(int i=0;i<keys.size();i++){
            var signature=Signature.getInstance("SHA256withRSA");signature.initSign(keys.get(i).getPrivate());signature.update(raw);
            rows.addObject().put("keyIndex",i).put("spkiSha256",hash(keys.get(i).getPublic().getEncoded()))
                .put("signatureBase64",Base64.getEncoder().encodeToString(signature.sign()));
        }return rows;
    }
    private static void verify(byte[] raw,JsonNode report,JsonNode signatures)throws Exception {
        SimpleSamlPhpMultipleDecryptionKeysEvidence.verifyPayloadSignatures(raw,report,signatures,keys.stream().map(KeyPair::getPublic).toList());
    }
    @Test void twoDistinctUsableNativeKeysProveCapability(){assertEquals(Outcome.SATISFIED,SimpleSamlPhpMultipleDecryptionKeysEvidence.compareKeyCapability(2,false));}
    @Test void selectedSingleKeyDoesNotProveCapabilityAbsence(){assertEquals(Outcome.NOT_VERIFIED,SimpleSamlPhpMultipleDecryptionKeysEvidence.compareKeyCapability(1,false));}
    @Test void sourceClosedOneKeyEngineDetectsCapabilityRemoval(){assertEquals(Outcome.VIOLATED,SimpleSamlPhpMultipleDecryptionKeysEvidence.compareKeyCapability(1,true));}
    @Test void inconsistentDiagnosticEngineCannotBecomeProductPass(){assertEquals(Outcome.NOT_VERIFIED,SimpleSamlPhpMultipleDecryptionKeysEvidence.compareKeyCapability(2,true));}
    @Test void exactFullPayloadIsVerifiedByBothNativeKeys()throws Exception {var r=report();byte[] raw=JSON.writeValueAsBytes(r);verify(raw,r,sign(raw));}
    @Test void coherentAlteredObservationCannotReuseSignatures()throws Exception {
        for(String field:List.of("control","settings","decrypt","classes")){
            var r=report();byte[] raw=JSON.writeValueAsBytes(r);var signatures=sign(raw);r.put(field,"forged");byte[] changed=JSON.writeValueAsBytes(r);
            assertThrows(Exception.class,()->verify(changed,r,signatures),field);
        }
    }
    @Test void duplicateNativeSignerIsRejectedEvenIfBothSignaturesValid()throws Exception {
        var r=report();byte[] raw=JSON.writeValueAsBytes(r);var signatures=sign(raw);
        var second=signatures.get(0).deepCopy();((ObjectNode)second).put("keyIndex",1);signatures.set(1,second);
        assertThrows(Exception.class,()->verify(raw,r,signatures));
    }
    @Test void substitutedSecondSignerCannotReuseOriginalKeyProof()throws Exception {
        var r=report();byte[] raw=JSON.writeValueAsBytes(r);var signatures=sign(raw);
        var signature=Signature.getInstance("SHA256withRSA");signature.initSign(keys.get(0).getPrivate());signature.update(raw);
        ((ObjectNode)signatures.get(1)).put("signatureBase64",Base64.getEncoder().encodeToString(signature.sign()));
        assertThrows(Exception.class,()->verify(raw,r,signatures));
    }
    @Test void sourcePatchRequiresExactOriginalBytes(){assertThrows(Exception.class,()->SimpleSamlPhpMultipleDecryptionKeysEvidence.capabilityRemovedSource("<?php fake".getBytes(java.nio.charset.StandardCharsets.UTF_8)));}
}
