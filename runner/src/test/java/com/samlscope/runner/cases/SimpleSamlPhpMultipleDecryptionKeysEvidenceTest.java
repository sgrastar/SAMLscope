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
    @Test void explicitCurrentOneKeyRowsVerifyWithoutPretendingToBeLegacyRestoration()throws Exception {
        var r=JSON.createObjectNode();r.put("schema","samlscope-native-configuration-source-current-v1");
        var rows=r.putArray("baselineKeys");rows.addObject().put("index",0).put("spkiSha256",hash(keys.get(0).getPublic().getEncoded()));
        r.putObject("input").put("sourceRunId","run_11111111111111111111111111").put("recipientRunId","run_00000000000000000000000000");
        byte[] raw=JSON.writeValueAsBytes(r);var signatures=sign(raw);signatures.remove(1);
        assertDoesNotThrow(()->SimpleSamlPhpMultipleDecryptionKeysEvidence.verifyPayloadSignaturesWithRows(raw,rows,signatures,List.of(keys.get(0).getPublic())));
        assertThrows(Exception.class,()->SimpleSamlPhpMultipleDecryptionKeysEvidence.verifyPayloadSignatures(raw,r,signatures,List.of(keys.get(0).getPublic())));
        var altered=r.deepCopy();((ObjectNode)altered.path("input")).put("recipientRunId","run_22222222222222222222222222");
        assertThrows(Exception.class,()->SimpleSamlPhpMultipleDecryptionKeysEvidence.verifyPayloadSignaturesWithRows(JSON.writeValueAsBytes(altered),rows,signatures,List.of(keys.get(0).getPublic())));
        assertThrows(Exception.class,()->SimpleSamlPhpMultipleDecryptionKeysEvidence.verifyPayloadSignaturesWithRows(raw,rows,signatures,List.of(keys.get(1).getPublic())));
    }
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
    private static ObjectNode diagnosticMatrix() {
        var report=JSON.createObjectNode();var controls=report.putArray("decryptionControls");
        for(boolean[] values:new boolean[][]{{true,false,false},{false,true,true}}) {
            var attempts=controls.addObject().putArray("attempts");for(boolean value:values)attempts.addObject().put("decrypted",value);
        }
        return report;
    }
    private static byte[] expectedDiagnostics() {
        String prefix="%date{M j H:i:s} simplesamlphp ERR [CL012345ab] ";
        String block=prefix+"Failed to decrypt symmetric key: Failure decrypting Data (openssl private) - error:02000079:rsa routines::oaep decoding error\n"
                +prefix+"Decryption failed: Unable to parse XML - \"FATAL[77]\": \"Premature end of data in tag root line 1\n"
                +"\" in \"(string)\" at line 1 on column 151\"\n";
        return block.repeat(3).getBytes(java.nio.charset.StandardCharsets.UTF_8);
    }
    @Test void expectedNegativeDiagnosticsAreCountedAfterTheMatrixIsValidated() {
        assertDoesNotThrow(()->SimpleSamlPhpMultipleDecryptionKeysEvidence.verifyDecryptionDiagnostics(expectedDiagnostics(),diagnosticMatrix()));
    }
    @Test void missingExtraForeignAndPositiveErrorDiagnosticsRemainUnproven() {
        String original=new String(expectedDiagnostics(),java.nio.charset.StandardCharsets.UTF_8);
        for(String altered:List.of("",original+"unexpected error\n",original.replace("FATAL[77]","FATAL[99]"),original.replace("CL012345ab","foreign"),original.substring(original.indexOf('\n')+1))) {
            assertThrows(IllegalArgumentException.class,()->SimpleSamlPhpMultipleDecryptionKeysEvidence.verifyDecryptionDiagnostics(altered.getBytes(),diagnosticMatrix()));
        }
        var positive=diagnosticMatrix();for(var row:positive.path("decryptionControls"))for(var attempt:row.path("attempts"))((ObjectNode)attempt).put("decrypted",true);
        assertThrows(IllegalArgumentException.class,()->SimpleSamlPhpMultipleDecryptionKeysEvidence.verifyDecryptionDiagnostics(expectedDiagnostics(),positive));
    }
    @Test void onlyActualExpiredSuitePeerWarningsFromRestoredMetadataAreRecognized() {
        String entity="http://localhost:18080/p/plan_00000000000000000000000000";
        String configuration="<?php\n$metadata=array (\n  '"+entity+"' => array (\n    'expire' => 1790578679,\n  ),\n);\n";
        String warning="%date{M j H:i:s} simplesamlphp WARNING [CL012345ab] Dropping metadata entity '"+entity+"', expired 2026-09-28T06:57:59Z.\n";
        var now=java.time.Instant.parse("2026-10-04T12:00:00Z");
        assertDoesNotThrow(()->SimpleSamlPhpMultipleDecryptionKeysEvidence.verifyExpiredMetadataWarnings(warning.getBytes(),configuration.getBytes(),now));
        for(String altered:List.of(warning.replace(entity,"https://external.example/sp"),warning.replace("06:57:59","06:57:58"),warning+warning,warning+"unknown native warning\n")) {
            assertThrows(IllegalArgumentException.class,()->SimpleSamlPhpMultipleDecryptionKeysEvidence.verifyExpiredMetadataWarnings(altered.getBytes(),configuration.getBytes(),now));
        }
        assertThrows(IllegalArgumentException.class,()->SimpleSamlPhpMultipleDecryptionKeysEvidence.verifyExpiredMetadataWarnings(warning.getBytes(),configuration.getBytes(),now.minusSeconds(86400*10)));
    }
}
