package com.samlscope.runner.cases;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.samlscope.store.JsonCodec;
import java.util.*;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class KeycloakPersistentIdentifierNormalizationTest {
    private static final String PEER="peer",KEY="saml.persistent.name.id.for.peer",VALUE="G-13abca15-8b2b-41ed-90ba-51a6f7a9b520";
    private ObjectNode report() {
        var json=new JsonCodec().mapper();var report=json.createObjectNode();
        report.put("schema","samlscope-keycloak-persistent-native-instrumentation-v1").put("scope","isolated-unchanged-native-persistent-construction-and-original-saved-state-reuse").put("helperSha256",KeycloakPersistentIdentifierEvidence.HELPER);
        for(String flag:List.of("nativeClassOverridden","randomnessSeededOrReplaced","signatureValidationPerformed","universalUserOpacityClaimed","verdictAdopted"))report.put(flag,false);
        for(String count:List.of("protocolSubmissions","credentialPosts","productSettingWrites","nativeStoreWrites"))report.put(count,0);
        var trace=json.createObjectNode().put("mode","empty-construction").put("nativeValue",VALUE).put("originalNameId","original-positive");trace.putObject("attributesBefore");
        trace.set("attributesAfter",json.valueToTree(Map.of(KEY,List.of(VALUE))));trace.set("setSingleAttributeEffects",json.valueToTree(List.of(Map.of("attribute",KEY,"value",VALUE))));
        trace.set("userMethodAccesses",json.valueToTree(List.of(Map.of("method","getFirstAttribute","arguments",List.of(KEY)),Map.of("method","getFirstAttribute","arguments",List.of("saml.persistent.name.id.for.*")),Map.of("method","setSingleAttribute","arguments",List.of(KEY,VALUE)))));
        report.putArray("traces").add(trace).add(json.createObjectNode().put("nativeValue",VALUE).put("mode","saved-original-reuse"));report.putArray("classes").add(json.createObjectNode().put("classSha256","original-class"));return report;
    }
    @Test void onlyFreshConstructionOccurrencesAreNormalized() {
        var original=report();var normalized=KeycloakPersistentIdentifierEvidence.normalize(original,PEER);
        assertEquals(VALUE,original.at("/traces/0/nativeValue").asText());assertEquals("<fresh-native-random-value>",normalized.at("/traces/0/nativeValue").asText());
        assertEquals(VALUE,normalized.at("/traces/1/nativeValue").asText());assertEquals("original-positive",normalized.at("/traces/0/originalNameId").asText());assertEquals(original.path("classes"),normalized.path("classes"));
    }
    @Test void principalReadCannotBeHiddenByRandomNormalization() {
        var report=report();((ObjectNode)report.at("/traces/0/userMethodAccesses/0")).put("method","getUsername");assertThrows(IllegalArgumentException.class,()->KeycloakPersistentIdentifierEvidence.normalize(report,PEER));
    }
    @Test void extraAttributeOrEffectCannotBeHidden() {
        var report=report();((ObjectNode)report.at("/traces/0/attributesAfter")).put("another","principal");assertThrows(IllegalArgumentException.class,()->KeycloakPersistentIdentifierEvidence.normalize(report,PEER));
    }
    @Test void seedClaimOrNonRandomVersionCannotBeNormalized() {
        var report=report();report.put("randomnessSeededOrReplaced",true);assertThrows(IllegalArgumentException.class,()->KeycloakPersistentIdentifierEvidence.normalize(report,PEER));
        var invalid=report();((ObjectNode)invalid.at("/traces/0")).put("nativeValue","G-13abca15-8b2b-11ed-90ba-51a6f7a9b520");assertThrows(IllegalArgumentException.class,()->KeycloakPersistentIdentifierEvidence.normalize(invalid,PEER));
    }
}
