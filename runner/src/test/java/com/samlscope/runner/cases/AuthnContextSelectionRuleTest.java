package com.samlscope.runner.cases;

import static org.junit.jupiter.api.Assertions.*;
import java.util.*;
import org.junit.jupiter.api.Test;
import com.samlscope.saml.normal.SamlRequestedAuthnContextRequestFactory.Comparison;
import static com.samlscope.runner.cases.AuthnContextSelectionRule.Status.*;

class AuthnContextSelectionRuleTest {
    private final AuthnContextSelectionRule.PreparedOrdering prepared=new AuthnContextSelectionRule.PreparedOrdering(
        Map.of("a",4,"b",7,"c",12),Set.of("a","b"),true);
    @Test void maximumRejectsWeakerChoiceEvenThoughItDoesNotExceedTheBound() {
        assertEquals(MATCH,AuthnContextSelectionRule.strength(Comparison.MAXIMUM,List.of("c"),"b",prepared).status());
        assertEquals(MISMATCH,AuthnContextSelectionRule.strength(Comparison.MAXIMUM,List.of("c"),"a",prepared).status());
        assertEquals(UNPROVEN,AuthnContextSelectionRule.strength(Comparison.MAXIMUM,List.of("c"),"b",
            new AuthnContextSelectionRule.PreparedOrdering(prepared.ranks(),prepared.available(),false)).status());
    }
    @Test void minimumAndBetterUseDeclaredStrengthNotLexicalOrder() {
        assertEquals(MATCH,AuthnContextSelectionRule.strength(Comparison.MINIMUM,List.of("a"),"a",prepared).status());
        assertEquals(MISMATCH,AuthnContextSelectionRule.strength(Comparison.BETTER,List.of("a"),"a",prepared).status());
        assertEquals(MATCH,AuthnContextSelectionRule.strength(Comparison.BETTER,List.of("a"),"b",prepared).status());
        var reverse=new AuthnContextSelectionRule.PreparedOrdering(Map.of("a",20,"b",10),Set.of("a","b"),true);
        assertEquals(MISMATCH,AuthnContextSelectionRule.strength(Comparison.BETTER,List.of("a"),"b",reverse).status());
        assertEquals(UNPROVEN,AuthnContextSelectionRule.strength(Comparison.MINIMUM,List.of("unknown"),"a",prepared).status());
    }
    @Test void preferenceRequiresReversalAndKnownSatisfiabilityWithoutUsingStrength() {
        assertEquals(MATCH,AuthnContextSelectionRule.preference(List.of("a","b"),"a",Set.of("a","b")).status());
        assertEquals(MATCH,AuthnContextSelectionRule.preference(List.of("b","a"),"b",Set.of("a","b")).status());
        assertEquals(MISMATCH,AuthnContextSelectionRule.preference(List.of("b","a"),"a",Set.of("a","b")).status());
        assertEquals(UNPROVEN,AuthnContextSelectionRule.preference(List.of("a","b"),"a",Set.of("a")).status());
    }
}
