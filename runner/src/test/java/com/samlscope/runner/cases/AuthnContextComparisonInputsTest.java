package com.samlscope.runner.cases;

import static org.junit.jupiter.api.Assertions.*;
import java.util.*;
import org.junit.jupiter.api.Test;
import com.samlscope.saml.normal.SamlRequestedAuthnContextRequestFactory.*;

class AuthnContextComparisonInputsTest {
    @Test void includesBothReferenceKindsAndReversedPreferenceWithoutInventingRank() {
        var references=new AuthnContextComparisonInputs.References("urn:a","urn:b","urn:c","urn:d");
        for(var kind:ReferenceKind.values()) {
            for(var entry:Map.of("ga",Comparison.MINIMUM,"gb",Comparison.BETTER,"gc",Comparison.MAXIMUM).entrySet()) {
                var inputs=AuthnContextComparisonInputs.forCase("IIP-SSO01-"+entry.getKey()+"-idp-01",kind,references);
                assertEquals(2,inputs.size());assertEquals(entry.getValue(),inputs.getFirst().request().comparison());
                assertEquals(kind,inputs.getFirst().request().kind());
                assertEquals(List.of(entry.getValue()==Comparison.MAXIMUM?"urn:c":"urn:a"),inputs.getFirst().request().references());
                assertEquals(List.of("urn:d"),inputs.getLast().request().references());
            }
            var preference=AuthnContextComparisonInputs.forCase("IIP-SSO01-gj-idp-01",kind,references);
            assertEquals(List.of("urn:a","urn:c"),preference.getFirst().request().references());
            assertEquals(List.of("urn:c","urn:a"),preference.getLast().request().references());
        }
    }
}
