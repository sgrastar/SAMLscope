package com.samlscope.runner.cases;

import java.util.*;
import com.samlscope.saml.normal.SamlRequestedAuthnContextRequestFactory.*;

/** Native adapter supplies actual references; no authentication mechanism has an implicit rank. */
final class AuthnContextComparisonInputs {
    record References(String low,String medium,String high,String unavailable) {
        References {
            var values=List.of(low,medium,high,unavailable);
            if(values.stream().anyMatch(String::isBlank) || new HashSet<>(values).size()!=values.size()) {
                throw new IllegalArgumentException("Distinct native comparison references required");
            }
        }
    }
    record Input(String condition,ContextRequest request) {}

    static List<Input> forCase(String caseId,ReferenceKind kind,References references) {
        Objects.requireNonNull(kind);Objects.requireNonNull(references);
        String prefix=kind==ReferenceKind.CLASS?"class-":"declaration-";
        if("IIP-SSO01-gj-idp-01".equals(caseId)) {
            return List.of(new Input(prefix+"forward",new ContextRequest(Comparison.EXACT,kind,List.of(references.low(),references.high()))),
                new Input(prefix+"reverse",new ContextRequest(Comparison.EXACT,kind,List.of(references.high(),references.low()))));
        }
        Comparison comparison=switch(caseId) {
            case "IIP-SSO01-ga-idp-01" -> Comparison.MINIMUM;
            case "IIP-SSO01-gb-idp-01" -> Comparison.BETTER;
            case "IIP-SSO01-gc-idp-01" -> Comparison.MAXIMUM;
            default -> throw new IllegalArgumentException("Unsupported authentication comparison case");
        };
        // Native preparation for maximum makes low/medium available and high unavailable.
        String threshold=comparison==Comparison.MAXIMUM?references.high():references.low();
        return List.of(new Input(prefix+"selection",new ContextRequest(comparison,kind,List.of(threshold))),
            new Input(prefix+"unachievable",new ContextRequest(comparison,kind,List.of(references.unavailable()))));
    }
}
