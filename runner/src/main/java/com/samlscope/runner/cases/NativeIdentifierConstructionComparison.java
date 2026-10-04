package com.samlscope.runner.cases;

import com.samlscope.core.evaluation.Outcome;
import java.util.*;

/** An original-bound construction proof is required; identifier appearance is never that proof. */
final class NativeIdentifierConstructionComparison {
    static Outcome compare(boolean nativeConstructionBound,String value,Set<String> principalIdentifiers) {
        if(!nativeConstructionBound||value==null||value.isBlank()||principalIdentifiers==null||principalIdentifiers.isEmpty())return Outcome.NOT_VERIFIED;
        if(principalIdentifiers.contains(value)||value.matches("[^\\s@]+@[^\\s@]+")
            ||value.matches("(?i)(?:[a-z][a-z0-9-]*|[0-9]+(?:\\.[0-9]+)+)=.+"))return Outcome.VIOLATED;
        return Outcome.SATISFIED;
    }
}
