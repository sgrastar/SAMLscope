package com.samlscope.runner.cases;

import static org.junit.jupiter.api.Assertions.assertEquals;
import com.samlscope.core.evaluation.Outcome;
import org.junit.jupiter.api.Test;

class NativeMechanismStateComparisonTest {
    private Outcome compare(boolean requested,String actualRequest,Boolean indicator,String actualMechanism) {
        return NativeMechanismStateComparison.compare(new NativeMechanismStateComparison.Observation(
            "request",requested,actualRequest,indicator,"password",actualMechanism));
    }
    @Test void falseAndTrueAreBothAccessible(){assertEquals(Outcome.SATISFIED,compare(false,"request",false,"password"));
        assertEquals(Outcome.SATISFIED,compare(true,"request",true,"password"));}
    @Test void RemovingIndicatorDetectsApprovedUnreachableIndicatorMutant(){assertEquals(Outcome.VIOLATED,compare(true,"request",null,"password"));}
    @Test void LosingTrueIndicatorIsDetected(){assertEquals(Outcome.VIOLATED,compare(true,"request",false,"password"));}
    @Test void AlwaysTrueDoesNotPassBaseline(){assertEquals(Outcome.VIOLATED,compare(false,"request",true,"password"));}
    @Test void AnotherRequestIsUncertain(){assertEquals(Outcome.NOT_VERIFIED,compare(true,"unrelated",true,"password"));}
    @Test void AnotherMechanismIsUncertain(){assertEquals(Outcome.NOT_VERIFIED,compare(true,"request",true,"other"));}
}
