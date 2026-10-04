package com.samlscope.runner.cases;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.*;
import java.time.Instant;
import java.util.*;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/** Process-origin controls are independent of the unfinished normative capability mutant. */
class KeycloakCaseCollisionCapabilityProcessTest {
    private static final Instant BEFORE=Instant.parse("2026-10-04T10:00:00Z"),AFTER=Instant.parse("2026-10-04T11:00:00Z");
    private ObjectNode supported(){
        String c="samlscope-reference-keycloak",h="/tmp/samlscope-idp21-canonical-20261004.java";
        var inspect=List.of("docker","inspect","--format","{{json .Id}} {{json .Image}} {{json .State.StartedAt}}",c);
        var absent=List.of("docker","exec",c,"test","!","-e",h);
        var commands=List.of(inspect,absent,List.of("docker","cp","dev/reference-acceptance/ProbeKeycloakCanonicalUuidFormatter.java",c+":"+h),List.of("docker","exec",c,"java","-XX:-UsePerfData","--add-opens","java.base/java.lang=ALL-UNNAMED","--add-opens","java.base/java.util=ALL-UNNAMED",h),List.of("docker","exec",c,"java","-XX:-UsePerfData","-XX:-CompactStrings","--add-opens","java.base/java.lang=ALL-UNNAMED","--add-opens","java.base/java.util=ALL-UNNAMED",h),List.of("docker","exec","--user","0",c,"rm","--",h),absent,inspect);
        var names=List.of("runtime-before","helper-absence-before","helper-copy","compact","utf16","helper-remove","helper-absence-after","runtime-after");
        var p=JsonNodeFactory.instance.objectNode();var rows=p.putArray("operations");for(int i=0;i<8;i++){var row=rows.addObject();var command=row.putArray("command");commands.get(i).forEach(command::add);row.put("startedAt",BEFORE.plusSeconds(i*2).toString());row.put("finishedAt",BEFORE.plusSeconds(i*2+1).toString());row.put("exitCode",0);row.put("stdoutFile",names.get(i)+".stdout.txt");row.put("stderrFile",names.get(i)+".stderr.txt");}return p;
    }
    private ObjectNode row(ObjectNode p,int index){return (ObjectNode)p.path("operations").get(index);}
    private void rejected(JsonNode p){assertThrows(IllegalArgumentException.class,()->KeycloakCaseCollisionCapabilityEvidence.verifyProcess(p,BEFORE,AFTER));}
    @Test void closedNativeInvocationsAreAccepted(){assertDoesNotThrow(()->KeycloakCaseCollisionCapabilityEvidence.verifyProcess(supported(),BEFORE,AFTER));}
    @Test void differentContainerCannotReuseProcessOutput(){var p=supported();((ArrayNode)row(p,3).path("command")).set(2,new TextNode("another-product"));rejected(p);}
    @Test void agentAndPatchModuleCannotBeHiddenBehindMatchingOutput(){for(String flag:List.of("-javaagent:/tmp/agent.jar","--patch-module=java.base=/tmp/replacement")){var p=supported();((ArrayNode)row(p,3).path("command")).insert(4,flag);rejected(p);}}
    @Test void stepsAndStdoutLabelsCannotBeReordered(){var p=supported();var rows=(ArrayNode)p.path("operations");var a=rows.get(3).deepCopy();rows.set(3,rows.get(4));rows.set(4,a);rejected(p);p=supported();row(p,3).put("stdoutFile","utf16.stdout.txt");rejected(p);}
    @Test void overlappingOrReversedInvocationTimesAreRejected(){var p=supported();row(p,4).put("startedAt",BEFORE.plusSeconds(6).toString());rejected(p);p=supported();row(p,3).put("finishedAt",BEFORE.plusSeconds(5).toString());rejected(p);}
    @Test void captureMustFollowSourceRestorationAndPrecedeEvaluation(){var p=supported();assertThrows(IllegalArgumentException.class,()->KeycloakCaseCollisionCapabilityEvidence.verifyProcess(p,BEFORE.plusSeconds(1),AFTER));assertThrows(IllegalArgumentException.class,()->KeycloakCaseCollisionCapabilityEvidence.verifyProcess(p,BEFORE,BEFORE.plusSeconds(14)));}
    @Test void helperAndCleanupRemainWithinTheCapturedExactBoundary(){var p=supported();((ArrayNode)row(p,1).path("command")).set(6,new TextNode("/tmp/other.java"));rejected(p);p=supported();((ArrayNode)row(p,5).path("command")).set(7,new TextNode("/tmp/another.java"));rejected(p);}
}
