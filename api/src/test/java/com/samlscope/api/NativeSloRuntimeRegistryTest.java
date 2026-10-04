package com.samlscope.api;

import static org.junit.jupiter.api.Assertions.*;

import com.samlscope.core.casedef.CaseDefinitionCatalog.Milestone;
import com.samlscope.core.casedef.CaseDefinitionCatalogMapper;
import com.samlscope.core.caseexec.*;
import com.samlscope.core.evaluation.Outcome;
import com.samlscope.core.plan.*;
import com.samlscope.core.run.Reachability;
import com.samlscope.core.transcript.*;
import com.samlscope.runner.*;
import com.samlscope.runner.cases.*;
import java.net.URI;
import java.nio.file.*;
import java.time.Clock;
import java.util.*;
import java.util.function.BiFunction;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** The signed catalog must reach the M3 runtime seam, rather than an unrelated M1 seam. */
class NativeSloRuntimeRegistryTest {
    private static final String RUN = "run_00000000000000000000000000";
    private static final String CASE = "IIP-IDP17-s-idp-01";
    @TempDir Path directory;

    @Test void approvedM3CaseUsesNativeEvidenceThroughTheRuntimeLogoutSeam() throws Exception {
        var catalog = CaseDefinitionCatalogMapper.fromDocument(
                CatalogDocuments.load().parsed("tests/cases.yaml"));
        assertEquals(Milestone.M3, catalog.require(CASE).milestone());
        TranscriptContentReader content = entry -> { throw new AssertionError("No original available"); };
        var m1 = ApprovedBrowserCaseRegistry.create(catalog, URI.create("https://suite.example"), Milestone.M1, content);
        assertFalse(m1.ids().contains(CASE));
        var m3 = ApprovedBrowserCaseRegistry.create(catalog, URI.create("https://suite.example"), Milestone.M3, content);
        assertInstanceOf(LogoutBrowserEvidenceTestCase.class, m3.require(CASE));

        // Supply an isolated data root to the same overload used by the public runtime seam.
        var seam = ApprovedBrowserCaseRegistry.class.getDeclaredMethod("withLogoutScenarios",
                TestCaseRegistry.class, BiFunction.class, TranscriptContentReader.class, Path.class);
        seam.setAccessible(true);
        BiFunction<String, String, IdpBasicLogoutScenarioTestCase.Configuration> configuration =
                (id, run) -> { throw new AssertionError("Passive proof must not send a fixture"); };
        var registry = (TestCaseRegistry)seam.invoke(null, m3, configuration, content, directory);
        assertEquals(m3.ids(), registry.ids());
        var test = registry.require(CASE);
        var context = context();
        assertInstanceOf(CaseStep.AwaitBrowser.class, test.start(context));

        var proof = directory.resolve("slo-propagation-evidence").resolve(RUN);
        Files.createDirectories(proof);
        Files.writeString(proof.resolve("manifest.json"), "{}");
        var finished = assertInstanceOf(CaseStep.Finish.class, test.start(context));
        assertEquals(Outcome.NOT_VERIFIED, finished.outcome().outcome());
        assertEquals("slo.native-propagation.evidence-incomplete", finished.outcome().reasonCode());
        assertFalse(((ProtocolEvidenceCase)test).evidenceStatus(context).ready());
    }

    @Test void multiKeyNativeEvidenceUsesTheRealM3SeamAndDoesNotPromoteOtherKeyCases()throws Exception{
        var catalog=CaseDefinitionCatalogMapper.fromDocument(CatalogDocuments.load().parsed("tests/cases.yaml"));
        assertEquals(Milestone.M3,catalog.require(IdpBasicLogoutScenarioTestCase.MULTI_KEY_ID).milestone());
        TranscriptContentReader content=entry->{throw new AssertionError("No original available");};
        var original=ApprovedBrowserCaseRegistry.create(catalog,URI.create("https://suite.example"),Milestone.M3,content);
        var seam=ApprovedBrowserCaseRegistry.class.getDeclaredMethod("withLogoutScenarios",
                TestCaseRegistry.class,BiFunction.class,TranscriptContentReader.class,Path.class);seam.setAccessible(true);
        BiFunction<String,String,IdpBasicLogoutScenarioTestCase.Configuration> configuration=
                (id,run)->{throw new AssertionError("Native proof must not send another fixture");};
        var registry=(TestCaseRegistry)seam.invoke(null,original,configuration,content,directory);
        assertEquals(original.ids(),registry.ids());
        assertInstanceOf(IdpBasicLogoutScenarioTestCase.class,registry.require(IdpBasicLogoutScenarioTestCase.ENCRYPTED_ID));
        var nativeCase=assertInstanceOf(EncryptedLogoutNativeTestCase.class,registry.require(IdpBasicLogoutScenarioTestCase.MULTI_KEY_ID));
        assertEquals(Outcome.NOT_VERIFIED,nativeCase.queuedEvidenceOutcome(context()).outcome());
        var owned=directory.resolve("encrypted-logout-evidence").resolve(RUN);Files.createDirectories(owned);Files.writeString(owned.resolve("manifest.json"),"{}");
        assertEquals(Outcome.NOT_VERIFIED,assertInstanceOf(CaseStep.Finish.class,nativeCase.start(context())).outcome().outcome());
        assertEquals(Outcome.NOT_VERIFIED,assertInstanceOf(CaseStep.Finish.class,
                nativeCase.resume(context(),null,new CaseEvent.TranscriptReady())).outcome().outcome());
        assertFalse(nativeCase.evidenceStatus(context()).ready());
    }

    private DefaultCaseContext context() {
        return new DefaultCaseContext(RUN, TargetRole.IDP, Clock.systemUTC(),
                TestPlan.Parameters.defaults(), TestPlan.Interaction.defaults(), Reachability.CONFIRMED,
                new TranscriptRecorder() {
                    public List<TranscriptEntry> list(String run) { return List.of(); }
                    public TranscriptEntry record(TranscriptInput input) { throw new AssertionError("Read only"); }
                    public TranscriptEntry updateSamlAnalysis(String id, String correlation, Map<String,Object> summary) {
                        throw new AssertionError("Read only");
                    }
                }, true);
    }
}
