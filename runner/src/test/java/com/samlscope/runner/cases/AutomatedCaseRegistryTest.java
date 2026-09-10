package com.samlscope.runner.cases;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import javax.xml.namespace.QName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import com.samlscope.core.caseexec.CaseExecution;
import com.samlscope.core.caseexec.CaseExecutionRepository;
import com.samlscope.core.caseexec.CaseIds;
import com.samlscope.core.caseexec.OutboundAction;
import com.samlscope.core.caseexec.OutboxEntry;
import com.samlscope.core.caseexec.OutboxStatus;
import com.samlscope.core.plan.TargetRole;
import com.samlscope.saml.crypto.FilePlanKeyStore;

class AutomatedCaseRegistryTest {
    @TempDir Path directory;

    @Test
    void registryExactlyMatchesEveryApprovedM1AutomatedCase() throws Exception {
        var registry = AutomatedCaseRegistry.create(dependencies());
        var approved = approvedAutomatedCases();

        assertEquals(67, approved.size());
        assertEquals(approved.keySet(), registry.ids());
        approved.forEach((caseId, obligation) -> assertEquals(obligation, CaseIds.obligationKey(caseId), caseId));
        assertTrue(registry.forRole(TargetRole.IDP).stream().allMatch(testCase -> testCase.role() == TargetRole.IDP));
        assertTrue(registry.forRole(TargetRole.SP).stream().allMatch(testCase -> testCase.role() == TargetRole.SP));
    }

    @Test
    void missingPerCaseFixtureFailsClosedAtCompositionTime() {
        var dependencies = dependencies();
        var missing = new AutomatedCaseDependencies(
                dependencies.transcriptContent(), Map.of(), dependencies.optionalFieldSelectors(),
                dependencies.targetSigningCertificates(), dependencies.peerEntityId(), dependencies.decryptionKeys(),
                dependencies.principalIdentities(), dependencies.caseExecutions(), dependencies.idpErrorProbe());

        org.junit.jupiter.api.Assertions.assertThrows(
                IllegalArgumentException.class, () -> AutomatedCaseRegistry.create(missing));
    }

    private AutomatedCaseDependencies dependencies() {
        var now = Instant.parse("2026-08-29T00:00:00Z");
        var certificate = new FilePlanKeyStore(directory, Clock.fixed(now, ZoneOffset.UTC))
                .getOrCreate("plan_0123456789ABCDEFGHJKMNPQRS").certificate();
        var fixtures = Map.of(
                "IIP-SSO01-dj-idp-01", new SamlAttributeReleaseFixture("no-values", null, List.of()),
                "IIP-SSO01-dk-idp-01", new SamlAttributeReleaseFixture(
                        "empty", null, List.of(SamlAttributeReleaseFixture.EmptyValue.INSTANCE)),
                "IIP-SSO01-dl-idp-01", new SamlAttributeReleaseFixture(
                        "null", null, List.of(SamlAttributeReleaseFixture.NullValue.INSTANCE)),
                "IIP-SSO01-du-idp-01", new SamlAttributeReleaseFixture(
                        "discrete", null, List.of(
                                new SamlAttributeReleaseFixture.TextValue("one"),
                                new SamlAttributeReleaseFixture.TextValue("two"))));
        var selector = SamlOptionalFieldObservationCase.Selector.element(new QName(
                "urn:oasis:names:tc:SAML:2.0:protocol", "Extensions"));
        return new AutomatedCaseDependencies(
                entry -> new byte[] {1},
                fixtures,
                Map.of("IIP-SSO07-a-idp-01", selector, "IIP-SSO07-a-sp-01", selector),
                List.of(certificate),
                "https://suite.example/peer",
                runId -> Optional.empty(),
                (runId, identifier) -> PrincipalIdentityResolver.Resolution.unknown(),
                emptyRepository(),
                new IdpErrorProbeConfiguration(
                        URI.create("https://idp.example/sso"), "https://suite.example/sp",
                        URI.create("https://suite.example/acs"), Duration.ofMinutes(2), true, true, true));
    }

    private Map<String, String> approvedAutomatedCases() throws Exception {
        var catalog = locateCasesYaml();
        var selected = new LinkedHashMap<String, String>();
        String id = null;
        String obligation = null;
        String mode = null;
        String milestone = null;
        for (var line : Files.readAllLines(catalog)) {
            if (line.startsWith("- id: ")) {
                addIfAutomated(selected, id, obligation, mode, milestone);
                id = line.substring("- id: ".length()).trim();
                obligation = null;
                mode = null;
                milestone = null;
            } else if (id != null && line.startsWith("  obligation: ")) {
                obligation = line.substring("  obligation: ".length()).trim();
            } else if (id != null && line.startsWith("  mode: ")) {
                mode = line.substring("  mode: ".length()).trim();
            } else if (id != null && line.startsWith("  milestone: ")) {
                milestone = line.substring("  milestone: ".length()).trim();
            }
        }
        addIfAutomated(selected, id, obligation, mode, milestone);
        return Map.copyOf(selected);
    }

    private void addIfAutomated(
            Map<String, String> selected, String id, String obligation, String mode, String milestone) {
        if (id != null && "AUTOMATED".equals(mode) && "M1".equals(milestone)) {
            if (obligation == null || selected.putIfAbsent(id, obligation) != null) {
                throw new IllegalStateException("Invalid approved case catalog entry: " + id);
            }
        }
    }

    private Path locateCasesYaml() {
        for (var candidate : List.of(Path.of("tests/cases.yaml"), Path.of("../tests/cases.yaml"))) {
            if (Files.isRegularFile(candidate)) return candidate;
        }
        throw new IllegalStateException("Cannot locate tests/cases.yaml from " + Path.of("").toAbsolutePath());
    }

    private CaseExecutionRepository emptyRepository() {
        return new CaseExecutionRepository() {
            @Override public Optional<CaseExecution> find(String runId, String caseId) { return Optional.empty(); }
            @Override public List<CaseExecution> list(String runId) { return List.of(); }
            @Override public boolean apply(long expectedRevision, CaseExecution execution, List<OutboundAction> actions) {
                throw new UnsupportedOperationException();
            }
            @Override public List<OutboxEntry> listOutbox(String runId) { return List.of(); }
            @Override public Optional<OutboxEntry> findOutbox(String actionId) { return Optional.empty(); }
            @Override public boolean transitionOutbox(String actionId, OutboxStatus expected, OutboxStatus next,
                    Map<String, Object> sendResult, String transcriptEntryId, Instant updatedAt) {
                throw new UnsupportedOperationException();
            }
            @Override public int recoverSendingAsUnknownDelivery(Instant updatedAt) { return 0; }
        };
    }
}
