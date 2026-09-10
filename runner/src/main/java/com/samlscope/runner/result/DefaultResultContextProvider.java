package com.samlscope.runner.result;

import java.net.URI;
import java.time.LocalDate;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Objects;
import java.util.function.Function;
import com.samlscope.runner.RunCampaignQuery;
import com.samlscope.core.evaluation.CaseRun;
import com.samlscope.core.evaluation.RunResult;
import com.samlscope.core.plan.TestPlan;
import com.samlscope.core.run.TestRun;

/** Builds truthful publication metadata from fixed Suite inputs and the exact evaluated snapshot. */
public final class DefaultResultContextProvider implements ResultContextProvider {
    private final ResultDocumentContext.Suite suite;
    private final ResultDocumentContext.EvaluationComponents components;
    private final URI requirementCatalog;
    private final URI caseCatalog;
    private final Function<TestRun, byte[]> targetMetadata;
    private final Function<String, RunCampaignQuery.CampaignReport> campaigns;

    public DefaultResultContextProvider(
            ResultDocumentContext.Suite suite,
            ResultDocumentContext.EvaluationComponents components,
            URI requirementCatalog,
            URI caseCatalog,
            Function<TestRun, byte[]> targetMetadata) {
        this(suite, components, requirementCatalog, caseCatalog, targetMetadata, null);
    }

    public DefaultResultContextProvider(
            ResultDocumentContext.Suite suite,
            ResultDocumentContext.EvaluationComponents components,
            URI requirementCatalog,
            URI caseCatalog,
            Function<TestRun, byte[]> targetMetadata,
            Function<String, RunCampaignQuery.CampaignReport> campaigns) {
        this.suite = Objects.requireNonNull(suite, "suite");
        this.components = Objects.requireNonNull(components, "components");
        this.requirementCatalog = absolute(requirementCatalog, "requirementCatalog");
        this.caseCatalog = absolute(caseCatalog, "caseCatalog");
        this.targetMetadata = Objects.requireNonNull(targetMetadata, "targetMetadata");
        this.campaigns = campaigns;
    }

    @Override
    public ResultDocumentContext context(
            TestRun run, TestPlan plan, List<CaseRun> cases, RunResult evaluation) {
        Objects.requireNonNull(run, "run");
        Objects.requireNonNull(plan, "plan");
        cases = List.copyOf(cases);
        Objects.requireNonNull(evaluation, "evaluation");
        var requirementUrls = new LinkedHashMap<String, String>();
        evaluation.requirements().forEach(value ->
                requirementUrls.put(value.id(), fragment(requirementCatalog, value.id())));
        var caseUrls = new LinkedHashMap<String, String>();
        cases.forEach(value -> caseUrls.put(value.id(), fragment(caseCatalog, value.id())));
        var metadata = targetMetadata.apply(run);
        if (metadata == null || metadata.length == 0) {
            throw new IllegalStateException("Target metadata is unavailable for public result provenance");
        }
        var evidenceClasses = new LinkedHashMap<String, String>();
        if (campaigns != null) {
            campaigns.apply(run.id()).campaigns().forEach(campaign -> campaign.caseIds().forEach(caseId ->
                    evidenceClasses.put(caseId, campaign.evidenceClass().name())));
        }
        return new ResultDocumentContext(
                suite, components,
                new ResultDocumentContext.ProfileSpec(
                        "SAML V2.0 Implementation Profile for Federation Interoperability",
                        "1.1", LocalDate.parse("2019-12-18"),
                        "The functional profile selects approved cases; each obligation's RFC 2119 level remains authoritative."),
                new ResultDocumentContext.TargetDeclaration(
                        plan.name(), "Test Plan operator", EvaluationArtifactDigests.digestBytes(metadata)),
                requirementUrls, caseUrls, evidenceClasses, List.of());
    }

    private static URI absolute(URI value, String name) {
        if (value == null || !value.isAbsolute() || value.getHost() == null) {
            throw new IllegalArgumentException(name + " must be an absolute URL");
        }
        return value;
    }

    private static String fragment(URI base, String value) {
        return URI.create(base.toString().split("#", 2)[0] + "#" + value).toString();
    }
}
