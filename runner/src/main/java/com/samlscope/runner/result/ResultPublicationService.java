package com.samlscope.runner.result;

import java.nio.charset.StandardCharsets;
import java.util.Objects;
import com.samlscope.core.evaluation.CoverageCatalog;
import com.samlscope.core.result.RunArtifactRepository;
import com.samlscope.runner.RunEvaluationService;

/** Generates and atomically persists the single authoritative public result for a Run. */
public final class ResultPublicationService implements ResultArtifactQuery, ReportArtifactQuery {
    private final CoverageCatalog catalog;
    private final RunEvaluationService evaluation;
    private final ResultContextProvider contexts;
    private final ResultJsonWriter json;
    private final RunArtifactRepository artifacts;
    private final ReportHtmlWriter reportHtml;

    public ResultPublicationService(
            CoverageCatalog catalog,
            RunEvaluationService evaluation,
            ResultContextProvider contexts,
            ResultJsonWriter json,
            RunArtifactRepository artifacts) {
        this.catalog = Objects.requireNonNull(catalog, "catalog");
        this.evaluation = Objects.requireNonNull(evaluation, "evaluation");
        this.contexts = Objects.requireNonNull(contexts, "contexts");
        this.json = Objects.requireNonNull(json, "json");
        this.artifacts = Objects.requireNonNull(artifacts, "artifacts");
        this.reportHtml = new ReportHtmlWriter();
    }

    public byte[] generate(String runId) {
        var snapshot = evaluation.snapshot(runId);
        var context = contexts.context(
                snapshot.run(), snapshot.plan(), snapshot.cases(), snapshot.result());
        var document = ResultDocumentAssembler.assemble(
                snapshot.definition().selectedCoverage(catalog), snapshot.plan(), snapshot.run(),
                snapshot.result(), snapshot.cases(), context);
        var bytes = json.write(document).getBytes(StandardCharsets.UTF_8);
        var report = reportHtml.write(bytes);
        artifacts.saveResult(runId, bytes);
        artifacts.saveReport(runId, report);
        return bytes.clone();
    }

    @Override
    public byte[] require(String runId) {
        return artifacts.findResult(runId)
                .orElseThrow(() -> new IllegalArgumentException("Result artifact has not been generated"));
    }

    @Override
    public byte[] requireReport(String runId) {
        return artifacts.findReport(runId)
                .orElseThrow(() -> new IllegalArgumentException("Report artifact has not been generated"));
    }
}
