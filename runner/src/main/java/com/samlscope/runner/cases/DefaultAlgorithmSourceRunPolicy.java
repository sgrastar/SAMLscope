package com.samlscope.runner.cases;

import com.fasterxml.jackson.databind.JsonNode;
import com.samlscope.core.caseexec.CaseContext;
import com.samlscope.core.evaluation.EvidenceRef;
import java.nio.file.Path;
import java.util.List;

/** A native consumer's explicit configuration equality proof, independent of outcome labels. */
public interface DefaultAlgorithmSourceRunPolicy {
    String adapter();
    List<EvidenceRef> verify(CaseContext destination, Path folder, JsonNode binding,
            Path sourceFolder, JsonNode sourceManifest) throws Exception;
}
