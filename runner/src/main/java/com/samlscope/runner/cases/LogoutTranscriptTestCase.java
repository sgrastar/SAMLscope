package com.samlscope.runner.cases;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.function.Function;
import com.samlscope.core.caseexec.CaseContext;
import com.samlscope.core.caseexec.CaseEvent;
import com.samlscope.core.caseexec.CaseState;
import com.samlscope.core.caseexec.CaseStep;
import com.samlscope.core.caseexec.TestCase;
import com.samlscope.core.plan.TargetRole;
import com.samlscope.core.transcript.TranscriptContentReader;

public final class LogoutTranscriptTestCase implements TestCase {
    private record Definition(LogoutTranscriptProfileCase.Rule rule, TargetRole role) {}
    private static final Map<String, Definition> DEFINITIONS = definitions();
    private final String id;
    private final TranscriptContentReader content;
    private final Function<String, List<X509Certificate>> certificates;

    public LogoutTranscriptTestCase(
            String id,
            TranscriptContentReader content,
            Function<String, List<X509Certificate>> certificates) {
        if (!DEFINITIONS.containsKey(id)) throw new IllegalArgumentException("Unapproved SLO case: " + id);
        this.id = id;
        this.content = Objects.requireNonNull(content, "content");
        this.certificates = Objects.requireNonNull(certificates, "certificates");
    }
    @Override public String id() { return id; }
    @Override public TargetRole role() { return DEFINITIONS.get(id).role(); }
    @Override public CaseStep start(CaseContext context) {
        if (!context.transcriptComplete()) return new CaseStep.Finish(LogoutTranscriptProfileCase.incompleteHistory());
        return new CaseStep.Finish(new LogoutTranscriptProfileCase(
                DEFINITIONS.get(id).rule(), certificates.apply(context.runId())).evaluate(
                context.runId(), context.transcript(), content));
    }
    @Override public CaseStep resume(CaseContext context, CaseState state, CaseEvent event) {
        throw new IllegalStateException("Passive SLO cases finish during start");
    }
    static java.util.Set<String> approvedIds() { return DEFINITIONS.keySet(); }

    private static Map<String, Definition> definitions() {
        var values = new LinkedHashMap<String, Definition>();
        bind(values, TargetRole.SP, "IIP-SP14-", Map.of(
                "aa", LogoutTranscriptProfileCase.Rule.UNIQUE_IDS,
                "ab", LogoutTranscriptProfileCase.Rule.IN_RESPONSE_TO,
                "ah", LogoutTranscriptProfileCase.Rule.CONSENT_SIGNATURE,
                "aj", LogoutTranscriptProfileCase.Rule.TOP_LEVEL_STATUS,
                "al", LogoutTranscriptProfileCase.Rule.RESPONSE_VERSION_CEILING,
                "am", LogoutTranscriptProfileCase.Rule.RESPONSE_VERSION_FLOOR,
                "ao", LogoutTranscriptProfileCase.Rule.REQUEST_VERSION_SUPPORTED,
                "ap", LogoutTranscriptProfileCase.Rule.REQUEST_VERSION_2,
                "as", LogoutTranscriptProfileCase.Rule.SCHEMA_STRUCTURE));
        bind(values, TargetRole.IDP, "IIP-IDP17-", Map.ofEntries(
                Map.entry("b3", LogoutTranscriptProfileCase.Rule.ASYNC_PLACEMENT),
                Map.entry("b4", LogoutTranscriptProfileCase.Rule.ASYNC_CHOICE),
                Map.entry("v", LogoutTranscriptProfileCase.Rule.UNIQUE_IDS),
                Map.entry("w", LogoutTranscriptProfileCase.Rule.IN_RESPONSE_TO),
                Map.entry("ac", LogoutTranscriptProfileCase.Rule.CONSENT_SIGNATURE),
                Map.entry("af", LogoutTranscriptProfileCase.Rule.RESPONSE_VERSION_CEILING),
                Map.entry("ag", LogoutTranscriptProfileCase.Rule.RESPONSE_VERSION_FLOOR),
                Map.entry("ai", LogoutTranscriptProfileCase.Rule.REQUEST_VERSION_SUPPORTED),
                Map.entry("aj", LogoutTranscriptProfileCase.Rule.REQUEST_VERSION_2),
                Map.entry("am", LogoutTranscriptProfileCase.Rule.SCHEMA_STRUCTURE),
                Map.entry("an", LogoutTranscriptProfileCase.Rule.TOP_LEVEL_STATUS)));
        return Map.copyOf(values);
    }

    private static void bind(
            Map<String, Definition> target,
            TargetRole role,
            String prefix,
            Map<String, LogoutTranscriptProfileCase.Rule> values) {
        values.forEach((suffix, rule) -> target.put(prefix + suffix + "-" + role.name().toLowerCase() + "-01",
                new Definition(rule, role)));
    }
}
