package com.samlscope.runner.cases;

import java.net.URI;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.function.Function;
import com.samlscope.core.caseexec.CaseContext;
import com.samlscope.core.caseexec.CaseEvent;
import com.samlscope.core.caseexec.CaseState;
import com.samlscope.core.caseexec.CaseStep;
import com.samlscope.core.caseexec.TestCase;
import com.samlscope.core.evaluation.CaseOutcome;
import com.samlscope.core.evaluation.EvidenceRef;
import com.samlscope.core.evaluation.Outcome;
import com.samlscope.core.plan.TargetRole;
import com.samlscope.saml.normal.SecureXml;
import com.samlscope.store.JsonCodec;
import org.w3c.dom.Element;

/** Only the decisive unsigned-over-unauthenticated-HTTP observation is automated. */
public final class PublisherRootSignatureConfigurationTestCase implements TestCase, ConfigurationPrompt,
        AttestationPrompt, ProtocolEvidenceCase, com.samlscope.runner.EvidenceCampaignCase {
    public static final String ID = "IIP-MD05-af-idp-01";
    private static final String MD = "urn:oasis:names:tc:SAML:2.0:metadata";
    private static final String DS = "http://www.w3.org/2000/09/xmldsig#";
    private final TestCase fallback;
    private final Function<String, byte[]> metadata;
    private final Path directory;

    public PublisherRootSignatureConfigurationTestCase(TestCase fallback,
            Function<String, byte[]> metadata, Path directory) {
        this.fallback = Objects.requireNonNull(fallback);
        this.metadata = Objects.requireNonNull(metadata);
        this.directory = Objects.requireNonNull(directory).toAbsolutePath().normalize();
        if (!ID.equals(fallback.id()) || !(fallback instanceof ConfigurationPrompt)
                || !(fallback instanceof AttestationPrompt)) {
            throw new IllegalArgumentException("Publisher signature requires approved CONFIG fallback");
        }
    }

    @Override public String id() { return fallback.id(); }
    @Override public TargetRole role() { return fallback.role(); }
    @Override public String instructionEn() { return ((ConfigurationPrompt) fallback).instructionEn(); }
    @Override public String promptEn() { return ((AttestationPrompt) fallback).promptEn(); }
    @Override public List<AttestationOption> options() { return ((AttestationPrompt) fallback).options(); }
    @Override public String evidenceCampaignId() { return "publisher-root-signature"; }
    @Override public String evidenceCampaignTitle() { return "Published metadata root signature"; }
    @Override public com.samlscope.runner.RunCampaignQuery.ActionKind evidenceActionKind() {
        return com.samlscope.runner.RunCampaignQuery.ActionKind.NONE;
    }
    @Override public CaseStep start(CaseContext context) { return fallback.start(context); }
    @Override public CaseStep resume(CaseContext context, CaseState state, CaseEvent event) {
        if (event instanceof CaseEvent.ConfigConfirmed && exists(context.runId())) {
            return new CaseStep.Finish(observe(context));
        }
        return fallback.resume(context, state, event);
    }
    @Override public EvidenceStatus evidenceStatus(CaseContext context) {
        var outcome = observe(context);
        var ready = outcome.outcome() == Outcome.VIOLATED;
        var required = List.of("unauthenticated-http-publication", "run-snapshot-byte-match", "root-signature-inspection");
        return new EvidenceStatus(ready, required, ready ? required : List.of(), outcome.details());
    }

    private boolean exists(String runId) {
        return runId != null && runId.matches("run_[0-9A-HJKMNP-TV-Z]{26}")
                && Files.isRegularFile(directory.resolve(runId + ".publisher/manifest.json"), LinkOption.NOFOLLOW_LINKS);
    }

    private CaseOutcome observe(CaseContext context) {
        try {
            var folder = directory.resolve(context.runId() + ".publisher").normalize();
            if (!context.transcriptComplete() || !exists(context.runId())
                    || !folder.getParent().equals(directory)) throw new IllegalArgumentException("Receipt missing");
            var manifest = new JsonCodec().mapper().readTree(original(folder, "manifest.json", 65536));
            if (!"samlscope-publisher-root-signature-v1".equals(manifest.path("schema").asText())
                    || !context.runId().equals(manifest.path("runId").asText())) {
                throw new IllegalArgumentException("Wrong Run receipt");
            }
            var source = URI.create(manifest.path("sourceUrl").asText());
            var request = new JsonCodec().mapper().readTree(original(folder, "request.json", 65536));
            if (!"http".equals(source.getScheme()) || !source.toString().equals(request.path("url").asText())
                    || !"GET".equals(request.path("method").asText())
                    || request.path("authorizationSent").asBoolean(true)
                    || request.path("cookieSent").asBoolean(true)
                    || !hash(original(folder, "request.json", 65536)).equals(manifest.path("requestSha256").asText())) {
                throw new IllegalArgumentException("Authenticated or unbound request");
            }
            var published = original(folder, "response.xml", 1048576);
            var snapshot = metadata.apply(context.runId());
            if (snapshot == null || !Arrays.equals(published, snapshot)
                    || !hash(published).equals(manifest.path("responseSha256").asText())
                    || manifest.path("statusCode").asInt() != 200) {
                throw new IllegalArgumentException("Published bytes do not match Run snapshot");
            }
            var root = SecureXml.parse(published).getDocumentElement();
            var entity = URI.create(root.getAttribute("entityID"));
            if (!MD.equals(root.getNamespaceURI()) || !"EntityDescriptor".equals(root.getLocalName())
                    || !"http".equals(entity.getScheme())
                    || !Objects.equals(entity.getAuthority(), source.getAuthority())) {
                throw new IllegalArgumentException("Unrelated publisher");
            }
            var signed = false;
            for (var child = root.getFirstChild(); child != null; child = child.getNextSibling()) {
                if (child instanceof Element element && DS.equals(element.getNamespaceURI())
                        && "Signature".equals(element.getLocalName())) signed = true;
            }
            if (signed) {
                // A signature's presence is not proof of a valid signature. This adapter does not
                // auto-pass the case until the signature is verified against native source evidence.
                throw new IllegalArgumentException("Root signature needs validation");
            }
            return new CaseOutcome(Outcome.VIOLATED, null, "metadata.publisher.root-signature-absent",
                    "metadata.publisher.root-signature-absent",
                    List.of(new EvidenceRef("publisher-metadata", context.runId() + ".publisher/manifest.json")),
                    Map.of("source_scheme", "http", "status_code", 200,
                            "metadata_sha256", hash(published), "root_signed", false));
        } catch (Exception unproven) {
            return new CaseOutcome(Outcome.NOT_VERIFIED, "publisher_context_unproven",
                    "metadata.publisher.evidence-incomplete", "metadata.publisher.evidence-incomplete",
                    List.of(), Map.of("evidence_issue", unproven.getClass().getSimpleName()));
        }
    }

    private static byte[] original(Path folder, String name, long maximum) throws Exception {
        var path = folder.resolve(name);
        if (!Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS) || Files.size(path) > maximum) {
            throw new IllegalArgumentException("Missing publisher original");
        }
        return Files.readAllBytes(path);
    }

    private static String hash(byte[] data) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(data));
    }
}
