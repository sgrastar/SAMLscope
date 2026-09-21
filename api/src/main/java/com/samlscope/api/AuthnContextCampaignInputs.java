package com.samlscope.api;

import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;
import com.samlscope.store.JsonCodec;
import com.samlscope.saml.normal.SamlRequestedAuthnContextRequestFactory.*;

/** Local native adapter inputs select messages only; they never grant conformance or controls. */
final class AuthnContextCampaignInputs {
    record Selected(String caseId, String condition, ContextRequest request, String sha256) {}
    static Selected read(Path directory, String runId, byte[] targetMetadata, String selection) throws Exception {
        require(runId.matches("run_[0-9A-HJKMNP-TV-Z]{26}"));
        require(selection != null && selection.matches("(ga|gb|gc|gj|control)-(class|declaration)-(selection|unachievable|forward|reverse|low|medium|high)"));
        var path = directory.resolve(runId + ".json");
        require(Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS) && Files.size(path) <= 65536);
        var raw = Files.readAllBytes(path);
        var root = new JsonCodec().mapper().readTree(raw);
        require("samlscope-authn-context-inputs-v1".equals(root.path("schema").asText()));
        require(runId.equals(root.path("runId").asText()));
        require(hash(targetMetadata).equals(root.path("targetMetadataSha256").asText()));
        require(root.path("inputs").isArray() && root.path("inputs").size() <= 24);
        var ids = new HashSet<String>(); Selected result = null;
        for (var input : root.path("inputs")) {
            var id = input.path("id").asText();
            require(ids.add(id));
            if (!selection.equals(id)) continue;
            var split = id.split("-", 2);
            var kind = input.path("kind").asText();
            var comparison = input.path("comparison").asText();
            require(input.path("references").isArray() && input.path("references").size() <= 8);
            var references = new ArrayList<String>();
            for (var ref : input.path("references")) {
                require(ref.isTextual() && ref.asText().length() <= 2048);
                references.add(ref.asText());
            }
            var request = new ContextRequest(Comparison.valueOf(comparison), ReferenceKind.valueOf(kind), references);
            require(split[1].startsWith(request.kind() == ReferenceKind.CLASS ? "class-" : "declaration-"));
            require(request.comparison() == switch (split[0]) {
                case "ga" -> Comparison.MINIMUM; case "gb" -> Comparison.BETTER;
                case "gc" -> Comparison.MAXIMUM; default -> Comparison.EXACT;
            });
            result = new Selected("control".equals(split[0]) ? "authn-context-control"
                    : "IIP-SSO01-" + split[0] + "-idp-01", split[1], request, hash(raw));
        }
        require(result != null);
        return result;
    }
    private static String hash(byte[] raw) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(raw));
    }
    private static void require(boolean condition) {
        if (!condition) throw new IllegalArgumentException("Unbound authentication context campaign input");
    }
}
