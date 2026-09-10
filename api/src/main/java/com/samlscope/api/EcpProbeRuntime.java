package com.samlscope.api;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Objects;
import com.samlscope.core.profile.FunctionalProfile;
import com.samlscope.core.plan.PlanRepository;
import com.samlscope.core.run.RunRepository;
import com.samlscope.core.run.RunStatus;
import com.samlscope.runner.outbox.EcpProbeService;
import com.samlscope.saml.ecp.EcpProbeEnvelopeFactory;
import com.samlscope.saml.metadata.MetadataService;
import com.samlscope.saml.metadata.TargetMetadataParser;
import com.samlscope.saml.normal.SamlProtocolService;
import com.samlscope.store.MetadataCache;

/** Composes the non-evaluative ECP exchange used as evidence by approved passive M3 cases. */
final class EcpProbeRuntime {
    private final URI peerBase;
    private final PlanRepository plans;
    private final RunRepository runs;
    private final MetadataCache metadataCache;
    private final TargetMetadataParser metadataParser;
    private final SamlProtocolService saml;
    private final EcpProbeEnvelopeFactory envelopes;
    private final EcpProbeService probes;

    EcpProbeRuntime(
            URI peerBase,
            PlanRepository plans,
            RunRepository runs,
            MetadataCache metadataCache,
            TargetMetadataParser metadataParser,
            SamlProtocolService saml,
            EcpProbeEnvelopeFactory envelopes,
            EcpProbeService probes) {
        this.peerBase = Objects.requireNonNull(peerBase, "peerBase");
        this.plans = Objects.requireNonNull(plans, "plans");
        this.runs = Objects.requireNonNull(runs, "runs");
        this.metadataCache = Objects.requireNonNull(metadataCache, "metadataCache");
        this.metadataParser = Objects.requireNonNull(metadataParser, "metadataParser");
        this.saml = Objects.requireNonNull(saml, "saml");
        this.envelopes = Objects.requireNonNull(envelopes, "envelopes");
        this.probes = Objects.requireNonNull(probes, "probes");
    }

    List<EcpProbeService.Result> execute(String runId, String username, String password) {
        if (username == null || username.isBlank() || username.contains(":")) {
            throw new IllegalArgumentException("HTTP Basic username must be non-blank and must not contain ':'");
        }
        if (password == null || password.isEmpty()) throw new IllegalArgumentException("Password must not be empty");
        var run = runs.find(runId).orElseThrow(() -> new IllegalArgumentException("Unknown Run"));
        if (run.status() != RunStatus.COMPLETED) {
            throw new IllegalArgumentException("ECP probing requires a completed baseline SSO round trip");
        }
        var plan = plans.find(run.planId()).orElseThrow(() -> new IllegalStateException("Run has no Test Plan"));
        if (plan.profile() != FunctionalProfile.ECP_IDP) {
            throw new IllegalArgumentException("The ECP probe is available only for an ECP — IdP Run");
        }
        var target = metadataParser.parse(
                metadataCache.getRunSnapshot(run.id(), plan.id()), plan.target().entityId());
        var endpoint = target.singleSignOnServices().stream()
                .filter(value -> MetadataService.SOAP.equals(value.binding()))
                .map(com.samlscope.saml.metadata.TargetMetadata.Endpoint::location)
                .findFirst().orElseThrow(() -> new IllegalArgumentException(
                        "Target metadata has no SOAP SingleSignOnService for ECP"));
        var responseConsumer = URI.create(peerBase.resolve("/p/" + plan.id() + "/sp/paos")
                + "?run=" + java.net.URLEncoder.encode(run.id(), StandardCharsets.UTF_8));
        var userBytes = username.getBytes(StandardCharsets.UTF_8);
        var passwordBytes = password.getBytes(StandardCharsets.UTF_8);
        var credential = new byte[userBytes.length + 1 + passwordBytes.length];
        System.arraycopy(userBytes, 0, credential, 0, userBytes.length);
        credential[userBytes.length] = ':';
        System.arraycopy(passwordBytes, 0, credential, userBytes.length + 1, passwordBytes.length);
        var allocatedEnvelopes = new ArrayList<byte[]>();
        try {
            var results = new ArrayList<EcpProbeService.Result>();
            var baseline = saml.buildEcpAuthnRequest(plan, endpoint, responseConsumer, "ecp-" + run.id());
            var baselineEnvelope = envelopes.baseline(baseline.xml());
            allocatedEnvelopes.add(baselineEnvelope);
            results.add(probes.execute(run.id(), endpoint, baselineEnvelope, credential));

            var bindingA = channelBinding(run.id(), "a");
            var bindingB = channelBinding(run.id(), "b");
            results.add(channelProbe(plan, run.id(), endpoint, responseConsumer, credential,
                    EcpProbeService.CHANNEL_BINDING_MATCH_SIGNED,
                    bindingA, bindingA, true, allocatedEnvelopes));
            results.add(channelProbe(plan, run.id(), endpoint, responseConsumer, credential,
                    EcpProbeService.CHANNEL_BINDING_MATCH_UNSIGNED,
                    bindingA, bindingA, false, allocatedEnvelopes));
            results.add(channelProbe(plan, run.id(), endpoint, responseConsumer, credential,
                    EcpProbeService.CHANNEL_BINDING_MISMATCH,
                    bindingA, bindingB, true, allocatedEnvelopes));
            results.add(channelProbe(plan, run.id(), endpoint, responseConsumer, credential,
                    EcpProbeService.CHANNEL_BINDING_REQUEST_ONLY,
                    bindingA, null, true, allocatedEnvelopes));
            var noExtension = saml.buildEcpAuthnRequest(
                    plan, endpoint, responseConsumer, "ecp-channel-header-only-" + run.id());
            var headerOnly = envelopes.channelBinding(noExtension.xml(), "tls-server-end-point", bindingA);
            allocatedEnvelopes.add(headerOnly);
            results.add(probes.execute(run.id(), EcpProbeService.CHANNEL_BINDING_HEADER_ONLY,
                    endpoint, headerOnly, credential));
            var samlEcRequest = saml.buildEcpAuthnRequest(
                    plan, endpoint, responseConsumer, "saml-ec-session-key-" + run.id());
            var samlEcEnvelope = envelopes.samlEcSessionKey(samlEcRequest.xml());
            allocatedEnvelopes.add(samlEcEnvelope);
            results.add(probes.execute(run.id(), EcpProbeService.SAML_EC_SESSION_KEY,
                    endpoint, samlEcEnvelope, credential));
            return List.copyOf(results);
        } finally {
            Arrays.fill(userBytes, (byte) 0);
            Arrays.fill(passwordBytes, (byte) 0);
            Arrays.fill(credential, (byte) 0);
            allocatedEnvelopes.forEach(value -> Arrays.fill(value, (byte) 0));
        }
    }

    private EcpProbeService.Result channelProbe(
            com.samlscope.core.plan.TestPlan plan, String runId, URI endpoint, URI responseConsumer,
            byte[] credential, String fixtureId, String requestValue, String headerValue, boolean signed,
            List<byte[]> allocatedEnvelopes) {
        var request = saml.buildEcpChannelBindingAuthnRequest(
                plan, endpoint, responseConsumer, fixtureId + "-" + runId,
                "tls-server-end-point", requestValue, signed);
        var envelope = headerValue == null
                ? envelopes.baseline(request.xml())
                : envelopes.channelBinding(request.xml(), "tls-server-end-point", headerValue);
        allocatedEnvelopes.add(envelope);
        return probes.execute(runId, fixtureId, endpoint, envelope, credential);
    }

    private String channelBinding(String runId, String discriminator) {
        try {
            var digest = java.security.MessageDigest.getInstance("SHA-256");
            return Base64.getEncoder().encodeToString(
                    digest.digest((runId + ":" + discriminator).getBytes(StandardCharsets.UTF_8)));
        } catch (java.security.NoSuchAlgorithmException impossible) {
            throw new IllegalStateException(impossible);
        }
    }
}
