package com.samlscope.runner;

import java.net.URI;
import java.time.Clock;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import com.samlscope.core.plan.PlanRepository;
import com.samlscope.core.run.RunRepository;
import com.samlscope.saml.metadata.MetadataService;

/**
 * Selects a controlled metadata fixture behind one stable, Run-scoped URL.
 *
 * <p>The target is configured through standard SAML metadata only. No product administration API
 * is involved. Selection is persisted in the Run context so a process restart cannot silently
 * change the fixture being served.</p>
 */
public final class MetadataLabService {
    private static final String CONTEXT_KEY = "metadata_lab";
    private static final String SELECTED_VARIANT = "selected_variant";
    private static final String INGESTION_MODE = "ingestion_mode";
    private static final String CAMPAIGN_VARIANTS = "campaign_variants";
    private static final String CAMPAIGN_INDEX = "campaign_index";
    private static final String CAMPAIGN_TOKEN = "campaign_token";
    private static final String CAMPAIGN_FETCHED = "campaign_fetched";
    private static final String CAMPAIGN_FETCHED_INDEX = "campaign_fetched_index";
    private static final String CAMPAIGN_ATTEMPTED_INDEX = "campaign_attempted_index";
    private static final String CAMPAIGN_CONTINUATION_ACTIONS = "campaign_continuation_actions";
    private static final String POLLING_DELAY_SECONDS = "polling_delay_seconds";
    public static final int DEFAULT_POLLING_DELAY_SECONDS = 15;
    public static final int MAX_POLLING_DELAY_SECONDS = 900;

    private final URI peerBase;
    private final PlanRepository plans;
    private final RunRepository runs;
    private final RunService runService;
    private final Clock clock;

    public MetadataLabService(
            URI peerBase,
            PlanRepository plans,
            RunRepository runs,
            RunService runService,
            Clock clock) {
        this.peerBase = Objects.requireNonNull(peerBase, "peerBase");
        this.plans = Objects.requireNonNull(plans, "plans");
        this.runs = Objects.requireNonNull(runs, "runs");
        this.runService = Objects.requireNonNull(runService, "runService");
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    public State state(String runId) {
        var run = requireRun(runId);
        plans.find(run.planId()).orElseThrow(() -> new IllegalStateException("Run has no Test Plan"));
        var lab = labContext(run.context());
        var selected = selected(run.context());
        var mode = mode(lab);
        var campaign = campaignVariants(lab);
        var campaignIndex = campaignIndex(lab, campaign.size());
        return new State(
                run.id(), run.planId(), selected.id(), liveUrl(run.planId(), run.id(), lab),
                java.util.Arrays.stream(MetadataService.Variant.values())
                        .filter(value -> value != MetadataService.Variant.BASELINE)
                        .map(MetadataService.Variant::id).toList(),
                mode, campaign, campaignIndex, campaignIndex >= campaign.size() && !campaign.isEmpty(),
                pollingDelaySeconds(lab), continuationActions(lab),
                automaticStartUrl(run.planId(), run.id(), lab, campaignIndex, campaign.size()),
                automaticContinueUrl(run.planId(), run.id(), lab, campaignIndex, campaign.size()),
                preloadedUrl(run.planId(), run.id(), lab), preloadedDownloadUrl(run.planId(), run.id(), lab),
                preloadedStartUrl(run.planId(), run.id(), lab),
                mode == IngestionMode.PRELOADED_AGGREGATE ? campaign : preloadedVariants(), Boolean.TRUE.equals(lab.get(CAMPAIGN_FETCHED)));
    }

    public State select(String runId, String variantId) {
        var run = requireRun(runId);
        var variant = MetadataService.Variant.parse(required(variantId, "variant"));
        if (variant == MetadataService.Variant.BASELINE) {
            throw new IllegalArgumentException(
                    "The live metadata lab requires a Run-correlated fixture; use control instead of baseline");
        }
        updateLab(run, Map.of(
                SELECTED_VARIANT, variant.id(),
                INGESTION_MODE, IngestionMode.MANUAL_REFRESH.name(),
                "selected_at", clock.instant().toString()));
        return state(runId);
    }

    /**
     * Arms a product-neutral campaign for targets that periodically retrieve the same metadata URL.
     * A fixture remains behind the URL until its correlated browser flow returns to SAMLscope. Targets
     * commonly fetch the same URL more than once while reloading a key, so a fetch alone must never
     * advance the campaign. No target administration API is used.
     */
    public State startAutomaticPolling(String runId, List<String> variantIds) {
        return startAutomaticPolling(runId, variantIds, DEFAULT_POLLING_DELAY_SECONDS);
    }

    public State startAutomaticPolling(String runId, List<String> variantIds, int pollingDelaySeconds) {
        var run = requireRun(runId);
        var variants = validatedCampaign(variantIds);
        if (pollingDelaySeconds < 0 || pollingDelaySeconds > MAX_POLLING_DELAY_SECONDS) {
            throw new IllegalArgumentException(
                    "Automatic polling delay must be between 0 and "
                            + MAX_POLLING_DELAY_SECONDS + " seconds");
        }
        var lab = new LinkedHashMap<String, Object>();
        lab.put(SELECTED_VARIANT, variants.getFirst());
        lab.put(INGESTION_MODE, IngestionMode.AUTOMATIC_POLLING.name());
        lab.put(CAMPAIGN_VARIANTS, variants);
        lab.put(CAMPAIGN_INDEX, 0);
        lab.put(CAMPAIGN_FETCHED_INDEX, -1);
        lab.put(CAMPAIGN_ATTEMPTED_INDEX, -1);
        lab.put(CAMPAIGN_CONTINUATION_ACTIONS, 0);
        lab.put(CAMPAIGN_TOKEN, com.samlscope.core.Identifiers.newId("poll"));
        lab.put(POLLING_DELAY_SECONDS, pollingDelaySeconds);
        lab.put("selected_at", clock.instant().toString());
        lab.put("campaign_started_at", clock.instant().toString());
        updateLab(run, lab);
        return state(runId);
    }

    /**
     * Arms one aggregate containing compatible positive-consumption fixtures. Static-import
     * products can import this document once instead of importing every positive fixture
     * separately. Negative and document-wide fixtures deliberately remain outside the aggregate.
     */
    public State startPreloadedCampaign(String runId) {
        return startPreloadedCampaign(runId, preloadedVariants());
    }

    public State startPreloadedCampaign(String runId, List<String> variants) {
        var run = requireRun(runId);
        if (variants == null || variants.isEmpty() || variants.stream().anyMatch(java.util.Objects::isNull)
                || new java.util.HashSet<>(variants).size() != variants.size()
                || !preloadedVariants().containsAll(variants)) {
            throw new IllegalArgumentException("Invalid preloaded campaign subset");
        }
        updateLab(run, Map.of(
                SELECTED_VARIANT, selected(run.context()).id(),
                INGESTION_MODE, IngestionMode.PRELOADED_AGGREGATE.name(),
                CAMPAIGN_VARIANTS, variants,
                CAMPAIGN_INDEX, 0,
                CAMPAIGN_TOKEN, com.samlscope.core.Identifiers.newId("preload"),
                CAMPAIGN_FETCHED, false,
                "campaign_started_at", clock.instant().toString()));
        return state(runId);
    }

    public State useManualRefresh(String runId) {
        var run = requireRun(runId);
        var current = selected(run.context());
        updateLab(run, Map.of(
                SELECTED_VARIANT, current.id(),
                INGESTION_MODE, IngestionMode.MANUAL_REFRESH.name(),
                "selected_at", clock.instant().toString()));
        return state(runId);
    }

    /** Records a fetch without advancing; repeated key-reload fetches must see the same fixture. */
    public State recordLiveFetch(String runId, String planId, String fetchedVariant, String campaignToken) {
        var run = requireRun(runId);
        if (!run.planId().equals(required(planId, "planId"))) {
            throw new IllegalArgumentException("Metadata lab Run belongs to another Test Plan");
        }
        var lab = labContext(run.context());
        if (mode(lab) != IngestionMode.AUTOMATIC_POLLING) return state(runId);
        if (!(lab.get(CAMPAIGN_TOKEN) instanceof String expectedToken)) {
            return state(runId);
        }
        // The configured metadata URL is intentionally stable and therefore has no campaign
        // secret. A non-empty token is accepted only when it matches (for legacy callers), while
        // a tokenless fetch can mark only the currently served fixture. It cannot advance the
        // campaign: the separately signed and token-bound SAML browser response is still required.
        if (campaignToken != null && !campaignToken.isBlank()
                && !java.security.MessageDigest.isEqual(
                        expectedToken.getBytes(java.nio.charset.StandardCharsets.UTF_8),
                        campaignToken.getBytes(java.nio.charset.StandardCharsets.UTF_8))) {
            return state(runId);
        }
        var campaign = campaignVariants(lab);
        var index = campaignIndex(lab, campaign.size());
        if (index >= campaign.size()
                || attemptedIndex(lab, campaign.size()) != index
                || !campaign.get(index).equals(fetchedVariant)) return state(runId);
        var updated = new LinkedHashMap<String, Object>(lab);
        updated.put(CAMPAIGN_FETCHED_INDEX, index);
        updated.put("last_fetched_variant", fetchedVariant);
        updated.put("last_fetched_at", clock.instant().toString());
        updateLab(run, updated);
        return state(runId);
    }

    /** Resolves the current polling member before its signed browser request is sent. */
    public PollingFlow requireAutomaticStartFlow(
            String runId, String planId, String campaignToken, int index) {
        var access = requireAutomaticAccess(runId, planId, campaignToken);
        var lab = labContext(access.run().context());
        var variants = campaignVariants(lab);
        var current = campaignIndex(lab, variants.size());
        if (index < 0 || index >= variants.size() || index != current) {
            throw new IllegalArgumentException("Automatic polling campaign index is not current");
        }
        var updated = new LinkedHashMap<String, Object>(lab);
        updated.put(CAMPAIGN_ATTEMPTED_INDEX, index);
        updated.put("last_attempted_variant", variants.get(index));
        updated.put("last_attempted_at", clock.instant().toString());
        updateLab(access.run(), updated);
        return pollingFlow(access.run(), campaignToken, variants, index);
    }

    /** Resolves and advances a member only after a fetch and its correlated browser response. */
    public PollingFlow requireAutomaticCompletedFlow(
            String runId, String planId, String campaignToken, int index) {
        return advanceAttemptedFlow(runId, planId, campaignToken, index, true, false);
    }

    /** Readiness is based on the current fixture's fetch, never an elapsed delay. */
    public boolean automaticStartReady(String runId, String planId, String campaignToken, int index) {
        var access = requireAutomaticAccess(runId, planId, campaignToken);
        var lab = labContext(access.run().context());
        var size = campaignVariants(lab).size();
        return index >= 0 && index < size && campaignIndex(lab, size) == index
                && attemptedIndex(lab, size) == index && fetchedIndex(lab, size) == index;
    }

    /**
     * Advances after the Target fetched a fixture but kept the browser on its own result page.
     * This is orchestration only: it records no satisfied/violated outcome and creates no target
     * evidence beyond the fetch that was already recorded.
     */
    public PollingFlow continueAfterObservedTargetResult(
            String runId, String planId, String campaignToken, int index) {
        return advanceAttemptedFlow(runId, planId, campaignToken, index, false, true);
    }

    private PollingFlow advanceAttemptedFlow(
            String runId, String planId, String campaignToken, int index,
            boolean requireFetch, boolean operatorContinuation) {
        var access = requireAutomaticAccess(runId, planId, campaignToken);
        var lab = labContext(access.run().context());
        var variants = campaignVariants(lab);
        var current = campaignIndex(lab, variants.size());
        if (index < 0 || index >= variants.size() || index != current
                || attemptedIndex(lab, variants.size()) != index
                || (requireFetch && fetchedIndex(lab, variants.size()) != index)) {
            throw new IllegalArgumentException(
                    requireFetch
                            ? "The automatic polling fixture has not been fetched by the target"
                            : "The automatic polling fixture has not been attempted");
        }
        var flow = pollingFlow(access.run(), campaignToken, variants, index);
        var nextIndex = index + 1;
        var nextSelected = nextIndex < variants.size() ? variants.get(nextIndex) : variants.getLast();
        var updated = new LinkedHashMap<String, Object>(lab);
        updated.put(SELECTED_VARIANT, nextSelected);
        updated.put(CAMPAIGN_INDEX, nextIndex);
        updated.put(CAMPAIGN_FETCHED_INDEX, -1);
        updated.put(CAMPAIGN_ATTEMPTED_INDEX, -1);
        if (operatorContinuation) {
            updated.put(CAMPAIGN_CONTINUATION_ACTIONS, continuationActions(lab) + 1);
        }
        updated.put("last_completed_variant", variants.get(index));
        updated.put("last_completed_at", clock.instant().toString());
        updateLab(access.run(), updated);
        return flow;
    }

    /** Validates and records a fetch of the preloaded aggregate, returning its logical fixtures. */
    public List<String> recordPreloadedFetch(String runId, String planId, String campaignToken) {
        var access = requirePreloadedAccess(runId, planId, campaignToken);
        var lab = new LinkedHashMap<String, Object>(labContext(access.run().context()));
        lab.put(CAMPAIGN_FETCHED, true);
        lab.put("last_fetched_at", clock.instant().toString());
        updateLab(access.run(), lab);
        return campaignVariants(lab);
    }

    /** Authorizes generation before any expensive preloaded-fixture work is performed. */
    public List<String> authorizePreloadedFetch(
            String runId, String planId, String campaignToken) {
        var access = requirePreloadedAccess(runId, planId, campaignToken);
        return campaignVariants(labContext(access.run().context()));
    }

    /** Authorizes an operator download without claiming that the Target fetched the document. */
    public List<String> authorizePreloadedDownload(
            String runId, String planId, String campaignToken) {
        var access = requirePreloadedAccess(runId, planId, campaignToken);
        return campaignVariants(labContext(access.run().context()));
    }

    /** Resolves one browser-flow member without trusting URL or RelayState values on their own. */
    public PreloadedFlow requirePreloadedFlow(
            String runId, String planId, String campaignToken, int index) {
        var access = requirePreloadedAccess(runId, planId, campaignToken);
        var variants = campaignVariants(labContext(access.run().context()));
        if (index < 0 || index >= variants.size()) {
            throw new IllegalArgumentException("Preloaded campaign index is out of range");
        }
        return new PreloadedFlow(
                access.run().id(), access.run().planId(), campaignToken, index,
                MetadataService.Variant.parse(variants.get(index)), index + 1 < variants.size());
    }

    public MetadataService.Variant selected(String runId, String planId) {
        var run = requireRun(runId);
        if (!run.planId().equals(required(planId, "planId"))) {
            throw new IllegalArgumentException("Metadata lab Run belongs to another Test Plan");
        }
        return selected(run.context());
    }

    private MetadataService.Variant selected(Map<String, Object> context) {
        var selected = labContext(context).get(SELECTED_VARIANT);
        return selected instanceof String value
                ? MetadataService.Variant.parse(value)
                : MetadataService.Variant.CONTROL;
    }

    private IngestionMode mode(Map<String, Object> lab) {
        var value = lab.get(INGESTION_MODE);
        if (!(value instanceof String text)) return IngestionMode.MANUAL_REFRESH;
        try { return IngestionMode.valueOf(text); }
        catch (IllegalArgumentException ignored) { return IngestionMode.MANUAL_REFRESH; }
    }

    private List<String> campaignVariants(Map<String, Object> lab) {
        var value = lab.get(CAMPAIGN_VARIANTS);
        if (!(value instanceof List<?> items)) return List.of();
        var result = new java.util.ArrayList<String>();
        for (var item : items) if (item instanceof String text) result.add(text);
        return List.copyOf(result);
    }

    private int campaignIndex(Map<String, Object> lab, int size) {
        var value = lab.get(CAMPAIGN_INDEX);
        var index = value instanceof Number number ? number.intValue() : 0;
        return Math.max(0, Math.min(index, size));
    }

    private int fetchedIndex(Map<String, Object> lab, int size) {
        var value = lab.get(CAMPAIGN_FETCHED_INDEX);
        var index = value instanceof Number number ? number.intValue() : -1;
        return index >= 0 && index < size ? index : -1;
    }

    private int attemptedIndex(Map<String, Object> lab, int size) {
        var value = lab.get(CAMPAIGN_ATTEMPTED_INDEX);
        var index = value instanceof Number number ? number.intValue() : -1;
        return index >= 0 && index < size ? index : -1;
    }

    private int continuationActions(Map<String, Object> lab) {
        var value = lab.get(CAMPAIGN_CONTINUATION_ACTIONS);
        return value instanceof Number number ? Math.max(0, number.intValue()) : 0;
    }

    private int pollingDelaySeconds(Map<String, Object> lab) {
        var value = lab.get(POLLING_DELAY_SECONDS);
        if (!(value instanceof Number number)) return DEFAULT_POLLING_DELAY_SECONDS;
        return Math.max(0, Math.min(number.intValue(), MAX_POLLING_DELAY_SECONDS));
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> labContext(Map<String, Object> context) {
        var value = context.get(CONTEXT_KEY);
        if (!(value instanceof Map<?, ?> raw)) return Map.of();
        var result = new LinkedHashMap<String, Object>();
        raw.forEach((key, item) -> { if (key instanceof String text) result.put(text, item); });
        return result;
    }

    private List<String> validatedCampaign(List<String> variantIds) {
        if (variantIds == null || variantIds.isEmpty()) {
            throw new IllegalArgumentException("Automatic polling requires at least one fixture");
        }
        if (variantIds.size() > MetadataService.Variant.values().length) {
            throw new IllegalArgumentException("Automatic polling fixture list is too large");
        }
        var unique = new LinkedHashSet<String>();
        for (var value : variantIds) {
            var variant = MetadataService.Variant.parse(required(value, "variant"));
            if (variant == MetadataService.Variant.BASELINE) {
                throw new IllegalArgumentException("Automatic polling requires Run-correlated fixtures");
            }
            if (!unique.add(variant.id())) throw new IllegalArgumentException("Duplicate campaign fixture: " + value);
        }
        return List.copyOf(unique);
    }

    private List<String> preloadedVariants() {
        return MetadataService.preloadedCampaignVariants().stream()
                .map(MetadataService.Variant::id).toList();
    }

    private PreloadedAccess requirePreloadedAccess(String runId, String planId, String token) {
        var run = requireRun(runId);
        if (!run.planId().equals(required(planId, "planId"))) {
            throw new IllegalArgumentException("Metadata lab Run belongs to another Test Plan");
        }
        var lab = labContext(run.context());
        if (mode(lab) != IngestionMode.PRELOADED_AGGREGATE
                || !(lab.get(CAMPAIGN_TOKEN) instanceof String expected)
                || token == null
                || !java.security.MessageDigest.isEqual(
                        expected.getBytes(java.nio.charset.StandardCharsets.UTF_8),
                        token.getBytes(java.nio.charset.StandardCharsets.UTF_8))) {
            throw new IllegalArgumentException("Preloaded metadata campaign token is invalid");
        }
        return new PreloadedAccess(run);
    }

    private AutomaticAccess requireAutomaticAccess(String runId, String planId, String token) {
        var run = requireRun(runId);
        if (!run.planId().equals(required(planId, "planId"))) {
            throw new IllegalArgumentException("Metadata lab Run belongs to another Test Plan");
        }
        var lab = labContext(run.context());
        if (mode(lab) != IngestionMode.AUTOMATIC_POLLING
                || !(lab.get(CAMPAIGN_TOKEN) instanceof String expected)
                || token == null
                || !java.security.MessageDigest.isEqual(
                        expected.getBytes(java.nio.charset.StandardCharsets.UTF_8),
                        token.getBytes(java.nio.charset.StandardCharsets.UTF_8))) {
            throw new IllegalArgumentException("Automatic polling campaign token is invalid");
        }
        return new AutomaticAccess(run);
    }

    private PollingFlow pollingFlow(
            com.samlscope.core.run.TestRun run, String token, List<String> variants, int index) {
        var lab = labContext(run.context());
        return new PollingFlow(
                run.id(), run.planId(), token, index,
                MetadataService.Variant.parse(variants.get(index)), index + 1 < variants.size(),
                pollingDelaySeconds(lab));
    }

    private void updateLab(com.samlscope.core.run.TestRun run, Map<String, Object> lab) {
        var context = new LinkedHashMap<String, Object>(run.context());
        context.put(CONTEXT_KEY, Map.copyOf(lab));
        runService.update(run, run.status(), run.targetToSuiteReachability(), context);
    }

    private URI liveUrl(String planId, String runId, Map<String, Object> lab) {
        return peerBase.resolve("/p/" + planId + "/metadata/live?run=" + runId);
    }

    private URI preloadedUrl(String planId, String runId, Map<String, Object> lab) {
        if (mode(lab) != IngestionMode.PRELOADED_AGGREGATE
                || !(lab.get(CAMPAIGN_TOKEN) instanceof String token)) return null;
        return peerBase.resolve("/p/" + planId + "/metadata/preloaded?run=" + runId
                + "&preload=" + java.net.URLEncoder.encode(token, java.nio.charset.StandardCharsets.UTF_8));
    }

    private URI preloadedDownloadUrl(String planId, String runId, Map<String, Object> lab) {
        if (mode(lab) != IngestionMode.PRELOADED_AGGREGATE
                || !(lab.get(CAMPAIGN_TOKEN) instanceof String token)) return null;
        return peerBase.resolve("/p/" + planId + "/metadata/preloaded/download?run=" + runId
                + "&preload=" + java.net.URLEncoder.encode(token, java.nio.charset.StandardCharsets.UTF_8));
    }

    private URI automaticStartUrl(
            String planId, String runId, Map<String, Object> lab, int index, int size) {
        if (mode(lab) != IngestionMode.AUTOMATIC_POLLING || index >= size
                || !(lab.get(CAMPAIGN_TOKEN) instanceof String token)) return null;
        return peerBase.resolve("/p/" + planId + "/start/metadata-polling/" + index + "?run=" + runId
                + "&poll=" + java.net.URLEncoder.encode(token, java.nio.charset.StandardCharsets.UTF_8));
    }

    private URI automaticContinueUrl(
            String planId, String runId, Map<String, Object> lab, int index, int size) {
        if (mode(lab) != IngestionMode.AUTOMATIC_POLLING || index >= size
                || attemptedIndex(lab, size) != index
                || !(lab.get(CAMPAIGN_TOKEN) instanceof String token)) return null;
        return peerBase.resolve("/p/" + planId + "/continue/metadata-polling/" + index + "?run=" + runId
                + "&poll=" + java.net.URLEncoder.encode(token, java.nio.charset.StandardCharsets.UTF_8));
    }

    private URI preloadedStartUrl(String planId, String runId, Map<String, Object> lab) {
        if (mode(lab) != IngestionMode.PRELOADED_AGGREGATE
                || !(lab.get(CAMPAIGN_TOKEN) instanceof String token)) return null;
        return peerBase.resolve("/p/" + planId + "/start/metadata-preloaded/0?run=" + runId
                + "&preload=" + java.net.URLEncoder.encode(token, java.nio.charset.StandardCharsets.UTF_8));
    }

    private com.samlscope.core.run.TestRun requireRun(String runId) {
        return runs.find(required(runId, "runId"))
                .orElseThrow(() -> new IllegalArgumentException("Unknown Run"));
    }

    private static String required(String value, String name) {
        if (value == null || value.isBlank()) throw new IllegalArgumentException(name + " is required");
        return value;
    }

    public enum IngestionMode { MANUAL_REFRESH, AUTOMATIC_POLLING, PRELOADED_AGGREGATE }

    public record State(
            String runId,
            String planId,
            String selectedVariant,
            URI metadataUrl,
            java.util.List<String> availableVariants,
            IngestionMode ingestionMode,
            List<String> campaignVariants,
            int campaignIndex,
            boolean campaignComplete,
            int pollingDelaySeconds,
            int operatorContinuationActions,
            URI automaticStartUrl,
            URI automaticContinueUrl,
            URI preloadedMetadataUrl,
            URI preloadedDownloadUrl,
            URI preloadedStartUrl,
            List<String> preloadedVariants,
            boolean preloadedFetched) {
        public State {
            availableVariants = java.util.List.copyOf(availableVariants);
            campaignVariants = List.copyOf(campaignVariants);
            preloadedVariants = List.copyOf(preloadedVariants);
        }
    }

    public record PreloadedFlow(
            String runId,
            String planId,
            String campaignToken,
            int index,
            MetadataService.Variant variant,
            boolean hasNext) {}

    public record PollingFlow(
            String runId,
            String planId,
            String campaignToken,
            int index,
            MetadataService.Variant variant,
            boolean hasNext,
            int pollingDelaySeconds) {}

    private record PreloadedAccess(com.samlscope.core.run.TestRun run) {}
    private record AutomaticAccess(com.samlscope.core.run.TestRun run) {}
}
