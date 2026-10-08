package com.samlscope.runner;

import com.samlscope.core.profile.FunctionalDefinitionIdentity;
import java.util.*;
import java.util.function.Supplier;

/** Stored bytes are read before live definition work; missing history never supplies a new verdict. */
public final class HistoricalRunReadPolicy {
    private final FunctionalReleaseRegistry releases;
    public HistoricalRunReadPolicy(FunctionalReleaseRegistry releases) { this.releases = Objects.requireNonNull(releases); }
    public record Availability(String code, boolean definitionAvailable, boolean readOnlyStored,
            boolean liveEvaluationAvailable, boolean newRunRequired) {}
    public Availability availability(FunctionalDefinitionIdentity identity) {
        var resolved = releases.find(identity);
        return resolved.map(release -> release.kind() == FunctionalReleaseContext.Kind.CURRENT
                ? new Availability("current-definition",true,false,true,false)
                : new Availability("retained-definition-read-only",true,true,false,true))
                .orElseGet(() -> new Availability("historical-definition-unavailable",false,true,false,true));
    }
    public byte[] read(FunctionalDefinitionIdentity identity, Supplier<Optional<byte[]>> cached,
            Supplier<byte[]> liveWhenNoCache) {
        var bytes = Objects.requireNonNull(cached.get(), "Cached lookup returned null");
        if (bytes.isPresent()) return bytes.get().clone();
        releases.require(identity);
        return Objects.requireNonNull(liveWhenNoCache.get(), "Live read returned null").clone();
    }
    /** Active release reads retain the existing reconciliation behavior; retained/unknown history is cached first. */
    public byte[] readForRuntime(FunctionalDefinitionIdentity identity, Supplier<Optional<byte[]>> cached,
            Supplier<byte[]> currentRead, Supplier<byte[]> historicalWhenNoCache) {
        var release = releases.find(identity);
        if (release.isPresent() && release.get().kind() == FunctionalReleaseContext.Kind.CURRENT)
            return Objects.requireNonNull(currentRead.get(), "Current read returned null").clone();
        return read(identity,cached,historicalWhenNoCache);
    }
    public FunctionalReleaseContext requireEvaluation(FunctionalDefinitionIdentity identity) { return releases.require(identity); }
    /** Current implementation registries have not been certified against changed or retired historical cases. */
    public FunctionalReleaseContext requireExecution(FunctionalDefinitionIdentity identity) {
        var release = releases.require(identity);
        if (release.kind() != FunctionalReleaseContext.Kind.CURRENT)
            throw new DefinitionUnavailable(identity,"retained-definition-read-only",
                    "This approved definition is retained for stored results and evidence. Create a new Plan and Run for new automatic tests.");
        return release;
    }
    public static DefinitionUnavailable incompleteArtifactPair() {
        return new DefinitionUnavailable(null,"historical-artifact-pair-incomplete",
                "The stored historical result/report pair is incomplete. The existing artifact is preserved; no new determination was made.");
    }
    public static final class DefinitionUnavailable extends IllegalStateException {
        private final FunctionalDefinitionIdentity identity;
        private final String code;
        public DefinitionUnavailable(FunctionalDefinitionIdentity identity) {
            this(identity,"historical-definition-unavailable",
                    "The original approved definition is unavailable. Stored evidence remains readable; create a new Plan and Run for new tests.");
        }
        private DefinitionUnavailable(FunctionalDefinitionIdentity identity,String code,String message) {
            super(message);
            this.identity = identity;
            this.code = code;
        }
        public String code() { return code; }
        public int httpStatus() { return 409; }
        public Optional<FunctionalDefinitionIdentity> identity() { return Optional.ofNullable(identity); }
    }
}
