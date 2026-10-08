package com.samlscope.runner;

import com.samlscope.core.profile.FunctionalDefinitionIdentity;
import com.samlscope.core.profile.FunctionalProfile;
import java.util.*;

/** Exact released identities coexist; only the active map may create a new Plan identity. */
public final class FunctionalReleaseRegistry {
    private final Map<FunctionalProfile,FunctionalReleaseContext> active;
    private final Map<FunctionalDefinitionIdentity,FunctionalReleaseContext> releases;

    public FunctionalReleaseRegistry(Collection<FunctionalReleaseContext> current,
            Collection<FunctionalReleaseContext> historical) {
        var active = new EnumMap<FunctionalProfile,FunctionalReleaseContext>(FunctionalProfile.class);
        var releases = new LinkedHashMap<FunctionalDefinitionIdentity,FunctionalReleaseContext>();
        for (var release : List.copyOf(current)) {
            if (release.kind() != FunctionalReleaseContext.Kind.CURRENT
                    || active.put(release.identity().profile(),release) != null
                    || releases.put(release.identity(),release) != null)
                throw new IllegalArgumentException("Duplicate or non-current active release");
        }
        var historicalIds = new HashSet<FunctionalDefinitionIdentity>();
        for (var release : List.copyOf(historical)) {
            if (release.kind() != FunctionalReleaseContext.Kind.HISTORICAL || !historicalIds.add(release.identity()))
                throw new IllegalArgumentException("Duplicate or non-historical retained release");
            var previous = releases.get(release.identity());
            if (previous != null) {
                // A currently installed release may also be retained for the next deployment.
                if (!previous.sourceDigests().equals(release.sourceDigests())
                        || !previous.definition().caseIds().equals(release.definition().caseIds()))
                    throw new IllegalArgumentException("Conflicting release source for exact identity");
            } else releases.put(release.identity(),release);
        }
        this.active = Map.copyOf(active);
        this.releases = Map.copyOf(releases);
    }
    public Set<FunctionalProfile> profiles() { return active.keySet(); }
    public FunctionalDefinitionIdentity identity(FunctionalProfile profile) {
        var release = active.get(profile);
        if (release == null) throw new IllegalArgumentException("Functional profile is not installed");
        return release.identity();
    }
    public Optional<FunctionalReleaseContext> find(FunctionalDefinitionIdentity identity) {
        return identity == null ? Optional.empty() : Optional.ofNullable(releases.get(identity));
    }
    public FunctionalReleaseContext require(FunctionalDefinitionIdentity identity) {
        return find(identity).orElseThrow(() -> new HistoricalRunReadPolicy.DefinitionUnavailable(identity));
    }
}
