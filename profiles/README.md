# Functional profile releases

Each profile definition is a versioned set of existing approved case IDs and
case digests. Cases remain the execution and verdict units. A definition never
creates per-variant runtime tests.

`release-pins.properties` is the runtime allowlist. A definition file that is
not listed there is a review candidate and is not exposed by `/api/profiles`.
Adding or changing a pin requires the normal independent G2 review of the exact
definition artifact and release commit.

The G2 validator treats this directory, the case-level membership inventory and
the runtime selection/result path as protected artifacts. A renewed approval must
therefore bind the exact candidate files and `release-pins.properties`; changing
either invalidates that approval.

The release sequence is:

1. Generate and review the profile JSON against the case inventory.
2. Independently approve the case membership and the exact artifact digest.
3. Add `<profile-id>=sha256:<artifact-digest>` to `release-pins.properties` in
   the independently signed approval commit.
4. Run the G2 and release verification checks against that commit.
