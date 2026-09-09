package com.samlscope.core.profile;

import com.samlscope.core.plan.TargetRole;

/** Stable public identifiers. Membership is supplied by a versioned mapping, never by this enum. */
public enum FunctionalProfile {
    BROWSER_SSO_IDP("browser_sso_idp", TargetRole.IDP),
    BROWSER_SSO_SP("browser_sso_sp", TargetRole.SP),
    METADATA_IDP("metadata_idp", TargetRole.IDP),
    METADATA_SP("metadata_sp", TargetRole.SP),
    SINGLE_LOGOUT_IDP("single_logout_idp", TargetRole.IDP),
    SINGLE_LOGOUT_SP("single_logout_sp", TargetRole.SP),
    ECP_IDP("ecp_idp", TargetRole.IDP);

    private final String id;
    private final TargetRole role;
    FunctionalProfile(String id, TargetRole role) { this.id = id; this.role = role; }
    public String id() { return id; }
    public TargetRole role() { return role; }
    public static FunctionalProfile fromId(String id) {
        for (var profile : values()) if (profile.id.equals(id)) return profile;
        throw new IllegalArgumentException("Unknown functional profile: " + id);
    }
}
