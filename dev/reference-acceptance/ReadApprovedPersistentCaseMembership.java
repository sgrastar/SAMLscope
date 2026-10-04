package com.samlscope.runner.cases;

import com.samlscope.store.JsonCodec;
import java.nio.file.*;
import java.util.*;

/** Read-only preflight of actual persisted Plan membership before reference-product operations. */
public final class ReadApprovedPersistentCaseMembership {
    public static void main(String[] args)throws Exception {
        if(args.length!=2)throw new IllegalArgumentException("Data root and real Run required");
        var rows=new ArrayList<Object>();
        for(var entry:Map.of("IIP-SSO05-a1-idp-01","sha256:eb4cdd50dca77f8e286b3f6e7f5166bd4e4723a4e0f4a73589486d871106c4c0",
            "IIP-SSO05-a8-idp-01","sha256:acd9b10dc4e281800ebc2ebdefbe189e3267a5b5e9f135fa953530b17756c466").entrySet()) {
            var binding=new DefaultAlgorithmSourceRunStore(Path.of(args[0]),entry.getKey(),entry.getValue()).planned(args[1]);
            if(!"browser_sso_idp".equals(binding.plan().profile().id()))throw new IllegalArgumentException("Approved browser source required");
            rows.add(Map.of("runId",binding.run().id(),"planId",binding.plan().id(),"profile",binding.plan().profile().id(),
                "caseId",entry.getKey(),"caseDigest",entry.getValue(),"definitionIdentity",binding.plan().definitionIdentity(),
                "targetEntityId",binding.plan().target().entityId(),"approvedMembership",true));
        }
        System.out.println(new JsonCodec().write(Map.of("schema","samlscope-approved-persistent-case-membership-v1",
            "cases",rows,"protocolSubmissions",0,"credentialPosts",0,"productSettingWrites",0,"caseStarted",false)));
    }
}
