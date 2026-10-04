package com.samlscope.api;

import com.samlscope.core.casedef.*;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.plan.*;
import com.samlscope.runner.PinnedFunctionalCaseDefinitionResolver;
import com.samlscope.store.JsonCodec;
import java.nio.file.*;
import java.sql.*;
import java.util.*;

/** Pre-M0 scope only. Reads the real Plan's pinned release without starting a case or generating a result. */
public final class ReadApprovedNativeCaseMembership {
    public static void main(String[] args)throws Exception {
        if(args.length!=2||!args[1].matches("run_[0-9A-HJKMNP-TV-Z]{26}"))throw new IllegalArgumentException("data root and bound Run required");
        Path data=Path.of(args[0]).toRealPath(),db=data.resolve("samlscope.db");
        if(!Files.isRegularFile(db,LinkOption.NOFOLLOW_LINKS))throw new IllegalArgumentException("Database unavailable");
        TestPlan plan;String runPlan;var codec=new JsonCodec();
        try(var connection=DriverManager.getConnection("jdbc:sqlite:file:"+db+"?mode=ro");var q=connection.prepareStatement("SELECT r.plan_id,p.document_json FROM runs r JOIN plans p ON r.plan_id=p.id WHERE r.id=?")) {
            q.setString(1,args[1]);try(var rows=q.executeQuery()) {
                if(!rows.next())throw new IllegalArgumentException("Unknown Run");runPlan=rows.getString(1);plan=codec.read(rows.getString(2),TestPlan.class);
                if(rows.next()||!runPlan.equals(plan.id())||plan.definitionIdentity()==null)throw new IllegalArgumentException("Ambiguous unpinned Run");
            }
        }
        var documents=CatalogDocuments.load();var releases=FunctionalProfileDocuments.load();
        var definitions=CaseDefinitionCatalogMapper.fromDocument(documents.parsed("tests/cases.yaml"));
        var coverage=CoverageCatalogMapper.fromDocument(documents.parsed("tests/coverage.yaml"));
        var resolver=new PinnedFunctionalCaseDefinitionResolver(releases.artifacts(),releases.digests(),Map.of(
                "tests/coverage.yaml",documents.bytes("tests/coverage.yaml"),"tests/cases.yaml",documents.bytes("tests/cases.yaml"),
                "tests/predicates.yaml",documents.bytes("tests/predicates.yaml")),definitions,coverage);
        var approved=resolver.resolve(plan.definitionIdentity()).cases();
        for(String required:List.of("IIP-IDP06-b-idp-01","IIP-SSO01-ae-idp-01","IIP-IDP06-c-idp-01"))if(approved.stream().filter(c->required.equals(c.id())).count()!=1)throw new IllegalArgumentException("Required native source operation is absent");
        var selected=approved.stream().filter(c->"IIP-IDP06-b-idp-01".equals(c.id())).toList();
        if(selected.size()!=1||selected.getFirst().role()!=TargetRole.IDP||selected.getFirst().mode()!=CaseDefinitionCatalog.ExecutionMode.ATTESTED
                ||!"browser_sso_idp".equals(plan.profile().id()))throw new IllegalArgumentException("Approved browser IDP06.b slot unavailable");
        var slot=selected.getFirst();var result=new TreeMap<String,Object>();result.put("schema","samlscope-approved-native-case-membership-v1");
        result.put("runId",args[1]);result.put("planId",runPlan);result.put("profile",plan.profile().id());result.put("caseId",slot.id());
        result.put("role",slot.role());result.put("mode",slot.mode());result.put("caseDigest",slot.caseDigest());result.put("definitionIdentity",plan.definitionIdentity());
        result.put("targetEntityId",plan.target().entityId());result.put("sourceOperationCases",approved.stream().filter(c->List.of("IIP-SSO01-ae-idp-01","IIP-IDP06-c-idp-01").contains(c.id())).map(c->Map.of("id",c.id(),"digest",c.caseDigest(),"mode",c.mode())).toList());result.put("scopeOnly",true);result.put("caseStarted",false);result.put("resultGenerated",false);
        result.put("protocolSubmissions",0);result.put("credentialPosts",0);System.out.println(codec.write(result));
    }
}
