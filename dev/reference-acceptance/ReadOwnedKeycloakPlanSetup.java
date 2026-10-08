package com.samlscope.api;
import static com.samlscope.api.ReadSyntheticArtifactRuntime.*;
import com.samlscope.core.plan.*;
import com.samlscope.core.profile.*;
import com.samlscope.store.JsonCodec;
import java.nio.file.Path;
import java.util.Map;

/** Exact owned Plan recovery only, before any client or Run creation. */
public final class ReadOwnedKeycloakPlanSetup {
    public static void main(String[] args)throws Exception {
        require(args.length==2&&args[1].matches("[a-z0-9][a-z0-9-]{0,35}"),"Owned generation required");
        var codec=new JsonCodec();
        try(var db=readOnlyDatabase(Path.of(args[0]).resolve("samlscope.db"))){
            try(var query=db.prepareStatement("SELECT id,document_json FROM plans WHERE json_extract(document_json,'$.name')=? LIMIT 2")){
                query.setString(1,"Owned Keycloak public-CI NameID v2 "+args[1]);
                try(var rows=query.executeQuery()){
                    require(rows.next(),"Owned Plan not found");var row=rows.getString(1);var plan=codec.read(rows.getString(2),TestPlan.class);
                    require(!rows.next()&&row.equals(plan.id())&&plan.profile()==FunctionalProfile.BROWSER_SSO_IDP&&plan.target().kind()==TargetKind.IDP
                        &&plan.target().entityId().equals("http://localhost:28080/realms/samlscope")&&plan.definitionIdentity()!=null
                        &&plan.definitionIdentity().version().equals("functional-case-v2-nameid")&&plan.definitionIdentity().digest().equals("sha256:05558838bf997f81d5be63d423df254b547ffe7c0600683157b6dadd566b7448")
                        &&plan.parameters().requestSigningMode()==TestPlan.RequestSigningMode.REQUIRED,"Owned Plan identity differs");
                    System.out.println(codec.write(Map.of("schema","owned-keycloak-plan-recovery-v1","planId",plan.id(),"definitionIdentity",plan.definitionIdentity(),"generation",args[1],"databaseAccess","URI-escaped-mode-ro-query-only","runCreated",false)));
                }
            }
        }
    }
}
