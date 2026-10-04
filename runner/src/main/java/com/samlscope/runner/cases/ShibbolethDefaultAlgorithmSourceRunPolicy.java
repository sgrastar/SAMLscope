package com.samlscope.runner.cases;

import com.fasterxml.jackson.databind.JsonNode;
import com.samlscope.core.caseexec.CaseContext;
import com.samlscope.core.evaluation.EvidenceRef;
import com.samlscope.core.transcript.*;
import com.samlscope.saml.normal.SecureXml;
import java.nio.file.Path;
import java.util.*;
import static com.samlscope.runner.cases.DefaultAlgorithmSourceRunEvidence.*;

/** Stock shared security bean equality; the ECP selection readback is not an ECP exchange. */
public final class ShibbolethDefaultAlgorithmSourceRunPolicy implements DefaultAlgorithmSourceRunPolicy {
    public static final String ADAPTER="shibboleth-stock-default-security-source-run-v1";
    public static final String ECP="http://shibboleth.net/ns/profiles/saml2/sso/ecp";
    private final TranscriptContentReader content;
    public ShibbolethDefaultAlgorithmSourceRunPolicy(TranscriptContentReader content){this.content=Objects.requireNonNull(content);}
    @Override public String adapter(){return ADAPTER;}
    @Override public List<EvidenceRef> verify(CaseContext destination,Path folder,JsonNode m,Path sourceFolder,JsonNode sourceManifest)throws Exception {
        require(ShibbolethDefaultAlgorithmNativeAdapter.ADAPTER.equals(text(sourceManifest,"adapter")));
        String sourceRun=text(sourceManifest,"runId"),selection=text(m,"selectionEntityId");
        var sourceBefore=DefaultAlgorithmPreventionEvidence.json(original(sourceFolder,"default-before-scope.json"));
        var sourceAfter=DefaultAlgorithmPreventionEvidence.json(original(sourceFolder,"default-after-scope.json"));
        var before=nativeScope(destination,folder,m,"beforeScope",selection,"before");
        var after=nativeScope(destination,folder,m,"afterScope",selection,"after");
        require(sourceRun.equals(text(sourceBefore,"runId"))&&sourceRun.equals(text(sourceAfter,"runId")));
        for(String key:List.of("runtime","classpath","propertiesSha256","selectedProperties","xmlSha256","overrideSourceInventory"))
            require(before.path(key).equals(after.path(key)));
        for(String key:List.of("classpath","propertiesSha256","selectedProperties","xmlSha256","overrideSourceInventory"))
            require(before.path(key).equals(sourceBefore.path(key))&&before.path(key).equals(sourceAfter.path(key)));
        require(text(before.path("runtime"),"image").equals(text(sourceBefore.path("runtime"),"image")));
        require(!java.time.Instant.parse(text(before,"startedAt")).isBefore(java.time.Instant.parse(text(sourceAfter,"completedAt")))
                &&!java.time.Instant.parse(text(after,"startedAt")).isBefore(java.time.Instant.parse(text(before,"completedAt"))));
        require(ShibbolethDefaultAlgorithmNativeAdapter.policy(sourceBefore).equals(ShibbolethDefaultAlgorithmNativeAdapter.policy(before)));
        for(var phase:List.of(before,after)) {
            for(String name:List.of("providers","audit","logback"))
                require(Arrays.equals(original(folder,text(phase.path("restoredConfigurationFiles"),name)),original(sourceFolder,"final-"+name+".xml")));
            var target=original(folder,text(phase,"liveTargetMetadataFile"));
            require(hash(target).equals(text(m,"targetMetadataSha256"))
                    &&text(m,"targetEntityId").equals(SecureXml.parse(target).getDocumentElement().getAttribute("entityID")));
            var selectedMetadata=SecureXml.parse(original(folder,text(phase,"selectionMetadataFile"))).getDocumentElement();
            require("EntityDescriptor".equals(selectedMetadata.getLocalName())&&DefaultAlgorithmPreventionEvidence.MD.equals(selectedMetadata.getNamespaceURI())
                    &&selection.equals(selectedMetadata.getAttribute("entityID"))
                    &&selectedMetadata.getElementsByTagNameNS(DefaultAlgorithmPreventionEvidence.MD,"SPSSODescriptor").getLength()==1);
            var ecp=DefaultAlgorithmPreventionEvidence.json(original(folder,text(phase,"ecpProfileFile")));
            var browser=DefaultAlgorithmPreventionEvidence.json(original(folder,text(phase.path("profileFiles"),"browser")));
            var sourceBrowser=DefaultAlgorithmPreventionEvidence.json(original(sourceFolder,text(sourceBefore.path("profileFiles"),"browser")));
            require(ECP.equals(text(ecp.path("ProfileConfiguration"),"id"))
                    &&"shibboleth.DefaultRelyingParty".equals(text(ecp.path("RelyingPartyConfiguration"),"id"))
                    &&"shibboleth.DefaultSecurityConfiguration".equals(text(ecp.path("RelyingPartyConfiguration"),"securityConfiguration"))
                    &&text(m,"targetEntityId").equals(text(ecp.path("RelyingPartyConfiguration"),"issuer"))
                    &&ecp.path("RelyingPartyConfiguration").equals(browser.path("RelyingPartyConfiguration"))
                    &&ecp.path("RelyingPartyConfiguration").equals(sourceBrowser.path("RelyingPartyConfiguration")));
            require(phase.path("settingsWrites").isInt()&&phase.path("settingsWrites").intValue()==0
                    &&phase.path("protocolSubmissions").isInt()&&phase.path("protocolSubmissions").intValue()==0
                    &&phase.path("credentialPosts").isInt()&&phase.path("credentialPosts").intValue()==0);
        }
        require(Arrays.equals(original(folder,text(before,"ecpProfileFile")),original(folder,text(after,"ecpProfileFile")))
                &&Arrays.equals(original(folder,text(before,"selectionMetadataFile")),original(folder,text(after,"selectionMetadataFile"))));
        return List.of(new EvidenceRef("transcript",text(m,"beforeScopeReference")),new EvidenceRef("transcript",text(m,"afterScopeReference")));
    }
    private JsonNode nativeScope(CaseContext c,Path folder,JsonNode m,String prefix,String selection,String phase)throws Exception {
        String ref=text(m,prefix+"Reference");var entries=c.transcript().listBounded(c.runId(),10_000).stream().filter(e->ref.equals(e.id())).toList();
        require(entries.size()==1);var entry=entries.getFirst();
        var recorderUrl=java.net.URI.create(entry.url());
        require(c.runId().equals(entry.runId())&&entry.direction()==Direction.INBOUND&&"POST".equals(entry.method())
                &&("transcripts/"+c.runId()+"/"+entry.id()+".saml.xml").equals(entry.decodedSamlRef())
                &&("/p/"+text(m,"planId")+"/sp/paos").equals(recorderUrl.getPath())
                &&("run="+c.runId()).equals(recorderUrl.getRawQuery())&&"application/json".equals(entry.contentType()));
        byte[] raw=content.readDecodedSaml(entry);require(raw!=null&&raw.length==entry.decodedSamlBytes()
                &&hash(raw).equals(text(m,prefix+"Sha256"))&&Arrays.equals(raw,original(folder,text(m,prefix+"File"))));
        var scope=DefaultAlgorithmPreventionEvidence.json(raw);
        var verified=ShibbolethDefaultAlgorithmNativeAdapter.scope(folder,scope,phase,c.runId(),selection);
        for(String name:List.of("ecpProfileFile","selectionMetadataFile","liveTargetMetadataFile"))
            require(hash(original(folder,text(verified,name))).equals(text(verified.path("files"),text(verified,name))));
        for(String name:List.of("providers","audit","logback")) {
            String file=text(verified.path("restoredConfigurationFiles"),name);
            require(hash(original(folder,file)).equals(text(verified.path("files"),file)));
        }
        return verified;
    }
}
