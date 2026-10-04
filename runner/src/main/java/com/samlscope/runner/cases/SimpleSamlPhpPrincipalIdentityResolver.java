package com.samlscope.runner.cases;

import com.fasterxml.jackson.databind.JsonNode;
import com.samlscope.saml.normal.SecureXml;
import java.util.*;

/** Narrow native reference-source semantics, bound by the owning evidence reader. */
final class SimpleSamlPhpPrincipalIdentityResolver implements PrincipalIdentityResolver {
    static final String S="urn:oasis:names:tc:SAML:2.0:assertion";
    static final String PERSISTENT="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent";
    static final String UNSPECIFIED="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified";
    private final String run,target,sp;
    private final Map<String,String> uids=new HashMap<>(),names=new HashMap<>();
    private final Map<String,JsonNode> attributes=new HashMap<>();

    SimpleSamlPhpPrincipalIdentityResolver(String run,String target,String sp,JsonNode nativePrincipals) {
        this.run=run;this.target=target;this.sp=sp;
        require(nativePrincipals.isArray()&&nativePrincipals.size()==2);
        for(var row:nativePrincipals) {
            String principal=text(row,"principal");var values=row.path("attributes");
            require(values.isObject()&&values.size()==2&&values.has("uid")&&values.has("eduPersonAffiliation"));
            var uid=values.path("uid");var affiliation=values.path("eduPersonAffiliation");
            require(uid.isArray()&&uid.size()==1&&uid.get(0).isTextual()&&!uid.get(0).asText().isBlank());
            require(affiliation.isArray()&&affiliation.size()==1&&"member".equals(affiliation.get(0).asText()));
            var name=row.path("nameId");String value=text(name,"value");
            require(value.matches("[0-9a-f]{40}")&&PERSISTENT.equals(text(name,"format"))
                &&name.path("nameQualifier").isNull()&&sp.equals(text(name,"spNameQualifier")));
            require(attributes.put(principal,values)==null&&uids.put(uid.get(0).asText(),principal)==null&&names.put(value,principal)==null);
        }
    }
    String principalForUid(String value){return uids.get(value);}
    JsonNode attributes(String principal){return attributes.get(principal);}
    Set<String> principals(){return Set.copyOf(attributes.keySet());}

    @Override public Resolution resolve(String runId,Identifier identifier) {
        try {
            if(!run.equals(runId))return Resolution.unknown();
            var xml=SecureXml.parse(identifier.value().getBytes(java.nio.charset.StandardCharsets.UTF_8)).getDocumentElement();
            require(S.equals(xml.getNamespaceURI()));
            for(var child=xml.getFirstChild();child!=null;child=child.getNextSibling())require(child.getNodeType()!=org.w3c.dom.Node.ELEMENT_NODE);
            String value=xml.getTextContent();String principal;
            if("NameID".equals(identifier.kind())) {
                require("NameID".equals(xml.getLocalName())&&identifier.format().equals(xml.getAttribute("Format"))&&!xml.hasAttribute("SPProvidedID"));
                require(!xml.hasAttribute("NameQualifier")||target.equals(xml.getAttribute("NameQualifier")));
                if(PERSISTENT.equals(identifier.format())) {
                    require(sp.equals(xml.getAttribute("SPNameQualifier")));principal=names.get(value);
                }else if(UNSPECIFIED.equals(identifier.format())) {
                    require(!xml.hasAttribute("SPNameQualifier"));principal=uids.get(value);
                }else return Resolution.unknown();
            }else if("Attribute:uid".equals(identifier.kind())) {
                require("AttributeValue".equals(xml.getLocalName()));principal=uids.get(value);
            }else if("Attribute:eduPersonAffiliation".equals(identifier.kind())) {
                require("AttributeValue".equals(xml.getLocalName()));
                // This exact shared membership is not an identifier, and never resolves a principal.
                return "member".equals(value)?Resolution.notSubjectIdentifying():Resolution.unknown();
            }else return Resolution.unknown();
            return principal==null?Resolution.unknown():Resolution.resolved(principal);
        }catch(Exception unproven){return Resolution.unknown();}
    }
    private static String text(JsonNode node,String field){var value=node.path(field);require(value.isTextual()&&!value.asText().isBlank());return value.asText();}
    private static void require(boolean value){if(!value)throw new IllegalArgumentException("Native principal semantics unproven");}
}
