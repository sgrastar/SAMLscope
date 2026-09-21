package com.samlscope.runner.cases;

import static com.samlscope.runner.cases.MetadataAlgorithmEvidence.children;
import java.util.*;
import org.w3c.dom.Element;
import com.samlscope.saml.normal.SamlRequestedAuthnContextRequestFactory.*;

/** Read the wire request's comparison and ordered references, rather than a fixture label. */
final class AuthnContextRequestEvidence {
    private static final String P="urn:oasis:names:tc:SAML:2.0:protocol",S="urn:oasis:names:tc:SAML:2.0:assertion";
    static ContextRequest read(Element request) {
        if(!P.equals(request.getNamespaceURI()) || !"AuthnRequest".equals(request.getLocalName())) throw invalid();
        var contexts=children(request,P,"RequestedAuthnContext");
        if(contexts.size()!=1) throw invalid();var context=contexts.getFirst();
        Comparison comparison=switch(context.getAttribute("Comparison")) {
            case "" -> { if(context.hasAttribute("Comparison")) throw invalid();yield Comparison.EXACT; }
            case "exact" -> Comparison.EXACT;
            case "minimum" -> Comparison.MINIMUM;
            case "better" -> Comparison.BETTER;
            case "maximum" -> Comparison.MAXIMUM;
            default -> throw invalid();
        };
        ReferenceKind kind=null;var values=new ArrayList<String>();
        for(var node=context.getFirstChild();node!=null;node=node.getNextSibling()) {
            if(!(node instanceof Element reference)) {
                if((node.getNodeType()==org.w3c.dom.Node.TEXT_NODE || node.getNodeType()==org.w3c.dom.Node.CDATA_SECTION_NODE)
                        && !node.getTextContent().isBlank()) throw invalid();
                continue;
            }
            if(!S.equals(reference.getNamespaceURI())) throw invalid();
            ReferenceKind current=switch(reference.getLocalName()) {
                case "AuthnContextClassRef" -> ReferenceKind.CLASS;
                case "AuthnContextDeclRef" -> ReferenceKind.DECLARATION;
                default -> throw invalid();
            };
            if(kind!=null && kind!=current) throw invalid();kind=current;
            for(var child=reference.getFirstChild();child!=null;child=child.getNextSibling()) if(child instanceof Element) throw invalid();
            values.add(reference.getTextContent().strip());
        }
        if(kind==null) throw invalid();
        return new ContextRequest(comparison,kind,values);
    }
    private static IllegalArgumentException invalid() { return new IllegalArgumentException("Unproven requested authentication context"); }
}
