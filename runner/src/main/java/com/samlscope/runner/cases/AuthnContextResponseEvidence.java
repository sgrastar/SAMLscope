package com.samlscope.runner.cases;

import static com.samlscope.runner.cases.MetadataAlgorithmEvidence.children;
import java.security.cert.X509Certificate;
import java.util.*;
import org.w3c.dom.Element;
import com.samlscope.saml.crypto.*;

/** Signed response evidence only. A protocol error is not a successful context selection. */
final class AuthnContextResponseEvidence {
    private static final String P="urn:oasis:names:tc:SAML:2.0:protocol";
    private static final String S="urn:oasis:names:tc:SAML:2.0:assertion";
    private static final String STATUS="urn:oasis:names:tc:SAML:2.0:status:";
    enum ResponseKind { SUCCESS, ERROR }
    record Observation(ResponseKind kind, Optional<String> classReference,
                       Optional<String> declarationReference, boolean inlineDeclaration) {
        @Override public String toString() { return "AuthnContextObservation[kind="+kind+"]"; }
    }

    static Observation read(Element response,String targetEntity,List<X509Certificate> signingKeys,
            Element preparedMetadata,Optional<PlanCredentials> encryptionKey,String requestId,String recipient) {
        try {
            require(requestId!=null && !requestId.isBlank() && recipient!=null && !recipient.isBlank());
            require(P.equals(response.getNamespaceURI()) && "Response".equals(response.getLocalName()));
            require(requestId.equals(response.getAttribute("InResponseTo")) && recipient.equals(response.getAttribute("Destination")));
            var statuses=children(response,P,"Status");require(statuses.size()==1);
            var codes=children(statuses.getFirst(),P,"StatusCode");require(codes.size()==1);
            String status=codes.getFirst().getAttribute("Value");
            if(!status.equals(STATUS+"Success")) {
                require(Set.of(STATUS+"Requester",STATUS+"Responder",STATUS+"VersionMismatch").contains(status));
                require(children(response,S,"Assertion").isEmpty() && children(response,S,"EncryptedAssertion").isEmpty());
                var verified=new VerifiedSignatureAlgorithms().read(response,targetEntity,signingKeys);
                require(verified.size()==1 && "Response".equals(verified.getFirst().element()));
                return new Observation(ResponseKind.ERROR,Optional.empty(),Optional.empty(),false);
            }
            var assertion=VerifiedResponseAssertion.read(response,targetEntity,signingKeys,preparedMetadata,encryptionKey,requestId,recipient);
            var statements=children(assertion,S,"AuthnStatement");require(statements.size()==1);
            var contexts=children(statements.getFirst(),S,"AuthnContext");require(contexts.size()==1);
            var context=contexts.getFirst();
            var classes=children(context,S,"AuthnContextClassRef");
            var declarations=children(context,S,"AuthnContextDeclRef");
            var inline=children(context,S,"AuthnContextDecl");
            require(classes.size()<=1 && declarations.size()<=1 && inline.size()<=1);
            require(declarations.size()+inline.size()<=1);
            require(!classes.isEmpty() || !declarations.isEmpty() || !inline.isEmpty());
            return new Observation(ResponseKind.SUCCESS,reference(classes),reference(declarations),!inline.isEmpty());
        } catch(Exception unproven) {
            // References, raw XML and crypto exception details must not leak through a failure message.
            throw new IllegalArgumentException("Authentication context response evidence unavailable");
        }
    }
    private static Optional<String> reference(List<Element> elements) {
        if(elements.isEmpty()) return Optional.empty();
        var element=elements.getFirst();
        for(var child=element.getFirstChild();child!=null;child=child.getNextSibling()) require(!(child instanceof Element));
        require(!element.getTextContent().isBlank());
        return Optional.of(element.getTextContent());
    }
    private static void require(boolean condition) { if(!condition) throw new IllegalArgumentException("Unproven authentication context"); }
}
