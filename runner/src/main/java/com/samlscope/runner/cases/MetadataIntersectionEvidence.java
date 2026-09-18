package com.samlscope.runner.cases;

import static com.samlscope.runner.cases.MetadataAlgorithmEvidence.children;
import java.util.*;
import java.security.interfaces.RSAPublicKey;
import java.security.MessageDigest;
import java.util.function.BiFunction;
import org.w3c.dom.Element;
import com.samlscope.core.caseexec.CaseContext;
import com.samlscope.core.evaluation.*;
import com.samlscope.core.transcript.TranscriptContentReader;
import com.samlscope.saml.crypto.PlanCredentials;

/** Peer-aware intersection: original input, verified output and matching-key decryption are all required. */
final class MetadataIntersectionEvidence {
    static final String ID="IIP-MD05-e8-idp-01";
    private static final String MD="urn:oasis:names:tc:SAML:2.0:metadata", ALG="urn:oasis:names:tc:SAML:metadata:algsupport";
    private static final String S="urn:oasis:names:tc:SAML:2.0:assertion", DS="http://www.w3.org/2000/09/xmldsig#";
    private static final String X="http://www.w3.org/2001/04/xmlenc#", X11="http://www.w3.org/2009/xmlenc11#";
    static final List<String> REQUIRED=List.of("control","algorithm-entity-sha256","algorithm-entity-sha384",
        "algorithm-encryption-aes128-gcm","algorithm-encryption-aes256-gcm",
        "algorithm-encryption-keysize-128","algorithm-encryption-keysize-256",
        "algorithm-oaep-10-sha1","algorithm-oaep-10-sha256","algorithm-oaep-11-sha1","algorithm-oaep-11-sha256",
        "algorithm-signing-256-keysize-excluded","algorithm-signing-384-keysize-excluded");
    record Encryption(String data,String transport,String digest,String mgf,Integer bits) {}
    record Sample(String campaign,String variant,List<String> mismatches,List<String> signatureAlgorithms,List<EvidenceRef> evidence) {}
    static CaseOutcome observe(CaseContext context,TranscriptContentReader content,byte[] target,
            BiFunction<String,String,Optional<PlanCredentials>> keys) {
        var collected=MetadataAlgorithmEvidence.collect(REQUIRED,context,content,target);
        var issues=new ArrayList<>(collected.issues());var samples=new ArrayList<Sample>();
        for(var exchange:collected.exchanges()) {
            try { samples.add(inspect(exchange,keys.apply(context.runId(),exchange.variant()).orElseThrow())); }
            catch(Exception unavailable) { issues.add("intersection_evidence_unavailable:"+exchange.variant()); }
        }
        return evaluate(samples,issues);
    }
    static Sample inspect(MetadataAlgorithmEvidence.Exchange e,PlanCredentials key) throws Exception {
        var role=children(e.metadata(),MD,"SPSSODescriptor").getFirst();
        var expected=expectedEncryption(e.variant());
        var descriptor=MetadataEncryptionProof.descriptor(role,key);
        checkEncryptionInput(descriptor,expected);
        checkSignatureInput(e.metadata(),role,e.variant());
        var mismatches=new ArrayList<String>();var actualSignatures=new ArrayList<String>();
        var signatures=new ArrayList<>(e.signatures());
        var encrypted=children(e.response(),S,"EncryptedAssertion");require(!encrypted.isEmpty());
        require(children(e.response(),S,"Assertion").isEmpty());
        for(var wrapper:encrypted) {
            var data=single(wrapper,X,"EncryptedData");
            var method=single(data,X,"EncryptionMethod");
            var transportKeys=wrapper.getElementsByTagNameNS(X,"EncryptedKey");require(transportKeys.getLength()==1);
            var transport=single((Element)transportKeys.item(0),X,"EncryptionMethod");
            signatures.addAll(MetadataEncryptionProof.decrypt(e,wrapper,key));
            if(expected!=null) {
                if(!expected.data().equals(method.getAttribute("Algorithm")))mismatches.add("encryption-intersection");
                if(expected.bits()!=null && !Objects.equals(expected.bits(),dataBits(method.getAttribute("Algorithm"))))mismatches.add("encryption-keysize-intersection");
                if(expected.transport()!=null) {
                    if(!expected.transport().equals(transport.getAttribute("Algorithm")))mismatches.add("transport-intersection");
                    if(!expected.digest().equals(optionalAlgorithm(transport,DS,"DigestMethod",DS+"sha1")))mismatches.add("oaep-digest-intersection");
                    if(!expected.mgf().equals(optionalAlgorithm(transport,X11,"MGF",X11+"mgf1sha1")))mismatches.add("oaep-mgf-intersection");
                }
            }
        }
        for(var signature:signatures) {
            actualSignatures.add(signature.signatureAlgorithm());
            if(e.variant().equals("algorithm-entity-sha256") || e.variant().equals("algorithm-entity-sha384")) {
                boolean sha256=e.variant().endsWith("256");
                if(!signature.signatureAlgorithm().equals(sha256?MetadataAlgorithmSelection.S256:MetadataAlgorithmSelection.S384))mismatches.add("signature-intersection");
                if(!signature.digestAlgorithm().equals(sha256?MetadataAlgorithmSelection.D256:MetadataAlgorithmSelection.D384))mismatches.add("digest-intersection");
            }
            if(e.variant().endsWith("keysize-excluded")) {
                var trusted=e.signingKeys().stream().filter(c->hash(c.getPublicKey().getEncoded()).equals(signature.signingKeySha256())).findFirst().orElseThrow();
                require(trusted.getPublicKey() instanceof RSAPublicKey);
                var excluded=e.variant().contains("256-keysize")?MetadataAlgorithmSelection.S256:MetadataAlgorithmSelection.S384;
                var allowed=e.variant().contains("256-keysize")?MetadataAlgorithmSelection.S384:MetadataAlgorithmSelection.S256;
                if(signature.signatureAlgorithm().equals(excluded) && ((RSAPublicKey)trusted.getPublicKey()).getModulus().bitLength()>1)mismatches.add("signing-keysize-intersection");
                else if(!signature.signatureAlgorithm().equals(allowed))mismatches.add("signature-intersection");
            }
        }
        return new Sample(e.campaign(),e.variant(),List.copyOf(mismatches),List.copyOf(actualSignatures),e.evidence());
    }
    private static Encryption expectedEncryption(String v) {
        return switch(v) {
            case "algorithm-encryption-aes128-gcm" -> new Encryption(X11+"aes128-gcm",null,null,null,null);
            case "algorithm-encryption-aes256-gcm" -> new Encryption(X11+"aes256-gcm",null,null,null,null);
            case "algorithm-encryption-keysize-128" -> new Encryption(X+"aes128-cbc",null,null,null,128);
            case "algorithm-encryption-keysize-256" -> new Encryption(X+"aes256-cbc",null,null,null,256);
            case "algorithm-oaep-10-sha1", "algorithm-oaep-10-sha256", "algorithm-oaep-11-sha1", "algorithm-oaep-11-sha256" -> {
                boolean old=v.contains("-10-"),sha1=v.endsWith("sha1");
                yield new Encryption(X11+"aes128-gcm",old?X+"rsa-oaep-mgf1p":X11+"rsa-oaep",sha1?DS+"sha1":X+"sha256",old||sha1?X11+"mgf1sha1":X11+"mgf1sha256",null);
            }
            default -> null;
        };
    }
    private static void checkEncryptionInput(Element descriptor,Encryption expected) {
        var methods=children(descriptor,MD,"EncryptionMethod");
        if(expected==null) { require(methods.isEmpty());return; }
        require(methods.size()==(expected.transport()==null?1:2));
        var data=methods.getFirst();require(expected.data().equals(data.getAttribute("Algorithm")));
        require(elementChildren(data).size()==(expected.bits()==null?0:1));
        if(expected.bits()!=null)require(expected.bits().toString().equals(single(data,X,"KeySize").getTextContent().trim()));
        if(expected.transport()!=null) {
            var method=methods.get(1);require(expected.transport().equals(method.getAttribute("Algorithm")));
            boolean old=expected.transport().equals(X+"rsa-oaep-mgf1p");
            require(elementChildren(method).size()==(old?1:2));
            require(expected.digest().equals(single(method,DS,"DigestMethod").getAttribute("Algorithm")));
            if(!old)require(expected.mgf().equals(single(method,X11,"MGF").getAttribute("Algorithm")));
        }
    }
    private static void checkSignatureInput(Element entity,Element role,String v) {
        var entityExt=children(entity,MD,"Extensions");var roleExt=children(role,MD,"Extensions");
        require(entityExt.size()<=1 && roleExt.size()<=1);
        boolean entityAlgorithms=v.equals("algorithm-entity-sha256") || v.equals("algorithm-entity-sha384");
        boolean excluded=v.endsWith("keysize-excluded");
        for(var parent:List.of(entity,role)) {
            var ext=children(parent,MD,"Extensions");
            var signing=ext.isEmpty()?List.<Element>of():children(ext.getFirst(),ALG,"SigningMethod");
            var digest=ext.isEmpty()?List.<Element>of():children(ext.getFirst(),ALG,"DigestMethod");
            if(parent==entity && entityAlgorithms) {
                boolean sha256=v.endsWith("256");require(signing.size()==1 && digest.size()==1);
                require((sha256?MetadataAlgorithmSelection.S256:MetadataAlgorithmSelection.S384).equals(signing.getFirst().getAttribute("Algorithm")));
                require((sha256?MetadataAlgorithmSelection.D256:MetadataAlgorithmSelection.D384).equals(digest.getFirst().getAttribute("Algorithm")));
                require(signing.getFirst().getAttributes().getLength()==1 && elementChildren(signing.getFirst()).isEmpty() && elementChildren(digest.getFirst()).isEmpty());
            } else if(parent==role && excluded) {
                require(signing.size()==2 && digest.isEmpty());boolean first256=v.contains("256-keysize");
                require((first256?MetadataAlgorithmSelection.S256:MetadataAlgorithmSelection.S384).equals(signing.getFirst().getAttribute("Algorithm")));
                require("1".equals(signing.getFirst().getAttribute("MaxKeySize")) && !signing.getFirst().hasAttribute("MinKeySize"));
                require((first256?MetadataAlgorithmSelection.S384:MetadataAlgorithmSelection.S256).equals(signing.get(1).getAttribute("Algorithm")));
                require(!signing.get(1).hasAttribute("MaxKeySize") && !signing.get(1).hasAttribute("MinKeySize"));
                require(signing.stream().allMatch(s->elementChildren(s).isEmpty()));
            } else require(signing.isEmpty() && digest.isEmpty());
        }
    }
    static CaseOutcome evaluate(List<Sample> samples,List<String> issues) {
        var campaigns=samples.stream().map(Sample::campaign).distinct().toList();
        if(campaigns.size()>1) {
            var outcomes=campaigns.stream().map(c->evaluate(samples.stream().filter(s->c.equals(s.campaign())).toList(),issues)).toList();
            return outcomes.stream().filter(o->o.outcome()==Outcome.VIOLATED).findFirst().orElseGet(()->outcomes.stream().filter(o->o.outcome()==Outcome.SATISFIED).findFirst().orElse(outcomes.getLast()));
        }
        var found=samples.stream().map(Sample::variant).distinct().toList();
        var missing=REQUIRED.stream().filter(v->!found.contains(v)).toList();
        var mismatches=samples.stream().flatMap(s->s.mismatches().stream().map(m->s.variant()+":"+m)).distinct().toList();
        var details=new LinkedHashMap<String,Object>();details.put("required_variants",REQUIRED);details.put("observed_variants",found);details.put("missing_variants",missing);
        details.put("evidence_issues",issues);details.put("selection_mismatches",mismatches);details.put("campaigns",campaigns);
        boolean complete=missing.isEmpty() && issues.isEmpty();
        // Both signature algorithms must be proven locally usable; a missing control is not a product failure.
        var algorithms=samples.stream().flatMap(s->s.signatureAlgorithms().stream()).distinct().toList();
        complete &= algorithms.containsAll(List.of(MetadataAlgorithmSelection.S256,MetadataAlgorithmSelection.S384));
        details.put("signature_capability_controls_verified",complete);
        var outcome=!complete?Outcome.NOT_VERIFIED:mismatches.isEmpty()?Outcome.SATISFIED:Outcome.VIOLATED;
        var code="metadata.algorithms."+(!complete?"intersection-evidence-incomplete":mismatches.isEmpty()?"intersection-observed":"intersection-violated");
        return new CaseOutcome(outcome,outcome==Outcome.NOT_VERIFIED?"metadata_algorithm_evidence_unavailable":null,code,code,samples.stream().flatMap(s->s.evidence().stream()).distinct().toList(),details);
    }
    private static Integer dataBits(String algorithm) {
        return algorithm.equals(X+"aes128-cbc") || algorithm.equals(X11+"aes128-gcm")?128:algorithm.equals(X+"aes256-cbc") || algorithm.equals(X11+"aes256-gcm")?256:null;
    }
    private static String optionalAlgorithm(Element e,String ns,String name,String fallback) { var values=children(e,ns,name);require(values.size()<=1);return values.isEmpty()?fallback:values.getFirst().getAttribute("Algorithm"); }
    private static Element single(Element e,String ns,String name) { var values=children(e,ns,name);require(values.size()==1);return values.getFirst(); }
    private static List<Element> elementChildren(Element e) { var out=new ArrayList<Element>();for(var n=e.getFirstChild();n!=null;n=n.getNextSibling())if(n instanceof Element child)out.add(child);return out; }
    private static String hash(byte[] data) { try { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(data)); }catch(Exception impossible){throw new IllegalStateException(impossible);} }
    private static void require(boolean condition) { if(!condition)throw new IllegalArgumentException("Unproven metadata intersection input"); }
}
