import java.util.*;
import java.io.*;
import java.nio.file.*;
import java.security.*;
import org.opensaml.core.config.InitializationService;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.profile.context.ProfileRequestContext;
import net.shibboleth.profile.context.RelyingPartyContext;
import net.shibboleth.idp.saml.saml2.profile.config.impl.BrowserSSOProfileConfiguration;
import net.shibboleth.idp.saml.profile.impl.InitializeAuthenticationContext;
import net.shibboleth.idp.authn.context.AuthenticationContext;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.StandardEvaluationContext;
public class NativeForceAuthnMechanismProbe {
 public record Scope(ProfileRequestContext opensamlProfileRequestContext){public ProfileRequestContext getOpensamlProfileRequestContext(){return opensamlProfileRequestContext;}}
 private static String sha(byte[] raw)throws Exception{return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(raw));}
 private static String quote(String x){return "\""+x.replace("\\","\\\\").replace("\"","\\\"").replace("\n","\\n").replace("\r","\\r")+"\"";}
 private static String clazz(Class<?> cls)throws Exception{
  var source=cls.getProtectionDomain().getCodeSource().getLocation();var jar=Path.of(source.toURI());
  try(var stream=cls.getResourceAsStream("/"+cls.getName().replace('.','/')+".class")){
   return "{\"class\":"+quote(cls.getName())+",\"jarFile\":"+quote(jar.getFileName().toString())+",\"jarSha256\":"+quote(sha(Files.readAllBytes(jar)))+",\"classSha256\":"+quote(sha(stream.readAllBytes()))+"}";
  }
 }
 private static String inspect(Path input,String mutation,String expression)throws Exception{
  byte[] raw=Files.readAllBytes(input);var factory=javax.xml.parsers.DocumentBuilderFactory.newInstance();factory.setNamespaceAware(true);factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl",true);
  var root=factory.newDocumentBuilder().parse(new ByteArrayInputStream(raw)).getDocumentElement();
  var request=(AuthnRequest)XMLObjectProviderRegistrySupport.getUnmarshallerFactory().getUnmarshaller(root).unmarshall(root);
  boolean expected=request.isForceAuthn();boolean passive=request.isPassive();String id=request.getID(),issuer=request.getIssuer().getValue();
  var prc=new ProfileRequestContext();var inbound=new MessageContext();inbound.setMessage(request);prc.setInboundMessageContext(inbound);
  var rp=prc.ensureSubcontext(RelyingPartyContext.class);rp.setRelyingPartyId(issuer);var profile=new BrowserSSOProfileConfiguration();rp.setProfileConfig(profile);
  if("strip-input-flag".equals(mutation))request.setForceAuthn(false);
  var action=new InitializeAuthenticationContext();action.initialize();action.execute(prc);
  var nativeContext=prc.getSubcontext(AuthenticationContext.class);if(nativeContext==null)throw new AssertionError("native action did not produce context");
  boolean initializedForce=nativeContext.isForceAuthn();ProfileRequestContext selected=prc;
  if("drop-context".equals(mutation))selected=new ProfileRequestContext();
  if("misbound-context".equals(mutation)){selected=new ProfileRequestContext();selected.ensureSubcontext(AuthenticationContext.class).setForceAuthn(expected);}
  if("lose-context-flag".equals(mutation))nativeContext.setForceAuthn(false);
  var evaluation=new StandardEvaluationContext(new Scope(selected));var value=new SpelExpressionParser().parseExpression(expression).getValue(evaluation);
  boolean contextExists=value instanceof AuthenticationContext;boolean sameObject=value==nativeContext;Boolean received=contextExists?((AuthenticationContext)value).isForceAuthn():null;
  boolean matches=contextExists&&sameObject&&received==expected;
  return "{\"mutation\":"+quote(mutation)+",\"inputFile\":"+quote(input.getFileName().toString())+",\"inputSha256\":"+quote(sha(raw))+",\"requestId\":"+quote(id)+",\"issuer\":"+quote(issuer)+",\"inputForceAuthn\":"+expected+",\"inputIsPassive\":"+passive+",\"nativeInitializerForceAuthn\":"+initializedForce+",\"mechanismContextExists\":"+contextExists+",\"sameNativeContextObject\":"+sameObject+",\"mechanismForceAuthn\":"+received+",\"indicatorReachable\":"+matches+"}";
 }
 public static void main(String[] args)throws Exception{
  InitializationService.initialize();String resource="net/shibboleth/idp/flows/authn/password-authn-flow.xml";byte[] flow;
  try(var source=NativeForceAuthnMechanismProbe.class.getClassLoader().getResourceAsStream(resource)){if(source==null)throw new AssertionError("flow missing");flow=source.readAllBytes();}
  var doc=javax.xml.parsers.DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(new ByteArrayInputStream(flow));var nodes=doc.getElementsByTagName("evaluate");String expression=null;int count=0;
  for(int i=0;i<nodes.getLength();i++){var e=(org.w3c.dom.Element)nodes.item(i);if("viewScope.authenticationContext".equals(e.getAttribute("result"))){expression=e.getAttribute("expression");count++;}}
  if(count!=1||expression==null)throw new AssertionError("actual native Password view expression ambiguous");
  var traces=new ArrayList<String>();traces.add(inspect(Path.of(args[0]),"none",expression));traces.add(inspect(Path.of(args[1]),"none",expression));
  for(String mutant:List.of("strip-input-flag","drop-context","misbound-context","lose-context-flag"))traces.add(inspect(Path.of(args[1]),mutant,expression));
  var classes=List.of(InitializeAuthenticationContext.class,AuthenticationContext.class,BrowserSSOProfileConfiguration.class,SpelExpressionParser.class,ProfileRequestContext.class);
  var origins=new ArrayList<String>();for(var cls:classes)origins.add(clazz(cls));
  Files.writeString(Path.of(args[2]),"{\"schema\":\"samlscope-shibboleth-forceauthn-native-instrumentation-v1\",\"nativeFlowResource\":"+quote(resource)+",\"nativeFlowSha256\":"+quote(sha(flow))+",\"nativeExpression\":"+quote(expression)+",\"scope\":\"isolated-native-stock-password-boundary-capability\",\"trueLivePasswordUiExecutionClaimed\":false,\"classes\":["+String.join(",",origins)+"],\"traces\":["+String.join(",",traces)+"]}\n");
  for(int i=0;i<traces.size();i++)System.out.println(traces.get(i));
 }
}
