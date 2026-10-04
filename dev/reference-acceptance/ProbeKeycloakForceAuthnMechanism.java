import java.io.*;
import java.lang.reflect.*;
import java.net.URI;
import java.nio.file.*;
import java.util.*;
import java.util.stream.Stream;
import jakarta.ws.rs.core.*;
import org.keycloak.authentication.*;
import org.keycloak.authentication.authenticators.browser.*;
import org.keycloak.dom.saml.v2.protocol.AuthnRequestType;
import org.keycloak.events.EventBuilder;
import org.keycloak.models.*;
import org.keycloak.models.sessions.infinispan.*;
import org.keycloak.models.sessions.infinispan.entities.AuthenticationSessionEntity;
import org.keycloak.protocol.LoginProtocol;
import org.keycloak.protocol.saml.*;
import org.keycloak.saml.validators.DestinationValidator;
import org.keycloak.sessions.*;
import org.keycloak.urls.*;
import org.keycloak.util.JsonSerialization;
import com.fasterxml.jackson.databind.JsonNode;

/** Bounded isolated native prototype. No login, product-store writes, or verdict adoption. */
public final class ProbeKeycloakForceAuthnMechanism {
    static final String FLAG="SAML_LOGIN_REQUEST_FORCEAUTHN";
    static final String REQUEST="SAML_REQUEST_ID";
    static final List<Map<String,Object>> traces=new ArrayList<>();
    static void require(boolean value,String why){if(!value)throw new IllegalArgumentException(why);}
    interface Call {Object apply(Method method,Object[]args)throws Throwable;}
    @SuppressWarnings("unchecked") static <T>T proxy(Class<T>type,Call call){return (T)Proxy.newProxyInstance(type.getClassLoader(),new Class<?>[]{type},(p,m,a)->{
        if(m.getDeclaringClass()==Object.class)return switch(m.getName()){case "toString"->"isolated-infrastructure-"+type.getSimpleName();case "hashCode"->System.identityHashCode(p);case "equals"->p==a[0];default->throw new AssertionError(m);};
        return call.apply(m,a==null?new Object[0]:a);
    });}
    static JsonNode read(Path path)throws Exception{return JsonSerialization.mapper.readTree(Files.readAllBytes(path));}
    static JsonNode reply(Path path)throws Exception{return JsonSerialization.mapper.readTree(Base64.getDecoder().decode(read(path).path("response_base64").asText()));}
    static class Boundary extends Error {}
    static String hash(byte[] raw)throws Exception{return HexFormat.of().formatHex(java.security.MessageDigest.getInstance("SHA-256").digest(raw));}
    static List<Map<String,Object>> origins()throws Exception {
        var names=List.of("org.keycloak.protocol.saml.SamlService","org.keycloak.protocol.saml.SamlService$BindingProtocol",
            "org.keycloak.protocol.AuthorizationEndpointBase","org.keycloak.models.utils.AuthenticationFlowResolver",
            "org.keycloak.authentication.AuthenticationProcessor","org.keycloak.authentication.AuthenticationProcessor$Result",
            "org.keycloak.authentication.DefaultAuthenticationFlow","org.keycloak.authentication.AuthenticationSelectionResolver",
            "org.keycloak.authentication.authenticators.browser.UsernamePasswordForm","org.keycloak.authentication.authenticators.browser.UsernamePasswordFormFactory",
            "org.keycloak.models.sessions.infinispan.AuthenticationSessionAdapter","org.keycloak.models.sessions.infinispan.entities.AuthenticationSessionEntity",
            "org.keycloak.protocol.saml.SamlProtocol","org.keycloak.saml.processing.core.parsers.saml.SAMLParser",
            "org.keycloak.dom.saml.v2.protocol.AuthnRequestType");
        var rows=new ArrayList<Map<String,Object>>();for(var name:names){var cls=Class.forName(name);var jar=Path.of(cls.getProtectionDomain().getCodeSource().getLocation().toURI());
            byte[] raw;try(var input=cls.getResourceAsStream("/"+name.replace('.','/')+".class")){require(input!=null,"Missing actual native class resource");raw=input.readAllBytes();}
            rows.add(Map.of("class",name,"jarPath",jar.toString(),"jarSha256",hash(Files.readAllBytes(jar)),"classSha256",hash(raw)));}return rows;
    }
    static class Environment {
        final JsonNode clientRead,executions,realmRead;final String mutation;final String flowId,alias;
        final AuthenticationFlowModel flow=new AuthenticationFlowModel();final AuthenticationExecutionModel execution=new AuthenticationExecutionModel();
        final UsernamePasswordFormFactory nativeFactory=new UsernamePasswordFormFactory();
        final RealmModel realm;final ClientModel client;final KeycloakSession session;final KeycloakContext context;final RootAuthenticationSessionModel root;
        final Map<String,Object> trace=new TreeMap<>();AuthenticationSessionModel nativeSession;KeycloakUriInfo uri;
        Environment(Path source,String mutation)throws Exception {
            this.mutation=mutation;trace.put("mutation",mutation);
            realmRead=reply(source.resolve("originals/native-realm-before.json"));clientRead=reply(source.resolve("originals/native-client-before.json"));executions=reply(source.resolve("originals/flow-executions-before.json"));
            require(executions.size()==1&&executions.get(0).path("requirement").asText().equals("REQUIRED")&&executions.get(0).path("providerId").asText().equals(nativeFactory.getId()),"Wrong selected native mechanism");
            flowId=clientRead.path("authenticationFlowBindingOverrides").path("browser").asText();
            alias=JsonSerialization.mapper.readTree(Base64.getDecoder().decode(read(source.resolve("originals/flow-creation.json")).path("request_base64").asText())).path("alias").asText();
            flow.setId(flowId);flow.setAlias(alias);flow.setProviderId("basic-flow");flow.setTopLevel(true);flow.setBuiltIn(false);
            execution.setId(executions.get(0).path("id").asText());execution.setAuthenticator(nativeFactory.getId());execution.setParentFlow(flowId);
            execution.setRequirement(AuthenticationExecutionModel.Requirement.REQUIRED);execution.setPriority(0);execution.setAuthenticatorFlow(false);
            realm=proxy(RealmModel.class,(m,a)->switch(m.getName()){
                case "getClientById"->{require(clientRead.path("id").asText().equals(a[0]),"Unknown captured client");yield capturedClient();}
                case "getId"->realmRead.path("id").asText();case "getName"->realmRead.path("realm").asText();case "getAuthenticationFlowById"->{require(flowId.equals(a[0]),"Unknown flow");yield flow;}
                case "getAuthenticationExecutionsStream"->{require(flowId.equals(a[0]),"Unknown selected flow");yield Stream.of(execution);}
                case "getAuthenticationExecutionById"->{require(execution.getId().equals(a[0]),"Unknown execution");yield execution;}
                case "getEventsListenersStream","getEnabledEventTypesStream"->Stream.empty();case "isEventsEnabled"->realmRead.path("eventsEnabled").asBoolean();case "isBruteForceProtected"->realmRead.path("bruteForceProtected").asBoolean();case "isInternationalizationEnabled"->realmRead.path("internationalizationEnabled").asBoolean();
                case "getAccessCodeLifespanLogin"->realmRead.path("accessCodeLifespanLogin").asInt();case "getAccessCodeLifespanUserAction"->realmRead.path("accessCodeLifespanUserAction").asInt();
                case "getAttribute"->realmRead.path("attributes").path((String)a[0]).asText(null);case "getAttributes"->{var values=new HashMap<String,String>();realmRead.path("attributes").fields().forEachRemaining(e->values.put(e.getKey(),e.getValue().asText()));yield values;}case "getRequiredActionsStream"->Stream.empty();
                default->throw new UnsupportedOperationException("Uncaptured realm method "+m.getName());
            });
            client=proxy(ClientModel.class,(m,a)->switch(m.getName()){
                case "getId"->clientRead.path("id").asText();case "getClientId"->clientRead.path("clientId").asText();case "getProtocol"->"saml";case "getRealm"->realm;
                case "getAttribute"->{var n=clientRead.path("attributes").path((String)a[0]);yield n.isMissingNode()?null:n.asText();}
                case "getAuthenticationFlowBindingOverride"->clientRead.path("authenticationFlowBindingOverrides").path((String)a[0]).asText(null);
                case "getRedirectUris"->{var set=new HashSet<String>();clientRead.path("redirectUris").forEach(n->set.add(n.asText()));yield set;}
                case "getRootUrl"->clientRead.path("rootUrl").asText(null);case "getBaseUrl"->clientRead.path("baseUrl").asText(null);case "getManagementUrl"->clientRead.path("adminUrl").asText(null);
                case "isEnabled"->true;case "isAlwaysDisplayInConsole","isConsentRequired"->false;
                default->throw new UnsupportedOperationException("Uncaptured client method "+m.getName());
            });
            int[] isolatedClock={org.keycloak.common.util.Time.currentTime()};
            root=proxy(RootAuthenticationSessionModel.class,(m,a)->switch(m.getName()){case "getRealm"->realm;case "getId"->"isolated-not-persisted";case "getTimestamp"->isolatedClock[0];case "setTimestamp"->{isolatedClock[0]=(Integer)a[0];yield null;}default->throw new UnsupportedOperationException("Root infrastructure "+m.getName());});
            var clientProvider=proxy(ClientProvider.class,(m,a)->{require(m.getName().equals("getClientById")&&clientRead.path("id").asText().equals(a[a.length-1]),"Unknown native client lookup");return client;});
            var headers=proxy(HttpHeaders.class,(m,a)->switch(m.getName()){case "getCookies"->Map.of();case "getRequestHeaders"->new MultivaluedHashMap<String,String>();case "getHeaderString"->null;default->throw new UnsupportedOperationException("Header infrastructure "+m.getName());});
            var connection=proxy(org.keycloak.common.ClientConnection.class,(m,a)->switch(m.getName()){case "getRemoteAddr","getLocalAddr"->"127.0.0.1";case "getRemoteHost"->"localhost";case "getRemotePort","getLocalPort"->18180;case "isSecure"->false;default->throw new UnsupportedOperationException("Connection infrastructure "+m.getName());});
            context=proxy(KeycloakContext.class,(m,a)->switch(m.getName()){
                case "getRealm"->realm;case "getConnection"->connection;case "getRequestHeaders"->headers;case "getHttpRequest"->null;case "getUri"->uri;case "getClient"->client;
                case "getAuthenticationSession"->nativeSession;case "setAuthenticationSession"->{nativeSession=(AuthenticationSessionModel)a[0];yield null;}
                default->throw new UnsupportedOperationException("Context infrastructure "+m.getName());
            });
            var factory=proxy(KeycloakSessionFactory.class,(m,a)->{
                if(m.getName().equals("getProviderFactoriesStream"))return Stream.empty();
                if(m.getName().equals("getProviderFactory")&&a[0]==FormAuthenticator.class&&a[1].equals(nativeFactory.getId()))return null;
                require(m.getName().equals("getProviderFactory")&&a[0]==Authenticator.class&&a[1].equals(nativeFactory.getId()),"Unknown provider factory "+m.getName()+" "+Arrays.toString(a));
                return proxy(AuthenticatorFactory.class,(fm,fa)->{
                    if(fm.getName().equals("create")) {
                        var nativeMechanism=mechanism();
                        return proxy(Authenticator.class,(am,aa)->{
                            if(am.getName().equals("authenticate")) {
                                var nativeContext=(AuthenticationFlowContext)aa[0];require(nativeContext.getClass()==AuthenticationProcessor.Result.class,"Synthetic mechanism context");
                                trace.put("nativeResultClass",nativeContext.getClass().getName());trace.put("nativeSelectedFlowExecuted",true);
                                var visible=proxy(AuthenticationFlowContext.class,(cm,ca)->{
                                    if(cm.getName().equals("getAuthenticationSession")) {
                                        var frames=StackWalker.getInstance().walk(stream->stream.map(StackWalker.StackFrame::getClassName).toList());
                                        require(frames.contains("org.keycloak.authentication.authenticators.browser.UsernamePasswordForm")&&frames.contains("org.keycloak.authentication.DefaultAuthenticationFlow"),"Native form flow boundary not executed");
                                        var actual=nativeContext.getAuthenticationSession();require(actual==nativeSession,"Native handoff changed session");
                                        trace.put("sameNativeSessionObject",true);trace.put("mechanismEntryExecuted",true);trace.put("mechanismClass",nativeMechanism.getClass().getName());
                                        trace.put("mechanismRequestId",actual.getClientNote(REQUEST));trace.put("mechanismNativeIndicator",new SamlProtocol().requireReauthentication(null,actual));
                                        trace.put("mechanismRawNotePresent",actual.getAuthNote(FLAG)!=null);throw new Boundary();
                                    }
                                    return cm.invoke(nativeContext,ca);
                                });
                                nativeMechanism.authenticate(visible);throw new AssertionError("Native mechanism boundary not reached");
                            }
                            return am.invoke(nativeMechanism,aa);
                        });
                    }
                    return fm.invoke(nativeFactory,fa);
                });
            });
            session=proxy(KeycloakSession.class,(m,a)->switch(m.getName()){
                case "getContext"->context;case "clients"->clientProvider;case "getKeycloakSessionFactory"->factory;
                case "tokens"->proxy(TokenManager.class,(tm,ta)->switch(tm.getName()) {
                    case "cekManagementAlgorithm"->"direct";case "encode"->JsonSerialization.writeValueAsString(ta[0]);
                    default->throw new UnsupportedOperationException("Cookie infrastructure token "+tm.getName());});
                case "keys"->proxy(KeyManager.class,(km,ka)->{require(km.getName().equals("getActiveKey"),"Unexpected cookie key operation");
                    var key=new org.keycloak.crypto.KeyWrapper();key.setKid("isolated-cookie-key");byte[] bytes=new byte[32];new java.security.SecureRandom().nextBytes(bytes);key.setSecretKey(new javax.crypto.spec.SecretKeySpec(bytes,"AES"));return key;});
                case "getProvider"->{if(a[0]==Authenticator.class){require(a.length==2&&a[1].equals(nativeFactory.getId()),"Uncaptured mechanism provider");yield mechanism();}if(a[0]==org.keycloak.cookie.CookieProvider.class)yield proxy(org.keycloak.cookie.CookieProvider.class,(cm,ca)->{require(cm.getName().equals("set"),"Unexpected cookie boundary");trace.put("isolatedRestartCookieBoundary",true);return null;});
                    require(a[0]==HostnameProvider.class,"Uncaptured native provider "+a[0]);yield proxy(HostnameProvider.class,(hm,ha)->switch(hm.getName()){
                    case "getBaseUri"->URI.create("http://localhost:18180/");case "getScheme"->"http";case "getHostname"->"localhost";case "getPort"->18180;case "getContextPath"->"/";default->throw new UnsupportedOperationException("Hostname infrastructure "+hm.getName());});}
                default->throw new UnsupportedOperationException("Session infrastructure "+m.getName());
            });
            var delegate=proxy(UriInfo.class,(m,a)->switch(m.getName()){
                case "getBaseUri"->URI.create("http://localhost:18180/");case "getAbsolutePath","getRequestUri"->URI.create("http://localhost:18180/realms/samlscope/protocol/saml");
                default->throw new UnsupportedOperationException("URI infrastructure "+m.getName());
            });uri=new KeycloakUriInfo(session,UrlType.FRONTEND,delegate);
        }
        ClientModel capturedClient() {return client;}
        AuthenticationSessionModel fresh() {
            var entity=new AuthenticationSessionEntity();entity.setClientUUID(clientRead.path("id").asText());
            var updater=new SessionEntityUpdater<AuthenticationSessionEntity>() {public AuthenticationSessionEntity getEntity(){return entity;}public void onEntityUpdated(){}public void onEntityRemoved(){throw new AssertionError("Session removed");}};
            var actual=new AuthenticationSessionAdapter(session,root,updater,"isolated-not-persisted");
            require(actual.getAuthNote(FLAG)==null,"Positive fixture manually seeded ForceAuthn");trace.put("nativeSessionClass",actual.getClass().getName());trace.put("nativeFlagInitiallyAbsent",true);trace.put("positiveFlagSeededByHarness",false);return actual;
        }
        Authenticator mechanism(){return nativeFactory.create(session);}
    }
    static class Producer extends SamlService {
        final Environment env;
        Producer(Environment e){super(e.session,new EventBuilder(e.realm,e.session).event(org.keycloak.events.EventType.LOGIN),0,DestinationValidator.forProtocolMap(null));env=e;}
        @Override protected AuthenticationSessionModel createAuthenticationSession(ClientModel client,String relay) {env.nativeSession=env.fresh();return env.nativeSession;}
        @Override protected Response handleBrowserAuthenticationRequest(AuthenticationSessionModel model,LoginProtocol protocol,boolean passive,boolean redirect) {
            require(model==env.nativeSession,"Source session changed");env.trace.put("producerNativeIndicator",new SamlProtocol().requireReauthentication(null,model));
            env.trace.put("producerRequestId",model.getClientNote(REQUEST));env.trace.put("producerRawNotePresent",model.getAuthNote(FLAG)!=null);
            switch(env.mutation){case "none"->{}case "drop-indicator"->model.removeAuthNote(FLAG);case "lose-indicator"->model.setAuthNote(FLAG,"false");case "misbound-request"->model.setClientNote(REQUEST,"unrelated");default->throw new IllegalArgumentException("Unknown calibration");}
            var flow=getAuthenticationFlow(model);require(flow.getId().equals(env.flowId),"Native resolver selected wrong flow");
            env.trace.put("nativeResolvedFlowId",flow.getId());return super.handleBrowserAuthenticationRequest(model,protocol,passive,redirect);
        }
        void produce(AuthnRequestType request)throws Exception {
            var binding=newPostBindingProtocol();var method=binding.getClass().getSuperclass().getDeclaredMethod("loginRequest",String.class,AuthnRequestType.class,ClientModel.class);method.setAccessible(true);
            try{method.invoke(binding,null,request,env.client);throw new AssertionError("Selected native boundary did not interrupt");}
            catch(InvocationTargetException stopped){if(!(stopped.getCause() instanceof Boundary))throw stopped;}
        }
    }
    public static void main(String[]args)throws Exception {
        require(args.length==4,"source original omitted original true output required");org.keycloak.common.Profile.configure();org.keycloak.common.crypto.CryptoIntegration.setProvider((org.keycloak.common.crypto.CryptoProvider)Class.forName("org.keycloak.crypto.def.DefaultCryptoProvider").getConstructor().newInstance());
        for(String mutation:List.of("none","drop-indicator","lose-indicator","misbound-request"))for(int i=1;i<=2;i++) {
            if(!mutation.equals("none")&&i==1)continue;
            var environment=new Environment(Path.of(args[0]),mutation);byte[]raw=Files.readAllBytes(Path.of(args[i]));
            var request=(AuthnRequestType)org.keycloak.saml.processing.core.parsers.saml.SAMLParser.getInstance().parse(org.keycloak.saml.common.util.StaxParserUtil.getXMLEventReader(new ByteArrayInputStream(raw)));
            boolean forced=Boolean.TRUE.equals(request.isForceAuthn());require(forced==(i==2),"Source input flag mismatch");
            environment.trace.put("inputSha256",hash(raw));environment.trace.put("requestId",request.getID());environment.trace.put("inputForceAuthn",forced);environment.trace.put("inputIsPassive",Boolean.TRUE.equals(request.isIsPassive()));
            new Producer(environment).produce(request);
            require(environment.trace.get("producerNativeIndicator").equals(forced)&&request.getID().equals(environment.trace.get("producerRequestId")),"Unchanged native producer did not create original indicator");
            if(mutation.equals("none"))require(environment.trace.get("mechanismNativeIndicator").equals(forced)&&request.getID().equals(environment.trace.get("mechanismRequestId")),"Native indicator handoff did not qualify");
            if(List.of("drop-indicator","lose-indicator").contains(mutation))require(environment.trace.get("mechanismNativeIndicator").equals(false),"Native lost-indicator control lacks detection power");
            if(mutation.equals("misbound-request"))require(environment.trace.get("mechanismRequestId").equals("unrelated"),"Native misbinding control lacks detection power");
            traces.add(environment.trace);
        }
        Files.writeString(Path.of(args[3]),JsonSerialization.writeValueAsPrettyString(Map.of("schema","samlscope-keycloak-forceauthn-native-instrumentation-v1","scope","isolated-native-request-producer-and-selected-password-boundary-capability","traces",traces,"classes",origins(),
                "protocolSubmissions",0,"credentialPosts",0,"productSettingWrites",0,"sourceOriginalsChanged",false,"verdictAdopted",false,"trueLivePasswordUiExecutionClaimed",false)));
    }
}
