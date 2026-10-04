import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.RSAPrivateCrtKey;
import java.util.*;
import javax.crypto.*;
/** Synthetic host-only keys stay in memory. No target configuration, SAML, login or key files. */
public final class TestDefaultCipherKeyEncoding {
 static int passed=0;
 static void check(boolean b){if(!b)throw new AssertionError("Synthetic key encoding test failed");passed++;}
 static void reject(byte[] pem)throws Exception{try{ShibbolethDefaultCipherInputValidation.decodeNativePrivateKey(pem);throw new AssertionError("Bad DER accepted");}catch(IllegalArgumentException|java.security.spec.InvalidKeySpecException expected){passed++;}}
 static byte[] join(List<byte[]> parts){int n=parts.stream().mapToInt(b->b.length).sum();byte[] out=new byte[n];int at=0;for(var p:parts){System.arraycopy(p,0,out,at,p.length);at+=p.length;}return out;}
 static byte[] pem(String type,byte[] der){return ("-----BEGIN "+type+"-----\n"+Base64.getMimeEncoder(64,new byte[]{10}).encodeToString(der)+"\n-----END "+type+"-----\n").getBytes(StandardCharsets.US_ASCII);}
 public static void main(String[]args)throws Exception{
  var generator=KeyPairGenerator.getInstance("RSA");generator.initialize(2048);var pair=generator.generateKeyPair();var k=(RSAPrivateCrtKey)pair.getPrivate();var ints=List.of(java.math.BigInteger.ZERO,k.getModulus(),k.getPublicExponent(),k.getPrivateExponent(),k.getPrimeP(),k.getPrimeQ(),k.getPrimeExponentP(),k.getPrimeExponentQ(),k.getCrtCoefficient());var parts=new ArrayList<byte[]>();for(var i:ints)parts.add(ShibbolethDefaultCipherInputValidation.der(2,i.toByteArray()));byte[] pkcs1=ShibbolethDefaultCipherInputValidation.der(48,join(parts));byte[] one=pem("RSA PRIVATE KEY",pkcs1),eight=pem("PRIVATE KEY",pair.getPrivate().getEncoded());
  byte[] clear="public synthetic input-only key test".getBytes(StandardCharsets.UTF_8);
  for(byte[] bytes:List.of(one,eight)){var key=ShibbolethDefaultCipherInputValidation.decodeNativePrivateKey(bytes);ShibbolethDefaultCipherInputValidation.validateCredential(key,pair.getPublic());for(String mode:List.of("RSA/ECB/PKCS1Padding","RSA/ECB/OAEPWithSHA-1AndMGF1Padding")){var encrypt=Cipher.getInstance(mode);encrypt.init(Cipher.ENCRYPT_MODE,pair.getPublic());var decrypt=Cipher.getInstance(mode);decrypt.init(Cipher.DECRYPT_MODE,key);check(Arrays.equals(clear,decrypt.doFinal(encrypt.doFinal(clear))));}}
  reject(pem("EC PRIVATE KEY",pkcs1));reject(pem("RSA PRIVATE KEY",Arrays.copyOf(pkcs1,pkcs1.length-8)));reject(pem("PRIVATE KEY",new byte[]{48,1,0}));
  try{ShibbolethDefaultCipherInputValidation.validateCredential(ShibbolethDefaultCipherInputValidation.decodeNativePrivateKey(one),generator.generateKeyPair().getPublic());throw new AssertionError("Foreign public certificate accepted");}catch(IllegalArgumentException expected){passed++;}
  check(passed==8);System.out.println("Synthetic host key encoding checks passed: "+(passed-1)+"; private keys persisted/exported=false; target operations=0");Arrays.fill(pkcs1,(byte)0);Arrays.fill(one,(byte)0);Arrays.fill(eight,(byte)0);
 }
}
