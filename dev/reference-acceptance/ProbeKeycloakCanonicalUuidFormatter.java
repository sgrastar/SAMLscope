import java.util.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.io.*;
public class ProbeKeycloakCanonicalUuidFormatter {
 static String hash(byte[] b)throws Exception{return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(b));}
 public static void main(String[] args)throws Exception{
  System.out.println("RUNTIME\t"+System.getProperty("java.runtime.version")+"\t"+System.getProperty("java.vendor")+"\t"+System.getProperty("java.home"));
  var jlaField=UUID.class.getDeclaredField("jla");jlaField.setAccessible(true);Object actualJla=jlaField.get(null);
  if(!actualJla.getClass().getName().equals("java.lang.System$2"))throw new IllegalStateException("unexpected actual JavaLangAccess instance");
  System.out.println("ACTUAL_JLA\t"+actualJla.getClass().getName()+"\t"+actualJla.getClass().getModule().getName());
  var compactField=String.class.getDeclaredField("COMPACT_STRINGS");compactField.setAccessible(true);System.out.println("ACTUAL_COMPACT_STRINGS\t"+compactField.getBoolean(null));
  Class<?> utf=Class.forName("java.lang.StringUTF16",false,null);
  for(String field:List.of("HI_BYTE_SHIFT","LO_BYTE_SHIFT")){var f=utf.getDeclaredField(field);f.setAccessible(true);System.out.println("FIELD\t"+field+"\t"+f.getInt(null));}
  String[] names={"jdk.internal.access.SharedSecrets","java.lang.System","java.util.UUID","java.lang.Long","java.lang.Integer","java.lang.System$2","jdk.internal.access.JavaLangAccess","java.lang.String","java.lang.StringLatin1","java.lang.StringUTF16","jdk.internal.util.HexDigits"};
  for(String n:names){try{Class<?> c=Class.forName(n,false,null);String path="/"+n.replace('.','/')+".class";byte[] b=c.getResourceAsStream(path).readAllBytes();System.out.println("CLASS\t"+n+"\t"+c.getModule().getName()+"\t"+c.getResource(path)+"\t"+hash(b)+"\t"+Base64.getEncoder().encodeToString(b));}catch(ClassNotFoundException missing){System.out.println("ABSENT\t"+n);}}
  var digitsField=Integer.class.getDeclaredField("digits");digitsField.setAccessible(true);
  char[] digits=((char[])digitsField.get(null)).clone();String alphabet=new String(digits,0,16);
  if(!alphabet.equals("0123456789abcdef"))throw new IllegalStateException("native digit table mismatch");
  System.out.println("ALPHABET\t"+alphabet);
  int count=0;
  for(int pos=0;pos<32;pos++)for(int digit=0;digit<16;digit++){
   long msb=pos<16?((long)digit << ((15-pos)*4)):0L,lsb=pos>=16?((long)digit << ((31-pos)*4)):0L;
   String actual=new UUID(msb,lsb).toString();
   String h=String.format(java.util.Locale.ROOT,"%016x%016x",msb,lsb);
   String expected=h.substring(0,8)+"-"+h.substring(8,12)+"-"+h.substring(12,16)+"-"+h.substring(16,20)+"-"+h.substring(20);
   if(!actual.equals(expected)||!actual.matches("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"))throw new IllegalStateException("formatter mismatch "+pos+"/"+digit);
   System.out.println("NIBBLE\t"+pos+"\t"+digit+"\t"+actual);count++;
  }
  long[][] edges={{0L,0L},{-1L,-1L},{Long.MIN_VALUE,Long.MAX_VALUE},{Long.MAX_VALUE,Long.MIN_VALUE}};
  for(long[] pair:edges){String v=new UUID(pair[0],pair[1]).toString();if(!v.matches("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"))throw new IllegalStateException("native edge alphabet mismatch");System.out.println("EDGE\t"+pair[0]+"\t"+pair[1]+"\t"+v);}
  String lower=new UUID(0xabcdefabcdefabcdL,0xabcdefabcdefabcdL).toString();
  char[] nativeTable=(char[])digitsField.get(null);String nativeChanged;
  try{for(int i=10;i<16;i++)nativeTable[i]=Character.toUpperCase(nativeTable[i]);nativeChanged=new UUID(0xabcdefabcdefabcdL,0xabcdefabcdefabcdL).toString();}
  finally{System.arraycopy(digits,0,nativeTable,0,digits.length);}
  boolean detected=!lower.equals(nativeChanged)&&lower.equalsIgnoreCase(nativeChanged)&&!nativeChanged.matches("[0-9a-f-]{36}")&&Arrays.equals(digits,nativeTable);
  System.out.println("NATIVE_DIAGNOSTIC\t"+lower+"\t"+nativeChanged+"\ttableRestored="+Arrays.equals(digits,nativeTable)+"\tproductJvmMutated=false");
  if(!detected)throw new IllegalStateException("case-only diagnostic failed");
  System.out.println("CONTROL\tpositive-native-formatter\t"+count);
  System.out.println("CONTROL\tdiagnostic-case-sensitive-only-formatter\t"+detected);
  System.out.println("CLAIMS\tproductClassOverridden=false\trandomnessUsed=false\ttargetSettingsWrites=0\thttpRequests=0\tnativeIdentifierProducerInvoked=false\tproductFailureClaimed=false");
 }
}
