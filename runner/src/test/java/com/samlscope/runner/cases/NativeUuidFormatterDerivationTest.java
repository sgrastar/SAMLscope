package com.samlscope.runner.cases;

import java.util.*;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class NativeUuidFormatterDerivationTest {
    private NativeUuidFormatterDerivation.Model model(String name)throws Exception{try(var in=getClass().getResourceAsStream("/"+name.replace('.','/')+".class")){assertNotNull(in);return new NativeUuidFormatterDerivation.Model(in.readAllBytes());}}
    @Test void originalLookupBytecodeFormatsEveryNibbleInBothEncodings()throws Exception{
        var longs=model("java.lang.Long");var digits=model("java.lang.Integer").digits();assertEquals("0123456789abcdef",new String(digits,0,16));
        for(boolean compact:List.of(true,false))for(int high:List.of(0,8)){
            var interpreter=new NativeUuidFormatterDerivation(longs,digits,compact,high,8-high);
            for(int p=0;p<32;p++)for(int d=0;d<16;d++){long most=p<16?(long)d<<((15-p)*4):0,least=p>=16?(long)d<<((31-p)*4):0;assertEquals(new UUID(most,least).toString(),interpreter.format(most,least));}
            for(long[] e:List.of(new long[]{0,0},new long[]{-1,-1},new long[]{Long.MIN_VALUE,Long.MAX_VALUE},new long[]{Long.MAX_VALUE,Long.MIN_VALUE}))assertEquals(new UUID(e[0],e[1]).toString(),interpreter.format(e[0],e[1]));
        }
    }
    @Test void changedLookupReallyProducesACaseOnlyPairWithoutPostprocessing()throws Exception{
        var longs=model("java.lang.Long");var original=model("java.lang.Integer").digits();var changed=original.clone();for(int i=10;i<16;i++)changed[i]=Character.toUpperCase(changed[i]);long bits=0xabcdefabcdefabcdL;
        for(boolean compact:List.of(true,false)){String first=new NativeUuidFormatterDerivation(longs,original,compact,0,8).format(bits,bits),second=new NativeUuidFormatterDerivation(longs,changed,compact,0,8).format(bits,bits);assertTrue(KeycloakCaseCollisionCapabilityEvidence.caseOnlyPair(first,second));assertNotEquals(first,second);}
        assertEquals("abcdef",new String(original,10,6));
    }
    @Test void unknownOpcodeAndChangedCallAreRejected()throws Exception{
        var model=model("java.lang.Long");var digits=model("java.lang.Integer").digits();var method=model.method("fastUUID(JJ)Ljava/lang/String;");byte[] original=method.code().clone();
        try{method.code()[0]=(byte)254;assertThrows(IllegalArgumentException.class,()->new NativeUuidFormatterDerivation(model,digits,true,0,8).format(0,0));}finally{System.arraycopy(original,0,method.code(),0,original.length);}
        try{method.code()[3]=(byte)167;assertThrows(IllegalArgumentException.class,()->new NativeUuidFormatterDerivation(model,digits,true,0,8).format(0,0));}finally{System.arraycopy(original,0,method.code(),0,original.length);}
    }
    @Test void corruptClassAndUnsupportedEncodingFailClosed(){assertThrows(Exception.class,()->new NativeUuidFormatterDerivation.Model(new byte[100]));assertThrows(IllegalArgumentException.class,()->new NativeUuidFormatterDerivation(null,new char[36],true,0,0));}
    @Test void sameValueAndUnrelatedValuesAreNotCaseCollisions(){assertFalse(KeycloakCaseCollisionCapabilityEvidence.caseOnlyPair("abc","abc"));assertFalse(KeycloakCaseCollisionCapabilityEvidence.caseOnlyPair("abc","abd"));assertFalse(KeycloakCaseCollisionCapabilityEvidence.caseOnlyPair(null,"ABC"));assertTrue(KeycloakCaseCollisionCapabilityEvidence.caseOnlyPair("abc","ABC"));}
}
