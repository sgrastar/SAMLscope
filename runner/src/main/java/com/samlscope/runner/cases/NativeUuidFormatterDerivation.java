package com.samlscope.runner.cases;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

/** Restricted interpretation of the reviewed UUID nibble formatter; not a general JVM. */
final class NativeUuidFormatterDerivation {
    record Member(String owner,String name,String descriptor){String key(){return owner+"."+name+descriptor;}}
    record Method(byte[] code,int stack,int locals){}
    static final class Model {
        final Object[] pool;final Map<String,Method> methods=new HashMap<>();final String owner;
        Model(byte[] bytes)throws IOException{
            require(bytes.length>100&&bytes.length<=524_288);var in=new DataInputStream(new ByteArrayInputStream(bytes));require(in.readInt()==0xcafebabe);in.readUnsignedShort();require(in.readUnsignedShort()==65);
            int count=in.readUnsignedShort();require(count>1&&count<=8192);pool=new Object[count];
            for(int i=1;i<count;i++){int tag=in.readUnsignedByte();pool[i]=switch(tag){case 1->in.readUTF();case 3->in.readInt();case 4->in.readFloat();case 5->{long x=in.readLong();i++;yield x;}case 6->{double x=in.readDouble();i++;yield x;}case 7,8,16,19,20->new int[]{tag,in.readUnsignedShort()};case 9,10,11,12,17,18->new int[]{tag,in.readUnsignedShort(),in.readUnsignedShort()};case 15->new int[]{tag,in.readUnsignedByte(),in.readUnsignedShort()};default->throw new IllegalArgumentException("Unknown class pool entry");};}
            in.readUnsignedShort();owner=className(in.readUnsignedShort());in.readUnsignedShort();int interfaces=in.readUnsignedShort();require(interfaces<128);in.skipNBytes(interfaces*2L);
            members(in,false);members(in,true);attributes(in,null);require(in.available()==0);
        }
        private void members(DataInputStream in,boolean save)throws IOException{int n=in.readUnsignedShort();require(n<1024);for(int i=0;i<n;i++){in.readUnsignedShort();String name=utf(in.readUnsignedShort()),desc=utf(in.readUnsignedShort());attributes(in,save?name+desc:null);}}
        private void attributes(DataInputStream in,String key)throws IOException{int n=in.readUnsignedShort();require(n<256);for(int i=0;i<n;i++){String name=utf(in.readUnsignedShort());int length=in.readInt();require(length>=0&&length<=524_288);byte[] data=in.readNBytes(length);require(data.length==length);if(key!=null&&name.equals("Code")){var c=new DataInputStream(new ByteArrayInputStream(data));int stack=c.readUnsignedShort(),locals=c.readUnsignedShort(),size=c.readInt();require(stack<=32&&locals<=32&&size>0&&size<=16_384);byte[] code=c.readNBytes(size);require(code.length==size&&methods.put(key,new Method(code,stack,locals))==null);}}}
        String utf(int index){require(index>0&&index<pool.length&&pool[index] instanceof String);return(String)pool[index];}
        String className(int index){var p=(int[])pool[index];require(p[0]==7);return utf(p[1]);}
        Member member(int index){var p=(int[])pool[index];require(Set.of(9,10,11).contains(p[0]));var nt=(int[])pool[p[2]];require(nt[0]==12);return new Member(className(p[1]),utf(nt[1]),utf(nt[2]));}
        Method method(String key){var m=methods.get(key);require(m!=null);return m;}
        char[] digits(){byte[] code=method("<clinit>()V").code();int p=9;require(u(code,p++)==16&&u(code,p++)==36&&u(code,p++)==188&&u(code,p++)==5);char[] digits=new char[36];
            for(int i=0;i<36;i++){require(u(code,p++)==89);int op=u(code,p++),index;if(op>=3&&op<=8)index=op-3;else{require(op==16);index=u(code,p++);}require(index==i&&u(code,p++)==16);digits[i]=(char)u(code,p++);require(u(code,p++)==85);}
            require(u(code,p++)==179&&member(two(code,p)).equals(new Member("java/lang/Integer","digits","[C")));return digits;
        }
    }
    private final Model longs;private final char[] digits;private final boolean compact;private final int highShift,lowShift;private int steps;
    NativeUuidFormatterDerivation(Model longs,char[] digits,boolean compact,int highShift,int lowShift){require(longs!=null&&digits!=null&&longs.owner.equals("java/lang/Long")&&digits.length==36&&Set.of(highShift,lowShift).equals(Set.of(0,8)));this.longs=longs;this.digits=digits.clone();this.compact=compact;this.highShift=highShift;this.lowShift=lowShift;}
    String format(long most,long least){steps=0;Object output=execute("fastUUID(JJ)Ljava/lang/String;",new Object[]{least,null,most,null},0);require(output instanceof Value);return ((Value)output).text(highShift,lowShift);}
    private static final class Value {byte[] bytes;int coder;String text(int high,int low){require(bytes!=null&&bytes.length<=72);if(coder==0)return new String(bytes,StandardCharsets.ISO_8859_1);require(coder==1&&bytes.length%2==0);var b=new StringBuilder();for(int i=0;i<bytes.length;i+=2)b.append((char)(((bytes[i]&255)<<high)|((bytes[i+1]&255)<<low)));return b.toString();}}
    private Object execute(String key,Object[] args,int depth){require(depth<=2&&Set.of("fastUUID(JJ)Ljava/lang/String;","formatUnsignedLong0(JI[BII)V","formatUnsignedLong0UTF16(JI[BII)V").contains(key));var method=longs.method(key);byte[] code=method.code();Object[] locals=new Object[method.locals()];System.arraycopy(args,0,locals,0,args.length);var stack=new ArrayList<Object>();int pc=0;
        while(pc<code.length){require(++steps<=4096&&stack.size()<=32);int at=pc,op=u(code,pc++);switch(op){
            case 0->{}case 3,4,5,6,7,8->stack.add(op-3);case 16->stack.add((int)(byte)code[pc++]);
            case 21,22,25->stack.add(locals[u(code,pc++)]);case 26,27,28,29->stack.add(locals[op-26]);case 30,31,32,33->stack.add(locals[op-30]);case 42,43,44,45->stack.add(locals[op-42]);
            case 54,55,58->locals[u(code,pc++)]=pop(stack);case 59,60,61,62->locals[op-59]=pop(stack);case 63,64,65,66->locals[op-63]=pop(stack);case 75,76,77,78->locals[op-75]=pop(stack);
            case 52->{int index=integer(pop(stack));var array=(char[])pop(stack);require(index>=0&&index<array.length);stack.add((int)array[index]);}
            case 84->{int value=integer(pop(stack)),index=integer(pop(stack));var array=(byte[])pop(stack);require(index>=0&&index<array.length);array[index]=(byte)value;}
            case 89->{require(!stack.isEmpty());stack.add(stack.getLast());}
            case 96->{int b=integer(pop(stack)),a=integer(pop(stack));stack.add(a+b);}case 100->{int b=integer(pop(stack)),a=integer(pop(stack));stack.add(a-b);}
            case 120->{int b=integer(pop(stack)),a=integer(pop(stack));stack.add(a<<(b&31));}case 125->{int b=integer(pop(stack));long a=(Long)pop(stack);stack.add(a>>>(b&63));}case 126->{int b=integer(pop(stack)),a=integer(pop(stack));stack.add(a&b);}
            case 132->{int index=u(code,pc++),delta=(byte)code[pc++];locals[index]=integer(locals[index])+delta;}
            case 136->stack.add((int)(long)(Long)pop(stack));case 145->stack.add((int)(byte)integer(pop(stack)));
            case 153->{int offset=(short)two(code,pc);pc+=2;require(key.startsWith("fastUUID")&&at==3);if(integer(pop(stack))==0)pc=at+offset;}
            case 163->{int offset=(short)two(code,pc);pc+=2;int b=integer(pop(stack)),a=integer(pop(stack));require(key.startsWith("formatUnsigned")&&at>=39&&at+offset==18);if(a>b)pc=at+offset;}
            case 176->{require(stack.size()==1);return pop(stack);}case 177->{require(stack.isEmpty());return null;}
            case 178->{var field=longs.member(two(code,pc));pc+=2;if(field.equals(new Member("java/lang/String","COMPACT_STRINGS","Z")))stack.add(compact?1:0);else{require(field.equals(new Member("java/lang/Integer","digits","[C")));stack.add(digits);}}
            case 183->{var call=longs.member(two(code,pc));pc+=2;require(call.equals(new Member("java/lang/String","<init>","([BB)V")));int coder=integer(pop(stack));byte[] bytes=(byte[])pop(stack);var value=(Value)pop(stack);value.bytes=bytes.clone();value.coder=coder;}
            case 184->{var call=longs.member(two(code,pc));pc+=2;if(call.owner().equals("java/lang/Long")&&Set.of("formatUnsignedLong0","formatUnsignedLong0UTF16").contains(call.name())&&call.descriptor().equals("(JI[BII)V")){int length=integer(pop(stack)),offset=integer(pop(stack));byte[] buffer=(byte[])pop(stack);int shift=integer(pop(stack));long value=(Long)pop(stack);require(shift==4&&length>0&&length<=12&&offset>=0&&offset+length<=36);execute(call.name()+call.descriptor(),new Object[]{value,null,shift,buffer,offset,length},depth+1);}else{require(call.equals(new Member("java/lang/StringUTF16","putChar","([BII)V")));int value=integer(pop(stack)),index=integer(pop(stack));byte[] buffer=(byte[])pop(stack);require(index>=0&&index*2+1<buffer.length);buffer[index*2]=(byte)(value>>highShift);buffer[index*2+1]=(byte)(value>>lowShift);}}
            case 187->{require(longs.className(two(code,pc)).equals("java/lang/String"));pc+=2;stack.add(new Value());}
            case 188->{require(u(code,pc++)==8);int size=integer(pop(stack));require(size==36||size==72);stack.add(new byte[size]);}
            default->throw new IllegalArgumentException("Unsupported formatter opcode");
        }}throw new IllegalArgumentException("Unterminated formatter");
    }
    static int u(byte[] code,int at){require(at>=0&&at<code.length);return code[at]&255;}static int two(byte[] code,int at){return(u(code,at)<<8)|u(code,at+1);}private static Object pop(List<Object> stack){require(!stack.isEmpty());return stack.removeLast();}private static int integer(Object value){require(value instanceof Integer);return(Integer)value;}static void require(boolean value){if(!value)throw new IllegalArgumentException("Native formatter derivation unavailable");}
}
