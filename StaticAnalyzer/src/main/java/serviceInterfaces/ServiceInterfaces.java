package serviceInterfaces;

import analysis.callChainsExtractor.CG;
import cfg.CFG;
import cfg.Node;
import dataflow.ClassAnalyzer;
import config.Common;
import main.Memory;
import util.Recorder;
import soot.SootMethod;
import soot.Unit;
import soot.Value;
import soot.jimple.InvokeExpr;
import soot.jimple.Stmt;
import soot.jimple.internal.JAssignStmt;
import util.StringUtil;
import util.TimeMeasurement;

import java.io.*;
import java.sql.ResultSet;
import java.util.*;

public class ServiceInterfaces {

    public static HashMap<String, String> serviceNameMapStubClass = new HashMap<>();
    public static HashMap<String, String> stubClassMapServiceName = new HashMap<>();
    public static HashMap<String, HashSet<String>> stubClassNameMapRawInterfaces = new HashMap<>();

    public static HashMap<String, String> serviceStubClassMapImplClass = new HashMap<>();

    public static HashSet<String> allRawInterfaceSigs = new HashSet<>();

    public static HashSet<String> frameworkRawInterfaceSigs = new HashSet<>();
    public static HashSet<String> nativeRawInterfaceSigs = new HashSet<>();
    public static HashSet<String> implInterfaceSigs = new HashSet<>();
    public static HashSet<String> accessibleImplInterfaceSigs = new HashSet<>();


    public static HashMap<String, String> rawInterfaceSigMapImplInterfaceSig = new HashMap<>();
    public static HashMap<String, String> implInterfaceSigMapRawInterfaceSig = new HashMap<>();

    public static HashMap<String, HashSet<String>> allRawInterfaceSigMapMethodsInDeserialization = new HashMap<>();


    private static void reset(){
        serviceNameMapStubClass.clear();
        stubClassMapServiceName.clear();
        stubClassNameMapRawInterfaces.clear();
        serviceStubClassMapImplClass.clear();
        allRawInterfaceSigs.clear();
        frameworkRawInterfaceSigs.clear();
        nativeRawInterfaceSigs.clear();
        implInterfaceSigs.clear();
        accessibleImplInterfaceSigs.clear();
        rawInterfaceSigMapImplInterfaceSig.clear();
        implInterfaceSigMapRawInterfaceSig.clear();
        allRawInterfaceSigMapMethodsInDeserialization.clear();
    }

    public static void init(boolean initFromDatabase) {
        // reset before init
        reset();

        TimeMeasurement.show("ServiceInterfaces init start");
        if (initFromDatabase){
            readServiceNameMapStubClassFromDatabase();
            readRawInterfaceSigMapImplInterfaceSig();
            readNativeInterfaceSigs();
        }else{
            readFormatFile();
        }
        allRawInterfaceSigs.addAll(frameworkRawInterfaceSigs);
        allRawInterfaceSigs.addAll(nativeRawInterfaceSigs);
        getDeserializationMethodsForInterfaces();
        TimeMeasurement.show("ServiceInterfaces init end");
    }

    public static void readFormatFile() {
        try {
            BufferedReader in = new BufferedReader(new FileReader(Common.ServiceInterfacePath));
            String str;
            String serviceName = "";
            String stubClassName = "";
            while ((str = in.readLine()) != null) {
                if (str.startsWith("Name:"))
                    serviceName = str.split(":")[1].trim();
                else if (str.startsWith("StubClassName:")) {
                    stubClassName = str.split(":")[1].trim() + "$Stub";
                    if (!stubClassName.equals("null$Stub")) {
                        serviceNameMapStubClass.put(serviceName, stubClassName);
                        stubClassMapServiceName.put(stubClassName, serviceName);
                        stubClassNameMapRawInterfaces.put(stubClassName,new HashSet<>());
                    }
                } else if (str.trim().startsWith("<")) {
                    str = replaceArrayFormatFromJavaToSoot(str.trim());
                    if (str.endsWith("android.os.IBinder asBinder()>") || str.endsWith("java.lang.String getInterfaceDescriptor()>"))
                        continue;
                    stubClassNameMapRawInterfaces.get(stubClassName).add(str);
                    if (!Memory.stubClassNameMapMultiImplClassNames.containsKey(StringUtil.getDeclareClassFromMethodSig(str).replace("$Proxy", ""))) {
                        ServiceInterfaces.nativeRawInterfaceSigs.add(str); // cannot find impl in framework, may in app/native
                    }else{
                        frameworkRawInterfaceSigs.add(str);
                    }
                }
            }
            in.close();

            // stubClass map impl class
            for (String stubClass:stubClassMapServiceName.keySet()){
                if (!Memory.stubClassNameMapMultiImplClassNames.containsKey(stubClass)){
                    serviceStubClassMapImplClass.put(stubClass,"null");
                }else if (Memory.stubClassNameMapMultiImplClassNames.get(stubClass).size()==1){
                    serviceStubClassMapImplClass.put(stubClass,Memory.stubClassNameMapMultiImplClassNames.get(stubClass).iterator().next());
                }else{
                    HashSet<String> tmp = new HashSet<>();
                    for (String implClass:Memory.stubClassNameMapMultiImplClassNames.get(stubClass)){
                        boolean allMethodExist = true;
                        for (String rawInterfaceSig:stubClassNameMapRawInterfaces.get(stubClass)){
                            if (!Memory.methodSignatureMapSootMethod.containsKey(StringUtil.replaceDeclaredClassOfMethodSig(rawInterfaceSig,implClass))){
                                allMethodExist = false;
                                break;
                            }
                        }
                        if (allMethodExist){
                            tmp.add(implClass);
                        }
                    }
                    if (tmp.size()==0){
                        System.out.println("StubMapImpl: 0 impl class with complete interface methods for "+stubClass);
                        serviceStubClassMapImplClass.put(stubClass,"null");
                    }else if (tmp.size()==1){
                        serviceStubClassMapImplClass.put(stubClass,tmp.iterator().next());
                    }else {
                        String res="";
                        for (String cs:tmp){
                            if (!cs.contains("$")){
                                if (res.equals(""))
                                    res = cs;
                                else
                                    System.out.println("StubMapImpl: Multi non-inner impl class with complete interface methods for "+stubClass);
                            }
                        }
                        if (res.equals("")){
                            System.out.println("StubMapImpl: impl classes are all inner class for "+stubClass);
                            res=tmp.iterator().next();
                        }
                        serviceStubClassMapImplClass.put(stubClass,res);
                    }
                }
            }

            for (String stubClass:serviceStubClassMapImplClass.keySet()){
                for (String rawInterfaceSig:stubClassNameMapRawInterfaces.get(stubClass)){
                    String implClass = serviceStubClassMapImplClass.get(stubClass);
                    String implInterfaceSig = StringUtil.replaceDeclaredClassOfMethodSig(rawInterfaceSig,implClass);

                    if (implClass.equals("null"))
                        continue;
                    if ( !Memory.methodSignatureMapSootMethod.containsKey(implInterfaceSig)
                            || (Memory.methodSignatureMapSootMethod.containsKey(implInterfaceSig) && !Memory.methodSignatureMapSootMethod.get(implInterfaceSig).isConcrete())
                            || CG.isBaseClassMethod(implInterfaceSig)){
                        ArrayList<String> res = new ArrayList<>(CG.getImplMethodSigsFromSonClasses(implInterfaceSig));
                        if (res.size()==0){
                            System.out.println("readFormatFile(): Get Real Impl Service Interface Failed for "+implInterfaceSig);
                        }else if (res.size()==1){
                            implInterfaceSig=res.get(0);
                            serviceStubClassMapImplClass.put(stubClass,StringUtil.getDeclareClassFromMethodSig(implInterfaceSig));
                        }else if (res.size()>1){
                            System.out.println("readFormatFile(): Get More than one Real Impl Service Interface for "+implInterfaceSig);
                            implInterfaceSig=res.get(0);
                        }
                    }
                    implInterfaceSigs.add(implInterfaceSig);
                    rawInterfaceSigMapImplInterfaceSig.put(rawInterfaceSig, implInterfaceSig);
                    implInterfaceSigMapRawInterfaceSig.put(implInterfaceSig, rawInterfaceSig);
                }
            }

            Recorder.showStubClassMapImplClass();

        } catch (Exception e) {
            e.printStackTrace();
        }

    }

    public static String replaceArrayFormatFromJavaToSoot(String methodSig) {
        if (methodSig.contains("[")) {
            methodSig = methodSig.replace("[B", "byte[]").replace("[I", "int[]").
                    replace("[Z", "boolean[]").replace("[F", "float[]").
                    replace("[C", "char[]").replace("[S", "short[]").
                    replace("[J", "long[]").replace("[D", "double[]");
            while (methodSig.contains("[L")) {
                String target = methodSig.substring(methodSig.indexOf("[L"), methodSig.indexOf(";") + 1);
                methodSig = methodSig.replace(target, target.substring(2, target.length() - 1) + "[]");
            }
        }
        return methodSig;
    }

    public static String replaceArraysFormatFromSootToJava(String methodSig) {
        if (methodSig.contains("[]")) {
            methodSig = methodSig.replace("byte[]", "[B").replace("int[]", "[I").
                    replace("boolean[]", "[Z").replace("float[]", "[F").
                    replace("char[]", "[C").replace("short[]", "[S").
                    replace("long[]", "[J").replace("double[]", "[D");
            if (!methodSig.contains("[]"))
                return methodSig;
            String returnType = StringUtil.getReturnTypeFromMethodSig(methodSig);
            if (returnType.contains("[]")) {
                methodSig = methodSig.replace(returnType, "[L" + returnType.substring(0, returnType.length() - 2) + ";");
            }
            if (!methodSig.contains("[]"))
                return methodSig;
            String[] params = StringUtil.extractMethodParamArrayFromMethodSig(methodSig);
            for (String param : params) {
                if (param.contains("[]"))
                    methodSig = methodSig.replace(param,"[L" + param.substring(0, param.length() - 2) + ";");
            }
            return methodSig;
        }
        return methodSig;
    }

    public static void getDeserializationMethodsForInterfaces(){
        for (String interfaceSig:allRawInterfaceSigs){
            String onTransactMethodSig = "<"+StringUtil.getDeclareClassFromMethodSig(interfaceSig).replace("$Proxy","")+": boolean onTransact(int,android.os.Parcel,android.os.Parcel,int)>";
            String invokeInterfaceSig = interfaceSig.replace("$Stub$Proxy","");
            HashSet<String> methodSigsInDeserialization = getDeserializationMethodsForInterface(onTransactMethodSig,invokeInterfaceSig);
            if (rawInterfaceSigMapImplInterfaceSig.containsKey(interfaceSig)){
                methodSigsInDeserialization.add(rawInterfaceSigMapImplInterfaceSig.get(interfaceSig));
                methodSigsInDeserialization.remove(invokeInterfaceSig);
            }
            allRawInterfaceSigMapMethodsInDeserialization.put(interfaceSig,methodSigsInDeserialization);
        }
    }

    public static HashSet<String> getDeserializationMethodsForInterface(String onTransactMethodSig, String invokeInterfaceSig){
        HashSet<String> methodSigsInDeserialization = new HashSet<>();
        SootMethod onTransactMethod = Memory.methodSignatureMapSootMethod.get(onTransactMethodSig);
        if (onTransactMethod == null){
            return methodSigsInDeserialization;
        }
        CFG cfg = CFG.getCFG(onTransactMethod);
        for (Unit unit:onTransactMethod.retrieveActiveBody().getUnits()){

            if (((Stmt)unit).containsInvokeExpr() && ((Stmt) unit).getInvokeExpr().getMethod().getSignature().equals(invokeInterfaceSig)){

                methodSigsInDeserialization.add(invokeInterfaceSig);
                Node sourceNode = cfg.getNodeByUnit(unit);
                List<Node> processedNodes = new ArrayList<>();
                List<Node> waitForProcessNodes = new ArrayList<>(sourceNode.precursorNodes);
                while (!waitForProcessNodes.isEmpty()){
                    Node curNode = waitForProcessNodes.get(0);
                    waitForProcessNodes.remove(curNode);
                    if (processedNodes.contains(curNode))
                        continue;
                    processedNodes.add(curNode);
                    Unit curUnit = curNode.unit;
                    if (((Stmt)curUnit).containsInvokeExpr()){
                        String invokeMethodSig = ((Stmt) curUnit).getInvokeExpr().getMethodRef().getSignature();
                        if (invokeMethodSig.equals("<android.os.Parcelable$Creator: java.lang.Object createFromParcel(android.os.Parcel)>")) {
                            String actualMethodSig = transformCreateFromParcel(cfg,curNode,invokeMethodSig);
                            methodSigsInDeserialization.add(actualMethodSig);
                        }else {
                            methodSigsInDeserialization.add(invokeMethodSig);
                        }
                    }
                    waitForProcessNodes.addAll(curNode.precursorNodes);
                }
                return methodSigsInDeserialization;
            }
        }
        return methodSigsInDeserialization;
    }

    private static String transformCreateFromParcel(CFG cfg, Node createFromParcelNode, String createMethodSig){
        Unit unit = createFromParcelNode.unit;
        if (unit.getUseBoxes().size()>0){
            InvokeExpr invokeExpr = ((Stmt)unit).getInvokeExpr();
            Value target = invokeExpr.getUseBoxes().get(invokeExpr.getUseBoxes().size()-1).getValue();
            List<Node> processedNodes = new ArrayList<>();
            List<Node> waitForProcessNodes = new ArrayList<>(createFromParcelNode.precursorNodes);
            while (!waitForProcessNodes.isEmpty()){
                Node curNode = waitForProcessNodes.get(0);
                waitForProcessNodes.remove(curNode);
                if (processedNodes.contains(curNode))
                    continue;
                processedNodes.add(curNode);
                Unit curUnit = curNode.unit;
                if (curUnit instanceof JAssignStmt && ClassAnalyzer.isValueDefinedInUnit(curUnit,target)
                        && ((JAssignStmt) curUnit).getRightOp().toString().endsWith("android.os.Parcelable$Creator CREATOR>")){
                    String targetClassName = ((JAssignStmt) curUnit).getFieldRef().getField().getDeclaringClass().getName();
                    String transformedMethodSig =  "<"+targetClassName+": void <init>("+String.join(",",StringUtil.extractMethodParamArrayFromMethodSig(createMethodSig))+")>";
                    if (Memory.methodSignatureMapSootMethod.containsKey(transformedMethodSig))
                        return transformedMethodSig;
                    else{
                        for (int i=1;i<=36;++i){
                            transformedMethodSig = "<"+targetClassName+"$"+i+": "+targetClassName+" createFromParcel(android.os.Parcel)>";
                            if (Memory.methodSignatureMapSootMethod.containsKey(transformedMethodSig))
                                return transformedMethodSig;
                        }
                        System.out.println("Not Found Feat Method for "+createMethodSig);
                        return createMethodSig;
                    }
                }
                waitForProcessNodes.addAll(curNode.precursorNodes);
            }
        }
        return createMethodSig;
    }

    public static HashMap<String,String> readServiceList() {
        HashMap<String,String> serviceNameMapIBinderClassName = new HashMap<>();
        try {
            BufferedReader in = new BufferedReader(new FileReader(Common.ServiceListPath));
            String str;
            while ((str = in.readLine()) != null) {
                String[] arr = str.split(":");
                String serviceName = arr[0].trim();
                String iBinderClassName = arr[1].trim().substring(1,arr[1].length()-2);
                serviceNameMapIBinderClassName.put(serviceName,iBinderClassName);
            }
            in.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return serviceNameMapIBinderClassName;
    }

    // ************************** database operations ****************************
    private static void insertStubService() {
        Common.database.executeUpdate("create table if not exists StubService (" +
                "Key text primary key," +
                "StubClassName text," +
                "ImplClassName text" +
                ");");

        for (String serviceName : ServiceInterfaces.serviceNameMapStubClass.keySet()) {
            String value = StringUtil.sqlString(serviceName) + "," +
                    StringUtil.sqlString(serviceNameMapStubClass.get(serviceName)) + "," +
                    StringUtil.sqlString(serviceStubClassMapImplClass.get(serviceNameMapStubClass.get(serviceName)));
            Common.database.executeUpdate("insert into StubService (Key,StubClassName,ImplClassName) values (" + value + ");");
        }
    }

    private static void insertServiceInterfaceSignature() {
        Common.database.executeUpdate("create table if not exists ServiceInterfaceSignature (" +
                "RawSignature text primary key," +
                "ImplSignature text" +
                ");");
        for (String rawsig : rawInterfaceSigMapImplInterfaceSig.keySet()) {
            String value = StringUtil.sqlString(rawsig) + "," + StringUtil.sqlString(rawInterfaceSigMapImplInterfaceSig.get(rawsig));
            Common.database.executeUpdate("insert into ServiceInterfaceSignature (RawSignature,ImplSignature) values (" + value + ");");
        }
    }

    private static void insertNativeServiceInterfacesSignature(){
        Common.database.executeUpdate("create table if not exists NativeServiceInterfaceSignatures (InterfaceSignature text primary key);");
        for (String sig:nativeRawInterfaceSigs){
            Common.database.executeUpdate("insert into NativeServiceInterfaceSignatures (InterfaceSignature) values ("+StringUtil.sqlString(sig)+");");
        }
    }

    private static void readServiceNameMapStubClassFromDatabase() {
        try {
            ResultSet resultSet = Common.database.select("select * from StubService;");
            while (resultSet != null && resultSet.next()) {
                String serviceName = resultSet.getString("Key");
                String stubClassName = resultSet.getString("StubClassName");
                String implClassName = resultSet.getString("ImplClassName");

                serviceNameMapStubClass.put(serviceName, stubClassName);
                stubClassMapServiceName.put(stubClassName, serviceName);
                if (!implClassName.equals("Null"))
                    serviceStubClassMapImplClass.put(stubClassName, implClassName);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void readRawInterfaceSigMapImplInterfaceSig() {
        try {
            ResultSet resultSet = Common.database.select("select * from ServiceInterfaceSignature;");
            while (resultSet != null && resultSet.next()) {
                String rawSig = resultSet.getString("RawSignature");
                String implSig = rawSig;

                frameworkRawInterfaceSigs.add(rawSig);
                if ((Memory.methodSignatureMapSootMethod.containsKey(implSig) && Memory.methodSignatureMapSootMethod.get(implSig).isAbstract())
                        || CG.isBaseClassMethod(implSig)){
                    ArrayList<String> res = new ArrayList<String>(CG.getImplMethodSigsFromSonClasses(implSig));
                    if (res.size()==1){
                        implSig=res.get(0);
                    }else if (res.size()>1){
                        implSig=res.get(0);
                        System.out.println("ServiceInterface: Get More than one Real Impl Service Interface for: "+implSig);
                    }else {
                        System.out.println("ServiceInterface: Get Real Impl Service Interface Failed for: "+implSig);
                    }
                }
                implInterfaceSigs.add(implSig);
                rawInterfaceSigMapImplInterfaceSig.put(rawSig, implSig);
                implInterfaceSigMapRawInterfaceSig.put(implSig, rawSig);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void readNativeInterfaceSigs(){
        try {
            ResultSet resultSet = Common.database.select("select * from NativeServiceInterfaceSignatures;");
            while (resultSet!=null && resultSet.next()){
                String nativeInterfaceSig = resultSet.getString("InterfaceSignature");
                nativeRawInterfaceSigs.add(nativeInterfaceSig);
            }
        }catch (Exception e){
            e.printStackTrace();
        }
    }

}
