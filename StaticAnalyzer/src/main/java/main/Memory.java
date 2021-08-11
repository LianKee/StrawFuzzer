package main;

import analysis.callChainsExtractor.CG;
import config.Common;
import dataflow.ClassAnalyzer;

import analysis.callChainsExtractor.UnAcquirablePermissions;
import serviceInterfaces.ServiceInterfaces;
import soot.*;
import soot.jimple.InvokeExpr;
import soot.jimple.Stmt;
import util.LogUtil;
import util.StringUtil;
import util.TimeMeasurement;

import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.Queue;
import java.util.concurrent.ConcurrentHashMap;

public class Memory {

    public static ConcurrentHashMap<String, SootClass> classNameMapSootClass = new ConcurrentHashMap<>();
    public static ConcurrentHashMap<String, String> stubClassNameMapImplClassName = new ConcurrentHashMap<>();
    public static ConcurrentHashMap<String, HashSet<String>> stubClassNameMapMultiImplClassNames = new ConcurrentHashMap<>();

    public static ConcurrentHashMap<String, String> sonClassNameMapFatherClassName = new ConcurrentHashMap<>();
    public static ConcurrentHashMap<String, HashSet<String>> fatherClassNameMapSonClassNames = new ConcurrentHashMap<>();
    public static ConcurrentHashMap<String, HashSet<String>> abstractClassNameMapNonAbstractSonClassNames = new ConcurrentHashMap<>();

    public static ConcurrentHashMap<String, HashSet<String>> implClassNameMapInterfaceClassNames = new ConcurrentHashMap<>();
    public static ConcurrentHashMap<String, HashSet<String>> interfaceClassNameMapImplClassNames = new ConcurrentHashMap<>();

    public static ConcurrentHashMap<String, SootMethod> methodSignatureMapSootMethod = new ConcurrentHashMap<>();
    public static ConcurrentHashMap<String, HashSet<String>> methodNameMapMethodSignatures = new ConcurrentHashMap<>();

    public static ConcurrentHashMap<String, HashSet<String>> calleeMethodSignatureMapCallerMethodSignatures = new ConcurrentHashMap<>();
    public static ConcurrentHashMap<String, HashSet<String>> callerMethodSignatureMapCalleeMethodSignatures = new ConcurrentHashMap<>();

    public static HashMap<Body, HashMap<InvokeExpr,String>> CGMethodMap = new HashMap<>();

    public static ConcurrentHashMap<String, HashSet<String>> simpleClassNameMapFullClassNames = new ConcurrentHashMap<>();
    public static ConcurrentHashMap<String, String> swappedMethodSignatureMapActualMethodSignature = new ConcurrentHashMap<>();

    public static void reset(){
        classNameMapSootClass.clear();
        stubClassNameMapImplClassName.clear();
        stubClassNameMapMultiImplClassNames.clear();
        sonClassNameMapFatherClassName.clear();
        fatherClassNameMapSonClassNames.clear();
        abstractClassNameMapNonAbstractSonClassNames.clear();
        implClassNameMapInterfaceClassNames.clear();
        interfaceClassNameMapImplClassNames.clear();
        methodSignatureMapSootMethod.clear();
        methodNameMapMethodSignatures.clear();
        calleeMethodSignatureMapCallerMethodSignatures.clear();
        callerMethodSignatureMapCalleeMethodSignatures.clear();
        CGMethodMap.clear();
        simpleClassNameMapFullClassNames.clear();
        swappedMethodSignatureMapActualMethodSignature.clear();
    }

    public static void init_forFramework() {
        init_forFramework(false);
    }

    public static void init_forFramework(boolean initFromDatabase) {
        TimeMeasurement.show("Memory init start");
        initBase();

        // init Service interfaces from DB or service interface list file
        ServiceInterfaces.init(initFromDatabase);
        // update stubClassNameMapImplClassName
        for (String stubClassName:ServiceInterfaces.serviceStubClassMapImplClass.keySet())
            stubClassNameMapImplClassName.put(stubClassName,ServiceInterfaces.serviceStubClassMapImplClass.get(stubClassName));
        filterServiceInterfaceByPermission();
        // build CG
        CG.buildCallGraph();
        TimeMeasurement.show("Memory init end");
    }


    private static void initBase(){
        // reset before init
        reset();
        // initialization
        for (SootClass sootClass : Scene.v().getClasses()){
            String sootClassName = sootClass.getName();
            classNameMapSootClass.put(sootClassName, sootClass);
            for (SootMethod sootMethod:sootClass.getMethods()){
                if (!ClassAnalyzer.isValidMethod(sootMethod))
                    continue;
                methodSignatureMapSootMethod.put(sootMethod.getSignature(), sootMethod);
            }
        }
        for (SootClass sootClass : Scene.v().getClasses()) {
            String sootClassName = sootClass.getName();
            if (ClassAnalyzer.isValidClass(sootClassName)){
                String simpleClassName = sootClassName.substring(sootClassName.lastIndexOf(".")+1);
                if (!simpleClassNameMapFullClassNames.containsKey(simpleClassName))
                    simpleClassNameMapFullClassNames.put(simpleClassName,new HashSet<>());
                simpleClassNameMapFullClassNames.get(simpleClassName).add(sootClassName);
            }
            if (sootClass.hasSuperclass()) {
                SootClass superClass = sootClass.getSuperclass();
                String fatherClassName = superClass.getName();
                if (!fatherClassName.equals(sootClassName)){
                    sonClassNameMapFatherClassName.put(sootClassName, fatherClassName);
                    if (!fatherClassNameMapSonClassNames.containsKey(fatherClassName))
                        fatherClassNameMapSonClassNames.put(fatherClassName,new HashSet<>());
                    fatherClassNameMapSonClassNames.get(fatherClassName).add(sootClassName);
                    if (fatherClassName.contains("$Stub")){
                        if (!stubClassNameMapMultiImplClassNames.containsKey(fatherClassName)){
                            stubClassNameMapMultiImplClassNames.put(fatherClassName,new HashSet<>());
                        }
                        stubClassNameMapMultiImplClassNames.get(fatherClassName).add(sootClassName);
                        stubClassNameMapImplClassName.put(fatherClassName, sootClassName);
                    }
                }
            }
            for (SootClass interFace : sootClass.getInterfaces()) {
                String interfaceName = interFace.getName();
                if (!implClassNameMapInterfaceClassNames.containsKey(sootClassName)) {
                    implClassNameMapInterfaceClassNames.put(sootClassName, new HashSet<>());
                }
                implClassNameMapInterfaceClassNames.get(sootClassName).add(interfaceName);

                if (!interfaceClassNameMapImplClassNames.containsKey(interfaceName))
                    interfaceClassNameMapImplClassNames.put(interfaceName,new HashSet<>());
                interfaceClassNameMapImplClassNames.get(interfaceName).add(sootClassName);
            }
            for (SootMethod sootMethod : sootClass.getMethods()) {
                if (!ClassAnalyzer.isValidMethod(sootMethod))
                    continue;
                callerMethodSignatureMapCalleeMethodSignatures.put(sootMethod.getSignature(), new HashSet<String>());
                if (!methodNameMapMethodSignatures.containsKey(sootMethod.getName()))
                    methodNameMapMethodSignatures.put(sootMethod.getName(), new HashSet<String>());
                methodNameMapMethodSignatures.get(sootMethod.getName()).add(sootMethod.getSignature());
                try {
                    if (sootMethod.isConcrete()) {
                        Body body = sootMethod.retrieveActiveBody();
                        for (Unit unit : body.getUnits()) {
                            if (((Stmt) unit).containsInvokeExpr()) {
                                String tmpMethodName = ((Stmt) unit).getInvokeExpr().getMethodRef().getName();
                                String tmpSig = ((Stmt) unit).getInvokeExpr().getMethodRef().getSignature();
                                if (!ClassAnalyzer.isValidMethodSignature(tmpSig)){
                                    continue;
                                }
                                if (!methodNameMapMethodSignatures.containsKey(tmpMethodName))
                                    methodNameMapMethodSignatures.put(tmpMethodName, new HashSet<String>());
                                methodNameMapMethodSignatures.get(tmpMethodName).add(tmpSig);

                                // call graph records
                                callerMethodSignatureMapCalleeMethodSignatures.get(sootMethod.getSignature()).add(tmpSig);
                                // calleeMapCaller init in CG.buildCG
                            }
                        }
                    }
                } catch (Exception e) {
                    System.out.println("Memory init Exception:"+e.getMessage());
                }
            }
        }
    }

    public static SootClass load_class(String className){
        if (classNameMapSootClass.containsKey(className))
            return classNameMapSootClass.get(className);
        try{
            SootClass sootClass = Scene.v().getSootClass(className);
            if (sootClass!=null){
                classNameMapSootClass.put(className,sootClass);
                return sootClass;
            }
        }catch (Exception e){
            return null;
        }
        return null;
    }

    public static SootMethod load_method(String methodSig){
        try {
            if (methodSignatureMapSootMethod.containsKey(methodSig))
                return methodSignatureMapSootMethod.get(methodSig);
            SootMethod sm = Scene.v().getMethod(methodSig);
            if(sm!=null) {
                methodSignatureMapSootMethod.put(methodSig, sm);
                return sm;
            }
            return null;
        }catch (Exception e){
            return null;
        }
    }

    public static HashSet<String> getNonAbstractSonClasses(String fatherClassName){
        if (abstractClassNameMapNonAbstractSonClassNames.containsKey(fatherClassName))
            return abstractClassNameMapNonAbstractSonClassNames.get(fatherClassName);
        HashSet<String> nonAbstractSonClasses = new HashSet<>();
        if (!fatherClassNameMapSonClassNames.containsKey(fatherClassName))
            return nonAbstractSonClasses;

        Queue<String> records = new LinkedList<>(fatherClassNameMapSonClassNames.get(fatherClassName));
        while (!records.isEmpty()){
            String curClassName = records.poll();
            if (classNameMapSootClass.containsKey(curClassName)){
                if (classNameMapSootClass.get(curClassName).isAbstract()){
                    if (fatherClassNameMapSonClassNames.containsKey(curClassName)){
                        records.addAll(fatherClassNameMapSonClassNames.get(curClassName));
                    }
                }else{
                    nonAbstractSonClasses.add(curClassName);
                }
            }
        }
        abstractClassNameMapNonAbstractSonClassNames.put(fatherClassName,nonAbstractSonClasses);
        return nonAbstractSonClasses;
    }

    // reduce FP without introducing FN
    public static void filterServiceInterfaceByPermission(){
        for (String implInterfaceSig : ServiceInterfaces.implInterfaceSigs){
            SootMethod sootMethod = methodSignatureMapSootMethod.get(implInterfaceSig);
            if (sootMethod == null){
                LogUtil.log("SootMethod is Null for" + implInterfaceSig);
                continue;
            }
            if (isAccessible(sootMethod))
                ServiceInterfaces.accessibleImplInterfaceSigs.add(implInterfaceSig);
        }
    }

    public static boolean isAccessible(SootMethod sootMethod){
        try {
            Body body = sootMethod.retrieveActiveBody();
            for (Unit unit : body.getUnits()){
                if (((Stmt)unit).containsInvokeExpr()){
                    if (UnAcquirablePermissions.permissionCheckMethodSigs.contains(((Stmt) unit).getInvokeExpr().getMethodRef().getSignature())){
                        for(Value value : ((Stmt) unit).getInvokeExpr().getArgs()){
                            if (UnAcquirablePermissions.systemPermissions.contains(value.toString().replace("\"","")))
                                return false;
                        }
                    }
                    return true;
                }
            }
            return true;
        }catch (Exception e){
            e.printStackTrace();
            return false;
        }
    }


    private static void insert() {
        Common.database.executeUpdate(
                "CREATE TABLE IF NOT EXISTS " + "MethodNameMapMethodSignatures" + " (" + "ID				INTEGER  PRIMARY KEY AUTOINCREMENT,"
                        + "MethodName     TEXT,"
                        + "MethodSignatures		TEXT"
                        + ");");
        for (String name : methodNameMapMethodSignatures.keySet()) {
            String value = StringUtil.sqlString(name) + "," +
                    StringUtil.sqlString(StringUtil.join(methodNameMapMethodSignatures.get(name), "\\|"));
            Common.database.executeUpdate(
                    "INSERT INTO " + "MethodNameMapMethodSignatures" + " ("
                            + "MethodName,MethodSignatures)"
                            + "VALUES (" + value + ");"
            );
        }
    }

}
