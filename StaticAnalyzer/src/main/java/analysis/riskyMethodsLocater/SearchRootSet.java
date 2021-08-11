package analysis.riskyMethodsLocater;


import analysis.callChainsExtractor.BackwardReachabilityAnalysis;
import cfg.CFG;
import dataflow.ClassAnalyzer;
import dataflow.DataFlowAnalyzer;
import config.Common;
import main.Memory;
import serviceInterfaces.ServiceInterfaces;
import soot.*;
import soot.jimple.*;
import util.StringUtil;
import util.TimeMeasurement;

import java.sql.ResultSet;
import java.util.*;


public class SearchRootSet {
    public static HashSet<SootField> allRootSetFields = new HashSet<>();
    public static HashSet<SootMethod> potentialRiskyMethods = new HashSet<>();

    public static HashMap<SootClass,SootField> chainClassMapField = new HashMap<>();
    public static HashSet<MethodAndStrawInstructionPair> methodAndStrawInstructionPairs=new HashSet<>();
    public static HashMap<MethodAndStrawInstructionPair,String> MSPairMapRootSetFieldSig = new HashMap<>();
    public static HashMap<String,HashSet<String>> methodSigMapStrawInstructions = new HashMap<>();

    public static HashSet<SootMethod> reachableRiskyMethods = new HashSet<>();
    public static HashMap<String,HashSet<String>> reachableMethodSigMapStrawInstructions=new HashMap<>();

    public static HashMap<String, HashSet<String>> riskyMethodMapImplEntryInterfaces = new HashMap<>();
    public static HashMap<String, ArrayList<String>> riskyMethodMapRankedImplServiceInterfaces = new HashMap<>();

    private static final String[] strawInstructionPatterns = new String[]{
            "<(java|android)\\.util\\..*(boolean|void) add.*>",
            "<(java|android)\\.util\\..*(java.lang.Object|void) put.*>",
            "<android\\.util\\.Sparse.*void (append|put).*>",
    };

    private static final String[] invokeBoxPatterns = new String[]{
            ".*invoke.*<(java|android)\\.util\\..*(boolean|void) add.*",
            ".*invoke.*<(java|android)\\.util\\..*(java.lang.Object|void) put.*",
            ".*invoke.*<android\\.util\\.Sparse.*void (append|put).*",

    };
    private static final String[] androidSpecificTypeArray = new String[]{
            "android.util.ArrayMap", "android.util.ArraySet", "android.util.SparseArray",
            "android.util.SparseBooleanArray", "android.util.SparseIntArray", "android.util.SparseLongArray",
            "android.database.sqlite.SQLiteDatabase"
    };
    private static final HashSet<String> androidSpecificTypeSet = new HashSet<>(Arrays.asList(androidSpecificTypeArray));

    private static final String[] databaseInsertSig = new String[]{
            "<android.database.sqlite.SQLiteDatabase: long insert(java.lang.String,java.lang.String,android.content.ContentValues)>",
            "<android.database.sqlite.SQLiteDatabase: long insertWithOnConflict(java.lang.String,java.lang.String,android.content.ContentValues,int)>",
    };
    private static final HashSet<String> databaseInsertSigSet = new HashSet<>(Arrays.asList(databaseInsertSig));

    private static void reset(){
        allRootSetFields.clear();
        potentialRiskyMethods.clear();
        chainClassMapField.clear();
        methodAndStrawInstructionPairs.clear();
        MSPairMapRootSetFieldSig.clear();
        methodSigMapStrawInstructions.clear();
        reachableRiskyMethods.clear();
        reachableMethodSigMapStrawInstructions.clear();
        riskyMethodMapImplEntryInterfaces.clear();
        riskyMethodMapRankedImplServiceInterfaces.clear();
    }

    public static void init_forFramework(Boolean fromDatabase) {
        reset();
        if (fromDatabase)
            initFromDatabase();
        else
            initFromSoot();
    }

    private static void initFromDatabase() {
        // step1: find all root set objects
        getAllSingletonField();
        TimeMeasurement.show("Search RootSet Field end. Size:"+allRootSetFields.size());
        // step2: find all method and straw instruction pairs
        getAllStrawInstructions();
        TimeMeasurement.show("Search raw straw instructions end. Size:"+methodAndStrawInstructionPairs.size());
        // step3: read reachability analysis results from DB
        readReachableMethods();
        TimeMeasurement.show("SearchRootSet init from Database end");
    }

    private static void initFromSoot() {
        // step1: find all root set objects
        getAllSingletonField();
        TimeMeasurement.show("Search RootSet Field end. Size:"+allRootSetFields.size());
        // step2: find all method and straw instruction pairs
        getAllStrawInstructions();
        TimeMeasurement.show("Search raw straw instructions end. Size:"+methodAndStrawInstructionPairs.size());
        // step3: reachability analysis
        for (MethodAndStrawInstructionPair pair:methodAndStrawInstructionPairs){
            if (BackwardReachabilityAnalysis.getAllEntryPointsForMSPair(pair,Common.rootSet_type).size()>0){
                reachableRiskyMethods.add(Memory.methodSignatureMapSootMethod.get(pair.getKey()));
                if (!reachableMethodSigMapStrawInstructions.containsKey(pair.getKey())){
                    reachableMethodSigMapStrawInstructions.put(pair.getKey(), new HashSet<>());
                }
                reachableMethodSigMapStrawInstructions.get(pair.getKey()).add(pair.getValue());
            }
        }
        TimeMeasurement.show("SearchRootSet init from Soot end");
    }


    // get all static fields and fields of singleton and static classes, including class which has static instances by recursion
    private static void getAllSingletonField(){
        HashSet<SootClass> allFieldNeededClass = new HashSet<>();
        // add all static field first
        for (SootClass sootClass : Scene.v().getClasses()) {
            if (ClassAnalyzer.isValidClass(sootClass)) {
                for (SootField sootField:sootClass.getFields()){
                    if (sootField.isStatic()){
                        if (isRootSetType(sootField))
                            allRootSetFields.add(sootField);
                        else {
                            String classType = sootField.getType().toString();
                            if (ClassAnalyzer.isValidClass(classType) && Memory.classNameMapSootClass.containsKey(classType)){
                                allFieldNeededClass.add(Memory.classNameMapSootClass.get(classType));
                            }
                        }
                    }
                }
            }
        }
        // add static class and service impl class
        for (SootClass sootClass : Scene.v().getClasses()) {
            if (ClassAnalyzer.isValidClass(sootClass)) {
                if (sootClass.isStatic() || ServiceInterfaces.serviceStubClassMapImplClass.containsValue(sootClass.getName())) {
                    allFieldNeededClass.add(sootClass);
                }
            }
        }
        // find all needed class by recursion
        ArrayList<SootClass> tobeAnalyzed = new ArrayList<>(allFieldNeededClass);
        HashSet<SootClass> hasbeenAnalyzed = new HashSet<>();
        while (!tobeAnalyzed.isEmpty()){
            SootClass curClass = tobeAnalyzed.remove(0);
            if (hasbeenAnalyzed.contains(curClass))
                continue;
            hasbeenAnalyzed.add(curClass);

            for (SootField sootField:curClass.getFields()){
                if (isRootSetType(sootField))
                    allRootSetFields.add(sootField);
                else{
                    String classType = sootField.getType().toString();
                    if (ClassAnalyzer.isValidClass(classType) && Memory.classNameMapSootClass.containsKey(classType)){
                        SootClass newClass = Memory.classNameMapSootClass.get(classType);
                        if (!hasbeenAnalyzed.contains(newClass) && !tobeAnalyzed.contains(newClass))
                            tobeAnalyzed.add(newClass);
                    }
                }
            }
        }
    }

    public static boolean isRootSetType(SootField sootField){
        if (sootField == null)
            return false;
        String classType = sootField.getType().toString();
        return isRootSetType(classType);
    }

    public static boolean isRootSetType(String classType){
        if (classType.startsWith("java.util")) {
            try {
                Class typeClass = Class.forName(classType);
                return isRootSetTypeOfJavaClass(typeClass);
            } catch (Exception e) {
                return false;
            }
        } else if (classType.startsWith("android.")) {
            if (isRootSetTypeOfAndroidClass(classType))
                return true;
            else {
                // android specific class that implements collection interfaces
                if (Memory.classNameMapSootClass.containsKey(classType)) {
                    for (SootClass interfaceClass : Memory.classNameMapSootClass.get(classType).getInterfaces()) {
                        if (interfaceClass.getName().startsWith("java.")) {
                            try {
                                Class tmpClass = Class.forName(classType);
                                if (isRootSetTypeOfJavaClass(tmpClass))
                                    return true;
                            } catch (Exception e) {
                            }
                        }
                    }
                }
            }
        }
        return false;
    }

    // Note that Class != SootClass
    public static boolean isRootSetTypeOfJavaClass(Class fieldClass) {
        return (java.util.List.class.isAssignableFrom(fieldClass) || java.util.Set.class.isAssignableFrom(fieldClass) ||
                java.util.Map.class.isAssignableFrom(fieldClass) || java.util.Queue.class.isAssignableFrom(fieldClass));
    }

    public static boolean isRootSetTypeOfAndroidClass(String classType) {
        return androidSpecificTypeSet.contains(classType);
    }

    public static boolean isIterableType(String classType){
        if (classType.startsWith("java.util")) {
            try {
                Class typeClass = Class.forName(classType);
                return isRootSetTypeOfJavaClass(typeClass);
            } catch (Exception e) {
                return false;
            }
        } else if (classType.startsWith("android.")) {
            if (classType.equals("android.database.sqlite.SQLiteDatabase"))
                return false;
            return isRootSetTypeOfAndroidClass(classType);
        }
        return false;
    }

    public static void getAllStrawInstructions(){
        for (SootClass sootClass : Scene.v().getClasses()) {
            if (ClassAnalyzer.isValidClass(sootClass)) {
                for (SootMethod sootMethod : sootClass.getMethods()) {
                    if (isValidSootMethod(sootMethod)){
                        try{
                            analyzeForMethod(sootMethod);
                        }catch (Exception e){
                            System.out.println("Wrong"+e.getMessage());
                        }
                    }
                }
            }
        }
        // init methodSigMapStrawInstructions
        for (MethodAndStrawInstructionPair pair:methodAndStrawInstructionPairs){
            SootMethod sootMethod = Memory.methodSignatureMapSootMethod.get(pair.getKey());
            potentialRiskyMethods.add(sootMethod);
            if (!methodSigMapStrawInstructions.containsKey(pair.getKey())){
                methodSigMapStrawInstructions.put(pair.getKey(), new HashSet<>());
            }
            methodSigMapStrawInstructions.get(pair.getKey()).add(pair.getValue());
        }
    }

    public static void analyzeForMethod(SootMethod sootMethod){
        Body body = sootMethod.retrieveActiveBody();
        HashSet<String> newLocals = new HashSet<>();
        HashMap<String,SootField> fieldLocalMapField = new HashMap<>();
        HashMap<SootField,HashSet<Unit>> fieldMapClearUnits = new HashMap<>();

        HashMap<String,Integer> paramLocalMapParamNumber = new HashMap<>();

        for (Unit unit:body.getUnits()){
            // auxiliary information collection
            if (unit instanceof IdentityStmt) {
                String rightOpString = ((IdentityStmt) unit).getRightOp().toString();
                if (rightOpString.startsWith("@parameter")){
                    String paramDesc = ((IdentityStmt) unit).getRightOp().toString().split(": ")[0];
                    int paramCount = Integer.parseInt(paramDesc.replace("@parameter", ""));
                    paramLocalMapParamNumber.put(((IdentityStmt) unit).getLeftOp().toString(), paramCount);
                }
            }
            if (unit instanceof AssignStmt){
                if (((AssignStmt) unit).getRightOp() instanceof NewExpr){
                    newLocals.add(((AssignStmt) unit).getLeftOp().toString());
                }
                if (((AssignStmt) unit).containsFieldRef()
                        && allRootSetFields.contains(((AssignStmt) unit).getFieldRef().getField())
                        && ((AssignStmt) unit).getRightOpBox().equals(((AssignStmt) unit).getFieldRefBox())){
                    String localName = ((AssignStmt) unit).getLeftOp().toString();
                    SootField fieldRef = ((AssignStmt) unit).getFieldRef().getField();
                    fieldLocalMapField.put(localName,fieldRef);
                }
            }
            if (((Stmt)unit).containsInvokeExpr()){
                InvokeExpr invokeExpr = ((Stmt) unit).getInvokeExpr();
                String classType = invokeExpr.getMethodRef().getDeclaringClass().getName();
                if (isRootSetType(classType)){
                    if (invokeExpr.getMethodRef().getName().equals("clear")){
                        String clearLocal = invokeExpr.getUseBoxes().get(invokeExpr.getUseBoxes().size()-1).getValue().toString();
                        if (fieldLocalMapField.containsKey(clearLocal)){
                            SootField clearField = fieldLocalMapField.get(clearLocal);
                            if(!fieldMapClearUnits.containsKey(clearField))
                                fieldMapClearUnits.put(clearField,new HashSet<>());
                            fieldMapClearUnits.get(clearField).add(unit);
                        }
                    }
                }
            }

            // straw instruction check
            if (((Stmt)unit).containsInvokeExpr()){
                InvokeExpr invokeExpr = ((Stmt) unit).getInvokeExpr();
                String methodSig = invokeExpr.getMethodRef().getSignature();
                String classType = invokeExpr.getMethodRef().getDeclaringClass().getName();
                if (isRootSetType(classType) && hasStrawParam(invokeExpr) && isStrawInstruction(methodSig)
                        && !clearedBeforeUse(sootMethod,unit,fieldLocalMapField,fieldMapClearUnits)){
                    if (databaseInsertSigSet.contains(methodSig)){
                        methodAndStrawInstructionPairs.add(new MethodAndStrawInstructionPair(sootMethod.getSignature(),unit.toString()));
                    }else{
                        ValueBox sourceBox = invokeExpr.getUseBoxes().get(invokeExpr.getUseBoxes().size()-1);
                        HashMap<Unit,ValueBox> allTaintUnitsAndValueBoxes = DataFlowAnalyzer.intra_findSinkUnitsAndValueBoxesForThis(body,unit,sourceBox);
                        HashSet<String> allTaintLocals = ClassAnalyzer.getAllValueBoxValues(allTaintUnitsAndValueBoxes);

                        if (ClassAnalyzer.containLocal(allTaintLocals,fieldLocalMapField.keySet())){
                            if (!ClassAnalyzer.containLocal(allTaintLocals,newLocals)) {
                                updateMSPairMapRootSetField(sootMethod,unit.toString(),fieldLocalMapField.get(ClassAnalyzer.getLocal(allTaintLocals,fieldLocalMapField.keySet())));
                                methodAndStrawInstructionPairs.add(new MethodAndStrawInstructionPair(sootMethod.getSignature(),unit.toString()));
                            }
                        }else if (ClassAnalyzer.containLocal(allTaintLocals,paramLocalMapParamNumber.keySet())){
                            int paramIndex = paramLocalMapParamNumber.get(ClassAnalyzer.getLocal(allTaintLocals,paramLocalMapParamNumber.keySet()));
                            if (Memory.calleeMethodSignatureMapCallerMethodSignatures.containsKey(sootMethod.getSignature())){
                                for (String callerSig: Memory.calleeMethodSignatureMapCallerMethodSignatures.get(sootMethod.getSignature())){
                                    SootMethod callerMethod = Memory.methodSignatureMapSootMethod.get(callerSig);
                                    SootField sootField = DataFlowAnalyzer.getRootSetFieldFromCaller(callerMethod,sootMethod,paramIndex,allRootSetFields);
                                    if (sootField!=null){
                                        updateMSPairMapRootSetField(sootMethod,unit.toString(),sootField);
                                        methodAndStrawInstructionPairs.add(new MethodAndStrawInstructionPair(sootMethod.getSignature(),unit.toString()));
                                        break;
                                    }
                                }
                            }
                        }else if (isReturnValueOfMethod(allTaintUnitsAndValueBoxes.keySet())){
                            for (SootMethod invokedMethod:getRelatedMethod(allTaintUnitsAndValueBoxes.keySet())){
                                SootField sootField = DataFlowAnalyzer.getRootSetFieldFromCallee(invokedMethod,allRootSetFields);
                                if (sootField!=null){
                                    updateMSPairMapRootSetField(sootMethod,unit.toString(),sootField);
                                    methodAndStrawInstructionPairs.add(new MethodAndStrawInstructionPair(sootMethod.getSignature(),unit.toString()));
                                    break;
                                }
                            }
                        }

                    }
                }
            }
        }
    }

    public static boolean isStrawInstruction(String methodSig){
        if (databaseInsertSigSet.contains(methodSig))
            return true;
        for (String pattern:strawInstructionPatterns){
            if (methodSig.matches(pattern))
                return true;
        }
        return false;
    }

    public static boolean hasStrawParam(InvokeExpr invokeExpr){
        for (Value value:invokeExpr.getArgs()){
            String type = value.getType().toString();
            if (!StringUtil.notIterabaleTypes.contains(type) && !StringUtil.isIInterface(type))
                return true;
        }
        return false;
    }

    public static boolean clearedBeforeUse(SootMethod sootMethod,Unit unit,HashMap<String,SootField> fieldLocalMapField,HashMap<SootField,HashSet<Unit>> fieldMapClearUnits){
        InvokeExpr invokeExpr = ((Stmt)unit).getInvokeExpr();
        String callerLocal = invokeExpr.getUseBoxes().get(invokeExpr.getUseBoxes().size()-1).getValue().toString();
        if (fieldLocalMapField.containsKey(callerLocal)){
            SootField callerField = fieldLocalMapField.get(callerLocal);
            if (fieldMapClearUnits.containsKey(callerField)){
                CFG cfg = CFG.getCFG(sootMethod);
                if (cfg!=null){
                    for (Unit clearUnit:fieldMapClearUnits.get(callerField)){
                        if (cfg.mustPassedByThisUnit(clearUnit,unit))
                            return true;
                    }
                }
            }
        }
        return false;
    }

    private static boolean isReturnValueOfMethod(Set<Unit> taintUnits){
        HashSet<SootMethod> res = getRelatedMethod(taintUnits);
        return res.size() > 0;
    }

    private static HashSet<SootMethod> getRelatedMethod(Set<Unit> taintUnits){
        HashSet<SootMethod> res = new HashSet<>();
        for (Unit unit:taintUnits){
            if (((Stmt)unit).containsInvokeExpr()){
                res.add(((Stmt) unit).getInvokeExpr().getMethod());
            }
        }
        return res;
    }

    private static boolean isValidSootMethod(SootMethod sootMethod) {
        if (!sootMethod.isConcrete() || sootMethod.getName().equals("<clinit>") || sootMethod.getDeclaringClass().getName().equals("android.os.Parcel"))
            return false;
        String methodName = sootMethod.getName();
        if (sootMethod.getParameterCount() == 0) {
            if (methodName.startsWith("init")) {
                if (sootMethod.getSignature().startsWith("<com.android.server.usb.descriptors.report.UsbStrings:"))
                    return false;
            } else if (methodName.equals("<init>")) {
                return false;
            }
        }
        return ClassAnalyzer.isValidMethod(sootMethod);
    }

    public static void updateMSPairMapRootSetField(SootMethod sootMethod, String unitStr ,SootField sootField){
        MethodAndStrawInstructionPair pair = new MethodAndStrawInstructionPair(sootMethod.getSignature(),unitStr);

        String rootSetFieldStr = "";
        if (sootField.isStatic()){
            rootSetFieldStr = "["+sootField.getDeclaringClass()+","+sootField.getName()+",<null>]";
        }else if (sootField.getDeclaringClass().getName().equals(sootMethod.getDeclaringClass().getName())){
            rootSetFieldStr = "["+sootField.getDeclaringClass()+","+sootField.getName()+",<self>]";
        }else {
            System.out.println("RootSet field is not in the same class with risky method");
        }
        if (!rootSetFieldStr.equals(""))
            MSPairMapRootSetFieldSig.put(pair,rootSetFieldStr);
    }

    public static void getChainClasses(){
        for (SootClass sootClass:Scene.v().getClasses()){
            if (ClassAnalyzer.isValidClass(sootClass)){
                String sootClassName = sootClass.getName();
                for (SootField sootField:sootClass.getFields()){
                    if (sootField.getType().toString().equals(sootClassName)){
                        chainClassMapField.put(sootClass, sootField);
                        break;
                    }
                }
            }
        }
    }

    private static void insertReachableMethods(){
        Common.database.executeUpdate("drop table if exists ReachableMethods_RootSet;");
        Common.database.executeUpdate("create table ReachableMethods_RootSet (MethodSignature text primary key);");
        for (String reachableMethodSig:reachableMethodSigMapStrawInstructions.keySet()){
            Common.database.executeUpdate("insert into ReachableMethods_RootSet (MethodSignature) values (" +
                    StringUtil.sqlString(reachableMethodSig)+");");
        }
    }

    private static void readReachableMethods(){
        try{
            ResultSet resultSet = Common.database.select("select * from ReachableMethods_RootSet;");
            String methodSig;
            while (resultSet!=null && resultSet.next()){
                methodSig = resultSet.getString("MethodSignature");
                reachableRiskyMethods.add(Memory.methodSignatureMapSootMethod.get(methodSig));
                reachableMethodSigMapStrawInstructions.put(methodSig,methodSigMapStrawInstructions.get(methodSig));
            }
        }catch (Exception e){
            e.printStackTrace();
        }
    }

    private static void insertMSPairMapRootSetField(){
        Common.database.executeUpdate("drop table if exists MSPairMapRootSetField;");
        Common.database.executeUpdate("create table if not exists MSPairMapRootSetField (" +
                "MSPair text primary key,"+
                "FieldSig text"+
                ");");
        for (MethodAndStrawInstructionPair msPair : MSPairMapRootSetFieldSig.keySet()) {
            String fieldSig = MSPairMapRootSetFieldSig.get(msPair);
            String value = StringUtil.sqlString(msPair.toString()) + "," + StringUtil.sqlString(fieldSig);
            Common.database.executeUpdate("insert into MSPairMapRootSetField (MSPair,FieldSig) values (" +
                    value + ");");
        }
    }

    private static void readMSPairMapRootSetField(){
        try{
            ResultSet resultSet = Common.database.select("select * from MSPairMapRootSetField;");
            String msPairStr;
            String fieldSig;
            while (resultSet!=null && resultSet.next()){
                msPairStr = resultSet.getString("MSPair");
                fieldSig = resultSet.getString("FieldSig");
                String[] res = msPairStr.split("--");
                MethodAndStrawInstructionPair pair = new MethodAndStrawInstructionPair(res[0],res[1]);
                MSPairMapRootSetFieldSig.put(pair,fieldSig);
            }
        }catch (Exception e){
            e.printStackTrace();
        }
    }

}
