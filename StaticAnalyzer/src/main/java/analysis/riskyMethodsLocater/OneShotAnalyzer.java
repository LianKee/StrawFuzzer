package analysis.riskyMethodsLocater;

import analysis.callChainsExtractor.BackwardReachabilityAnalysis;
import cfg.CFG;
import cfg.Node;
import dataflow.ClassAnalyzer;
import javafx.util.Pair;
import config.Common;
import main.Memory;
import soot.*;
import soot.jimple.*;
import soot.jimple.internal.JAssignStmt;
import soot.jimple.internal.JNewArrayExpr;
import util.StringUtil;
import util.TimeMeasurement;


import java.util.*;


public class OneShotAnalyzer {
    public static HashSet<SootMethod> potentialRiskyMethods = new HashSet<>();
    public static HashSet<SootMethod> newArrayMethodsInDeserialization = new HashSet<>(); // 用于createTypedObjectArray
    public static HashMap<SootMethod, HashSet<Pair<Unit, ArrayList<Value>>>> riskyMethodMapUnitAndValue = new HashMap<>();
    public static HashMap<String,HashSet<String>> reachableMethodSigMapStrawInstructions=new HashMap<>();

    public static ArrayList<String> TPCandidatesInUnparcel = new ArrayList<>();
    public static HashSet<SootMethod> reachableRiskyMethods = new HashSet<>();

    public static HashMap<String, HashSet<String>> riskyMethodMapImplEntryInterfaces = new HashMap<>();
    public static HashMap<String, ArrayList<String>> riskyMethodMapRankedImplServiceInterfaces = new HashMap<>();

    private static String[] specialRiskyMethodSigs= new String[]{
            "<android.os.Parcel: void readList(java.util.List,java.lang.ClassLoader)>",
            "<android.os.Parcel: void readStringList(java.util.List)>",
            "<android.os.Parcel: void readBinderList(java.util.List)>",
            "<android.os.Parcel: void readTypedList(java.util.List,android.os.Parcelable$Creator)>",
            "<android.os.Parcel: java.util.List readParcelableList(java.util.List,java.lang.ClassLoader)>",
            "<android.os.Parcel: android.os.Parcelable readParcelable(java.lang.ClassLoader)>",
    };
    public static HashSet<String> specialRiskyMethodSigSet = new HashSet<>(Arrays.asList(specialRiskyMethodSigs));


    public static void init(){
        potentialRiskyMethods = new HashSet<>();
        newArrayMethodsInDeserialization = new HashSet<>();
        riskyMethodMapUnitAndValue = new HashMap<>();
        TPCandidatesInUnparcel = new ArrayList<>();
        reachableRiskyMethods = new HashSet<>();
        reachableMethodSigMapStrawInstructions = new HashMap<>();
        riskyMethodMapImplEntryInterfaces=new HashMap<>();
        riskyMethodMapRankedImplServiceInterfaces = new HashMap<>();
        TimeMeasurement.show("OneShotAnalyzer start");
        searchOneShotRiskyMethods();
        TimeMeasurement.show("OneShotAnalyzer end");
    }

    private static void searchOneShotRiskyMethods(){
        for(SootClass sootClass: Scene.v().getClasses()){
            if(!ClassAnalyzer.isValidClass(sootClass))
                continue;
            for(SootMethod sootMethod:sootClass.getMethods()){
                try{
                    if(isRiskyMethod(sootMethod)){
                        if (sootMethod.getSignature().endsWith("newArray(int)>")){
                            newArrayMethodsInDeserialization.add(sootMethod);
                        } else{
                            potentialRiskyMethods.add(sootMethod);
                        }
                    }
                }catch (Exception e){
                    e.printStackTrace();
                }

            }
        }
        riskyMethodsInDeserializationInit();
        for (String methodSig:specialRiskyMethodSigs){
            if (Memory.methodSignatureMapSootMethod.containsKey(methodSig))
                potentialRiskyMethods.add(Memory.methodSignatureMapSootMethod.get(methodSig));
        }

        for (SootMethod potentialRiskyMethod: potentialRiskyMethods){
            if (BackwardReachabilityAnalysis.getImplEntryPointsForMethod(potentialRiskyMethod, Common.oneShot_type).size()>0){
                if (riskyMethodMapUnitAndValue.containsKey(potentialRiskyMethod)){
                    for (Pair<Unit,ArrayList<Value>> pair:riskyMethodMapUnitAndValue.get(potentialRiskyMethod)){
                        MethodAndStrawInstructionPair msPair = new MethodAndStrawInstructionPair(potentialRiskyMethod.getSignature(),pair.getKey().toString());
                        if (BackwardReachabilityAnalysis.getAllEntryPointsForMSPair(msPair,Common.oneShot_type).size()>0){
                            reachableRiskyMethods.add(potentialRiskyMethod);
                            if (!reachableMethodSigMapStrawInstructions.containsKey(msPair.getKey())){
                                reachableMethodSigMapStrawInstructions.put(msPair.getKey(), new HashSet<>());
                            }
                            reachableMethodSigMapStrawInstructions.get(msPair.getKey()).add(msPair.getValue());
                        }
                    }
                }else{
                    MethodAndStrawInstructionPair msPair = new MethodAndStrawInstructionPair(potentialRiskyMethod.getSignature(),"--------- No Unit ---------");
                    if (BackwardReachabilityAnalysis.getAllEntryPointsForMSPair(msPair,Common.oneShot_type).size()>0){
                        reachableRiskyMethods.add(potentialRiskyMethod);
                        if (!reachableMethodSigMapStrawInstructions.containsKey(msPair.getKey())){
                            reachableMethodSigMapStrawInstructions.put(msPair.getKey(), new HashSet<>());
                        }
                        reachableMethodSigMapStrawInstructions.get(msPair.getKey()).add(msPair.getValue());
                    }
                }

            }
        }
    }

    public static boolean isRiskyMethod(SootMethod sootMethod){
        if(!sootMethod.isConcrete())
            return false;
        Body body = null;
        try{
            body = sootMethod.retrieveActiveBody();
            if (body == null)
                return false;
        }catch (Exception e){
            return false;
        }

        List<Local> params = body.getParameterLocals();
        Map<Local, Boolean> pollutedLocals = new HashMap<>();
        for(Local local: params){
            pollutedLocals.put(local,false);
        }

        for(Unit unit: body.getUnits()){
            if(unit instanceof JAssignStmt){
                JAssignStmt assignStmt = (JAssignStmt) unit;
                Value left = assignStmt.leftBox.getValue();
                if(!(left instanceof Local)){
                    if(left.getUseBoxes().size()==0)
                        continue;
                    left = left.getUseBoxes().get(0).getValue();
                }
                if(isPolluted(assignStmt,params)){
                    params.add((Local) left);
                    pollutedLocals.put((Local) left, false);
                }

                if(assignStmt.containsInvokeExpr()){
                    InvokeExpr invokeExpr = assignStmt.getInvokeExpr();
                    if(invokeExpr.getMethodRef().getSignature().equals("<android.os.Parcel: int readInt()>")){
                        params.add((Local) left);
                        pollutedLocals.put((Local) left, false);
                    }
                }

                if(assignStmt.getRightOp() instanceof JNewArrayExpr){
                    JNewArrayExpr newArrayExpr = (JNewArrayExpr) assignStmt.getRightOp();
                    if (newArrayExpr.getSize() instanceof IntConstant)
                        continue;
                    Local target = (Local) newArrayExpr.getSize();
                    if(params.contains(target)){
                        if (!hasUpperBoundCheck(sootMethod,unit,newArrayExpr.getSize())){
                            ArrayList<Value> values = new ArrayList<>();
                            values.add(newArrayExpr.getSize());
                            if (!riskyMethodMapUnitAndValue.containsKey(sootMethod)){
                                riskyMethodMapUnitAndValue.put(sootMethod,new HashSet<>());
                            }
                            riskyMethodMapUnitAndValue.get(sootMethod).add(new Pair<>(unit,values));
                            return true;
                        }
                    }
                }
            }else if (((Stmt)unit).containsInvokeExpr()){
                InvokeExpr invokeExpr = ((Stmt) unit).getInvokeExpr();
                if (invokeExpr.getMethodRef().getSignature().endsWith("void <init>(int)>")){
                    if (invokeExpr.getArg(0) instanceof IntConstant)
                        continue;
                    Local arg = (Local) invokeExpr.getArg(0);
                    if (params.contains(arg)){
                        SootClass objectClass = invokeExpr.getMethodRef().getDeclaringClass();
                        if (SearchRootSet.isIterableType(objectClass.getName())){
                            if (!hasUpperBoundCheck(sootMethod,unit,arg)){
                                // record for riskyMethodMapUnitAndValue
                                ArrayList<Value> values = new ArrayList<>();
                                values.add(arg);
                                if (!riskyMethodMapUnitAndValue.containsKey(sootMethod)){
                                    riskyMethodMapUnitAndValue.put(sootMethod,new HashSet<>());
                                }
                                riskyMethodMapUnitAndValue.get(sootMethod).add(new Pair<>(unit,values));
                                return true;
                            }
                        }
                    }
                }
            }
        }
        return false;
    }

    public static boolean isPolluted(JAssignStmt assignStmt, List<Local> params){
        Value right = assignStmt.rightBox.getValue();
        ArrayList<Value> rights = new ArrayList<>();
        for(ValueBox valueBox:right.getUseBoxes()){
            if (valueBox.getValue() instanceof Local){
                rights.add(valueBox.getValue());
            }
        }
        boolean ispolluted = false;
        for(Value r:rights){
            if(params.contains(r)){
                ispolluted = true;
            }
        }
        return ispolluted;
    }

    public static boolean hasUpperBoundCheck(SootMethod sootMethod, Unit sourceUnit, Value value){
        CFG cfg = CFG.getCFG(sootMethod);
        if (cfg==null)
            return false;
        Node sourceNode = cfg.getNodeByUnit(sourceUnit);

        List<Node> processedNodes = new ArrayList<>();
        List<Node> waitForProcessNodes = new ArrayList<>(sourceNode.precursorNodes);
        while (!waitForProcessNodes.isEmpty()){
            Node curNode = waitForProcessNodes.get(0);
            waitForProcessNodes.remove(curNode);
            if (processedNodes.contains(curNode))
                continue;
            processedNodes.add(curNode);
            Unit curUnit = curNode.unit;
            if (!curUnit.toString().contains(value.toString()))
                continue;
            if (curUnit instanceof IfStmt){
                ConditionExpr expr = (ConditionExpr)((IfStmt) curUnit).getConditionBox().getValue();
                Value op1 = expr.getOp1();
                Value op2 = expr.getOp2();
                if (op1.toString().equals(value.toString())){
                    if (op2 instanceof IntConstant && ((IntConstant) op2).value == 0)
                        return false;
                    else if (expr.toString().contains(">") && !processedNodes.contains(cfg.getNodeByUnit(((IfStmt) curUnit).getTarget())))
                        return true;
                    else
                        return false;
                }else if (op2.toString().equals(value.toString())){
                    if (op1 instanceof IntConstant && ((IntConstant) op1).value == 0)
                        return false;
                    else if (expr.toString().contains("<") && !processedNodes.contains(cfg.getNodeByUnit(((IfStmt) curUnit).getTarget())))
                        return true;
                    else
                        return false;
                }
            }else if (curUnit instanceof AssignStmt && ClassAnalyzer.isValueDefinedInUnit(curUnit, value)){
                return false;
            }else if (curUnit instanceof IdentityStmt) {
                return false;
            }
            waitForProcessNodes.addAll(curNode.precursorNodes);
        }
        return false;
    }

    public static void riskyMethodsInDeserializationInit(){
        if (!TPCandidatesInUnparcel.isEmpty())
            return;

        ArrayList<String> methodsInParcel = new ArrayList<>();
        ArrayList<String> methodsInConstructor = new ArrayList<>();

        for (SootMethod sootMethod: potentialRiskyMethods){
            if (sootMethod.getDeclaringClass().getName().equals("android.os.Parcel"))
                methodsInParcel.add(sootMethod.getSignature());
            else {
                for (Type type:sootMethod.getParameterTypes()){
                    if (type.toString().equals("android.os.Parcel")){
                        methodsInConstructor.add(sootMethod.getSignature());
                        break;
                    }
                }
            }
        }
        TPCandidatesInUnparcel.addAll(methodsInParcel);
        TPCandidatesInUnparcel.addAll(specialRiskyMethodSigSet);
        TPCandidatesInUnparcel.addAll(methodsInConstructor);
    }

    public static boolean isPotentialByCheckParamType(String methodSig){
        String[] params = StringUtil.extractMethodParamArrayFromMethodSig(methodSig);
        for (String param:params){
            if (StringUtil.isBasic(param) || StringUtil.isIInterface(param) || param.equals("android.os.Bundle")){
                continue;
            }else {
                return true;
            }
        }
        return false;
    }

    public static void show(){
        for (SootMethod sootMethod:reachableRiskyMethods){
            System.out.println(sootMethod.getSignature());
        }
    }

}
