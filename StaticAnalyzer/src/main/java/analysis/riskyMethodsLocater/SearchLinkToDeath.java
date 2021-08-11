package analysis.riskyMethodsLocater;

import analysis.callChainsExtractor.BackwardReachabilityAnalysis;
import dataflow.ClassAnalyzer;
import config.Common;
import main.Memory;
import polyglot.ast.If;
import soot.*;
import soot.jimple.Stmt;
import util.StringUtil;
import util.TimeMeasurement;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;

import static util.StringUtil.extractMethodParamsFromMethodSig;

public class SearchLinkToDeath {
    public static HashSet<SootMethod> potentialRiskyMethods = new HashSet<>();
    public static HashMap<String,HashSet<String>> methodSigMapStrawInstructions = new HashMap<>();
    public static HashSet<String> classesWithIBinder = new HashSet<>();

    public static HashSet<SootMethod> reachableRiskyMethods = new HashSet<>();
    public static HashMap<String,HashSet<String>> reachableMethodSigMapStrawInstructions=new HashMap<>();

    public static HashMap<String, HashSet<String>> riskyMethodMapImplEntryInterfaces = new HashMap<>();
    public static HashMap<String, ArrayList<String>> riskyMethodMapRankedImplServiceInterfaces = new HashMap<>();


    public static void init(){
        potentialRiskyMethods = new HashSet<>();
        methodSigMapStrawInstructions = new HashMap<>();
        reachableRiskyMethods = new HashSet<>();
        reachableMethodSigMapStrawInstructions = new HashMap<>();
        riskyMethodMapImplEntryInterfaces = new HashMap<>();
        riskyMethodMapRankedImplServiceInterfaces = new HashMap<>();

        TimeMeasurement.show("SearchLinkToDeath start");
        searchClassesWithIBinder();
        TimeMeasurement.show("searchClassesWithIBinder end ("+classesWithIBinder.size()+")");
        searchMethodsContainLinkToDeath();
        TimeMeasurement.show("SearchLinkToDeath end");
    }

    private static void searchClassesWithIBinder(){
        for (SootClass sootClass:Scene.v().getClasses()){
            if (sootClass.getInterfaces().size()==1 && sootClass.getInterfaces().iterator().next().getName().equals("android.os.IInterface")){
                String className = sootClass.getName();
                classesWithIBinder.add(className);
            }
        }
        classesWithIBinder.add("android.os.IBinder");

        HashSet<String> toBeAnalyzed = new HashSet<>();
        do {
            toBeAnalyzed.clear();
            for (SootClass sootClass:Scene.v().getClasses()){
                if (classesWithIBinder.contains(sootClass.getName()))
                    continue;
                for (SootField sootField:sootClass.getFields()){
                    String fieldType = sootField.getType().toString();
                    if (classesWithIBinder.contains(fieldType)){
                        classesWithIBinder.add(sootClass.getName());
                        toBeAnalyzed.add(sootClass.getName());
                        break;
                    }
                }
            }
        }while (!toBeAnalyzed.isEmpty());
    }

    private static void searchMethodsContainLinkToDeath(){
        for (SootClass sootClass: Scene.v().getClasses()){
            if (ClassAnalyzer.isValidClass(sootClass)){
                for (SootMethod sootMethod:sootClass.getMethods()){
                    try {
                        if (sootMethod.isConcrete()){
                            Body body = sootMethod.retrieveActiveBody();
                            for (Unit unit:body.getUnits()){
                                if (((Stmt)unit).containsInvokeExpr()){
                                    if (((Stmt) unit).getInvokeExpr().getMethodRef().getSignature().equals("<android.os.IBinder: void linkToDeath(android.os.IBinder$DeathRecipient,int)>")){
                                        potentialRiskyMethods.add(sootMethod);
                                        String methodSig = sootMethod.getSignature();
                                        if (!methodSigMapStrawInstructions.containsKey(methodSig)){
                                            methodSigMapStrawInstructions.put(methodSig,new HashSet<>());
                                        }
                                        methodSigMapStrawInstructions.get(methodSig).add(unit.toString());
                                    }
                                }
                            }
                        }
                    }catch (Exception e){
                    }
                }
            }
        }
        TimeMeasurement.show("searchMethodsContainLinkToDeath end");
        for (SootMethod sootMethod: potentialRiskyMethods){
            String methodSig = sootMethod.getSignature();
            for (String strawUnit:methodSigMapStrawInstructions.get(methodSig)){
                MethodAndStrawInstructionPair msPair = new MethodAndStrawInstructionPair(methodSig,strawUnit);
                if (BackwardReachabilityAnalysis.getAllEntryPointsForMSPair(msPair, Common.linkToDeath_type).size()>0){
                    reachableRiskyMethods.add(sootMethod);
                    if (!reachableMethodSigMapStrawInstructions.containsKey(methodSig)){
                        reachableMethodSigMapStrawInstructions.put(methodSig, new HashSet<>());
                    }
                    reachableMethodSigMapStrawInstructions.get(methodSig).add(strawUnit);
                }
            }


        }
        TimeMeasurement.show("backward analysis end");
    }


    public static boolean hasParamContainsIInterface(String methodSig){
        for (String param:extractMethodParamsFromMethodSig(methodSig)){
            if (classesWithIBinder.contains(param))
                return true;
        }
        return false;
    }


    public static boolean containRiskyMethod(SootMethod sootMethod){
        return reachableRiskyMethods.contains(sootMethod);
    }

    public static boolean containRiskyMethod(String methodSig){
        if (Memory.methodSignatureMapSootMethod.containsKey(methodSig)){
            return containRiskyMethod(Memory.methodSignatureMapSootMethod.get(methodSig));
        }
        return false;
    }

    public static void show(){
        System.out.println("===================== Reachable Methods that contain linkToDeath ("+reachableRiskyMethods.size()+")");
        for (SootMethod sootMethod:reachableRiskyMethods){
            System.out.println(sootMethod.getSignature());
        }
    }
}
