package analysis.callChainsExtractor;

import InputKnowledge.InputScope;
import analysis.riskyMethodsLocater.*;
import cfg.CFG;
import dataflow.DataFlowAnalyzer;
import javafx.util.Pair;
import config.Common;
import main.Memory;
import serviceInterfaces.ServiceInterfaces;
import soot.SootMethod;
import soot.Unit;
import soot.jimple.AssignStmt;
import soot.jimple.InvokeExpr;
import soot.jimple.NewArrayExpr;
import soot.jimple.Stmt;
import util.LogUtil;
import util.StringUtil;
import util.TimeMeasurement;

import java.net.CookieHandler;
import java.util.*;
import java.util.concurrent.ConcurrentLinkedQueue;

import static analysis.riskyMethodsLocater.LocateRiskyMethods.getRiskyMethodMapImplEntryInterfacesByType;

/**
 * Backward analysis on Call Graph to find call chains from public service interfaces to risky method
 */

public class BackwardReachabilityAnalysis {
    public static HashMap<MethodAndStrawInstructionPair, HashSet<String>> MSPairMapEntryInterfaces = new HashMap<>();

    public static HashSet<ArrayList<String>> allVulnerableCallPaths = new HashSet<>();
    // <Service Interface，Risky Method> map <Call paths>
    public static HashMap<Pair<String, String>, HashSet<ArrayList<String>>> entryPointToRiskyMethodPaths = new HashMap<>();
    public static HashMap<Integer, Integer> pathNumMapCount = new HashMap<>();

    private static final int Max_CallPath_Number = 1000;
    private static final int Max_SearchTime = 120000; // ms

    public static void reset() {
        MSPairMapEntryInterfaces.clear();
        allVulnerableCallPaths.clear();
        entryPointToRiskyMethodPaths.clear();
        pathNumMapCount.clear();
    }

    public static HashSet<String> getAllEntryPointsForMSPair(MethodAndStrawInstructionPair msPair, String type){
        return getAllEntryPointsForMSPair(ServiceInterfaces.allRawInterfaceSigs,ServiceInterfaces.implInterfaceSigs,msPair,type);
    }

    public static HashSet<String> getAllEntryPointsForMSPair(HashSet<String> alternativeRawInterfaceSigs, HashSet<String> alternativeImplInterfaceSigs,
                                                             MethodAndStrawInstructionPair msPair, String type) {
        if (MSPairMapEntryInterfaces.containsKey(msPair))
            return MSPairMapEntryInterfaces.get(msPair);
        HashSet<String> entryInterfaces = getImplEntryPointsForMethod(alternativeRawInterfaceSigs,alternativeImplInterfaceSigs,msPair.getKey(),type);
        if (entryInterfaces.size()==0)
            return entryInterfaces;

        HashSet<String> result = new HashSet<>();
        if (OneShotAnalyzer.specialRiskyMethodSigSet.contains(msPair.getKey()) && type.equals(Common.oneShot_type)){
            if (alternativeRawInterfaceSigs.isEmpty()){
                result.addAll(entryInterfaces);
            }else {
                for (String implSig:entryInterfaces)
                    result.addAll(getServiceInterfaceSigs(implSig, type));
            }
        }else{
            // get Unit
            Unit targetUnit=null;
            for (Unit unit:Memory.methodSignatureMapSootMethod.get(msPair.getKey()).retrieveActiveBody().getUnits()){
                if (unit.toString().equals(msPair.getValue())){
                    targetUnit = unit;
                    break;
                }
            }
            if (targetUnit != null){
                // get target ValueBoxes according to type, for dataflow analysis
                HashSet<String> argNames = new HashSet<>();
                if (type.equals(Common.rootSet_type)){
                    InvokeExpr invokeExpr = ((Stmt)targetUnit).getInvokeExpr();
                    for (int i=0;i<invokeExpr.getArgCount();++i){
                        argNames.add(invokeExpr.getArg(i).toString());
                    }
                }else if (type.equals(Common.oneShot_type)){
                    if ((targetUnit instanceof AssignStmt) && (((AssignStmt) targetUnit).getRightOp() instanceof NewArrayExpr)){
                        argNames.add(((NewArrayExpr) ((AssignStmt) targetUnit).getRightOp()).getSize().toString());
                    }else if (((Stmt)targetUnit).containsInvokeExpr()){
                        argNames.add(((Stmt) targetUnit).getInvokeExpr().getArg(0).toString());
                    }
                }else if (type.equals(Common.linkToDeath_type)){
                    InvokeExpr invokeExpr = ((Stmt)targetUnit).getInvokeExpr();
                    for (int i=0;i<invokeExpr.getArgCount();++i){
                        argNames.add(invokeExpr.getArg(i).toString());
                    }
                }

                if (argNames.size()==0){
                    if (alternativeRawInterfaceSigs.isEmpty()){
                        result.addAll(entryInterfaces);
                    }else {
                        for (String implSig:entryInterfaces)
                            result.addAll(getServiceInterfaceSigs(implSig, type));
                    }
                }else {
                    for (String implInterfaceSig:entryInterfaces){
                        if (StringUtil.getDeclareClassFromMethodSig(msPair.getKey()).equals("android.os.Parcel")){
                            if (alternativeRawInterfaceSigs.isEmpty()){
                                result.add(implInterfaceSig);
                            }else {
                                result.addAll(getServiceInterfaceSigs(implInterfaceSig, type));
                            }
                        }else if (type.equals(Common.linkToDeath_type) && StringUtil.extractMethodParamsFromMethodSig(msPair.getKey()).size() == 0){
                            result.addAll(getServiceInterfaceSigs(implInterfaceSig,type));
                        } else if (DataFlowAnalyzer.isArgumentTaintedByEntryInputs(implInterfaceSig,msPair.getKey(),targetUnit,argNames)){
                            if (alternativeRawInterfaceSigs.isEmpty()){
                                result.add(implInterfaceSig);
                            }else {
                                result.addAll(getServiceInterfaceSigs(implInterfaceSig, type));
                            }
                        }
                    }
                }
            }
        }

        MSPairMapEntryInterfaces.put(msPair, result);
        return result;
    }

    public static HashSet<String> getAllEntryPointsForMethod(String riskyMethodSig, String type){
        HashMap<String,HashSet<String>> reachableMethodSigMapStrawInstructions = LocateRiskyMethods.getReachableMethodSigMapStrawInstructions(type);
        String pickedInstruction = reachableMethodSigMapStrawInstructions.get(riskyMethodSig).iterator().next();
        MethodAndStrawInstructionPair pickedPair = new MethodAndStrawInstructionPair(riskyMethodSig,pickedInstruction);
        return getAllEntryPointsForMSPair(pickedPair,type);
    }


    public static HashSet<String> getImplEntryPointsForMethod(SootMethod sootMethod, String type) {
        String targetSig = sootMethod.getSignature();
        return getImplEntryPointsForMethod(targetSig,type);
    }

    public static HashSet<String> getImplEntryPointsForMethod(String targetSig, String type) {
        return getImplEntryPointsForMethod(ServiceInterfaces.allRawInterfaceSigs, ServiceInterfaces.implInterfaceSigs, targetSig, type);
    }

    public static HashSet<String> getImplEntryPointsForMethod(HashSet<String> alternativeRawInterfaceSigs, HashSet<String> alternativeImplInterfaceSigs,
                                                              String targetSig, String type){
        HashMap<String, HashSet<String>> riskyMethodMapImplEntryInterfaces = getRiskyMethodMapImplEntryInterfacesByType(type);
        if (riskyMethodMapImplEntryInterfaces.containsKey(targetSig))
            return riskyMethodMapImplEntryInterfaces.get(targetSig);

        HashSet<String> entryPointsForThisMethod = new HashSet<>();
        Queue<String> sigQueue = new LinkedList<>();
        sigQueue.add(targetSig);
        String curSig;

        HashSet<String> searchRecords = new HashSet<>();
        while (!sigQueue.isEmpty()) {
            curSig = sigQueue.poll();
            if (searchRecords.contains(curSig))
                continue;
            searchRecords.add(curSig);

            if (Memory.calleeMethodSignatureMapCallerMethodSignatures.containsKey(curSig)) {
                for (String callerSig : Memory.calleeMethodSignatureMapCallerMethodSignatures.get(curSig)) {
                    if (alternativeRawInterfaceSigs.contains(callerSig)) {
                        if (isValidAsEntry(entryPointsForThisMethod, curSig, targetSig, type)) {
                            entryPointsForThisMethod.add(curSig);
                            continue;
                        }
                    } else if (alternativeImplInterfaceSigs.contains(callerSig)) {
                        if (type.equals(Common.oneShot_type) && !alternativeRawInterfaceSigs.isEmpty())
                            continue;
                        if (isValidAsEntry(entryPointsForThisMethod, callerSig, targetSig, type)) {
                            entryPointsForThisMethod.add(callerSig);
                        }
                    }
                    sigQueue.add(callerSig);
                }
            }
        }

        if (!riskyMethodMapImplEntryInterfaces.containsKey(targetSig)){
            riskyMethodMapImplEntryInterfaces.put(targetSig, entryPointsForThisMethod);
        }
        return riskyMethodMapImplEntryInterfaces.get(targetSig);
    }


    private static HashSet<String> getServiceInterfaceSigs(String implEntrySig, String type){
        HashSet<String> entryPointsForThisMethod = new HashSet<>();
        if (Memory.calleeMethodSignatureMapCallerMethodSignatures.containsKey(implEntrySig)) {
            for (String callerSig : Memory.calleeMethodSignatureMapCallerMethodSignatures.get(implEntrySig)) {
                if (ServiceInterfaces.allRawInterfaceSigs.contains(callerSig)){
                    if (StringUtil.extractMethodParamsFromMethodSig(callerSig).size()==0)
                        continue;
                    entryPointsForThisMethod.add(callerSig);
                }
            }
        }
        return entryPointsForThisMethod;
    }

    private static boolean isValidAsEntry(HashSet<String> entryPoints, String entrySig, String targetSig ,String type){
        if (entryPoints.contains(entrySig))
            return false;
        if (type.equals(Common.rootSet_type)){
            return (StringUtil.extractMethodParamsFromMethodSig(entrySig).size()>0)
                    && (!StringUtil.onlyHasNonIterableParam(entrySig))
                    && (InputScope.getTaintedParamLocalsByEntryInputs(entrySig, targetSig).size() > 0);
        }else if (type.equals(Common.linkToDeath_type)){
            return SearchLinkToDeath.hasParamContainsIInterface(entrySig);
        }else if (type.equals(Common.oneShot_type)){
            ;
        }
        return true;
    }

    // calculate distance
    public static HashMap<String,Double> assignWeightForMethods(String entrySig, String targetSig){
        try{
            ArrayList<String> waitForProcess = new ArrayList<>();
            waitForProcess.add(entrySig);
            HashSet<String> methodNodes = new HashSet<>();
            while (!waitForProcess.isEmpty()) {
                String curMethodSig = waitForProcess.get(0);
                waitForProcess.remove(0);
                if (methodNodes.contains(curMethodSig))
                    continue;
                methodNodes.add(curMethodSig);
                if (Memory.callerMethodSignatureMapCalleeMethodSignatures.containsKey(curMethodSig))
                    waitForProcess.addAll(Memory.callerMethodSignatureMapCalleeMethodSignatures.get(curMethodSig));
            }
            HashMap<String, Double> methodMapWeight = new HashMap<>();
            waitForProcess.add(targetSig);
            HashSet<String> searchRecords = new HashSet<>();
            methodMapWeight.put(targetSig, 1.0);
            while (!waitForProcess.isEmpty()) {
                String curMethodSig = waitForProcess.get(0);
                waitForProcess.remove(0);
                if (searchRecords.contains(curMethodSig)){
                    continue;
                }
                searchRecords.add(curMethodSig);
                if (Memory.calleeMethodSignatureMapCallerMethodSignatures.containsKey(curMethodSig)) {
                    HashSet<String> callers = new HashSet<>(Memory.calleeMethodSignatureMapCallerMethodSignatures.get(curMethodSig));
                    callers.retainAll(methodNodes);
                    if (!callers.isEmpty()) {
                        waitForProcess.addAll(callers);
                        double curWeight = methodMapWeight.get(curMethodSig);
                        for (String caller : callers) {
                            double callerWeight = calculateWeightRadio(caller,curMethodSig) * curWeight;
                            if (methodMapWeight.containsKey(caller)) {
                                if (methodMapWeight.get(caller) > callerWeight)
                                    continue;
                            }
                            methodMapWeight.put(caller, callerWeight);
                        }
                    }
                }
            }
            return methodMapWeight;
        }catch (Exception e){
            System.out.println("Exception in assignWeightForMethods for "+entrySig+"--"+targetSig);
            e.printStackTrace();
            return new HashMap<>();
        }

    }

    public static double calculateWeightRadio(String callerSig, String targetSig){
        if (ServiceInterfaces.allRawInterfaceSigs.contains(callerSig)){
            return 1.0;
        }
        SootMethod callerMethod = Memory.methodSignatureMapSootMethod.get(callerSig);
        if (callerMethod==null){
            System.out.println("Error in calculateWeight: null sootMethod -- "+callerSig);
            return 0.0;
        }
        CFG cfg = CFG.getCFG(callerMethod);
        if (cfg == null){
            System.out.println("Error in calculateWeight: null cfg -- "+callerSig);
            return 0.0;
        }
        Set<String> calleeSigs = cfg.getSignaturesOfDirectCallees();
        ConcurrentLinkedQueue<ArrayList<String>> methodChains = cfg.getAllMethodChains();
        int countSum = 0;
        HashMap<String,Integer> calleeMethodMapReachChainNum = new HashMap<>();
        for (String calleeSig:calleeSigs){
            int count=0;
            for (ArrayList<String> methodChain:methodChains){
                if (methodChain.contains(calleeSig))
                    count+=1;
            }
            calleeMethodMapReachChainNum.put(calleeSig,count);
            countSum+=count;
        }
        if (calleeMethodMapReachChainNum.containsKey(targetSig)){
            int target = calleeMethodMapReachChainNum.get(targetSig);
            return (double)target/countSum;
        }else {
            return 1.0/Memory.calleeMethodSignatureMapCallerMethodSignatures.get(targetSig).size();
        }

    }


    public static void showAllVulnerableCallPaths() {
        System.out.println("\n\n");
        System.out.println("==================================== Vulnerable call paths Size:" + allVulnerableCallPaths.size());
        for (ArrayList<String> path : allVulnerableCallPaths) {
            System.out.println(path.get(0));
            for (int i = 1; i < path.size(); ++i)
                System.out.println("        " + path.get(i));
        }
    }

    public static void showPathsOfEachPair() {
        LogUtil.log("========================== Paths of Each Pair =========================");
        for (Pair<String, String> pair : entryPointToRiskyMethodPaths.keySet()) {
            LogUtil.log(pair.getKey() + " -- " + pair.getValue() + " (" + entryPointToRiskyMethodPaths.get(pair).size() + " paths)");
            for (ArrayList<String> path : entryPointToRiskyMethodPaths.get(pair)) {
                showArrayList(path, "    ");
            }
        }
    }

    public static void showArrayList(ArrayList<String> arrayList) {
        System.out.println(arrayList.get(0));
        for (int i = 1; i < arrayList.size(); ++i)
            System.out.println("    " + arrayList.get(i));
    }

    public static void showArrayList(ArrayList<String> arrayList, String prefix) {
        System.out.println(prefix + arrayList.get(0));
        for (int i = 1; i < arrayList.size(); ++i)
            System.out.println(prefix + "     " + arrayList.get(i));
    }

    public static void showPathNumDistribution() {
        ArrayList<Integer> keys = new ArrayList<>(pathNumMapCount.keySet());
        Collections.sort(keys);
        int count = 0;
        System.out.println("==================== Path Num Distribution ==========================");
        for (int size : keys) {
            System.out.println(size + ":" + pathNumMapCount.get(size));
            count += pathNumMapCount.get(size);
        }
        System.out.println("Total Paths: " + count);
    }

    public static void showWeights(HashMap<String, Double> methodWeights) {
        for (String methodSig : methodWeights.keySet()) {
            System.out.println(methodSig + ": " + methodWeights.get(methodSig));
        }
    }
}
