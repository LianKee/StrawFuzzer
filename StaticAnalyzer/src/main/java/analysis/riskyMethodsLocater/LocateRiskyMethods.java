package analysis.riskyMethodsLocater;

import analysis.callChainsExtractor.BackwardReachabilityAnalysis;
import config.Common;
import soot.SootMethod;
import util.TimeMeasurement;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;

public class LocateRiskyMethods {
    public static HashSet<SootMethod> allRiskyMethods = new HashSet<>();
    public static HashMap<Integer, Integer> entryPointsNumMapCount = new HashMap<>();

    public static void locateAllRiskyMethods_inFramework(boolean fromDatabase){
        allRiskyMethods = new HashSet<>();
        entryPointsNumMapCount = new HashMap<>();

        OneShotAnalyzer.init();
        SearchRootSet.init_forFramework(fromDatabase);
        SearchLinkToDeath.init();

        allRiskyMethods.addAll(SearchRootSet.reachableRiskyMethods);
        allRiskyMethods.addAll(SearchLinkToDeath.reachableRiskyMethods);
        allRiskyMethods.addAll(OneShotAnalyzer.reachableRiskyMethods);

        TimeMeasurement.show("locateAllRiskyMethods end");
    }


    public static HashMap<String,HashSet<String>> getReachableMethodSigMapStrawInstructions(String typeName){
        if (typeName.equals(Common.rootSet_type))
            return SearchRootSet.reachableMethodSigMapStrawInstructions;
        else if (typeName.equals(Common.linkToDeath_type))
            return SearchLinkToDeath.reachableMethodSigMapStrawInstructions;
        else if (typeName.equals(Common.oneShot_type))
            return OneShotAnalyzer.reachableMethodSigMapStrawInstructions;
        return null;
    }

    public static HashMap<String, HashSet<String>> getRiskyMethodMapImplEntryInterfacesByType(String typeName){
        if (typeName.equals(Common.rootSet_type)){
            return SearchRootSet.riskyMethodMapImplEntryInterfaces;
        }else if (typeName.equals(Common.linkToDeath_type)){
            return SearchLinkToDeath.riskyMethodMapImplEntryInterfaces;
        }else if (typeName.equals(Common.oneShot_type)){
            return OneShotAnalyzer.riskyMethodMapImplEntryInterfaces;
        }else{
            return null;
        }
    }


}
