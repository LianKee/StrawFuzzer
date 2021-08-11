package main;

import InputKnowledge.InputScope;
import analysis.callChainsExtractor.BackwardReachabilityAnalysis;
import analysis.riskyMethodsLocater.LocateRiskyMethods;
import analysis.riskyMethodsLocater.OneShotAnalyzer;
import analysis.riskyMethodsLocater.SearchLinkToDeath;
import analysis.riskyMethodsLocater.SearchRootSet;
import cfg.CFG;
import config.Common;
import config.SystemSootConfig;
import serviceInterfaces.ParamInfoExtractor;
import serviceInterfaces.ServiceInterfaces;
import soot.*;
import util.Recorder;
import util.StringUtil;
import util.TimeMeasurement;

import java.util.HashMap;
import java.util.HashSet;


public class Analyze_Framework {
    public static void main(String[] args){
        TimeMeasurement.begin();
        // "Pixel3XL_Android11","Oneplus7_Android10","Pixel3_Android10","HUAWEI_Mate30_Android10","Pixel3XL_Android9","Pixel_Android8"
        String[] Devices = new String[]{"Pixel3XL_Android11"};
        for (String deviceInfo:Devices){
            System.out.println("Analysis for "+deviceInfo);
            analysis(deviceInfo);
//            convertToJimple(deviceInfo);
        }
        TimeMeasurement.show("Total Finish");
        System.exit(0);
    }

    // analysis once
    public static void analysis(String deviceInfo){
        Common.init(deviceInfo);
        if (Common.DeviceInfo == null){
            System.out.println("Error: DeviceInfo is Null");
            return;
        }
        try {
            TimeMeasurement.show("Analysis for "+Common.DeviceInfo);
            SystemSootConfig.init();
            reset();
            Memory.init_forFramework();
            // Recorder.recordCG();
            InputScope.init_forFramework();
            // locate all risky methods
            LocateRiskyMethods.locateAllRiskyMethods_inFramework(false);

            // risky method record
            // Recorder.showRootSetFields(SearchRootSet.allRootSetFields);
            Recorder.showRiskyMethodsInfo(Common.rootSet_type, SearchRootSet.potentialRiskyMethods, SearchRootSet.reachableRiskyMethods);
            Recorder.showRiskyMethodsInfo(Common.linkToDeath_type,SearchLinkToDeath.potentialRiskyMethods,SearchLinkToDeath.reachableRiskyMethods);
            Recorder.showRiskyMethodsInfo(Common.oneShot_type, OneShotAnalyzer.potentialRiskyMethods ,OneShotAnalyzer.reachableRiskyMethods);
            // unParcel related risky method record
            Recorder.showMethodWithAllEntryPoints(Common.oneShot_type,OneShotAnalyzer.TPCandidatesInUnparcel);
            // Json output
            Recorder.OutputJson(Common.rootSet_type,SearchRootSet.reachableRiskyMethods);
            Recorder.OutputJson(Common.linkToDeath_type,SearchLinkToDeath.reachableRiskyMethods);
            Recorder.OutputJson(Common.oneShot_type,OneShotAnalyzer.reachableRiskyMethods);

        }catch (Exception e){
            e.printStackTrace();
        }finally {
            if(Common.database!=null && !Common.database.isClosed())
                Common.database.close();
        }
    }

    public static void reset(){
        BackwardReachabilityAnalysis.reset();
        CFG.reset();
    }

    // convert java to jimple
    public static void convertToJimple(String deviceInfo){
        Common.init(deviceInfo);
        SystemSootConfig.initForJimple();

        searchServiceImpl();
    }

    public static void searchServiceImpl(){
        ServiceInterfaces.readFormatFile();
        HashSet<String> stubClassNames = new HashSet<>(ServiceInterfaces.stubClassMapServiceName.keySet());
        HashMap<String,HashSet<String>> foundRes = new HashMap<>();
        for (SootClass sootClass:Scene.v().getClasses()){
            if (sootClass.hasSuperclass()){
                String superClassName = sootClass.getSuperclass().getName();
                if (stubClassNames.contains(superClassName)){
                    if (!foundRes.containsKey(superClassName))
                        foundRes.put(superClassName,new HashSet<>());
                    foundRes.get(superClassName).add(sootClass.getName());
                }
            }
        }
        System.out.println("All Stub Class: "+stubClassNames.size());
        System.out.println("Found son class: "+foundRes.size());
        System.out.println("Not found: "+(stubClassNames.size()-foundRes.size()));
        for (String classname : stubClassNames){
            if (!foundRes.containsKey(classname))
                System.out.println(classname);
        }
        System.out.println("\n\n ============ Details ============");
        for (String classname:foundRes.keySet()){
            System.out.println(classname);
            for(String sonClass:foundRes.get(classname))
                System.out.println("      "+sonClass);
        }
    }

}
