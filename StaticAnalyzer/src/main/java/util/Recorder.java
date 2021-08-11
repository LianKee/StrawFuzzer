package util;

import InputKnowledge.InputScope;
import analysis.callChainsExtractor.BackwardReachabilityAnalysis;
import analysis.riskyMethodsLocater.LocateRiskyMethods;
import analysis.riskyMethodsLocater.MethodAndStrawInstructionPair;
import analysis.riskyMethodsLocater.SearchRootSet;
import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;
import config.Common;
import dataflow.ClassAnalyzer;
import main.Memory;
import serviceInterfaces.ServiceInterfaces;
import serviceInterfaces.SystemServiceInfo;
import soot.*;
import soot.jimple.*;

import java.io.*;
import java.util.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadPoolExecutor;

import static analysis.callChainsExtractor.BackwardReachabilityAnalysis.*;
import static main.Memory.*;
import static util.Recorder.getJSONObjectInfo;
import static util.Recorder.writeToFileWithSizeLimit;

public class Recorder {

    private static int jsonFileLimit = 50; // MB

    public static void showRootSetFields(HashSet<SootField> rootSetFields){
        try{
            BufferedWriter bufferedWriter = new BufferedWriter(new FileWriter(Common.resultDirPath+ File.separator+Common.rootSet_type+"_rootSetFields.txt"));
            bufferedWriter.write("========================== RootSetFields("+rootSetFields.size()+") ==============================\n");
            for (SootField sootField:rootSetFields){
                bufferedWriter.write(sootField.getSignature()+"\n");
            }
        }catch (Exception e){
            e.printStackTrace();
        }
    }

    public static void showRiskyMethodsInfo(String typeName, HashSet<SootMethod> rawRiskyMethods, HashSet<SootMethod> reachableRiskyMethods){
        try {
            TimeMeasurement.show("Record RiskyMethodsInfo for "+typeName+" start");
            HashSet<SootMethod> unReachableRiskyMethods = new HashSet<>(rawRiskyMethods);
            unReachableRiskyMethods.removeAll(reachableRiskyMethods);
            BufferedWriter bufferedWriter = new BufferedWriter(new FileWriter(Common.resultDirPath+ File.separator+typeName+"_riskyMethods.txt"));
            bufferedWriter.write("========================== UnReachableRiskyMethods("+unReachableRiskyMethods.size()+") ==============================\n");
            for (SootMethod sootMethod:unReachableRiskyMethods){
                bufferedWriter.write(sootMethod.getSignature()+"\n");
            }
            bufferedWriter.write("\n\n\n========================== ReachableRiskyMethods("+reachableRiskyMethods.size()+") ==============================\n");
            for (SootMethod sootMethod:reachableRiskyMethods){
                bufferedWriter.write(sootMethod.getSignature()+"\n");
            }
            bufferedWriter.write("\n\n\n========================== AllEntryPointNumForMSPair ==================================\n");
            int sumPairs=0;
            HashMap<String,HashSet<String>> reachableRiskyMethodMapEntries = new HashMap<>();
            HashSet<String> entryPoints = new HashSet<>();
            HashMap<String,HashSet<String>> reachableMethodSigMapStrawInstructions = LocateRiskyMethods.getReachableMethodSigMapStrawInstructions(typeName);
            for (String methodSig:reachableMethodSigMapStrawInstructions.keySet()){
                for (String strawUnit:reachableMethodSigMapStrawInstructions.get(methodSig)){
                    MethodAndStrawInstructionPair msPair = new MethodAndStrawInstructionPair(methodSig,strawUnit);
                    int size = getAllEntryPointsForMSPair(msPair,typeName).size();
                    sumPairs+=size;
                    entryPoints.addAll(getAllEntryPointsForMSPair(msPair,typeName));
                    bufferedWriter.write("<"+msPair.toString()+">: "+size+"\n");

                    if (!reachableRiskyMethodMapEntries.containsKey(methodSig))
                        reachableRiskyMethodMapEntries.put(methodSig,new HashSet<>());
                    reachableRiskyMethodMapEntries.get(methodSig).addAll(getAllEntryPointsForMSPair(msPair,typeName));
                }
            }
            bufferedWriter.write("Pair Sum: "+sumPairs+"\n");
            bufferedWriter.write("Interface Num: "+entryPoints.size()+"\n");

            bufferedWriter.write("\n\n\n========================== AllEntryPoints ====================================\n");
            for (String methodSig:reachableMethodSigMapStrawInstructions.keySet()){
                for (String strawUnit:reachableMethodSigMapStrawInstructions.get(methodSig)) {
                    MethodAndStrawInstructionPair msPair = new MethodAndStrawInstructionPair(methodSig, strawUnit);
                    bufferedWriter.write(msPair.toString()+"\n");
                    for (String sig: getAllEntryPointsForMSPair(msPair,typeName)){
                        bufferedWriter.write("        "+sig+"\n");
                    }
                }

            }

            bufferedWriter.write("\n\n\n========================== RiskyMethodAndUnits ====================================\n");
            for (String methodSig:reachableMethodSigMapStrawInstructions.keySet()){
                bufferedWriter.write(methodSig+"\n");
                for (String unit:reachableMethodSigMapStrawInstructions.get(methodSig)){
                    bufferedWriter.write("        "+unit+"\n");
                }
            }


            if (typeName.equals(Common.rootSet_type)){
                ArrayList<String> targetInterfaces = findInterfacesWithParamsContainingIBinderField();
                ArrayList<String> res = new ArrayList<>();
                ArrayList<String> allInterfaces = new ArrayList<>();
                for (SootMethod riskyMethod:reachableRiskyMethods){
                    allInterfaces.addAll(getAllEntryPointsForMethod(riskyMethod.getSignature(),typeName));
                }
                for (String interfaceSig:targetInterfaces){
                    if (allInterfaces.contains(interfaceSig)){
                        res.add(interfaceSig);
                    }
                }
                bufferedWriter.write("\n\n\n========================== RiskyMethodWithParamContainingIBinder ====================================\n");
                bufferedWriter.write("Size:"+res.size());
                for (String s:res){
                    bufferedWriter.write(s+"\n");
                }
            }
            bufferedWriter.close();

            // json record for risky method Map entries
            JSONObject jsonObject = new JSONObject();
            for (String riskyMethodSig:reachableRiskyMethodMapEntries.keySet())
                jsonObject.put(riskyMethodSig,reachableRiskyMethodMapEntries.get(riskyMethodSig));
            writeJsonObjectToFile(Common.resultDirPath+File.separator+typeName+"_R2E.json",jsonObject);

            TimeMeasurement.show("Record RiskyMethodsInfo for "+typeName+" end");
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static void showMethodWithAllEntryPoints(String typeName, ArrayList<String> riskyMethodSigs){
        try{
            TimeMeasurement.show("showMethodWithAllEntryPoints for "+typeName+" start");
            BufferedWriter bufferedWriter = new BufferedWriter(new FileWriter(Common.resultDirPath+ File.separator+typeName+"_RiskyMethodsMapAllEntryPoints.txt"));
            bufferedWriter.write("========================== AllRiskyMethods ==================================\n");
            for (String riskyMethodSig:riskyMethodSigs){
                bufferedWriter.write(riskyMethodSig+"\n");
            }
            bufferedWriter.close();
            TimeMeasurement.show("showMethodWithAllEntryPoints for "+typeName+" end");
        }catch (Exception e){
            e.printStackTrace();
        }
    }

    public static void showStubClassMapImplClass(){
        try{
            BufferedWriter bufferedWriter = new BufferedWriter(new FileWriter(Common.resultDirPath+ File.separator+"stubClassMapImplClass.txt"));
            bufferedWriter.write("========================Service not in framework===============================\n");
            for (String stubClass:ServiceInterfaces.serviceStubClassMapImplClass.keySet()){
                if (ServiceInterfaces.serviceStubClassMapImplClass.get(stubClass).equals("null"))
                    bufferedWriter.write(ServiceInterfaces.stubClassMapServiceName.get(stubClass)+" -- "+stubClass+"\n");
            }
            bufferedWriter.write("\n\n=====================Stub Map Impl==================================\n");
            for (String stubClass:ServiceInterfaces.serviceStubClassMapImplClass.keySet()){
                bufferedWriter.write(stubClass+"--"+ServiceInterfaces.serviceStubClassMapImplClass.get(stubClass)+"\n");
            }
            bufferedWriter.write("\n\n=======================================================\n");
            for (String rawSig:ServiceInterfaces.rawInterfaceSigMapImplInterfaceSig.keySet()){
                bufferedWriter.write(rawSig+" -- "+ServiceInterfaces.rawInterfaceSigMapImplInterfaceSig.get(rawSig)+"\n");
            }
            bufferedWriter.close();
        }catch (Exception e){
            e.printStackTrace();
        }
    }

    public static void OutputJsonForOneMethod(String riskyMethodSig, String type){
        JSONArray output = new JSONArray();
        HashSet<String> riskyMethodSigs = new HashSet<>();
        riskyMethodSigs.add(riskyMethodSig);
        LogUtil.log("EntryPoints Num for "+riskyMethodSig+" :" + getAllEntryPointsForMethod(riskyMethodSig,type).size());
        for (String interfaceSig:BackwardReachabilityAnalysis.getAllEntryPointsForMethod(riskyMethodSig,type)){
            if (interfaceSig.contains("<com.android.internal.os.IDropBoxManagerService$Stub$Proxy: boolean isTagEnabled(java.lang.String)>"))
                output.add(getJSONObjectInfo(interfaceSig,riskyMethodSigs));
        }

        try {
            String methodName = StringUtil.getMethodNameFromMethodSig(riskyMethodSig);
            PrintWriter writer = new PrintWriter(new BufferedWriter(new FileWriter(new File(Common.resultDirPath+File.separator+"FuzzInfo_"+methodName+".json"))));
            writer.write(output.toString());
            writer.close();
        }catch (Exception e){
            e.printStackTrace();
        }
    }


    public static void OutputJson(String typeName,HashSet<SootMethod> reachableRiskyMethods) {
        HashMap<String, HashSet<String>> serviceInterfacesMapRiskyMethods = new HashMap<>();
        for (SootMethod sootMethod : reachableRiskyMethods){
            for(String interfaceSig : BackwardReachabilityAnalysis.getAllEntryPointsForMethod(sootMethod.getSignature(),typeName)){
                if (!serviceInterfacesMapRiskyMethods.containsKey(interfaceSig))
                    serviceInterfacesMapRiskyMethods.put(interfaceSig,new HashSet<>());
                serviceInterfacesMapRiskyMethods.get(interfaceSig).add(sootMethod.getSignature());
            }
        }
        TimeMeasurement.show("Sum Interfaces to test:"+serviceInterfacesMapRiskyMethods.keySet().size());

        try {
            String typeDir = Common.resultDirPath+File.separator+typeName+"_StaticAnalysisResults";
            File dir = new File(typeDir);
            if (dir.exists() && dir.isDirectory()){
                for (File jsonfile:dir.listFiles())
                    jsonfile.delete();
            }else{
                if(!dir.mkdir())
                    System.out.println("Make StaticAnalysisResults directory failed");
            }

            ExecutorService executorService = Executors.newFixedThreadPool(Common.ThreadSize);
            ThreadPoolExecutor tpe = (ThreadPoolExecutor) executorService;

            int sum = serviceInterfacesMapRiskyMethods.keySet().size();
            for (String interfaceSig:serviceInterfacesMapRiskyMethods.keySet()){
                executorService.execute(new OutputRunnable(typeDir,interfaceSig,serviceInterfacesMapRiskyMethods.get(interfaceSig)));
            }
            while (true){
                long completedTaskCount = tpe.getCompletedTaskCount();
                System.out.println("Active:"+tpe.getActiveCount()+"; Queue:"+tpe.getQueue().size()+"; Complete:"+completedTaskCount+"/"+sum);
                if (tpe.getActiveCount()==0 && tpe.getQueue().size() == 0){
                    break;
                }else {
                    Thread.sleep(6000);
                }
            }

        }catch (Exception e){
            e.printStackTrace();
        }
        TimeMeasurement.show("OutputToJson for "+typeName+" end");
    }

    public static JSONObject getJSONObjectInfo(String interfaceSig, HashSet<String> riskyMethodSigs){
        JSONObject jsonObject = new JSONObject();
        // service interface information
        jsonObject.put("signature",interfaceSig);
        // input scope
        String implSig = interfaceSig;
        if (ServiceInterfaces.rawInterfaceSigMapImplInterfaceSig.containsKey(interfaceSig))
            implSig = ServiceInterfaces.rawInterfaceSigMapImplInterfaceSig.get(interfaceSig);
        JSONObject methodScope;
        try{
            methodScope = InputScope.getMethodScope(implSig);
        }catch (Exception e){
            LogUtil.log("Exception occurs when get input scope for "+implSig);
            methodScope = null;
            e.printStackTrace();
        }
        if (methodScope == null)
            jsonObject.put("scope",new HashMap<String,ArrayList<String>>());
        else
            jsonObject.putAll(methodScope);

        JSONArray riskMethods = new JSONArray();
        for (String riskyMethodSig : riskyMethodSigs){
            HashMap<String,Double> methodWeights = assignWeightForMethods(interfaceSig,riskyMethodSig);
            JSONObject riskyMethod = new JSONObject();
            riskyMethod.put("signature",riskyMethodSig);
            riskyMethod.put("methodWeights",methodWeights);

            JSONObject dividedInputs = InputScope.divideInput(implSig,riskyMethodSig,null);
            if (dividedInputs==null){
                riskyMethod.put("controlFlowInputs",new ArrayList<String>());
                riskyMethod.put("memoryConsumptionInputs",new ArrayList<String>());
            }else {
                riskyMethod.putAll(dividedInputs);
            }

            ArrayList<ArrayList<String>> rootSets = new ArrayList<>();
            SootMethod sootMethod = Memory.methodSignatureMapSootMethod.get(riskyMethodSig);
            riskyMethod.put("rootSets",rootSets);

            riskMethods.add(riskyMethod);
        }
        jsonObject.put("riskyMethods",riskMethods);
        return jsonObject;
    }

    public static void readJson(){
        try{
            BufferedReader bufferedReader = new BufferedReader(new FileReader("StaticAnalysis_Result.json"));
            StringBuilder jsonStr = new StringBuilder();
            String tmp;
            while ((tmp=bufferedReader.readLine())!=null){
                jsonStr.append(tmp);
            }
            JSONArray output = JSON.parseArray(jsonStr.toString());
            System.out.println(output.size());
            for (int i=0;i<output.size();++i){
                JSONObject jsonObject = output.getJSONObject(i);
                System.out.println(jsonObject.getString("methodName"));
                System.out.println(jsonObject.getJSONArray("riskyMethods").size());
                System.out.println(jsonObject.getJSONArray("riskyMethods").getJSONObject(0).getString("methodName"));
            }

        }catch (Exception e){
            e.printStackTrace();
        }
    }

    public static void recordCG(){
        try{
            PrintWriter writer = new PrintWriter(new BufferedWriter(new FileWriter(new File(Common.resultDirPath+File.separator+"CG_CalleeMapCaller.txt"))));
            for (String calleeSig : calleeMethodSignatureMapCallerMethodSignatures.keySet()) {
                writer.write(calleeSig+"\n");
                for (String element : calleeMethodSignatureMapCallerMethodSignatures.get(calleeSig))
                    writer.write("------" + element+"\n");
            }
            writer.close();

            writer =  new PrintWriter(new BufferedWriter(new FileWriter(new File(Common.resultDirPath+File.separator+"CG_CallerMapCallee.txt"))));
            for (String callerSig : callerMethodSignatureMapCalleeMethodSignatures.keySet()) {
                writer.write(callerSig+"\n");
                for (String element : callerMethodSignatureMapCalleeMethodSignatures.get(callerSig)) {
                    writer.write("------" + element+"\n");
                }
            }
            writer.close();
        }catch (Exception e){
            e.printStackTrace();
        }
    }

    public static void writeToFileWithSizeLimit(String filePath, JSONArray output){
        try{
            int fileSize = output.toJSONString().length()/1024/1024;
            JSONObject staticInfo = output.getJSONObject(0);
            // file.length() == jsonStr.toString().length()
            if (fileSize>jsonFileLimit){
                int file_count = 1;
                String basicFilePath = filePath.substring(0,filePath.length()-5);

                JSONObject dividedObject = new JSONObject();
                dividedObject.put("signature",staticInfo.getString("signature"));
                dividedObject.put("scope",staticInfo.get("scope"));
                dividedObject.put("riskyMethods",new JSONArray());

                JSONArray riskyMethods = staticInfo.getJSONArray("riskyMethods");
                JSONArray dividedRiskyMethods = new JSONArray();
                for (int i=0;i<riskyMethods.size();++i){
                    JSONObject riskyMethod = riskyMethods.getJSONObject(i);
                    dividedObject.getJSONArray("riskyMethods").add(riskyMethod);
                    int curSize = dividedObject.toString().length()/1024/1024;
                    int riskyMethodSize = dividedObject.getJSONArray("riskyMethods").size();
                    if (curSize>jsonFileLimit){
                        if (riskyMethodSize == 1){
                            JSONArray dividedRes = new JSONArray();
                            dividedRes.add(dividedObject);
                            writeJsonArrayToFile(basicFilePath+"_"+file_count+".json",dividedRes);
                        }else{
                            dividedObject.getJSONArray("riskyMethods").remove(riskyMethodSize-1);
                            JSONArray dividedRes = new JSONArray();
                            dividedRes.add(dividedObject);
                            writeJsonArrayToFile(basicFilePath+"_"+file_count+".json",dividedRes);
                        }
                        file_count++;

                        dividedObject = new JSONObject();
                        dividedObject.put("signature",staticInfo.getString("signature"));
                        dividedObject.put("scope",staticInfo.get("scope"));
                        dividedObject.put("riskyMethods",new JSONArray());
                        if (riskyMethodSize>1)
                            dividedObject.getJSONArray("riskyMethods").add(riskyMethod);
                    }
                }
                if (dividedObject.getJSONArray("riskyMethods").size()>0){
                    JSONArray dividedRes = new JSONArray();
                    dividedRes.add(dividedObject);
                    writeJsonArrayToFile(basicFilePath+"_"+file_count+".json",dividedRes);
                }
            }else {
                writeJsonArrayToFile(filePath,output);
            }

        }catch (Exception e){
            e.printStackTrace();
        }

    }

    public static void writeJsonArrayToFile(String filePath, JSONArray jsonArray){
        try{
            PrintWriter writer = new PrintWriter(new BufferedWriter(new FileWriter(new File(filePath))));
            writer.write(jsonArray.toString());
            writer.close();
        }catch (Exception e){
            e.printStackTrace();
        }
    }

    public static void writeJsonObjectToFile(String filePath, JSONObject jsonObject){
        try{
            PrintWriter writer = new PrintWriter(new BufferedWriter(new FileWriter(new File(filePath))));
            writer.write(jsonObject.toString());
            writer.close();
        }catch (Exception e){
            e.printStackTrace();
        }
    }

    public static void extractInstructionsAddingStraws(){
        HashSet<String> methodNames = new HashSet<>();
        HashSet<String> methodSigs = new HashSet<>();
        HashSet<String> methodRefSigs = new HashSet<>();
        for (SootClass sootClass: Scene.v().getClasses()){
            if (ClassAnalyzer.isValidClass(sootClass)){
                for (SootMethod sootMethod:sootClass.getMethods()){
                    if (sootMethod.isConcrete()){
                        try {
                            Body body = sootMethod.retrieveActiveBody();
                            for (Unit unit:body.getUnits()){
                                if (((Stmt)unit).containsInvokeExpr()) {
                                    InvokeExpr invokeExpr = ((Stmt) unit).getInvokeExpr();
                                    if (SearchRootSet.isStrawInstruction(invokeExpr.getMethodRef().getSignature())) {
                                        String methodRefSig = invokeExpr.getMethodRef().getSignature();
                                        methodSigs.add(invokeExpr.getMethod().getSignature());
                                        methodRefSigs.add(methodRefSig);
                                        methodNames.add(StringUtil.getMethodNameFromMethodSig(methodRefSig));
                                    }
                                }
                            }
                        }catch (Exception e){
                            e.printStackTrace();
                        }
                    }
                }
            }
        }
        try{
            PrintWriter printWriter = new PrintWriter(new FileWriter(new File(Common.resultDirPath+File.separator+"AddStrawInstructions.txt")));
            printWriter.write(">>>>>>>>>>>>>>>>>>>>>>>>>>> "+"MethodNames "+methodNames.size()+"\n");
            for (String s:methodNames){
                printWriter.write(s+"\n");
            }
            printWriter.write(">>>>>>>>>>>>>>>>>>>>>>>>>>> "+"MethodSigs "+ methodSigs.size()+"\n");
            for (String s:methodSigs){
                printWriter.write(s+"\n");
            }
            printWriter.write(">>>>>>>>>>>>>>>>>>>>>>>>>>> "+"MethodRefSigs "+methodRefSigs.size()+"\n");
            for (String s:methodRefSigs){
                printWriter.write(s+"\n");
            }
            printWriter.close();
        }catch (Exception e){
            e.printStackTrace();
        }
    }

    public static void extractRegisteredServiceInfo(){
        HashMap<String,String> serviceNameMapIBinderClassName = ServiceInterfaces.readServiceList();
        HashMap<String, HashSet<String>> classMapInterfaces = new HashMap<>();

        int interfaceSize = 0;
        for (SootClass sootClass:Scene.v().getClasses()) {
            if (sootClass.getName().endsWith("$Stub") && serviceNameMapIBinderClassName.values().contains(sootClass.getName().replace("$Stub", ""))) {
                HashSet<String> interfaces = getServiceInterfaces(sootClass);
                interfaceSize+=interfaces.size();
                classMapInterfaces.put(sootClass.getName().replace("$Stub", ""), interfaces);
            }
        }

        System.out.println("***************************** Class with transactions *************************************************");
        System.out.println("Service Size: "+serviceNameMapIBinderClassName.keySet().size());
        System.out.println("Public Service Size: "+interfaceSize);
        interfaceSize = 0;
        for (String className:classMapInterfaces.keySet()){
            System.out.println(className+" -- "+classMapInterfaces.get(className).size());
            interfaceSize+=classMapInterfaces.get(className).size();
            for (String interfaceName: classMapInterfaces.get(className))
                System.out.println("      "+interfaceName);
        }
        System.out.println("Recheck Interface Size: "+interfaceSize);
    }

    public static HashSet<String> getServiceInterfaces(SootClass sootClass){
        HashSet<String> serviceInterfaces = new HashSet<>();
        for (SootField sootField:sootClass.getFields()){
            if (sootField.isStatic() && sootField.isFinal() && sootField.getName().startsWith("TRANSACTION_")){
                serviceInterfaces.add(sootField.getName());
            }
        }
        return serviceInterfaces;
    }


    public static void recordForInputScope(){
        try{
            PrintWriter printWriter = new PrintWriter(new FileWriter(new File(Common.resultDirPath+File.separator+"RiskyMethodRelatedInput_forZZB.json")));
            JSONArray jsonArray = new JSONArray();
            for (SootMethod sootMethod: LocateRiskyMethods.allRiskyMethods){
                String riskyMethodSig = sootMethod.getSignature();
                for (String entrySig:BackwardReachabilityAnalysis.getAllEntryPointsForMethod(riskyMethodSig,"tmp")){
                    String implEntrySig = ServiceInterfaces.rawInterfaceSigMapImplInterfaceSig.get(entrySig);
                    try{
                        ArrayList<String> result = InputScope.getRiskyMethodRelatedInput(implEntrySig, riskyMethodSig);
                        JSONObject jsonObject = new JSONObject();
                        jsonObject.put("entryImplSig",implEntrySig);
                        jsonObject.put("riskyMethodSig",riskyMethodSig);
                        jsonObject.put("relatedInput",result);
                        jsonArray.add(jsonObject);
                    }catch (Exception e){
                        e.printStackTrace();
                    }
                }
            }
            printWriter.write(jsonArray.toString());
            printWriter.close();
        }catch (Exception e){
            e.printStackTrace();
        }
    }

    public static HashSet<String> findAllClassWithIBinderField(){
        HashSet<String> classNames = new HashSet<>();
        for (SootClass sootClass:Scene.v().getClasses()){
            if (ClassAnalyzer.isValidClass(sootClass)){
                for (SootField sootField:sootClass.getFields()){
                    if (StringUtil.isIInterface(sootField.getType().toString())){
                        classNames.add(sootClass.getName());
                        break;
                    }
                }
            }
        }
        return classNames;
    }

    public static ArrayList<String> findInterfacesWithParamsContainingIBinderField(){
        HashSet<String> targetClassNames = findAllClassWithIBinderField();
        ArrayList<String> targetInterfaces = new ArrayList<>();
        for (String rawInterface:ServiceInterfaces.allRawInterfaceSigs){
            for(String paramType:StringUtil.extractMethodParamsFromMethodSig(rawInterface)){
                if (targetClassNames.contains(paramType)){
                    targetInterfaces.add(rawInterface);
                    break;
                }
            }
        }
        return targetInterfaces;
    }
}

class OutputRunnable implements Runnable{
    private String typeDir;
    private String interfaceSig;
    private HashSet<String> riskyMethodSigs;

    public OutputRunnable(String typeDir,String interfaceSig, HashSet<String> riskyMethodSigs){
        this.typeDir = typeDir;
        this.interfaceSig = interfaceSig;
        this.riskyMethodSigs = riskyMethodSigs;
    }

    @Override
    public void run() {
        JSONArray output = new JSONArray();
        output.add(getJSONObjectInfo(interfaceSig,riskyMethodSigs));
        String fileName = StringUtil.getSimpleSig(interfaceSig);
        String filePath = typeDir+File.separator+fileName+".json";
        writeToFileWithSizeLimit(filePath,output);
    }
}

