package InputKnowledge;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;
import fj.Hash;
import javafx.util.Pair;
import main.Memory;
import serviceInterfaces.ParamInfoExtractor;
import serviceInterfaces.ServiceInterfaces;
import soot.Local;
import soot.SootMethod;
import util.LogUtil;
import util.TimeMeasurement;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.lang.reflect.Array;
import java.lang.reflect.Method;
import java.rmi.server.ExportException;
import java.util.*;

public class InputScope {

    public static HashMap<String, MethodScope> methodScopes = new HashMap<>();

    public static HashMap<String, HashMap<String,HashSet<String>>> basicScope = new HashMap<>();
    public static ArrayList<String> visitedMethod = new ArrayList<>();

    public static HashMap<Pair<String,String>,HashSet<Local>> methodPairMapTaintedLocals = new HashMap<>();

    public static List<String> specialInvoke = Arrays.asList("<java.lang.String: boolean equals(java.lang.Object)>");
    public static List<String> infectInvoke = Arrays.asList("<java.lang.StringBuilder: java.lang.StringBuilder append(java.lang.String)>");

    public static void reset(){
        methodScopes.clear();
        basicScope.clear();
        visitedMethod.clear();
        methodPairMapTaintedLocals.clear();
    }

    public static void init_forFramework(){
        TimeMeasurement.show("InputScope init start");
        reset();
        ParamInfoExtractor.extractParamNamesForServiceInterfaces();
        for(String interfaceSig : ServiceInterfaces.implInterfaceSigs){
            MethodScope methodScope = new MethodScope(interfaceSig,null,0);
            methodScope.init();
            methodScopes.put(interfaceSig,methodScope);
            visitedMethod.clear();
        }
        TimeMeasurement.show("init for methods in deserialization ...");
        for (String rawInterfaceSig:ServiceInterfaces.allRawInterfaceSigs){
            if (ServiceInterfaces.allRawInterfaceSigMapMethodsInDeserialization.containsKey(rawInterfaceSig)){
                for (String unParcelMethodSig: ServiceInterfaces.allRawInterfaceSigMapMethodsInDeserialization.get(rawInterfaceSig)){
                    if (!methodScopes.containsKey(unParcelMethodSig)){
                        MethodScope methodScope = new MethodScope(unParcelMethodSig,null,0);
                        methodScope.init();
                        methodScopes.put(unParcelMethodSig,methodScope);
                        visitedMethod.clear();
                    }
                }
            }
        }

        TimeMeasurement.show("InputScope init done");
    }

    public static void init_forEntrySigs(HashSet<String> entryInterfaces){
        TimeMeasurement.show("InputScope init start");
        reset();
        ParamInfoExtractor.extractParamNamesForServiceInterfaces();
        for(String interfaceSig : entryInterfaces){
            MethodScope methodScope = new MethodScope(interfaceSig,null,0);
            methodScope.init();
            methodScopes.put(interfaceSig,methodScope);
            visitedMethod.clear();
        }
        TimeMeasurement.show("InputScope init done");
    }

    public static void init_forEntryMethods(HashSet<String> entryMethodSigs){
        TimeMeasurement.show("InputScope init start");
        // reset before init
        reset();
        ParamInfoExtractor.extractParamNamesForServiceInterfaces();
        for(String interfaceSig : entryMethodSigs){
            MethodScope methodScope = new MethodScope(interfaceSig,null,0);
            methodScope.init();
            methodScopes.put(interfaceSig,methodScope);
            visitedMethod.clear();
        }
        TimeMeasurement.show("InputScope init done");
    }


    public static void saveBasicScopes(){
        JSONObject jsonObject = new JSONObject();
        jsonObject.put("TotalInputScopes",basicScope);
        try {
            PrintWriter writer = new PrintWriter(new BufferedWriter(new FileWriter(new File("InputScope.json"))));
            writer.write(jsonObject.toString());
            writer.close();
        }catch (Exception e){
            e.printStackTrace();
        }

        JSONObject CFG_perInterface = new JSONObject();
        for(String methodSig:methodScopes.keySet()){
            CFG_perInterface.put(methodSig, methodScopes.get(methodSig).mergeScope(null));
        }
        try {
            PrintWriter writer = new PrintWriter(new BufferedWriter(new FileWriter(new File("CFGScope.json"))));
            writer.write(CFG_perInterface.toString());
            writer.close();
        }catch (Exception e){
            e.printStackTrace();
        }
    }

    /**For seed generation
     * methodSig: impl sig
     * scope: {"param1":["value1",...], "param2":["value2"]}
     **/
    public static JSONObject getMethodScope(String methodSig) throws Exception{
        if(methodScopes.size()==0)
            throw new Exception("Please init InputScope first");
        JSONObject params = new JSONObject();
        MethodScope methodScope = methodScopes.get(methodSig);
        if(methodScope==null)
            return null;
        params.put("scope",methodScope.mergeScope(null));
        return params;
    }

    /**For seed generation
     *return: {"controlFlowInputs":["paramIndex1","paramIndex2",...], "memoryConsumptionInputs":["paramIndex3"...]}
     **/
    public static JSONObject divideInput(String entry, String end, ArrayList<String> methods){
        if(!methodScopes.containsKey(entry)) {
            System.out.println("entry method not exists: "+entry);
            return null;
        }
        JSONObject result = new JSONObject();
        result.put("controlFlowInputs",new ArrayList<String>());
        result.put("memoryConsumptionInputs",new ArrayList<String>());

        HashMap<String, ArgumentScope> argMap = new HashMap<>();

        MethodScope entryMethod = methodScopes.get(entry);
        JSONObject possibleScopes = entryMethod.mergeScope(methods);
        for(String param: possibleScopes.keySet()){
            ArrayList<String> tmp = new ArrayList<String>((possibleScopes.getObject(param,HashSet.class)));
            if(tmp.size()==0){
                ((ArrayList) result.get("memoryConsumptionInputs")).add(param);
            }else{
                ((ArrayList) result.get("controlFlowInputs")).add(param);
            }
        }
        return result;
    }

    public static ArrayList<String> getRiskyMethodRelatedInput(String entryMethod, String riskyMethod){
        if(methodScopes.size()==0)
            LogUtil.log("Please init InputScope first");
        MethodScope entry = methodScopes.get(entryMethod);
        return entry.getRiskyInputs(riskyMethod);
    }

    public static Set<Local> getTaintedParamLocalsByEntryInputs(String entryMethodSig, String riskyMethodSig){
        if(methodScopes.size()==0)
            LogUtil.log("Please init InputScope first");
        Pair<String, String> pair = new Pair<String, String>(entryMethodSig,riskyMethodSig);
        if (methodPairMapTaintedLocals.containsKey(pair))
            return methodPairMapTaintedLocals.get(pair);
        MethodScope entry = methodScopes.get(entryMethodSig);
        if (entry==null){
            return new HashSet<>();
        }
        Set<Local> res = entry.getTaintedLocalsInTargetMethod(riskyMethodSig);
        methodPairMapTaintedLocals.put(pair,new HashSet<>(res));
        return res;
    }

    /**For interface selection,
     * only consider controlFlow related inputs*/
    public static int methodScopeSize(String methodSig) throws Exception{
        if(methodScopes.size()==0)
            throw new Exception("Please init InputScope first");
        MethodScope methodScope = methodScopes.get(methodSig);
        if(methodScope==null) {
            System.out.println("Calculate method scope size failed for "+methodSig);
            return 99999999;
        }
        int scopeSize = 0;
        for(ArgumentScope argScope : methodScope.fetchScopes()){
            scopeSize+=argScope.scopeSize();
        }
        return scopeSize;
    }

    private static void addToBasic(ArgumentScope argumentScope){
        for(ArgumentScope subField : argumentScope.subFields){
            addToBasic(subField);
        }
        HashMap<String, HashSet<String>> nameScopes ;
        if(basicScope.containsKey(argumentScope.argType)){
            nameScopes = basicScope.get(argumentScope.argType);
        }else{
            nameScopes = new HashMap<>();
            basicScope.put(argumentScope.argType,nameScopes);
        }
        if(!nameScopes.containsKey(argumentScope.argName))
            nameScopes.put(argumentScope.argName, new HashSet<>());
        for(Object value : argumentScope.getValues("Total")){
            nameScopes.get(argumentScope.argName).add(value.toString());
        }

    }

}
