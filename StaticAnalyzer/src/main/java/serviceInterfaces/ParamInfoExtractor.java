package serviceInterfaces;

import dataflow.ClassAnalyzer;
import main.Memory;
import soot.SootClass;
import soot.SootMethod;
import soot.Type;
import util.LogUtil;
import util.StringUtil;

import java.io.*;
import java.util.*;

import static config.Common.javaSourceDir;
import static serviceInterfaces.ServiceInterfaces.implInterfaceSigs;

public class ParamInfoExtractor {
    public static HashMap<String, ArrayList<SourceParam>> interfaceSigMapParams = new HashMap<>();
    private static ArrayList<String> errorMethods = new ArrayList<>();

    public static HashMap<String, ArrayList<String>> typeMapVariables = new HashMap<>();
    public static HashMap<String, HashMap<String, Integer>> typeMapVariableNames = new HashMap<>();
    public static int basicParamNum = 0;
    public static int nonBasicParamNum = 0;
    public static HashSet<String> basicDataTypes = new HashSet<>();
    public static HashSet<String> nonBasicDataTypes = new HashSet<>();

    final static String[] basicTypes = new String[]{"String", "int", "long", "byte", "double", "float", "char", "boolean",
            "String[]", "byte []", "int[]", "long[]", "byte[]", "double[]", "float[]", "char[]", "boolean[]"};
    final static HashSet<String> basicTypeSet = new HashSet<>(Arrays.asList(basicTypes));

    final static String[] noNeedAnalyzedClassNames = new String[]{"T","?","android.os.Handler","Item",
            "Object","Integer","android.os.Parcel"};
    final static HashSet<String> noNeedAnalyzedClassNameSet = new HashSet<>(Arrays.asList(noNeedAnalyzedClassNames));

    public static HashMap<String, HashMap<ArrayList<String>, ArrayList<String>>> classNameMapConstructorParams = new HashMap<>();
    public static HashMap<String, String> classNameMapFailReason = new HashMap<>();

    public static HashMap<String, ArrayList<SootMethod>> classNameMapConstructors = new HashMap<>();


    public static void extractParamNamesForServiceInterfaces() {
        for (String interfaceSig : implInterfaceSigs) {
            getParamNameForMethod(interfaceSig);
        }
    }

    public static ArrayList<SourceParam> getParamNameForMethod(String interfaceSig){
        if (interfaceSigMapParams.containsKey(interfaceSig))
            return interfaceSigMapParams.get(interfaceSig);
        if (errorMethods.contains(interfaceSig))
            return new ArrayList<>();

        String[] paramTypes = StringUtil.extractMethodParamArrayFromMethodSig(interfaceSig);
        if (paramTypes.length == 0) {
            interfaceSigMapParams.put(interfaceSig, new ArrayList<>());
            return new ArrayList<>();
        }
        String className = StringUtil.getDeclareClassFromMethodSig(interfaceSig);
        String returnType = StringUtil.getReturnTypeFromMethodSig(interfaceSig);
        String methodName = StringUtil.getMethodNameFromMethodSig(interfaceSig);
        ArrayList<SourceParam> params = getParamNameForMethod(className, returnType, methodName, paramTypes);
        if (params != null) {
            interfaceSigMapParams.put(interfaceSig, params);
        } else {
            errorMethods.add(interfaceSig);
        }
        return params;
    }

    private static ArrayList<SourceParam> getParamNameForMethod(String className, String returnType, String methodName, String[] paramTypes) {
        String filepath = getFilePath(className);
        String tidyReturnType = returnType;
        if (returnType.contains("."))
            tidyReturnType = returnType.substring(returnType.lastIndexOf(".") + 1);
        String methodNamePattern = " " + methodName + "(";
        try {
            BufferedReader bufferedReader = new BufferedReader(new FileReader(filepath));
            String line;
            while ((line = bufferedReader.readLine()) != null) {
                line = line.trim();
                if (!line.startsWith("//") && !line.startsWith("*") &&
                        (!line.endsWith(";") || line.endsWith("{;")) && !line.endsWith(":") && !line.contains("new ") &&
                        !line.contains(methodName + "()") && !line.startsWith("return") &&
                        ((line.contains(methodNamePattern) && checkPreCharLegality(line, methodNamePattern)) || line.startsWith(methodName + "(") || line.startsWith(methodName + " ("))) {
                    if (line.contains("{") || line.endsWith(")")) {
                        // all in one line
                        if (line.contains("()"))
                            continue;
                        String paramStr = line.substring(line.indexOf("(") + 1, line.indexOf(")"));
                        if (paramStr.contains("<") || paramStr.contains("("))
                            paramStr = removeRedundancy(paramStr);

                        String[] pairs = paramStr.split(", ");
                        if (checkParamType(paramTypes, pairs)) {
                            ArrayList<SourceParam> paramArrayList = new ArrayList<>();
                            for (String pair : pairs) {
                                int lastindex = pair.lastIndexOf(" ");
                                paramArrayList.add(new SourceParam(pair.substring(0, lastindex), pair.substring(lastindex + 1)));
                            }
                            return paramArrayList;
                        }
                    } else {
                        if (line.endsWith(","))
                            line = line.substring(0, line.length() - 1);
                        String tmp = line.substring(line.indexOf("(") + 1);
                        ArrayList<String> pairs = new ArrayList<>();
                        if (tmp.length() != 0) {
                            if (tmp.contains("<")||tmp.contains("("))
                                tmp = removeRedundancy(tmp);
                            String[] tmpParams = tmp.split(", ");
                            if (tmpParams[0].contains(" "))
                                pairs.addAll(Arrays.asList(tmpParams));
                            else
                                continue;
                        }
                        line = bufferedReader.readLine().trim();
                        if (pairs.size() > 0 && !pairs.get(pairs.size() - 1).contains(" ")) {
                            line = pairs.get(pairs.size() - 1) + " " + line;
                            pairs.remove(pairs.size() - 1);
                        }
                        while (!line.contains("{") && !line.contains(")")) {
                            if (line.contains("<") || line.contains("("))
                                line = removeRedundancy(line);
                            if (line.endsWith(",")) {
                                line = line.substring(0, line.length() - 1);
                                pairs.addAll(Arrays.asList(line.split(", ")));
                                line = bufferedReader.readLine().trim();
                            } else {
                                String ps = line.substring(0, line.lastIndexOf(", "));
                                String tmpResidual = line.substring(line.lastIndexOf(", ") + 2);
                                pairs.addAll(Arrays.asList(ps.split(", ")));
                                line = tmpResidual + " " + bufferedReader.readLine().trim();
                            }
                        }
                        line = line.substring(0, line.lastIndexOf(")"));
                        if (line.contains("<") || line.contains("("))
                            line = removeRedundancy(line);
                        if (line.length() > 0) {
                            pairs.addAll(Arrays.asList(line.split(", ")));
                        }

                        if (!pairs.get(0).contains(" "))
                            continue;
                        if (checkParamType(paramTypes, pairs.toArray(new String[pairs.size()]))) {
                            ArrayList<SourceParam> paramArrayList = new ArrayList<>();
                            for (String pair : pairs) {
                                int lastindex = pair.lastIndexOf(" ");
                                if (lastindex>0)
                                    paramArrayList.add(new SourceParam(pair.substring(0, lastindex), pair.substring(lastindex + 1)));
                            }
                            return paramArrayList;
                        }
                    }
                }
            }
        }catch (FileNotFoundException e){
            LogUtil.log("File not found for "+className);
        } catch (Exception e) {
            LogUtil.log(e.getMessage()+" -- "+className+" -- "+methodName);
        }
        return null;
    }

    private static String getFilePath(String className) {
        String filepath = className.replace(".", File.separator);
        if (filepath.endsWith("[]"))
            filepath = filepath.replace("[]","");

        if (filepath.contains("$"))
            return javaSourceDir + File.separator + filepath.substring(0, filepath.indexOf("$")) + ".java";
        else
            return javaSourceDir + File.separator + filepath + ".java";
    }


    private static boolean checkParamType(String[] paramTypes, String[] params) {
        if (paramTypes.length == params.length) {
            return true;
        }
        return false;
    }

    private static boolean checkPreCharLegality(String line, String pattern) {
        char c = line.charAt(line.indexOf(pattern) - 1);
        if (c == '&' || c == '=' || c == '|' || c == '*')
            return false;
        return true;
    }

    public static void showSourceParam() {
        System.out.println("Errors:");
        for (String interfaceSig : errorMethods) {
            System.out.println("  " + interfaceSig);
        }
        System.out.println("Results:");
        for (String interfaceSig : interfaceSigMapParams.keySet()) {
            if (interfaceSigMapParams.get(interfaceSig).size() == 0)
                continue;
            System.out.println(interfaceSig);
            System.out.print("----");
            for (SourceParam sourceParam : interfaceSigMapParams.get(interfaceSig)) {
                System.out.print(sourceParam.toString() + ", ");
            }
            System.out.println();
        }
    }

    public static void getDistribution() {
        for (String interfaceSig : interfaceSigMapParams.keySet()) {
            ArrayList<SourceParam> arrayList = interfaceSigMapParams.get(interfaceSig);
            for (SourceParam sourceParam : arrayList) {
                String type = sourceParam.getType();
                String name = sourceParam.getName();
                if (isBasicType(type)) {
                    basicDataTypes.add(type);
                    basicParamNum += 1;
                } else {
                    nonBasicParamNum += 1;
                    if (isIInterfaceType(type))
                        type = "IInterface";
                    nonBasicDataTypes.add(type);
                }
                if (!typeMapVariables.containsKey(type))
                    typeMapVariables.put(type, new ArrayList<>());
                typeMapVariables.get(type).add(name);
                if (!typeMapVariableNames.containsKey(type))
                    typeMapVariableNames.put(type, new HashMap<>());
                if (!typeMapVariableNames.get(type).containsKey(name))
                    typeMapVariableNames.get(type).put(name, 1);
                else
                    typeMapVariableNames.get(type).put(name, typeMapVariableNames.get(type).get(name) + 1);
            }

        }
    }

    private static boolean isBasicType(String type) {
        return basicTypeSet.contains(type);
    }

    private static boolean isIInterfaceType(String type) {
        if (type.contains("."))
            type = type.substring(type.lastIndexOf(".") + 1);
        return type.startsWith("I") && Character.isUpperCase(type.charAt(1));
    }

    public static void showDistribution() {
        System.out.println("------------------------------------------");
        System.out.println("All Params: " + (basicParamNum + nonBasicParamNum) + ", basicNum: " + basicParamNum + ", nonBasicNum: " + nonBasicParamNum);
        System.out.println("Basic Types:" + basicDataTypes.size());
        for (String s : basicDataTypes)
            System.out.println("    " + s + ":" + typeMapVariables.get(s).size());
        System.out.println("Non Basic Types:" + nonBasicDataTypes.size());
        for (String s : nonBasicDataTypes)
            System.out.println("    " + s + ":" + typeMapVariables.get(s).size());
        System.out.println("------------------------------------------");
        for (String type : typeMapVariableNames.keySet()) {
            System.out.println(type + "(" + typeMapVariableNames.get(type).keySet().size() + " Names)");
            for (String name : typeMapVariableNames.get(type).keySet()) {
                System.out.println("    " + name + ":" + typeMapVariableNames.get(type).get(name));
            }
        }
    }

    public static void extractAllConstructorParams(){
        for (String interfaceSig:implInterfaceSigs){
            String[] paramTypes = StringUtil.extractMethodParamArrayFromMethodSig(interfaceSig);
            if (paramTypes.length == 0) {
                interfaceSigMapParams.put(interfaceSig, new ArrayList<>());
                continue;
            }
            for (String className:paramTypes){
                extractConstructorParams(className);
            }
        }
        HashSet<String> toBeAnalyzedSet = new HashSet<>(classNameMapConstructorParams.keySet());
        HashSet<String> analyzedSet = new HashSet<>(classNameMapConstructorParams.keySet());
        analyzedSet.addAll(classNameMapFailReason.keySet());
        HashSet<String> todoSet = new HashSet<>();
        do {
            for (String className:toBeAnalyzedSet){
                if (classNameMapFailReason.containsKey(className))
                    continue;
                if (!classNameMapConstructorParams.containsKey(className))
                    System.out.println("No key -- "+className);
                for (ArrayList<String> typeList:classNameMapConstructorParams.get(className).keySet()){
                    if (typeList.contains("android.os.Parcel"))
                        continue;
                    for (String type:typeList){
                        checkClass(analyzedSet,type,todoSet);
                    }
                }
            }

            for (String className:todoSet){
                extractConstructorParams(className);
            }
            analyzedSet.addAll(todoSet);
            toBeAnalyzedSet = todoSet;
            todoSet = new HashSet<>();
        }while (toBeAnalyzedSet.size()>0);

        System.out.println("--------------------------");
        showConstructorParamInfo();
    }

    public static void extractConstructorParams(String className) {
        if (noNeedAnalyzed(className))
            return;
        String type = className;
        if (type.endsWith("[]"))
            type = type.substring(0,type.length()-2);
        if (classNameMapConstructorParams.containsKey(type) || classNameMapFailReason.containsKey(type))
            return;
        if (getConstructors(type).size()==0 || (getConstructors(type).size()==1 && getConstructors(type).get(0).getSignature().contains("<init>()"))){
            classNameMapFailReason.put(type,"Only non-param constructor");
            return;
        }

        String targetFilePath = getFilePath(className);
        if (type.contains("."))
            type = type.substring(type.lastIndexOf(".") + 1);
        if (type.contains("$"))
            type = type.substring(type.indexOf("$")+1);

        try {
            BufferedReader bufferedReader = new BufferedReader(new FileReader(targetFilePath));
            String line;
            String constructorFlag1 = "public " + type + "(";
            String constructorFlag2 = "protected " + type + "(";
            String constructorFlag3 = "private " + type + "(";
            String constructorFlag4 = type+"(";
            while ((line = bufferedReader.readLine()) != null) {
                line = line.trim();
                if (line.startsWith("/*") && line.contains("*/"))
                    line = line.substring(line.indexOf("*/")+2).trim();
                if (line.startsWith(constructorFlag1) || line.startsWith(constructorFlag2) || line.startsWith(constructorFlag3) || line.startsWith(constructorFlag4)) {
                    if (line.contains("{") || line.endsWith(")")) {
                        if (line.contains("()"))
                            continue;
                        String paramStr = line.substring(line.indexOf("(") + 1, line.indexOf(")"));
                        if (paramStr.contains("<") || paramStr.contains("("))
                            paramStr = removeRedundancy(paramStr);

                        String[] pairs = paramStr.split(", ");
                        ArrayList<String> typeList = new ArrayList<>();
                        ArrayList<String> nameList = new ArrayList<>();
                        for (String pair : pairs) {
                            int lastindex = pair.lastIndexOf(" ");
                            SourceParam sourceParam = new SourceParam(className,pair.substring(0, lastindex), pair.substring(lastindex + 1));
                            typeList.add(sourceParam.getType());
                            nameList.add(sourceParam.getName());
                        }
                        if (!classNameMapConstructorParams.containsKey(className))
                            classNameMapConstructorParams.put(className, new HashMap<>());
                        typeList = getFullParamTypes(className,typeList);
                        classNameMapConstructorParams.get(className).put(typeList, nameList);
                    } else {
                        if (line.endsWith(","))
                            line = line.substring(0, line.length() - 1);
                        String tmp = line.substring(line.indexOf("(") + 1);
                        ArrayList<String> pairs = new ArrayList<>();
                        if (tmp.length() != 0) {
                            if (tmp.contains("<")||tmp.contains("("))
                                tmp = removeRedundancy(tmp);
                            String[] tmpParams = tmp.split(", ");
                            if (tmpParams[0].contains(" "))
                                pairs.addAll(Arrays.asList(tmpParams));
                            else
                                continue;
                        }
                        line = bufferedReader.readLine().trim();
                        if (pairs.size() > 0 && !pairs.get(pairs.size() - 1).contains(" ")) {
                            line = pairs.get(pairs.size() - 1) + " " + line;
                            pairs.remove(pairs.size() - 1);
                        }

                        while (!line.contains("{") && !line.contains(")")) {
                            if (line.contains("<") || line.contains("("))
                                line = removeRedundancy(line);
                            if (line.endsWith(",")) {
                                line = line.substring(0, line.length() - 1);
                                pairs.addAll(Arrays.asList(line.split(", ")));
                                line = bufferedReader.readLine().trim();
                            } else {
                                String ps = line.substring(0, line.lastIndexOf(", "));
                                String tmpResidual = line.substring(line.lastIndexOf(", ") + 2);
                                pairs.addAll(Arrays.asList(ps.split(", ")));
                                line = tmpResidual + " " + bufferedReader.readLine().trim();
                            }
                        }
                        line = line.substring(0, line.lastIndexOf(")"));
                        if (line.contains("<") || line.contains("("))
                            line = removeRedundancy(line);
                        if (line.length() > 0) {
                            pairs.addAll(Arrays.asList(line.split(", ")));
                        }
                        if (!pairs.get(0).contains(" "))
                            continue;
                        ArrayList<String> typeList = new ArrayList<>();
                        ArrayList<String> nameList = new ArrayList<>();
                        for (String pair : pairs) {
                            int lastindex = pair.lastIndexOf(" ");
                            SourceParam sourceParam = new SourceParam(className,pair.substring(0, lastindex), pair.substring(lastindex + 1));
                            typeList.add(sourceParam.getType());
                            nameList.add(sourceParam.getName());
                        }
                        typeList = getFullParamTypes(className,typeList);
                        if (!classNameMapConstructorParams.containsKey(className))
                            classNameMapConstructorParams.put(className, new HashMap<>());
                        classNameMapConstructorParams.get(className).put(typeList, nameList);
                    }
                }
            }
        } catch (Exception e) {
            classNameMapFailReason.put(className,e.getMessage());
            return;
        }
        if (!classNameMapConstructorParams.containsKey(className))
            classNameMapFailReason.put(className,"Fail to analyze source file");
    }

    public static boolean noNeedAnalyzed(String className){
        if (isBasicType(className) || isIInterfaceType(className) || !ClassAnalyzer.isValidClass(className) ||
                noNeedAnalyzedClassNameSet.contains(className))
            return true;
        if (Memory.classNameMapSootClass.containsKey(className) && !Memory.classNameMapSootClass.get(className).isConcrete())
            return true;
        return false;
    }

    public static String removeRedundancy(String paramStr){
        String res="";
        try{
            while (paramStr.contains("<")){
                int beginIdx = paramStr.indexOf("<");
                int endIdx = paramStr.indexOf(">");
                if (endIdx<beginIdx){
                    res+=paramStr;
                    paramStr="";
                }else{
                    res += paramStr.substring(0,beginIdx)+paramStr.substring(beginIdx,endIdx+1).replace(", ",",");
                    paramStr = paramStr.substring(endIdx+1);
                }
            }
            while (paramStr.contains("(")){
                int beginIdx = paramStr.indexOf("(");
                int endIdx = paramStr.indexOf(")");
                if (endIdx<beginIdx){
                    res+=paramStr;
                    paramStr="";
                }else {
                    res += paramStr.substring(0,beginIdx)+paramStr.substring(beginIdx,endIdx+1).replace(", ",",");
                    paramStr = paramStr.substring(endIdx+1);
                }
            }
            res+=paramStr;
        }catch (Exception e){
            LogUtil.log(e.getMessage()+"--"+paramStr);
            return paramStr;
        }
        return res;
    }

    public static void checkClass(HashSet<String> analyzedClassNames,String type,HashSet<String> todoSet){
        if (noNeedAnalyzed(type) || analyzedClassNames.contains(type))
            return;

        if (type.contains("List<") || type.contains("Set<")){
            String tmp = type.substring(type.indexOf("<")+1,type.lastIndexOf(">"));
            checkClass(analyzedClassNames,tmp,todoSet);
        }else if (type.contains("Map<")){
            String[] mapTypes = type.substring(type.indexOf("<")+1,type.indexOf(">")).split(",");
            for (String mapType:mapTypes)
                checkClass(analyzedClassNames,mapType,todoSet);
        }else if(type.contains("[]")){
            checkClass(analyzedClassNames,type.replace("[]",""),todoSet);
        }else if (type.contains("<?>")){
            checkClass(analyzedClassNames,type.replace("<?>",""),todoSet);
        } else{
            if (Memory.simpleClassNameMapFullClassNames.containsKey(type) && Memory.simpleClassNameMapFullClassNames.get(type).size() == 1)
                todoSet.addAll(Memory.simpleClassNameMapFullClassNames.get(type));
            else if (Memory.classNameMapSootClass.containsKey(type))
                todoSet.add(type);
            else{
                classNameMapFailReason.put(type,"Cannot find full className");
            }
        }
    }

    public static ArrayList<String> getFullParamTypes(String className,ArrayList<String> typeList){
        if (className.endsWith("[]"))
            className = className.substring(0,className.length()-2);
        ArrayList<SootMethod> constructors = getConstructors(className);
        if (constructors.size()==0)
            return typeList;
        int paramNum = typeList.size();
        for (SootMethod constructor:constructors){
            if (constructor.getParameterCount() == paramNum){
                List<Type> types = constructor.getParameterTypes();
                boolean flag = true;
                ArrayList<String> res = new ArrayList<>();
                for (int i=0;i<paramNum;++i){
                    if (!types.get(i).toString().endsWith(typeList.get(i))){
                        if (typeList.get(i).contains("<")){
                            String tmp = typeList.get(i);
                            if (types.get(i).toString().endsWith(tmp.substring(0,tmp.indexOf("<")))){
                                res.add(types.get(i).toString()+tmp.substring(tmp.indexOf("<")));
                                continue;
                            }
                        }
                        flag=false;
                        break;
                    }
                    res.add(types.get(i).toString());
                }
                if (flag)
                    return res;
            }
        }
        return typeList;
    }

    public static ArrayList<SootMethod> getConstructors(String className){
        if (classNameMapConstructors.containsKey(className))
            return classNameMapConstructors.get(className);
        else {
            if (Memory.classNameMapSootClass.containsKey(className)){
                SootClass sootClass = Memory.classNameMapSootClass.get(className);
                ArrayList<SootMethod> constructors = new ArrayList<>();
                for(SootMethod sootMethod:sootClass.getMethods()){
                    if (sootMethod.getName().equals("<init>"))
                        constructors.add(sootMethod);
                }
                classNameMapConstructors.put(className,constructors);
                return classNameMapConstructors.get(className);
            }else {
                System.out.println("No find SootClass for "+className);
                return new ArrayList<>();
            }
        }
    }

    public static void showConstructorParamInfo(){
        for (String className:classNameMapConstructorParams.keySet()){
            System.out.println(className);
            for (ArrayList<String> typeList:classNameMapConstructorParams.get(className).keySet()){
                System.out.print("    "+typeList.toString()+"---");
                System.out.println(classNameMapConstructorParams.get(className).get(typeList).toString());
            }
        }
        System.out.println("-------------------------- Failed Classes:");
        for (String className:classNameMapFailReason.keySet()){
            System.out.println(className+" -- "+classNameMapFailReason.get(className));
        }
    }

    public static String getInterfaceParamNames(String methodSig, int index) throws Exception{
        if(interfaceSigMapParams.size()==0)
            throw new Exception("init ParamInfoExtractor first!");
        ArrayList<SourceParam> params = interfaceSigMapParams.get(methodSig);
        if(params==null)
            return "null";
        return params.get(index).getName();
    }

}

class SourceParam {
    private String type;
    private String name;

    public SourceParam(String type, String name) {
        init(type,name);
    }

    public SourceParam(String className,String type, String name){
        init(type,name);
        if (type.endsWith("Builder") && Memory.classNameMapSootClass.containsKey(className+"$Builder")){
            this.type = className+"$Builder";
        }else if (type.equals("Class<?>")){
            this.type = "java.lang.Class";
        }else if (Memory.classNameMapSootClass.containsKey(className+"$"+this.type)){
            this.type = className+"$"+this.type;
        }
    }

    private void init(String type, String name){
        if (type.equals("byte []"))
            type = "byte[]";
        if (type.contains(" ")) {
            type = type.substring(type.lastIndexOf(" ") + 1);
        }
        this.type = type;
        this.name = name;
    }

    public String getType() {
        return this.type;
    }

    public String getName() {
        return this.name;
    }

    public String toString() {
        return this.type + " " + this.name;
    }
}



