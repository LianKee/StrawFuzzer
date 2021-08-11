package util;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;

public class StringUtil {
    private static final String[] array_basicTpyes = new String[]{"int","boolean","long","float","byte","double","java.lang.String"};
    public static ArrayList<String> basicTypes = new ArrayList<>(Arrays.asList(array_basicTpyes));
    private static final String[] array_notIterabaleTypes = new String[]{"int","boolean","long","float","byte","double",
            "java.lang.Boolean","java.lang.Byte","java.lang.Integer","java.lang.Long","java.lang.Float","java.lang.Double"};
    public static ArrayList<String> notIterabaleTypes = new ArrayList<>(Arrays.asList(array_notIterabaleTypes));

    public static String join(String[] strings, String delimiter) {
        if (strings == null)
            return null;
        StringBuilder builder = new StringBuilder();
        for (String string : strings) {
            builder.append(string);
            builder.append(delimiter);
        }
        return builder.toString();
    }

    public static String join(HashSet<String> strings, String delimiter) {
        if (strings == null)
            return null;
        StringBuilder builder = new StringBuilder();
        for (String string : strings) {
            builder.append(string);
            builder.append(delimiter);
        }
        return builder.toString();
    }

    public static String join(List<String> strings, String delimiter) {
        return join(strings.toArray(new String[strings.size()]), delimiter);
    }

    public static boolean isEmpty(String string) {
        return string == null || string.length() <= 0;
    }

    public static String sqlString(String string) {
        if (isEmpty(string))
            string="Null";
        return "'" + string.replace("\\", "").replace("'", "") + "'";
    }

    public static String getDeclareClassFromMethodSig(String methodSig){
        return methodSig.substring(1,methodSig.indexOf(":"));
    }

    public static String getMethodNameFromMethodSig(String methodSig){
        String methodInfo = methodSig.split(" ")[2];
        return methodInfo.substring(0,methodInfo.indexOf("("));
    }

    public static String getReturnTypeFromMethodSig(String methodSig){
        return methodSig.split(" ")[1];
    }

    public static String[] extractMethodParamArrayFromMethodSig(String methodSig){
        String paramInfo = methodSig.substring(methodSig.indexOf("(")+1,methodSig.indexOf(")"));
        if (paramInfo.equals(""))
            return new String[0];
        else
            return paramInfo.split(",");
    }

    public static HashSet<String> extractMethodParamsFromMethodSig(String methodSig){
        return new HashSet<>(Arrays.asList(extractMethodParamArrayFromMethodSig(methodSig)));
    }

    public static String getSubSig(String methodSig){
        return methodSig.substring(methodSig.indexOf(":")+2,methodSig.length()-1);
    }

    // for file name
    public static String getSimpleSig(String methodSig){
        String className = getDeclareClassFromMethodSig(methodSig);
        String methodName = getMethodNameFromMethodSig(methodSig);
        className = className.replace("$Stub$Proxy","");
        return className+"_"+methodName;
    }

    public static String replaceDeclaredClassOfMethodSig(String methodSig, String newDeclaredClassName){
        String oldDeclaredClassName = getDeclareClassFromMethodSig(methodSig);
        return "<"+newDeclaredClassName+methodSig.substring(methodSig.indexOf(oldDeclaredClassName)+oldDeclaredClassName.length());
    }

    public static boolean isNumeric(String string){
        if (string==null || string.length()==0)
            return false;
        for (int i=0;i<string.length();++i){
            if (!Character.isDigit(string.charAt(i)))
                return false;
        }
        return true;
    }

    public static boolean isMatchPattern(String[] patterns,String valueStr) {
        for (String pattern : patterns) {
            if (valueStr.matches(pattern))
                return true;
        }
        return false;
    }

    public static String addStubInSig(String methodSig){
        int index = methodSig.indexOf(":");
        return methodSig.substring(0,index)+"$Stub"+methodSig.substring(index);
    }

    public static String addStubProxyInSig(String methodSig){
        int index = methodSig.indexOf(":");
        return methodSig.substring(0,index)+"$Stub$Proxy"+methodSig.substring(index);
    }

    public static boolean isBasic(String param){
        return basicTypes.contains(param);
    }

    public static boolean isIInterface(String className){
        String[] strArr = className.split("\\.");
        if(strArr[strArr.length-1].startsWith("I") && Character.isUpperCase(strArr[strArr.length-1].charAt(1))){
            return true;
        }else{
            return false;
        }
    }

    public static boolean containIInterfaceParam(String methodSig){
        for (String className: extractMethodParamsFromMethodSig(methodSig)){
            if (isIInterface(className))
                return true;
        }
        return false;
    }

    public static boolean withRegisterAndAddMeaning(String methodSig){
        String methodName = getMethodNameFromMethodSig(methodSig).toLowerCase();
        return methodName.startsWith("add") || methodName.startsWith("register");
    }

    public static boolean onlyHasNonIterableParam(String methodSig){
        for (String param:extractMethodParamsFromMethodSig(methodSig)){
            if (!notIterabaleTypes.contains(param) && !isIInterface(param))
                return false;
        }
        return true;
    }

}
