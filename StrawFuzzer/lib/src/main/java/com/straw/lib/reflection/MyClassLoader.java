package com.straw.lib.reflection;


import android.content.Context;
import android.os.Build;
import android.util.Log;

import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;
import com.straw.lib.utils.LogUtils;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.lang.reflect.Array;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.ArrayList;

import dalvik.system.DexClassLoader;
import dalvik.system.PathClassLoader;
import me.weishu.reflection.Reflection;

public class MyClassLoader {
    private static final String logTag = "Straw_ClassLoader";
    private static Boolean injectFlag = false;
    private static ClassLoader cl = null;
    private static Context context = null;

    private static LoadingCache<String, Class> classCache = CacheBuilder.newBuilder().concurrencyLevel(1).maximumSize(500).build(
            new CacheLoader<String, Class>() {
                @Override
                public Class load(String className) {
                    Class clazz = null;
                    try {
                        if (null == cl) {
                            cl = getClass().getClassLoader();
                        }
                        prepare();
                        try {
                            clazz = cl.loadClass(className);
                        } catch (Exception e) {}
                        // handle some class array
                        if (null == clazz && className.endsWith(";")) {
                            int bracketIdx = 0;
                            while (className.charAt(bracketIdx) == '[') ++bracketIdx;
                            String componentName = className.substring(bracketIdx + 1, className.length() - 1);
                            clazz = load(componentName);
                            if (null != clazz) {
                                while (bracketIdx > 0) {
                                    bracketIdx--;
                                    clazz = Array.newInstance(clazz, 0).getClass();
                                }
                            }
                        }
                    } catch (Exception e) {
                    }
                    if (clazz == null) {
                        Log.d(logTag, "Fail to find class: " + className);
                    }
                    return clazz;
                }
            }
    );

    private static void prepare() {
        try {
            if (!injectFlag) {
                // if fail to inject, don't retry
                injectFlag = true;
                DexUtils.injectDexes((PathClassLoader) cl, true);
                Reflection.unseal(context);
            }
        } catch (Exception e) {
            LogUtils.failTo(logTag, "inject dex", e);
        }
    }

    public static void setClassLoader(ClassLoader classLoader) {
        cl = classLoader;
        prepare();
    }

    public static void setContext(Context context) {
        MyClassLoader.context = context;
    }

    public static Class loadClass(String className) {
        // handling primitive types
        switch (className) {
            case "boolean":
                return boolean.class;
            case "byte":
                return byte.class;
            case "short":
                return short.class;
            case "int":
                return int.class;
            case "long":
                return long.class;
            case "float":
                return float.class;
            case "double":
                return double.class;
            case "char":
                return char.class;
            case "void":
                return void.class;
            default:
                try {
                    return classCache.get(className);
                } catch (Exception e) {
                    return null;
                }
        }
    }

    public static Field loadField(String className, String fieldName) {
        Class clazz = loadClass(className);
        if (null == clazz) {
            return null;
        }
        try {
            Field field = clazz.getDeclaredField(fieldName);
            field.setAccessible(true);
            return field;
        } catch (NoSuchFieldException e) {
            Log.d(logTag, "Fail to load field " + className + "." + fieldName);
            return null;
        }
    }

    public static Constructor loadConstructor(String className, String[] paramTypes) {
        Class[] paramClasses = getParamTypes(paramTypes);
        return loadConstructor(className, paramClasses);
    }

    public static Constructor loadConstructor(String className, Class[] paramTypes) {
        Class clazz = loadClass(className);
        if (null == clazz) {
            return null;
        }
        try {
            Constructor constructor = clazz.getDeclaredConstructor(paramTypes);
            return constructor;
        } catch (NoSuchMethodException e) {
            return null;
        }
    }

    public static Method loadMethod(String className, String methodName, String[] paramTypes) {
        Class[] paramClasses = getParamTypes(paramTypes);
        return loadMethod(className, methodName, paramClasses);
    }

    public static Method loadMethod(String className, String methodName, Class[] paramClasses) {
        Class clazz = loadClass(className);
        if (null == clazz) {
            return null;
        }
        try {
            Method method = clazz.getDeclaredMethod(methodName, paramClasses);
            return method;
        } catch (NoSuchMethodException e) {
            Log.d(logTag, "Fail to load method " +
                    new ParcelableMethod(className, methodName, MyClassLoader.getStringParamTypes(paramClasses), "void"));
            return null;
        }
    }

    public static String[] getStringParamTypesOfMethod(Method method) {
        Class[] paramClasses = method.getParameterTypes();
        return getStringParamTypes(paramClasses);
    }

    public static String[] getStringParamTypesOfConstructor(Constructor constructor) {
        Class[] paramClasses = constructor.getParameterTypes();
        return getStringParamTypes(paramClasses);
    }

    public static Class[] getParamTypes(String[] paramTypes) {
        Class[] paramClasses = new Class[paramTypes.length];
        for (int i = 0; i < paramTypes.length; ++i) {
            String paramType = paramTypes[i];
            Class paramClass = loadClass(paramType);
            paramClasses[i] = paramClass;
        }
        return paramClasses;
    }

    public static String[] getStringParamTypes(Class[] paramClasses) {
        String[] paramTypes = new String[paramClasses.length];
        for (int i = 0; i < paramTypes.length; ++i) {
            paramTypes[i] = paramClasses[i].getName();
        }
        return paramTypes;
    }
}

class DexUtils {

    private static PathClassLoader classLoader = null;

    public static void injectDexes(PathClassLoader cl, boolean privApp) throws NoSuchFieldException, IllegalAccessException, ClassNotFoundException {
        ArrayList<String> mydexPathList = new ArrayList<String>();
        mydexPathList.addAll(getSystemJarPaths());
        if (privApp) {
            mydexPathList.addAll(getSystemApplist());
        }

        Object allDexElements = getDexElements(getPathList(cl));
//        System.out.println(Array.getLength(allDexElements));
        for (String dexPath : mydexPathList){
            DexClassLoader dexClassLoader = new DexClassLoader(dexPath,null, dexPath, cl);
            Object newDexElements = getDexElements(getPathList(dexClassLoader));
            allDexElements = combineArray(allDexElements,newDexElements);
        }
        Object pathList = getPathList(cl);
        ReflectionUtils.setField(pathList, pathList.getClass(), "dexElements", allDexElements);
//        System.out.println(Array.getLength(getDexElements(getPathList(getPathClassLoader()))));
    }

    public static void injectDexAtFirst(ClassLoader cl, String dexPath, String defaultDexOptPath) throws NoSuchFieldException, IllegalAccessException, ClassNotFoundException {
        DexClassLoader dexClassLoader = new DexClassLoader(dexPath, defaultDexOptPath, dexPath, cl);
        Object baseDexElements = getDexElements(getPathList(cl));
        Object newDexElements = getDexElements(getPathList(dexClassLoader));
        Object allDexElements = combineArray(newDexElements, baseDexElements);
        Object pathList = getPathList(cl);
        ReflectionUtils.setField(pathList, pathList.getClass(), "dexElements", allDexElements);
    }


    private static Object getDexElements(Object paramObject)
            throws IllegalArgumentException, NoSuchFieldException, IllegalAccessException {
        return ReflectionUtils.getField(paramObject, paramObject.getClass(), "dexElements");
    }

    private static Object getPathList(Object baseDexClassLoader)
            throws IllegalArgumentException, NoSuchFieldException, IllegalAccessException, ClassNotFoundException {
        return ReflectionUtils.getField(baseDexClassLoader, Class.forName("dalvik.system.BaseDexClassLoader"), "pathList");
    }

    private static Object combineArray(Object firstArray, Object secondArray) {
        Class<?> localClass = firstArray.getClass().getComponentType();
        int firstArrayLength = Array.getLength(firstArray);
        int allLength = firstArrayLength + Array.getLength(secondArray);
        Object result = Array.newInstance(localClass, allLength);
        for (int k = 0; k < allLength; ++k) {
            if (k < firstArrayLength) {
                Array.set(result, k, Array.get(firstArray, k));
            } else {
                Array.set(result, k, Array.get(secondArray, k - firstArrayLength));
            }
        }
        return result;
    }

    private static ArrayList<String> getSystemJarPaths(){
        ArrayList<String> jarlist = new ArrayList<String>();
        jarlist.add("/system/framework/services.jar");
        jarlist.add("/system/framework/framework.jar");
        try{
            Process process = Runtime.getRuntime().exec("ls /system/framework/");
            BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String line;
            while ((line = bufferedReader.readLine()) != null){
                line = line.trim();
                if (line.endsWith(".jar")) {
                    if (line.equals("services.jar") || line.equals("framework.jar")) {
                        continue;
                    } else {
                        jarlist.add("/system/framework/" + line);
                    }
                }
            }

            process = Runtime.getRuntime().exec("ls /system/product/framework/");
            bufferedReader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            while ((line = bufferedReader.readLine()) != null){
                if (line.trim().endsWith(".jar")) {
                    jarlist.add("/system/product/framework/" + line.trim());
                }
            }

            process = Runtime.getRuntime().exec("ls /vendor/framework/");
            bufferedReader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            while ((line = bufferedReader.readLine()) != null) {
                if (line.trim().endsWith(".jar"))
                    jarlist.add("/vendor/framework/" + line.trim());
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return jarlist;
    }

    private static ArrayList<String> getSystemApplist(){
        ArrayList<String> applist = new ArrayList<String>();
        try{
            Process process = Runtime.getRuntime().exec("ls -R /system/priv-app | grep apk");
            BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String line;
            while ((line = bufferedReader.readLine()) != null){
                if(line.trim().endsWith(".apk"))
                    applist.add("/system/priv-app/"+line.substring(0,line.length()-4)+"/"+line.trim());
            }
            process = Runtime.getRuntime().exec("ls -R /system/app | grep apk");
            bufferedReader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            while ((line = bufferedReader.readLine()) != null){
                if(line.trim().endsWith(".apk"))
                    applist.add("/system/app/"+line.substring(0,line.length()-4)+"/"+line.trim());
            }
        }catch (Exception e){
            e.printStackTrace();
        }
        return applist;
    }

}



