package com.straw.strawfuzzer.Input;


import android.util.Log;

import com.straw.lib.reflection.MyClassLoader;
import com.straw.lib.reflection.ReflectionUtils;

import java.util.Arrays;
import java.util.HashSet;


public class HardClassHandler {

    private static final String TAG = "Straw_HardClassHandler";

    public static final String[] HardClasses = new String[]{
            "com.android.server.restrictions.RestrictionsManagerService$RestrictionsManagerImpl"
    };
    public static final HashSet<String> HardClassSet = new HashSet<>(Arrays.asList(HardClasses));

    public static <T> T HandleHardCase(String className){
        try {
            Log.d(TAG,"HardCaseHandler for "+className);
            T Target;
            if(className.equals("com.android.server.restrictions.RestrictionsManagerService$RestrictionsManagerImpl")){
                // get param of its outer-class
                Class clazz = MyClassLoader.loadClass("com.android.server.restrictions.RestrictionsManagerService");
                Object outerTarget = InputGenerator.generateSeedByClass("com.android.server.restrictions.RestrictionsManagerService");
                Target = (T) ReflectionUtils.getField(outerTarget,clazz,"mRestrictionsManagerImpl");
                return Target;
            }else {
                return null;
            }
        }catch (Exception e){
            e.printStackTrace();
            return null;
        }

    }
}

