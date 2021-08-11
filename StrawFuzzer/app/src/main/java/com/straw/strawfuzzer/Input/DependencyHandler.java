package com.straw.strawfuzzer.Input;


import android.content.Context;
import android.util.Log;

import com.straw.strawfuzzer.MainActivity;
import com.straw.lib.reflection.MyClassLoader;

import java.util.Arrays;
import java.util.HashSet;

public class DependencyHandler {
    public static final String[] DependentClasses = new String[]{
            "com.android.server.wifi.WifiInjector",
            "com.android.internal.telephony.SubscriptionController",
    };
    public static final HashSet<String> DependentClassSet = new HashSet<>(Arrays.asList(DependentClasses));

    public static void HandleDependency(String className){
        if (!DependentClassSet.contains(className)){
//            Log.d("DependencyHandler","do not have dependency");
        }else {
            try {
//                Log.d("DependencyHandler","handle dependency for "+className);
                if(className.equals("com.android.server.wifi.WifiInjector")){
                    if (MainActivity.context.getSystemService(MyClassLoader.loadClass("android.net.NetworkScoreManager")) == null){
                        // todo
                        InputGenerator.generateSeedByClass("android.net.NetworkScoreManager");
                    }
                }else if (className.equals("com.android.internal.telephony.SubscriptionController")){
                    Object Target = InputGenerator.generateSeedByClass("com.android.internal.telephony.uicc.UiccController");
                    // make then getInstance
                    Class clazz = MyClassLoader.loadClass("com.android.internal.telephony.uicc.UiccController");
                    Class rawParamClass = MyClassLoader.loadClass("[Lcom.android.internal.telephony.CommandsInterface;");
                    Object[] secondParam = InputGenerator.generateSeedByClass("[Lcom.android.internal.telephony.CommandsInterface;");
                    clazz.getDeclaredMethod("make", Context.class,rawParamClass).invoke(Target,MainActivity.context,rawParamClass.cast(secondParam));
                    clazz.getDeclaredMethod("getInstance").invoke(Target);
                    Log.d("DependencyHandler","DependencyHandler end");
                }
            }catch (Exception e){
                e.printStackTrace();
            }

        }
    }
}
