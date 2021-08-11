package com.straw.strawfuzzer.Hook;

import android.content.Context;
import android.content.SharedPreferences;

import com.crossbowffs.remotepreferences.RemotePreferences;
import com.straw.strawfuzzer.BuildConfig;
import com.straw.lib.system.ServiceInfo;

import java.util.ArrayList;
import java.util.List;

import de.robv.android.xposed.XSharedPreferences;
import de.robv.android.xposed.XposedHelpers;

public class PreferenceUtils {

    public static String prefName = BuildConfig.APPLICATION_ID + "_preferences";

    public static List<String> loadServices(SharedPreferences pref) {
        List<String> serviceNames = new ArrayList<>();
        String targetServiceNamesString = pref.getString("services", "");
        for (String serviceName: targetServiceNamesString.split(",")) {
            serviceName = serviceName.trim();
            if (null != ServiceInfo.getServiceInfo(serviceName)) {
                serviceNames.add(serviceName);
            }
        }
        return serviceNames;
    }

    public static int loadFilterUID(SharedPreferences pref) {
        return Integer.valueOf(pref.getString("filterUID", "0"));
    }

    public static boolean loadDisableHook(SharedPreferences pref) {
        return pref.getBoolean("disable_hook", false);
    }

    public static boolean loadDisableCrashHook(SharedPreferences pref) {
        return pref.getBoolean("disable_crash_hook", false);
    }

    public static XSharedPreferences getModuleSharedPreferences() {
        XSharedPreferences preferences = new XSharedPreferences(BuildConfig.APPLICATION_ID);
        preferences.makeWorldReadable();
        preferences.reload();
        return preferences;
    }

    @Deprecated
    public static SharedPreferences getRemoteSharedPreferences(ClassLoader classLoader) {
        if (null == classLoader) {
            classLoader = ClassLoader.getSystemClassLoader();
        }
        Context context = (Context) XposedHelpers.callMethod(
                XposedHelpers.callStaticMethod(
                        XposedHelpers.findClass("android.app.ActivityThread", classLoader),"currentActivityThread"),
                "getSystemContext" );

        return new RemotePreferences(context, BuildConfig.APPLICATION_ID, prefName, true);
    }

}
