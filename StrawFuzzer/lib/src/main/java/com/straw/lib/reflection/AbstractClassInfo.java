package com.straw.lib.reflection;


import java.util.HashMap;


public class AbstractClassInfo {
    public static HashMap<String,String> AbstractClassMap = new HashMap<String,String>(){};
    static {
        AbstractClassMap.put("com.android.internal.telephony.CommandsInterface","com.android.internal.telephony.imsphone.ImsPhoneCommandInterface");
        AbstractClassMap.put("android.os.UserManagerInternal","com.android.server.pm.UserManagerService$LocalService");
        AbstractClassMap.put("android.app.usage.UsageStatsManagerInternal","com.android.server.usage.UsageStatsService$LocalService");
        AbstractClassMap.put("android.os.strictmode.Violation","android.os.strictmode.CleartextNetworkViolation");

        //todo
//        AbstractClassMap.put("android.app.IActivityManager","tmp");
//        AbstractClassMap.put("android.os.INetworkManagementService","tmp");
//        AbstractClassMap.put("com.android.internal.telephony.Phone","tmp");
//        AbstractClassMap.put("com.android.server.NsdService$DaemonConnectionSupplier","tmp");
//        AbstractClassMap.put("android.content.pm.IPackageManager","tmp");
//        AbstractClassMap.put("com.android.server.net.NetworkStatsService$NetworkStatsSettings","tmp");
//        AbstractClassMap.put("com.android.server.wm.TransactionFactory","tmp");
//        AbstractClassMap.put("android.net.IDnsResolver","tmp");
//        AbstractClassMap.put("android.net.INetd","tmp");
//        AbstractClassMap.put("android.net.INetworkStatsService","tmp");
//        AbstractClassMap.put("com.android.server.NsdService$NsdSettings","com.android.server.NsdService$NsdSettings$1");
//        AbstractClassMap.put("android.content.ContentResolver","android.content.ContentResolver$1");
//        AbstractClassMap.put("android.net.INetworkPolicyManager","tmp");
//        AbstractClassMap.put("com.android.server.policy.WindowManagerPolicy","tmp");
//        AbstractClassMap.put("java.time.Clock","java.time.Clock$SystemClock");
//        AbstractClassMap.put("java.time.ZoneId","java.time.ZoneRegion");
    }
}

