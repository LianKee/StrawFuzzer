package com.straw.strawfuzzer.Hook;

import android.annotation.SuppressLint;
import android.app.ActivityManager;
import android.app.ApplicationErrorReport;
import android.app.Service;
import android.content.BroadcastReceiver;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.ServiceConnection;
import android.content.SharedPreferences;
import android.os.Binder;
import android.os.DropBoxManager;
import android.os.IBinder;
import android.os.RemoteException;

import com.straw.lib.reflection.ParcelableMethod;
import com.straw.strawfuzzer.BuildConfig;
import com.straw.strawfuzzer.Fuzz.Fuzzer;
import com.straw.strawfuzzer.Fuzz.MemoryInfo;
import com.straw.lib.reflection.ClassDependencyInfo;
import com.straw.lib.reflection.MyClassLoader;
import com.straw.lib.system.SystemService;

import java.lang.reflect.Constructor;
import java.lang.reflect.Member;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import dalvik.system.PathClassLoader;
import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

public class XposedHook implements IXposedHookLoadPackage {

    public static int filterUID = 0;
    public static boolean disableHook = false;
    public static boolean disableCrashHook = false;
    public static List<String> targetServiceNames = new ArrayList<>();

    private static IHookService hookService = null;

    private static String TAG = "Straw_Xposed: ";

    private static Context context = null;

    private static Set<String> hookedClassNames = new HashSet<>();

    private static Set<ParcelableMethod> hookedMethods = new HashSet<>();
    private static List<SystemService> hookedServices = new ArrayList<>(1000);

    private boolean hooked = false;

    private static JavaCrashHandlerHook javaCrashHandlerHook = null;

    private static NativeCrashHandlerHook nativeCrashHandlerHook = null;

    private static CrashHandlerHook crashHandlerHook = null;

    private static ServiceConnection serviceConnection = null;

    private static Intent crashIntent = null;

    private static void log(String message) {
        XposedBridge.log(TAG + message);
    }

    private static void log(Throwable t) {
        XposedBridge.log(t);
    }

    @Override
    public void handleLoadPackage(XC_LoadPackage.LoadPackageParam lpparam) {
        if (lpparam.packageName.equals("android")) {
            handleLoadPackageAndroid(lpparam);
        }
    }

    @SuppressLint("WrongConstant")
    private void handleLoadPackageAndroid(XC_LoadPackage.LoadPackageParam lpparam) {
        // Hook system server
        ClassLoader cl = lpparam.classLoader;
        context = getSystemContext(cl);
        MyClassLoader.setClassLoader((PathClassLoader) cl);
        MyClassLoader.setContext(context);

        crashIntent = new Intent(HookService.CRASH_START_ACTION);
        crashIntent.setFlags(0x400000);
        crashIntent.setComponent(new ComponentName("com.straw.strawfuzzer", "com.straw.strawfuzzer.Fuzz.Fuzzer$CrashStartReceiver"));

        // Load preferences
        try {
            SharedPreferences prefs = PreferenceUtils.getModuleSharedPreferences();
            filterUID = PreferenceUtils.loadFilterUID(prefs);
            targetServiceNames = PreferenceUtils.loadServices(prefs);
            disableHook = PreferenceUtils.loadDisableHook(prefs);
            disableCrashHook = PreferenceUtils.loadDisableCrashHook(prefs);
            log("Loaded perfs " + prefs.getAll());
        } catch (Exception e) {
            log("Failed load perfs: " + e);
        }

        launchConnectionDog(cl);

        if (disableHook) {
            log("Hooking disabled");
            hooked = true;
            return;
        }
        log("Hooking start");

        if (!disableCrashHook) {
            hookCrashHandle(cl);
        }

        // Hook classes for prioritization
        hookForPrioritization();

        log("Hooking end. " + hookedServices.size() + " services " + hookedMethods.size() + " methods hooked");
        hooked = true;
    }

    private void hookCrashHandle(ClassLoader cl) {
        try {
            String className = "com.android.server.DropBoxManagerService";
            @SuppressLint("PrivateApi") Class clazz = cl.loadClass(className);
            String methodName = "add";
            Class[] paramTypes = new Class[]{DropBoxManager.Entry.class};
            Method method = clazz.getDeclaredMethod(methodName, paramTypes);
            nativeCrashHandlerHook = new NativeCrashHandlerHook();
            XposedBridge.hookMethod(method, nativeCrashHandlerHook);
            log("Hooked NativeUncaughtHandler");
        } catch (Exception e) {
            log("Fail to hook native uncaught crash handler " + e.toString());
        }

        try {
            String className = "com.android.server.am.ActivityManagerService";
            @SuppressLint("PrivateApi") Class clazz = cl.loadClass(className);
            String methodName = "handleApplicationCrashInner";
            Class[] paramTypes = new Class[]{String.class, cl.loadClass("com.android.server.am.ProcessRecord"), String.class, ApplicationErrorReport.CrashInfo.class};
            Method method = clazz.getDeclaredMethod(methodName, paramTypes);
            crashHandlerHook = new CrashHandlerHook();
            XposedBridge.hookMethod(method, crashHandlerHook);
            log("Hooked NativeUncaughtHandler2");
        } catch (Exception e) {
            log("Fail to hook common uncaught crash handler" + e.toString());
        }
    }

    private void hookForPrioritization() {
        for (String serviceName : targetServiceNames) {
            SystemService service = SystemService.getSystemService(serviceName);
            hookedServices.add(service);

            // Hooking by static information
            log("Hooking according to static_info of service " + service.getServiceName());
            List<StaticInfo> serviceStaticInfos = StaticInfo.getInfosByService(serviceName);
            for (StaticInfo staticInfo: serviceStaticInfos) {
                Set<ParcelableMethod> methodsToHook = new HashSet<>();
                // Hook entry
                ParcelableMethod entryMethod = staticInfo.getMethod();
                Member entryMember = entryMethod.toMethod();
                if (null == entryMember) {
                    log("Fail to hook member " + entryMethod.toString());
                }
                methodsToHook.add(entryMethod);
//                hookMethod(entryMember, true);

                for (StaticInfo.RiskyMethod riskyMethod: staticInfo.getRiskyMethods()) {
                    for (Map.Entry<ParcelableMethod, Double> entry: riskyMethod.weights.entrySet()) {
                        if (null == entry.getValue()) {
                            continue;
                        }
                        ParcelableMethod method = entry.getKey();
                        if (entry.getValue() != 0 || entryMethod.methodName.equals(method.methodName)) {
                            methodsToHook.add(method);
                        }
                    }
                }

                for (ParcelableMethod method: methodsToHook) {
                    Member member;
                    if (method.isConstructor()) {
                        member = method.toConstructor();
                    } else {
                        member = method.toMethod();
                    }
                    if (null == member) {
                        log("Fail to hook member " + method.toString());
                        continue;
                    }
                    boolean isEntry = entryMethod.methodName.equals(method.methodName);
                    hookMethod(member, isEntry);
                }
            }
        }
    }

    /**
     * Start a thread to continually get connection to {@link HookService}
     */
    private void launchConnectionDog(ClassLoader cl) {
        serviceConnection = new ServiceConnection() {

            private boolean traceStartReceiverRegistered = false;
            private boolean getMemoryInfoReceiverRegistered = false;
            private boolean rebootReceiverRegistered = false;
            private boolean crashHandledReceiverRegistered = false;

            @Override
            public void onServiceConnected(ComponentName name, IBinder service) {
                log("ConnectionDog connected to HookService");
                hookService = IHookService.Stub.asInterface(service);
                if (null == hookService) {
                    log("HookService is null");
                    return;
                }

                int methodCount = TraceData.methodTable.size();
                log("postMethods start " + methodCount);
                try {
                    // post multiple times to prevent binder buffer overflow.
                    for (int i = 0; i < methodCount; i += 500) {
                        hookService.postMethods(TraceData.methodTable.subList(i, Math.min(i + 500, methodCount)), i);
                    }
                    log("postMethods end");
                } catch (RemoteException e) {
                    hookService = null;
                    log("Fail to postMethods to HookService");
                }

                try {
                    log("methodCounts: " + hookService.getMethodCount());
                } catch (RemoteException e) {
                    e.printStackTrace();
                }

                Thread t = new Thread(() -> {
                    if (null == hookService) return;

                    Context context = getSystemContext(cl);
                    // Register receiver to receive change from HookService
                    if (!traceStartReceiverRegistered) {
                        try {
                            IntentFilter intentFilter = new IntentFilter(HookService.TRACE_START_ACTION);
                            context.registerReceiver(new TraceStartReceiver(), intentFilter);
                            log("Registered TraceStartReceiver");
                            traceStartReceiverRegistered = true;
                        } catch (Exception e) {
                            log("Fail to register TraceStartReceiver " + e.toString());
                        }
                    }
                    if (!getMemoryInfoReceiverRegistered) {
                        try {
                            IntentFilter intentFilter = new IntentFilter(HookService.GET_MEMORY_INFO_ACTION);
                            context.registerReceiver(new GetMemoryInfoReceiver(), intentFilter);
                            log("Registered GetMemoryInfoReceiver");
                            getMemoryInfoReceiverRegistered = true;
                        } catch (Exception e) {
                            log("Fail to register TraceStartReceiver " + e.toString());
                        }
                    }
                    if (!rebootReceiverRegistered) {
                        try {
                            IntentFilter intentFilter = new IntentFilter(HookService.REBOOT_ACTION);
                            context.registerReceiver(new RebootReceiver(), intentFilter);
                            log("Registered RebootReceiver");
                            rebootReceiverRegistered = true;
                        } catch (Exception e) {
                            log("Fail to register RebootReceiver " + e.toString());
                        }
                    }
                    if (!crashHandledReceiverRegistered) {
                        try {
                            IntentFilter intentFilter = new IntentFilter(HookService.CRASH_HANDLED_ACTION);
                            context.registerReceiver(new CrashHandledReceiver(), intentFilter);
                            log("Registered CrashHandledReceiver");
                            crashHandledReceiverRegistered = true;
                        } catch (Exception e) {
                            log("Fail to register CrashHandledReceiver " + e.toString());
                        }
                    }
                });
                t.start();
            }

            @Override
            public void onServiceDisconnected(ComponentName name) {
            }
        };

        Thread t = new Thread(() -> {
            while (true) {
                try {
                    if (null != hookService) {
                        // Become active for sync with service
                        Thread.sleep(1000);
                    } else {
                        Thread.sleep(5000);
                    }
                } catch (InterruptedException e) {}

                if (!hooked) continue;
                if (null == hookService) {
                    establishServiceConnection(serviceConnection, cl);
                }
            }
        });
        t.start();
    }

    private boolean establishServiceConnection(ServiceConnection serviceConnection, ClassLoader cl) {
        // Get context and packageContext
        context = getSystemContext(cl);
        if (null == context) {
            log("ConnectionDog fail to get context");
            return false;
        }
        Context packageContext;
        try {
            packageContext = context.createPackageContext(BuildConfig.APPLICATION_ID, Context.CONTEXT_IGNORE_SECURITY);
        } catch (Exception e) {
            log("ConnectionDog fail to create package context");
            return false;
        }
        try {
            log("ConnectionDog is Trying to connect with HookService");
            Intent intent = new Intent(packageContext, HookService.class);
            boolean bindRes = context.bindService(intent, serviceConnection, Context.BIND_AUTO_CREATE);
            if (!bindRes) {
                log("ConnectionDog fail to connect to HookService");
                return false;
            } else {
                return true;
            }
        } catch (Exception e) {
            log("ConnectionDog fail to connect to HookService for exception " + e.toString());
            return false;
        }
    }

    private void recursiveHookClassMethods(SystemService service, Class clazz, ClassLoader cl, boolean isService) {
        if (hookedClassNames.contains(clazz.getName())) return;

        // Hook service class
        hookClass(service, clazz, isService);

        // Hook parent class. for handling class like com.android.server.DropBoxManagerService$2
        hookParentClassIfExist(service, clazz, cl);

        // Hook inner classes
        hookInnerClasses(service, clazz, cl);

        // Hook dependencies classes
        hookDependencyClasses(service, clazz, cl);
    }

    /**
     * Recursively hook dependency classes of a
     * @param service
     * @param clazz
     */
    private void hookDependencyClasses(SystemService service, Class clazz, ClassLoader cl) {
        String[] dependencies = ClassDependencyInfo.getDependencyOf(clazz.getName());
        if (null == dependencies) return;
        log("Find " + dependencies.length + " dependency classes of " + clazz.getName() + " for service " + service.getServiceName());
        for (String depClassName: dependencies) {
            Class depClass;
            try {
                depClass = cl.loadClass(depClassName);
            } catch (ClassNotFoundException e) {
                log("Fail to load dependency class " + depClassName + " of " + clazz.getName() + " for service " + service.getServiceName());
                continue;
            }
            recursiveHookClassMethods(service, depClass, cl, false);
        }
    }

    /**
     * A service class probably call methods of its subClass. So we recursively hook its subclasses.
     *
     * @param service
     * @param clazz
     */
    private void hookInnerClasses(SystemService service, Class clazz, ClassLoader cl) {
        Class[] innerClasses = clazz.getDeclaredClasses();
        if (0 != innerClasses.length) {
            log("Find " + innerClasses.length + " inner classes of " + clazz.getName() + " for service " + service.getServiceName());
            for (Class innerClass : innerClasses) {
                recursiveHookClassMethods(service, innerClass, cl, false);
//                hookClassMethods(service, innerClass, false);
            }
        }
    }

    private void hookParentClassIfExist(SystemService service, Class clazz, ClassLoader cl) {
        String serviceClassName = service.getServiceClassName();
        if (serviceClassName.contains("$")) ;
        {
            String[] splits = serviceClassName.split("\\$", 3);
            // Assume there are only one parent class
            assert splits.length == 2;
            String parentClassName = splits[0];
            if (hookedClassNames.contains(parentClassName)) return;
            Class parentClass = null;
            try {
                parentClass = cl.loadClass(parentClassName);
            } catch (ClassNotFoundException e) {
                log("Fail to load parent class for service " + service.getServiceName());
            }
            if (null != parentClass) {
                log("Find parent class " + parentClassName + " of " + clazz.getName() + " for service " + service.getServiceName());
                recursiveHookClassMethods(service, parentClass, cl, false);
            }
        }
    }

    private void hookClass(SystemService service, Class clazz, boolean checkEntry) {
        String className = clazz.getName();
        // Prevent duplicated hook
        if (hookedClassNames.contains(className)) return;
        hookedClassNames.add(className);

        log("Hooking class " + className + " for service " + service.getServiceName());

        // Hook constructors
        Constructor[] constructors = clazz.getDeclaredConstructors();
        for (Constructor constructor: constructors) {
            hookMethod(constructor, false);
        }

        // Hook methods
        Method[] methods = clazz.getDeclaredMethods();
        for (Method method : methods) {
            hookMethod(method, checkEntry);
        }
        log("Finish hooking class " + clazz.getName());
    }

    private void hookMethod(Member member, boolean isEntry) {
        String logTarget = "";
        ParcelableMethod parcelableMethod;
        if (member instanceof Method) {
            parcelableMethod = new ParcelableMethod((Method) member);
        } else if (member instanceof Constructor) {
            parcelableMethod = new ParcelableMethod((Constructor) member);
        } else {
            assert false;
            return;
        }

        if (hookedMethods.contains(parcelableMethod)) {
            return;
        }
        hookedMethods.add(parcelableMethod);

        StaticInfo.ValueSpec[] rootSets = StaticInfo.getRootSets(parcelableMethod);
        try {
            if (member instanceof Method) {
                Method method = (Method) member;
                logTarget = "[" + method.getName() + "] " + method.toGenericString();
                int modifier = method.getModifiers();
                if (Modifier.isNative(modifier)) {
//                    log("Fail to hook Native " + logTarget);
                } else if (Modifier.isInterface(modifier)) {
//                    log("Fail to hook Interface " + logTarget);
                } else if (Modifier.isAbstract(modifier)) {
//                    log("Fail to hook Abstract " + logTarget);
                } else {
//                    boolean isEntry = false;
//                    if (checkEntry && Modifier.isPublic(modifier) && !Modifier.isStatic(modifier)) {
//                        isEntry = true;
//                    }
                    XC_MethodHook hook = new SystemServerMethodHook(TraceData.id, isEntry, rootSets);
                    XposedBridge.hookMethod(method, hook);
                    log("Hooked " + (isEntry ? "(entry)" : "") + logTarget + " id " + TraceData.id);

                    TraceData.registerMethod(method);
                }
            } else if (member instanceof Constructor) {
                Constructor constructor = (Constructor) member;
                logTarget = constructor.toGenericString();
                XC_MethodHook hook = new SystemServerMethodHook(TraceData.id, false, rootSets);
                XposedBridge.hookMethod(constructor, hook);
                log("Hooked constructor " + logTarget + " id " + TraceData.id);
                TraceData.registerConstructor(constructor);
            } else {
                log("Internal Error: Fail to hook " + member.getName());
            }
        } catch (Exception e) {
            log("Fail to hook " + logTarget);
        }

    }

    private Context getSystemContext(ClassLoader cl) {
        Context context = (Context) XposedHelpers.callMethod(
                XposedHelpers.callStaticMethod(
                        XposedHelpers.findClass("android.app.ActivityThread", cl), "currentActivityThread"),
                "getSystemContext");
        return context;
    }

    // ------------------------- Receivers ----------------------------------

    /**
     * A receiver to monitor setTraceStart {@link HookService}.
     */
    static class TraceStartReceiver extends BroadcastReceiver {
        @Override
        public void onReceive(Context context, Intent intent) {
            boolean traceStart = intent.getBooleanExtra("traceStart", false);
            SystemServerMethodHook.traceStart = traceStart;
//            try {
//                if (traceStart != hookService.isTraceStart()) {
//                    log("traceStart is not consistent");
//                }
//            } catch (RemoteException e) { }
//
//            if (traceStart) {
//                log("Trace starts");
//            } else {
//                log("Trace ends");
//            }
        }
    }

    /**
     * A receiver to monitor setTraceStart {@link HookService}.
     */
    static class GetMemoryInfoReceiver extends BroadcastReceiver {

        ActivityManager am = null;
//        int[] pids = new int[] { XposedHook.pid };
//        private MemoryInfo memoryInfo = new MemoryInfo();

        @Override
        public void onReceive(Context context, Intent intent) {
            if (null == am) {
                am = (ActivityManager) context.getSystemService(Service.ACTIVITY_SERVICE);
            }
//            Debug.MemoryInfo[] memoryInfos = am.getProcessMemoryInfo(pids);
//            Debug.MemoryInfo memoryInfo = memoryInfos[0];
            MemoryInfo memoryInfo = MemoryInfo.getCurrentMemoryInfo();
            try {
//                log("Try to post MemoryInfo");
                if (null == memoryInfo) {
                    hookService.postNullMemoryInfo();
                } else {
                    hookService.postMemoryInfo(memoryInfo);
                }
            } catch (RemoteException e) {
                e.printStackTrace();
            }
        }
    }

    static class RebootReceiver extends BroadcastReceiver {
        @Override
        public void onReceive(Context context, Intent intent) {
            log("Reboot Action Received");
            throw new OutOfMemoryError();
        }
    }

    static class CrashHandledReceiver extends BroadcastReceiver {
        @Override
        public void onReceive(Context context, Intent intent) {
            synchronized (javaCrashHandlerHook) {
                synchronized (nativeCrashHandlerHook) {
                    synchronized (crashHandlerHook) {
                        javaCrashHandlerHook.notifyAll();
                        nativeCrashHandlerHook.notifyAll();
                        crashHandlerHook.notifyAll();
                    }
                }
            }
        }
    }

    // ------------------------- Method Hook ----------------------------------

    static class JavaCrashHandlerHook extends XC_MethodHook {
        @Override
        protected void beforeHookedMethod(MethodHookParam param) {
            boolean isSystemServer = true;
            try {
                isSystemServer = param.thisObject.getClass().getDeclaredField("mApplicationObject").get(param.thisObject) == null;
            } catch (NoSuchFieldException | IllegalAccessException e) {
                log(e);
            }
            if (isSystemServer) {
                log("----------------Before Java Crash----------------");
                context.sendBroadcast(crashIntent);
                synchronized (this) {
                    try {
                        this.wait();
                    } catch (InterruptedException e) {
                        e.printStackTrace();
                    }
                }
            }
        }
    }

    static class NativeCrashHandlerHook extends XC_MethodHook {

        protected void beforeHookedMethod(MethodHookParam param) {
            DropBoxManager.Entry entry = (DropBoxManager.Entry) param.args[0];
            if (entry.getTag().equals("system_server_native_crash")) {
                log("----------------Before Native Crash----------------");
                context.sendBroadcast(crashIntent);
                synchronized (this) {
                    try {
                        this.wait();
                    } catch (InterruptedException e) {
                        e.printStackTrace();
                    }
                }
            }
        }
    }

    static class CrashHandlerHook extends XC_MethodHook {

        @SuppressLint("WrongConstant")
        protected void beforeHookedMethod(MethodHookParam param) {
            String processName = (String) param.args[2];
            if (processName.equals("system_server")) {
                log("----------------Before Crash----------------");
                context.sendBroadcast(crashIntent);
                synchronized (this) {
                    try {
                        this.wait();
                    } catch (InterruptedException e) {
                        e.printStackTrace();
                    }
                }
            }
        }
    }

    /**
     * Method/Constructor hook for tracing.
     */
    static class SystemServerMethodHook extends XC_MethodHook {

        public static boolean traceStart = false;
        public static boolean recordStart = false;

        private final int id;
        private final boolean isEntry;
        private final StaticInfo.ValueSpec[] rootSets;
        private Object[] rootSetObjects = null;
        private int traceCount = 0;

        public SystemServerMethodHook(int id, boolean isEntry, StaticInfo.ValueSpec[] rootSets) {
            this.id = id;
            this.isEntry = isEntry;
            this.rootSets = rootSets;
        }

        protected int getRootSetSize(MethodHookParam param) {
            int rootSetSize = -1;
            if (null == rootSets || rootSets.length == 0) {
                return rootSetSize;
            }
            if (null == rootSetObjects) {
                rootSetObjects = new Object[rootSets.length];
                for (int i = 0; i < rootSets.length; ++i) {
                    try {
                        StaticInfo.ValueSpec valueSpec = rootSets[i];
                        Object rootSet = valueSpec.getValue(null, param.thisObject);
                        rootSetObjects[i] = rootSet;
                    } catch (Exception e) {
                        log("Fail to get RootSet for " + e);
                    }
                }
            }
            for (Object rootSet: rootSetObjects) {
                try {
                    if (rootSet instanceof Number) {
                        rootSetSize += (Integer) rootSet;
                    } else if (rootSet instanceof Collection) {
                        rootSetSize += ((Collection) rootSet).size();
                    } else if (rootSet instanceof Map) {
                        rootSetSize += ((Map) rootSet).size();
                    } else {
                        log("Unknown RootSet type " + rootSet.getClass());
                    }
                } catch (Exception e) {
                    log("Fail to get RootSet size on " + rootSet + " for " + e);
                }
            }
            return rootSetSize;
        }

        @Override
        protected void beforeHookedMethod(MethodHookParam param) throws RemoteException {
            if (!traceStart || null == hookService) return;
            if (isEntry && Binder.getCallingUid() == filterUID) {
                // The last trace is not finished
//                if (recordStart) {
//                    hookService.markDirty();
//                }
                recordStart = true;
//                log("> " + id);
            }
            if (!recordStart) return;

            hookService.traceAt(id);
//            if (traceCount % Fuzzer.SAMPLE_RATE == 0) {
//                try {
//                    int rootSetSize = getRootSetSize(param);
//                    if (rootSetSize > 0) {
//                        hookService.postRootSetSize(id, rootSetSize);
//                    }
//                } catch (Exception e) {
//                    log(e);
//                }
//            }
//            ++traceCount;
        }

        @Override
        protected void afterHookedMethod(MethodHookParam param) throws RemoteException {
            if (!traceStart || null == hookService) return;

            if (isEntry && Binder.getCallingUid() == filterUID && recordStart) {
                recordStart = false;
//                hookService.setTraceReady();
                try {
                    int rootSetSize = getRootSetSize(param);
                    if (rootSetSize >= 0) {
                        hookService.postRootSetSize(id, rootSetSize);
                    }
                } catch (Exception e) {
                    log(e);
                }
            }

        }
    }
}
