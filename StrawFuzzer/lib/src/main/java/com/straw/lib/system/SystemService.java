package com.straw.lib.system;

import android.os.IBinder;
import android.os.RemoteException;
import android.util.Log;

import com.straw.lib.reflection.MyClassLoader;
import com.straw.lib.reflection.ParcelableMethod;
import com.straw.lib.utils.LogUtils;

import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class SystemService {

    private static final String TAG = "Straw_SS";
    private static final Map<String, SystemService> systemServiceMap = new HashMap<>();

    private String serviceName;
    private ServiceInfo serviceInfo;

    // Runtime
    private IBinder iBinder;
    private Class interfaceClass;
    private Class stubClass;
    private Class proxyClass;
    private Object managerObject;

    private Map<String, Integer> funcCodeMap = new HashMap<>();
    private Map<String, Method> methodMap = new HashMap<>();
    private Map<String, ParcelableMethod> parcelableMethodMap = new HashMap<>();

    protected SystemService(String serviceName) {
        this.serviceName = serviceName;
        this.serviceInfo = ServiceInfo.getServiceInfo(serviceName);

        this.iBinder = null;
        this.interfaceClass = null;
        this.stubClass = null;
        this.proxyClass = null;
        this.managerObject = null;
    }

    /**
     * Check whether a system service is supported by the tool
     * @return whether the service is supported.
     */
    public boolean isSupported() {
        return !getServiceClassName().equals("null");
    }

    public String getServiceName() {
        return serviceName;
    }

    public Object getManagerObject() {
        if (null == managerObject) {
            IBinder iBinder = getIBinder();
            Class stubClass = getStubClass();
            try {
                managerObject = stubClass.getMethod("asInterface",IBinder.class).invoke(null,iBinder);
            } catch (IllegalAccessException | InvocationTargetException | NoSuchMethodException e) {
                return null;
            }
        }
        return managerObject;
    }

    public IBinder getIBinder() {
        if (null == iBinder) {
            iBinder = getService(serviceName);
        }
        return iBinder;
    }

    public Class getInterfaceClass() {
        if (null == interfaceClass) {
            interfaceClass = MyClassLoader.loadClass(getInterfaceName());
        }
        return interfaceClass;
    }

    public Class getProxyClass() {
        if (null == proxyClass) {
            proxyClass = MyClassLoader.loadClass(getProxyClassName());
        }
        return proxyClass;
    }

    public Class getStubClass() {
        if (null == stubClass) {
            stubClass = MyClassLoader.loadClass(getStubClassName());
        }
        return stubClass;
    }

    public String getInterfaceName() {
        if (null == getIBinder()) return "";
        try {
            return iBinder.getInterfaceDescriptor();
        } catch (RemoteException e) {
            e.printStackTrace();
        }
        return "";
    }

    public String getStubClassName() {
        String interfaceName = getInterfaceName();
        if (interfaceName.length() == 0) {
            return "";
        }
        return interfaceName + "$Stub";
    }

    public String getProxyClassName() {
        String stubClassName = getStubClassName();
        if (stubClassName.length() == 0) {
            return stubClassName;
        }
        return stubClassName + "$Proxy";
    }

    public String getServiceClassName() {
        if (null == serviceInfo) {
            return "null";
        }
        if ("null".equals(serviceInfo.serviceClassName.toLowerCase())) {
            return "null";
        }
        return serviceInfo.serviceClassName;
    }

    public int getFunctionCode(String methodName) {
        Integer functionCode = funcCodeMap.get(methodName);
        if (null == functionCode) functionCode = -1;
        if (functionCode < 0) {
            try {
                Field field = getStubClass().getDeclaredField("TRANSACTION_" + methodName);
                field.setAccessible(true);
                Object res = field.get(null);
                if (res != null) {
                    functionCode = (int) res;
                    funcCodeMap.put(methodName, functionCode);
                }
            } catch (Exception e) { }
        }
        if (functionCode < 0) {
            LogUtils.failTo(TAG, "get functionCode for" + methodName);
        }
        return functionCode;
    }

    public ParcelableMethod getParcelableMethod(String methodName) {
        ParcelableMethod parcelableMethod = parcelableMethodMap.get(methodName);
        if (null == parcelableMethod) {
            Method method = getMethod(methodName);
            if (null == method) return null;
            parcelableMethod = new ParcelableMethod(method);
            parcelableMethodMap.put(methodName, parcelableMethod);
        }
        return parcelableMethod;
    }

    public Method getMethod(String methodName) {
        Method res = methodMap.get(methodName);
        if (null == res) {
            for (Method method : getProxyClass().getDeclaredMethods()) {
                if (method.getName().equals(methodName)) {
                    res = method;
                    methodMap.put(methodName, method);
                    break;
                }
            }
        }
        if (null == res) {
            Log.w(TAG, "Fail to get method " + methodName);
        }
        return res;
    }


    /*
        Static methods
     */


    public static SystemService getSystemService(String serviceName) {
        SystemService systemService = systemServiceMap.get(serviceName);
        if (null == systemService) {
            systemService = new SystemService(serviceName);
            systemServiceMap.put(serviceName, systemService);
            return systemService;
        }
        if (null == systemService) {
            Log.w(TAG, "Fail to get SystemService " + serviceName);
        }
        return systemService;
    }

    public static SystemService getSystemServiceByStubClassName(String stubClassName) {
        ServiceInfo info = ServiceInfo.getServiceInfoByStubClass(stubClassName);
        if (null == info) return null;
        SystemService service = getSystemService(info.serviceName);
        return service;
    }

    public static SystemService getSystemServiceByServiceClassName(String serviceClassName) {
        ServiceInfo info = ServiceInfo.getServiceInfoByServiceClass(serviceClassName);
        if (null == info) return null;
        SystemService service = getSystemService(info.serviceName);
        return service;
    }

    public static List<SystemService> getSystemServices() {
        List<SystemService> allServices = new ArrayList<>();
        String[] serviceNames = listServices();
        for (String serviceName : serviceNames) {
            SystemService service = getSystemService(serviceName);
            if (null != service) {
                allServices.add(service);
            }
        }
        return allServices;
    }

    public static List<SystemService> getSystemServicesFromInfo() {
        List<SystemService> allServices = new ArrayList<>();
        for (String serviceName: ServiceInfo.getAvailableServices()) {
            SystemService service = getSystemService(serviceName);
            if (null != service && "null" != service.getServiceName()) {
                allServices.add(service);
            }
        }
        return allServices;
    }

    private static IBinder getService(String serviceName) {
        try {
            return (IBinder) mGetService.invoke(null, serviceName);
        } catch (IllegalAccessException | InvocationTargetException e) {}
        return null;
    }

    private static String[] listServices() {
        try {
            return (String[]) mListServices.invoke(null);
        } catch (IllegalAccessException | InvocationTargetException e) {}
        return new String[] {};
    }

    private static Class cServiceManager;
    private static Method mGetService;
    private static Method mListServices;

    static {
        try {
            cServiceManager = MyClassLoader.loadClass("android.os.ServiceManager");
            mGetService = cServiceManager.getDeclaredMethod("getService", String.class);
            mListServices = cServiceManager.getDeclaredMethod("listServices");
        } catch (NoSuchMethodException e) {
            e.printStackTrace();
        }
    }

}
