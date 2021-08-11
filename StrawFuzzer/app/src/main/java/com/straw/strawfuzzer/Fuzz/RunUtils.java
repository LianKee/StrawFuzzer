package com.straw.strawfuzzer.Fuzz;

import android.os.Binder;
import android.os.IBinder;
import android.os.Parcel;

import com.straw.lib.reflection.ParcelableMethod;
import com.straw.lib.utils.LogUtils;
import com.straw.lib.utils.ParcelUtils;
import com.straw.strawfuzzer.Input.InputGenerator;
import com.straw.lib.reflection.MyClassLoader;
import com.straw.lib.system.SystemService;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

public class RunUtils {

    private static String TAG = "RunUtils";

    /**
     * Execute method of service once.
     * @param service Target service, must be supported.
     * @param methodName Name of target method.
     * @param paramClassTypes Class types of method parameters
     * @param paramValues Input parameters
     * @return
     */
    public static RunException run(SystemService service, String methodName, String[] paramClassTypes, Object[] paramValues){
//        Log.d(logTag, "Run " + service.getServiceName() + " " + methodName);
        RunException runException;
//        if (InputGenerator.hasInterfaceType(paramClassTypes)){
//            runException = transactRun(service, methodName, paramClassTypes, paramValues);
//        } else{
            // invokeRun is a safe way to invoke target interface, but passing a crafted IInterface argument doesn't work
            runException = invokeRun(service, methodName, paramClassTypes, paramValues);
//        }
//        if (runException != null) Log.d(logTag, runException.toString());
        return runException;
    }

    public static RunException run(SystemService service, String methodName, Seed seed) {
        return run(service, methodName, seed.getParamTypes(), seed.getParamValues());
    }

    public static RunException run(String serviceName, String methodName, String[] paramClassTypes, Object[] paramValues){
        SystemService service = SystemService.getSystemService(serviceName);
        if (null == service) {
            String message = "Unsupported service " + serviceName;
            return new RunException(RunExceptionType.SERVICE_NOT_FOUND, message, null);
        }
        return run(service, methodName, paramClassTypes, paramValues);
    }

    public static RunException invokeRun(SystemService service, String methodName, String[] paramClassTypes, Object[] paramValues) {

//        Log.d(logTag,"InvokeRun start");
        Class[] paramClass = InputGenerator.getClassByString(paramClassTypes);
        for (int i = 0; i < paramClass.length; ++i) {
            if (InputGenerator.isInterfaceType(paramClassTypes[i]) &&
                    !"android.os.IBinder".equals(paramClassTypes[i]) && paramValues[i] instanceof Binder) {
                try {
                    Class stubClass = MyClassLoader.loadClass(paramClassTypes[i] + "$Stub");
                    if (null == stubClass) {
                        continue;
                    }
                    Object obj = stubClass.getMethod("asInterface", IBinder.class).invoke(null, paramValues[i]);
                    paramValues[i] = paramClass[i].cast(obj);
                } catch (NoSuchMethodException | IllegalAccessException | InvocationTargetException e) {
                    LogUtils.failTo(TAG, "convert to IInterface " + paramClassTypes[i]);
                }
            }
        }

        Object managerObject = service.getManagerObject();
        if (null == managerObject) {
            String message = "Fail to get manager object of service " + service.getServiceName();
            return new RunException(RunExceptionType.REFLECTION_NOT_FOUND, message, null);
        }
        Class proxyClass = service.getProxyClass();
        if (null == proxyClass) {
            String message = "Fail to get proxy class of service " + service.getServiceName();
            return new RunException(RunExceptionType.REFLECTION_NOT_FOUND, message, null);
        }

        Method invokeMethod = service.getMethod(methodName);
        if (null == invokeMethod) {
            String message = "Fail to get method " + methodName + " of service " + service.getServiceName();
            return new RunException(RunExceptionType.REFLECTION_NOT_FOUND, message, null);
        }
        if (!invokeMethod.isAccessible()) {
            invokeMethod.setAccessible(true);
        }

        try {
//            Log.d(logTag,"Method Invoke Start.");
            Object res = invokeMethod.invoke(managerObject, paramValues);
//            Log.d(logTag, "Method Invoke End.");
            return null;
        } catch (IllegalAccessException | IllegalArgumentException e) {
            return new RunException(RunExceptionType.ILLEGAL_INVOKE, "Illegal invoke", e);
        } catch (InvocationTargetException e) {
            return new RunException(RunExceptionType.TARGET_EXCEPTION, "InvocationTargetException", e);
        }
    }

    public static RunException transactRun(SystemService service, String methodName, String[] paramClassTypes, Object[] paramValues){
//        Log.d(logTag,"TransactRun start");

        IBinder iBinder = service.getIBinder();
        if (null == iBinder) {
            String message ="Fail to get IBinder of service " + service.getServiceName();
            return new RunException(RunExceptionType.REFLECTION_NOT_FOUND, message, null);
        }
        Class stubClass = service.getStubClass();
        if (null == stubClass) {
            String message = "Fail to get stub class of service " + service.getServiceName();
            return new RunException(RunExceptionType.REFLECTION_NOT_FOUND, message, null);
        }
        int functionCode = service.getFunctionCode(methodName);
        if(functionCode == -1){
            String message = "Fail to get function code of method " + methodName + " of service " + service.getServiceName();
            return new RunException(RunExceptionType.ILLEGAL_TRANSACTION, message, null);
        }
        ParcelableMethod parcelableMethod = service.getParcelableMethod(methodName);

        Parcel in = Parcel.obtain();
        Parcel out = Parcel.obtain();
        try {
            in.writeInterfaceToken(service.getInterfaceName());
            parcelableMethod.writeParamValuesToParcel(in, paramValues);
            for (int i = 0; i < paramValues.length; ++i) {
                String paramType = paramClassTypes[i];
                Object value = paramValues[i];
                if (InputGenerator.isInterfaceType(paramType)) {
                    // This is done by generate
//                    ((Binder) value).attachInterface(null, paramType);
                    in.writeStrongBinder((IBinder) value);
                } else {
                    ParcelUtils.writeToParcel(in, paramType, value);
                }
            }
        } catch (Exception e) {
            String message = "Fail to write parcel. on method " + methodName + "of service" + service.getServiceName() + " : " + e.toString();
            in.recycle();
            out.recycle();
            return new RunException(RunExceptionType.ILLEGAL_TRANSACTION, message, e);
        }

        try{
//            Log.d(logTag,"Transact Start.");
            Boolean onTransactRes = iBinder.transact(functionCode,in,out,0);
            if (!onTransactRes) {
                String message = "Transact function code is not understood.";
                return new RunException(RunExceptionType.ILLEGAL_TRANSACTION, message, null);
            }
            out.readException();
            return null;
        }catch (Exception e){
            String message = "Transact End with " + e.toString();
            return new RunException(RunExceptionType.TARGET_EXCEPTION, message, e);
        }finally {
            in.recycle();
            out.recycle();
        }
    }

    public enum RunExceptionType { REFLECTION_NOT_FOUND, SERVICE_NOT_FOUND, ILLEGAL_INVOKE, ILLEGAL_TRANSACTION, TARGET_EXCEPTION, DEFAULT }

    public static class RunException extends Exception {

        private RunExceptionType type;
        private Exception realException;

        public RunException(RunExceptionType type, String message, Exception realException) {
            super(message);
            this.type = type;
            this.realException = realException;
        }

        public Exception getRealException() {
            return realException;
        }

        public RunExceptionType getType() {
            return type;
        }

        @Override
        public String toString() {
            StringBuilder sb = new StringBuilder();
            sb.append("RunException{");
            sb.append("type=");
            sb.append(type.toString());
            sb.append(", msg=[");
            String thisExceptionMessage = this.getMessage();
            if (thisExceptionMessage.length() > 256) {
                thisExceptionMessage = thisExceptionMessage.substring(0, 256) + "...";
            }
            sb.append(thisExceptionMessage);
            sb.append("], realException=");
            if (null == realException) {
                sb.append("null}");
            } else {
                sb.append("[");
                String realExceptionMessage;
                if (realException instanceof InvocationTargetException) {
                    realExceptionMessage = ((InvocationTargetException) realException).getTargetException().getMessage();
                } else {
                    realExceptionMessage = realException.getMessage();
                }
                if (null != realExceptionMessage && realExceptionMessage.length() > 256) {
                    realExceptionMessage = realExceptionMessage.substring(0, 128) + "..." + realExceptionMessage.substring(realExceptionMessage.length() - 128);
                }
                if (null != realExceptionMessage) {
                    sb.append(realExceptionMessage);
                }
                sb.append("]}");
            }
            return sb.toString();
        }
    }
}
