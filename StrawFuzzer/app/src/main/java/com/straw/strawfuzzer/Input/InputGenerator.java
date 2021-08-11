package com.straw.strawfuzzer.Input;

import android.os.Binder;
import android.os.IBinder;
import android.util.Log;

import com.straw.strawfuzzer.Constants;
import com.straw.lib.reflection.AbstractClassInfo;
import com.straw.strawfuzzer.MainActivity;
import com.straw.lib.reflection.MyClassLoader;

import java.lang.reflect.Array;
import java.lang.reflect.Constructor;
import java.lang.reflect.Modifier;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.Set;


public class InputGenerator {

    public static final int BINDER_POOL_SIZE = 6;
    public static Binder[] binders = new Binder[BINDER_POOL_SIZE];

    private static final String TAG = "Straw_InputGenerator";

    private static CharSequence CHAR_SEQUENCE = "char_sequence";
    private static List<Object> LISTSEED = new ArrayList<>();
    private static Map<String,String> MAPSEED = new HashMap<>();
    private static Binder binder = new Binder();

    private static Random random = new Random((int)(System.currentTimeMillis()%100));
    private static int iv = random.nextInt();

    private static Set<String> banedParamTypes = new HashSet<>();

    private static final int RECURSION_LIMIT = 20;
    private static final int FETCH_LIMIT = 256;
    private static int binder_pool_idx = 0;

    private static Set<Constructor> bannedConstructor = new HashSet<>();
    // Not support constructor param
    private static Set<Class> unsupportedParams = new HashSet<>();

    static {
        for (int i = 0; i < BINDER_POOL_SIZE; ++i) {
            binders[i] = new Binder();
        }
        unsupportedParams.add(MyClassLoader.loadClass("android.os.Parcel"));
        unsupportedParams.add(MyClassLoader.loadClass("android.os.ParcelFileDescriptor"));
        unsupportedParams.add(MyClassLoader.loadClass("java.io.File"));
    }

    public static Class getClassByString(String classTypeName){
        Class result;
        switch (classTypeName) {
            case "int":
                result = int.class;
                break;
            case "long":
                result = long.class;
                break;
            case "float":
                result = float.class;
                break;
            case "boolean":
                result = boolean.class;
                break;
            case "char":
                result = char.class;
                break;
            case "double":
                result = double.class;
                break;
            case "byte":
                result = byte.class;
                break;
            case "short":
                result = short.class;
                break;
            default:
                result = MyClassLoader.loadClass(classTypeName);
                break;
        }
        return result;
    }

    public static Class[] getClassByString(String[] paramClassType){
        Class[] paramClass = new Class[paramClassType.length];
        for(int i=0; i<paramClassType.length; ++i){
            String classTypeName = paramClassType[i];
            paramClass[i] = getClassByString(classTypeName);
        }
        return paramClass;
    }

    public static <T> T generateSeedByClass(Class clazz){
        String classTypeName = clazz.getName();
        return generateSeedByClass(classTypeName, RECURSION_LIMIT);
    }

    public static <T> T generateSeedByClass(String classTypeName){
        T instance =  generateSeedByClass(classTypeName, RECURSION_LIMIT);
        return instance;
    }

    public static <T> T generateBasicSeedByClass(String classTypeName) {
        switch (classTypeName) {
            case "int":
            case "java.lang.Integer":
                int tmp = random.nextInt(1000);
                tmp = tmp + 4 - tmp % 4;
//            tmp = 208;
//                Log.d(Constants.INPUTGENERATOR_TAG, "random int: " + tmp);
                return (T) (Object) (tmp);
            case "long":
            case "java.lang.Long":
                long tmplong = random.nextLong();
                if (tmplong < 0)
                    tmplong = Math.abs(tmplong);
                tmplong = tmplong + 4 - tmplong % 4;
//                Log.d(TAG, "random long: " + tmplong);
                return (T) (Object) (tmplong);
            case "float":
            case "java.lang.Float":
                return (T) (Object) (random.nextFloat());
            case "boolean":
            case "java.lang.Boolean":
                return (T) (Object) (random.nextBoolean());
            case "char":
            case "java.lang.Character":
                return (T) (Object) ((char) (random.nextInt(107) + 20));
            case "double":
            case "java.lang.Double":
                return (T) (Object) (random.nextDouble());
            case "byte":
            case "java.lang.Byte":
                return (T) (Object) ((byte) random.nextInt(128));
            case "short":
            case "java.lang.Short":
                return (T) (Object) ((short) random.nextInt(32767));
            case "java.lang.String":
                String tmpString = getRandomString(getRandomLength(32768));
//                String tmpString = getRandomString(getRandomLength(10));
//                Log.d(Constants.INPUTGENERATOR_TAG, "string length: " + tmpString.length());
                return (T) (tmpString);
            case "java.lang.CharSequence":
                CHAR_SEQUENCE = getRandomString(random.nextInt(100));
                return (T) (CHAR_SEQUENCE);
            case "java.util.List":
                if (LISTSEED.isEmpty()) {
                    IBinder iBinder = null;
                    LISTSEED.add(iBinder);
                }
                return (T) (LISTSEED);
            case "java.util.Map":
                if (MAPSEED.isEmpty())
                    MAPSEED.put(getRandomString(random.nextInt(100)), getRandomString(random.nextInt(100)));
                return (T) (MAPSEED);
            case "android.content.Context":
                return (T) MainActivity.context;
            default:
                break;
        }
        return null;
    }

    public static <T> T generateSeedByClass(String classTypeName, int recursionLeft){
        if (banedParamTypes.contains(classTypeName)) return null;
        // todo: handle hard classes
        if (HardClassHandler.HardClassSet.contains(classTypeName)){
            return HardClassHandler.HandleHardCase(classTypeName);
        }
        // recursion depth check
        recursionLeft--;
        if (recursionLeft == 0){
            Log.d(TAG,"recursion depth exceeds limit: 20");
            return null;
        }
        // generate input
        T basicResult = generateBasicSeedByClass(classTypeName);
        if (null != basicResult) {
            return basicResult;
        }

        if (isInterfaceType(classTypeName)) {
            try{
                binder.attachInterface(null,classTypeName);
                if (classTypeName.equals("android.os.IBinder"))
                    return (T)(binder);
                return (T)(MyClassLoader.loadClass(classTypeName+"$Stub").getMethod("asInterface", IBinder.class).invoke(null,binder));
            }catch (Exception e){
                Log.d(TAG,"Exception in generating seed for class "+classTypeName);
                if (!classTypeName.equals("android.os.IBinder"))
                    e.printStackTrace();
                return null;
            }
        } else if (classTypeName.startsWith("[")) {
            if (classTypeName.startsWith("[[")) {
                //todo: 其他数据类型二维数组的处理
                if (classTypeName.equals("[[Ljava.lang.String;")) {
                    String[][] tmpStrings = new String[getRandomLength(100)][getRandomLength(100)];
                    for (int i = 0; i < tmpStrings.length; ++i) {
                        for (int j=0;j<tmpStrings[0].length;++j) {
                            tmpStrings[i][j] = getRandomString(random.nextInt(100));
                        }
                    }
                    return (T)(tmpStrings);
                }
                else {
                    Log.d(TAG,"Not Support Type: "+classTypeName);
                    return null;
                }
            }

            if (classTypeName.equals("[Z")){
                boolean[] tmpboolean = new boolean[getRandomLength(1000)];
                for (int i=0;i<tmpboolean.length;++i){
                    tmpboolean[i] = random.nextBoolean();
                }
                return (T)(tmpboolean);
            } else if (classTypeName.equals("[B")){
                byte[] tmpBytes = new byte[getRandomLength(1000)];
                random.nextBytes(tmpBytes);
                return (T)(tmpBytes);
            } else if (classTypeName.equals("[C")){
                return (T)(getRandomString(random.nextInt(1000)).toCharArray());
            } else if (classTypeName.equals("[S")){
                short[] tmpshort = new short[getRandomLength(1000)];
                for (int i =0;i<tmpshort.length;++i)
                    tmpshort[i] = (short)random.nextInt(32767);
                return (T)(tmpshort);
            } else if (classTypeName.equals("[I")){
                int[] tmpint = new int[getRandomLength(1000)];
                for (int i=0;i<tmpint.length;++i)
                    tmpint[i]=random.nextInt(Integer.MAX_VALUE);
                return (T)(tmpint);
            } else if (classTypeName.equals("[J")){
                long[] tmplong = new long[getRandomLength(1000)];
                for (int i=0;i<tmplong.length;++i)
                    tmplong[i] = random.nextLong();
                return (T)(tmplong);
            } else if (classTypeName.equals("[F")){
                float[] tmpfloat = new float[getRandomLength(1000)];
                for (int i=0;i<tmpfloat.length;++i)
                    tmpfloat[i] = random.nextFloat()*99;
                return (T)(tmpfloat);
            } else if (classTypeName.equals("[D")){
                double[] tmpdouble = new double[getRandomLength(1000)];
                for (int i=0;i<tmpdouble.length;++i)
                    tmpdouble[i] = random.nextDouble()*99;
                return (T)(tmpdouble);
            } else if (classTypeName.startsWith("[L")){
                String tmpClassName = classTypeName.substring(2,classTypeName.length()-1);
                int arrLen = getRandomLength(10);
//                Log.d(Constants.INPUTGENERATOR_TAG,"Array length: "+arrLen);
                Class arrTypeClass = MyClassLoader.loadClass(tmpClassName);
                if (null ==arrTypeClass) {
                    return null;
                }
                Object[] tmpObject = (Object[]) Array.newInstance(arrTypeClass,arrLen);
                if (tmpClassName.equals("java.lang.String")) {
                    for (int i = 0; i < arrLen; ++i) {
                        tmpObject[i] = getRandomString(getRandomLength(3276));
                    }
                } else {
                    for (int i = 0; i < arrLen; ++i) {
                        tmpObject[i] = generateSeedByClass(tmpClassName, recursionLeft);
                    }
                }
                return (T) MyClassLoader.loadClass(classTypeName).cast(tmpObject);
            } else{
                Log.d(TAG,"Not Support Type: "+classTypeName);
                return null;
            }
        } else if (classTypeName.equals("Object")) {
            return null;
        } else {
            try{
                Class clazz = MyClassLoader.loadClass(classTypeName);
                // todo: handle abstract class
                if (Modifier.isAbstract(clazz.getModifiers())){
                    if(AbstractClassInfo.AbstractClassMap.containsKey(classTypeName)){
                        classTypeName = AbstractClassInfo.AbstractClassMap.get(classTypeName);
                        clazz = MyClassLoader.loadClass(classTypeName);
                    }else {
                        Log.d(TAG,"Error -- Not handle abstract class "+classTypeName);
                        return null;
                    }
                }
                // todo: handle class dependency
                DependencyHandler.HandleDependency(classTypeName);

                Object targetInstance = null;
                try{
                    targetInstance = clazz.newInstance();
                }catch (Exception e){
//                    Log.d(TAG,classTypeName+" does not have a non-param constructor");
                }
                if (targetInstance != null){
//                    Log.d(TAG,classTypeName+" has a non-param constructor");
                    return (T)targetInstance;
                }
                // handle class with builder
                targetInstance = getInstanceByBuilder(classTypeName);
                if (targetInstance != null){
//                    Log.d(TAG,classTypeName+" getInstance by Builder");
                    return (T)targetInstance;
                }

                Constructor constructor = null;
                // filter situations which has self-type object as constructor params
                constructor = getProperConstructor(clazz);
                if (constructor == null) {
                    bannedConstructor.clear(); // make a path for banned constructors
                    Log.d(TAG,"No proper constructor for "+classTypeName+", return null");
                    return null;
                }
                if (!constructor.isAccessible())
                    constructor.setAccessible(true);

                Class[] classes = constructor.getParameterTypes();

                if (classes.length == 0) {
//                    Log.d(TAG,classTypeName+" has a private non-param constructor");
//                    return null;
                    targetInstance = constructor.newInstance();
                } else {
                    Object[] paramValues = new Object[classes.length];
//                    Log.d(TAG,classTypeName + " constructor " + constructor.toString());
                    if (classTypeName.equals("android.accounts.Account")){
                        paramValues[0] = InputGenerator.generateSeedByClass("java.lang.String");
                        paramValues[1] = "badloopAccount";
                        paramValues[2] = InputGenerator.generateSeedByClass("java.lang.String");
                    } else {
                        for (int i =0; i < classes.length; ++i){
                            if (classes[i].getName().equals("java.lang.Object")) {
                                if(classTypeName.equals("com.android.server.pm.permission.PermissionManagerService")){
                                    paramValues[i] = InputGenerator.generateSeedByClass("java.util.concurrent.locks.ReentrantLock",recursionLeft);
                                    Log.d(TAG,classTypeName+": replace Object with java.util.concurrent.locks.ReentrantLock");
                                    continue;
                                }
                            }
//                            Log.d(TAG,classTypeName+":"+classes[i].getName());
                            paramValues[i] = InputGenerator.generateSeedByClass(classes[i].getName(),recursionLeft);
                        }
                    }
                    if (!constructor.isAccessible())
                        constructor.setAccessible(true);
                    targetInstance = constructor.newInstance(paramValues);
                }
                // temporary ban a constructor
                if (null == targetInstance) {
                    bannedConstructor.add(constructor);
                }
                return (T)targetInstance;
            } catch (Exception e) {
                e.printStackTrace();
                System.out.println("Error:"+classTypeName);
                Log.d(TAG,"Exception in "+classTypeName);
                return null;
            }
        }
    }

    public static <T> T generateSmallSeedByClass(String classTypeName){
        T instance =  generateSmallSeedByClass(classTypeName, RECURSION_LIMIT);
        if (instance != null){
//            Log.d(TAG,"get instance successfully: "+classTypeName);
        }else{
            Log.d(TAG,"fail to get instance: "+classTypeName);
        }
        return instance;
    }

    public static <T> T generateSmallSeedByClass(String classTypeName,int recursionLeft){
        // recursion depth check
        recursionLeft--;
        if (recursionLeft == 0){
            return null;
        }
        // generate input
        if (classTypeName.equals("android.content.Context")){
            return (T) MainActivity.context;
        }else if (classTypeName.equals("java.lang.Object")){
            return null;
        }

        if (isInterfaceType(classTypeName)){
            return generateSeedByClass(classTypeName);
        }else if (classTypeName.equals("int")){
            int tmp = 4;
//            Log.d(TAG,"small int: "+tmp);
            return (T)(Object)(tmp);
        } else if(classTypeName.equals("long")) {
            long tmplong = 4L;
//            Log.d(TAG,"small long: "+tmplong);
            return (T)(Object)(tmplong);
        } else if(classTypeName.equals("float")) {
            return (T)(Object)(random.nextFloat());
        } else if(classTypeName.equals("boolean")) {
            return (T)(Object)(random.nextBoolean());
        } else if(classTypeName.equals("char")) {
            return (T)(Object)((char)(random.nextInt(107)+20));
        } else if(classTypeName.equals("double")) {
            return (T)(Object)(random.nextDouble());
        } else if(classTypeName.equals("byte")) {
            return (T)(Object)((byte)random.nextInt(128));
        } else if(classTypeName.equals("short")) {
            T t = (T) (Object) ((short) 8);
            return t;
        } else if (classTypeName.equals("java.lang.String")) {
            String tmpString = getRandomString(getRandomLength(100));
//            Log.d(TAG,"string length: "+tmpString.length());
            return (T)(tmpString);
        } else if (classTypeName.equals("java.lang.CharSequence")){
            CHAR_SEQUENCE = getRandomString(random.nextInt(100));
            return (T)(CHAR_SEQUENCE);
        }
        else if (classTypeName.equals("java.util.List")){
            if (LISTSEED.isEmpty()){
                IBinder iBinder = null;
                LISTSEED.add(iBinder);
            }
            return (T)(LISTSEED);
        }else if (classTypeName.equals("java.util.Map")){
            if (MAPSEED.isEmpty())
                MAPSEED.put(getRandomString(random.nextInt(100)),getRandomString(random.nextInt(100)));
            return (T)(MAPSEED);
        }else if (classTypeName.startsWith("[")){
            if (classTypeName.startsWith("[[")){
                //todo: 其他数据类型二维数组的处理
                if (classTypeName.equals("[[Ljava.lang.String;")) {
                    String[][] tmpStrings = new String[getRandomLength(10)][getRandomLength(10)];
                    for (int i = 0; i < tmpStrings.length; ++i){
                        for (int j=0;j<tmpStrings[0].length;++j)
                            tmpStrings[i][j] = getRandomString(random.nextInt(100));
                    }
                    return (T)(tmpStrings);
                }
                else {
                    Log.d(TAG,"Not Support Type: "+classTypeName);
                    return null;
                }
            }

            if (classTypeName.equals("[Z")){
                boolean[] tmpboolean = new boolean[getRandomLength(10)];
                for (int i=0;i<tmpboolean.length;++i){
                    tmpboolean[i] = random.nextBoolean();
                }
                return (T)(tmpboolean);
            } else if (classTypeName.equals("[B")){
                byte[] tmpBytes = new byte[getRandomLength(10)];
                random.nextBytes(tmpBytes);
                return (T)(tmpBytes);
            } else if (classTypeName.equals("[C")){
                return (T)(getRandomString(random.nextInt(10)).toCharArray());
            }
            else if (classTypeName.equals("[S")){
                short[] tmpshort = new short[getRandomLength(10)];
                for (int i =0;i<tmpshort.length;++i)
                    tmpshort[i] = (short)random.nextInt(32);
                return (T)(tmpshort);
            } else if (classTypeName.equals("[I")){
                int[] tmpint = new int[getRandomLength(10)];
                for (int i=0;i<tmpint.length;++i)
                    tmpint[i]=random.nextInt(10);
                return (T)(tmpint);
            } else if (classTypeName.equals("[J")){
                long[] tmplong = new long[getRandomLength(10)];
                for (int i=0;i<tmplong.length;++i)
                    tmplong[i] = 4L;
                return (T)(tmplong);
            } else if (classTypeName.equals("[F")){
                float[] tmpfloat = new float[getRandomLength(10)];
                for (int i=0;i<tmpfloat.length;++i)
                    tmpfloat[i] = random.nextFloat()*9;
                return (T)(tmpfloat);
            }
            else if (classTypeName.equals("[D")){
                double[] tmpdouble = new double[getRandomLength(10)];
                for (int i=0;i<tmpdouble.length;++i)
                    tmpdouble[i] = random.nextDouble()*9;
                return (T)(tmpdouble);
            } else if (classTypeName.startsWith("[L")){
                String tmpClassName = classTypeName.substring(2,classTypeName.length()-1);
                int arrLen = getRandomLength(10);
//                Log.d(TAG,"Array length: "+arrLen);
                Object[] tmpObject = new Object[arrLen];
                for (int i=0;i<tmpObject.length;++i)
                    tmpObject[i] = generateSmallSeedByClass(tmpClassName,recursionLeft);
                return (T)(tmpObject);
            } else{
                Log.d(TAG,"Not Support Type: "+classTypeName);
                return null;
            }
        } else{
            try{
                Class clazz = MyClassLoader.loadClass(classTypeName);
                // Abstract class
                if (Modifier.isAbstract(clazz.getModifiers())){
                    Log.d(TAG,"Abstract class -- "+classTypeName);
                    return null;
                }

                Object targetInstance = null;
                try{
                    targetInstance = clazz.newInstance();
                }catch (Exception e){
//                    Log.d(TAG,classTypeName+" do not have a non-param constructor");
                }
                if (targetInstance != null){
//                    Log.d(TAG,classTypeName+" have a non-param constructor");
                    return (T)targetInstance;
                }

                Constructor constructor = null;
                // filter situations which has self-type object as constructor params
                constructor = getProperConstructor(clazz);
                if (constructor == null){
                    Log.d(TAG,"No proper constructor for "+classTypeName+", return null");
                    return null;
                }
                if (!constructor.isAccessible())
                    constructor.setAccessible(true);

                Class[] classes = constructor.getParameterTypes();

                if (classes.length == 0){
//                    Log.d(TAG,classTypeName+" has a private non-param constructor");
                    targetInstance = constructor.newInstance();
                }else{
                    Object[] paramValues = new Object[classes.length];
//                    Log.d(TAG,classTypeName+" constructor has "+classes.length+" fields");
                    if (classTypeName.equals("android.accounts.Account")){
                        paramValues[0] = InputGenerator.generateSmallSeedByClass("java.lang.String");
                        paramValues[1] = "badloopAccount";
                        paramValues[2] = InputGenerator.generateSmallSeedByClass("java.lang.String");

                    }else {
                        for (int i =0;i<classes.length;++i){
//                            Log.d(TAG,classTypeName+":"+classes[i].getName());
                            paramValues[i] = InputGenerator.generateSmallSeedByClass(classes[i].getName(),recursionLeft);
                            if (paramValues[i] == null)
                                return null;
                        }
                    }
                    if (!constructor.isAccessible())
                        constructor.setAccessible(true);
                    targetInstance = constructor.newInstance(paramValues);
                }
                return (T)targetInstance;
            }catch (Exception e){
                Log.d(TAG,"Exception in " + classTypeName + " " + e);
                return null;
            }
        }
    }

    public static Constructor getProperConstructor(Class clazz) {
//        Class builderClass = MyClassLoader.loadClass(clazz.getName()+"$Builder");

        Constructor properConstructor = null;
        Constructor noParamConstructor = null;
        int tmpclassesLength = 0;
        boolean advancedParamFlag = false;
        for (Constructor constructor : clazz.getDeclaredConstructors()) {
            if (bannedConstructor.contains(constructor)) continue;
            Class[] classes = constructor.getParameterTypes();
            List<Class> classList = Arrays.asList(classes);
            boolean hasUnsupportedParamClass = false;
            for (Class paramClass: classList) {
                if (unsupportedParams.contains(paramClass)) {
                    hasUnsupportedParamClass = true;
                    break;
                }
            }
            if (hasUnsupportedParamClass || classList.contains(clazz))
                continue;
            if (classes.length == 1 && classes[0].getName().equals("android.content.Context"))
                return constructor;
            if (properConstructor == null){
                properConstructor = constructor;
                tmpclassesLength = classes.length;
                if (hasAdvancedParamType(classes))
                    advancedParamFlag = true;
                else
                    advancedParamFlag = false;
                continue;
            } else{
                if (classes.length == 0){
                    noParamConstructor = constructor;
                }

                if (classes.length < tmpclassesLength){
                    continue;
                }else if (classes.length == tmpclassesLength){
                    if (advancedParamFlag && !hasAdvancedParamType(classes)){
                        properConstructor = constructor;
                        tmpclassesLength = classes.length;
                        advancedParamFlag = false;
                    }
                }else {
                    properConstructor = constructor;
                    tmpclassesLength = classes.length;
                    if (hasAdvancedParamType(classes))
                        advancedParamFlag = true;
                    else
                        advancedParamFlag = false;
                }
            }
        }
        if (properConstructor == null){
            properConstructor = noParamConstructor;
        }
        return properConstructor;
    }


    public static Boolean hasInterfaceType(String[] paramTypes){
        for (String paramType : paramTypes){
            if (isInterfaceType(paramType))
                return true;
        }
        return false;
    }

    public static Boolean isInterfaceType(String paramType) {
        String[] strArr = paramType.split("\\.");
        if (strArr[strArr.length - 1].startsWith("I") && Character.isUpperCase(strArr[strArr.length - 1].charAt(1))) {
            return true;
        } else {
            return false;
        }
    }

    public static Boolean hasAdvancedParamType(Class[] classes){
        ArrayList<String> classNames = new ArrayList<>();
        for (Class c : classes)
            classNames.add(c.getName());
        return hasAdvancedParamType(classNames.toArray(new String[classes.length]));
    }

    public static Boolean hasAdvancedParamType(String[] paramTypes){
        for (String paramType : paramTypes){
            if (!Constants.typicalParamType.contains(paramType))
                return true;
        }
        return false;
    }

    public static int getRandomLength(int length){
        return random.nextInt(length)+1;
    }

    public static String getRandomString(int length){
        String str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        StringBuilder sb = new StringBuilder(length);
        int fetchSize = Math.min(length, FETCH_LIMIT);
        for (int i=0; i < fetchSize; ++i) {
            sb.append(str.charAt(random.nextInt(62)));
        }
        if (fetchSize < length) {
            String ivStr = String.valueOf(iv);
            sb.append(ivStr, 0, Math.min(length - fetchSize, ivStr.length()));
            String repeatSlice = sb.toString();
            int increaseCount = length / sb.length();
            for (int i = 0; i < increaseCount; ++i) {
                sb.append(repeatSlice);
            }
            // complete
            for (int i=sb.length(); i < length; ++i) {
                sb.append(str.charAt(random.nextInt(62)));
            }
        }
        return sb.toString();
    }

    public static Object getInstanceByBuilder(String classTypeName){
        Class builderClass = MyClassLoader.loadClass(classTypeName+"$Builder");
        if (builderClass == null)
            return null;
        banedParamTypes.add(classTypeName);
        Object builder = InputGenerator.generateSeedByClass(builderClass);
        banedParamTypes.remove(classTypeName);
        if (null == builder) {
            return null;
        }
        try{
            return builderClass.getDeclaredMethod("build").invoke(builder);
        }catch (Exception e){
            return null;
        }
    }

    public static Object generateInput(String parameterType) {
        if (isInterfaceType(parameterType)) {
            Binder binder = binders[binder_pool_idx];
            binder_pool_idx = (binder_pool_idx + 1) % BINDER_POOL_SIZE;
            binder.attachInterface(null, parameterType);
            return binder;
        } else {
            return generateSeedByClass(parameterType);
        }
    }
}



