package com.straw.strawfuzzer.Hook;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;
import com.straw.lib.reflection.MyClassLoader;
import com.straw.lib.reflection.ParcelableMethod;
import com.straw.lib.system.ServiceInfo;
import com.straw.lib.system.SystemService;
import com.straw.lib.utils.LogUtils;
import com.straw.lib.utils.Optional;
import com.straw.strawfuzzer.Fuzz.Mutation;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.lang.reflect.Array;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

public class StaticInfo {

    private static Map<ParcelableMethod, StaticInfo> infoMap = new HashMap<>();
    private static Map<String, List<StaticInfo>> serviceMap= new HashMap<>();
    private static Map<ParcelableMethod, ValueSpec[]> rootSetsMap = new HashMap<>();
    private static Map<ParcelableMethod, Map<ParcelableMethod, Double>> weightMap = new HashMap<>();

    private static String TAG = "Straw_StaticInfo";

    static {
        try {
            InputStream is = new FileInputStream(new File("/data/data/com.straw.strawfuzzer/static_info.json"));
            StaticInfo.init(is);
            is.close();
        } catch (Exception e) {
            LogUtils.failTo(TAG, "load static_info", e);
        }
    }

    /**
     * Initialize parameter information
     * @param in the InputStream of static_info.json
     */
    public static void init(InputStream in) throws IOException {
        BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(in));
        StringBuilder sb = new StringBuilder();
        String line;
        String ls = System.getProperty("line.separator");
        while((line = bufferedReader.readLine()) != null) {
            sb.append(line);
            sb.append(ls);
        }

        String text = sb.toString();
        JSONArray jsonArray = JSON.parseArray(text);
        for (int i = 0; i < jsonArray.size(); ++i) {
            JSONObject methodObject = jsonArray.getJSONObject(i);

            // retrieve ParcelableMethod
            String signature = methodObject.getString("signature");

            ParcelableMethod method = ParcelableMethod.parseOne(signature);
            if (null == method) {
                LogUtils.failTo(TAG, "parse " + signature);
                continue;
            }

            // retrieve value scope for mutation and generation
            Map<String, List<ValueSpec>> scope = new HashMap<>();
            JSONObject scopeObject = methodObject.getJSONObject("scope");
            for(String param: scopeObject.keySet()) {
                ParamFieldSpec paramFieldSpec = new ParamFieldSpec(param);
                int index = paramFieldSpec.index;
                JSONArray values = scopeObject.getJSONArray(param);
//                ValueSpec[] valueSpecs = new ValueSpec[values.size()];
                List<ValueSpec> valueSpecs = new ArrayList<>();
                for (int j = 0; j < values.size(); ++j) {
                    Object value = values.get(j);
                    ValueSpec valueSpec = new ValueSpec(value);
//                    Object val = valueSpec.getValue(null, null);
                    // Remove invalid values, which can't be used in seed generation
                    if (valueSpec.type == ValueSpec.ValueSpecType.PRIMITIVE
                            && !Mutation.ObjectMutator.isSupported(method.paramTypes[index])) {
                        continue;
                    }
                    valueSpecs.add(valueSpec);
                }
                scope.put(param, valueSpecs);
            }

            // retrieve risky methods, especially the relative root sets
            JSONArray riskyMethodsArray = methodObject.getJSONArray("riskyMethods");
            RiskyMethod[] riskyMethods = new RiskyMethod[riskyMethodsArray.size()];
            for (int j = 0; j < riskyMethods.length; ++j) {
                JSONObject riskyMethodObject = riskyMethodsArray.getJSONObject(j);
                String riskySignature = riskyMethodObject.getString("signature");
                ParcelableMethod parcelableRiskyMethod = ParcelableMethod.parseOne(riskySignature);
                if (null == parcelableRiskyMethod) {
                    LogUtils.failTo(TAG, "parse " + riskySignature);
                    continue;
                }
                // root set
                JSONArray rootSetsArray;
                if (riskyMethodObject.containsKey("rootSets")) {
                    rootSetsArray = riskyMethodObject.getJSONArray("rootSets");
                } else {
                    rootSetsArray = new JSONArray();
                }
                ValueSpec[] rootSets = new ValueSpec[rootSetsArray.size()];
                for (int k = 0; k < rootSetsArray.size(); ++k) {
                    rootSets[k] = new ValueSpec(rootSetsArray.get(k));
                }
                // method weight
                JSONObject weightObject = riskyMethodObject.getJSONObject("methodWeights");
                Map<ParcelableMethod, Double> weights = new HashMap<>();
                for (String weightSignature: weightObject.keySet()) {
                    Double weight = weightObject.getDouble(weightSignature);
                    ParcelableMethod weightMethod = ParcelableMethod.parseOne(weightSignature);
                    if (null == weightMethod) {
                        LogUtils.failTo(TAG, "parse " + weightSignature);
                        continue;
                    }
                    weights.put(weightMethod, weight);
                }
                // retrieve control-flow relative inputs
                JSONArray controlFlowInputsArray = riskyMethodObject.getJSONArray("controlFlowInputs");
                String[] controlFlowInputs = controlFlowInputsArray.toArray(new String[0]);
                // retrieve consumption relative inputs
                JSONArray memoryConsumptionInputsArray = riskyMethodObject.getJSONArray("memoryConsumptionInputs");
                String[] memoryConsumptionInputs = memoryConsumptionInputsArray.toArray(new String[0]);

                RiskyMethod riskyMethod = new RiskyMethod(parcelableRiskyMethod, rootSets, weights, controlFlowInputs, memoryConsumptionInputs);
                riskyMethods[j] = riskyMethod;
                // add root sets to map
                rootSetsMap.put(riskyMethod, rootSets);
                weightMap.put(riskyMethod, weights);
            }

            StaticInfo staticInfo = new StaticInfo(method, scope, riskyMethods);

            infoMap.put(method, staticInfo);

            // initialize service map
            String className = method.className.replace("$Proxy", "");
//            Log.d(TAG, className);
            ServiceInfo serviceInfo;
            if (className.endsWith("$Stub")) {
                serviceInfo = ServiceInfo.getServiceInfoByStubClass(className);
            } else {
                serviceInfo = ServiceInfo.getServiceInfoByServiceClass(className);
            }
            if (null != serviceInfo) {
                String serviceName = serviceInfo.serviceName;
                if (!serviceMap.containsKey(serviceName)) {
                    serviceMap.put(serviceName, new ArrayList<>());
                }
                serviceMap.get(serviceName).add(staticInfo);

                // register nullable information
                JSONArray nullableJ = methodObject.getJSONArray("nullable");
                if (null != nullableJ) {
                    try {
                        List<Integer> nullable = nullableJ.toJavaList(Integer.class);
                        SystemService systemService =SystemService.getSystemService(serviceName);
                        if (!systemService.getInterfaceName().isEmpty()) {
                            systemService.getParcelableMethod(method.methodName).setNullables(nullable);
                        }
                    } catch (Exception e) {}
                }
            }
        }
    }

    /**
     * Get parameter information of method
     * @param method target method
     * @return the parameter information for the method.
     */
    public static StaticInfo getInfo(ParcelableMethod method) {
        StaticInfo staticInfo = infoMap.getOrDefault(method, null);
        if (null == staticInfo) {
            // create a default paramsInfo, regard all inputs may related to control flow
            List<String> controlFlowInputs = new ArrayList<>();
            for (int i = 0; i < method.paramTypes.length; ++i) {
                String paramType = method.paramTypes[i];
                if (Mutation.ObjectMutator.isSupported(paramType)) {
                    controlFlowInputs.add(String.valueOf(i));
                }
            }
            staticInfo = new StaticInfo(method, new HashMap<>(), new RiskyMethod[0]);
        }
        return staticInfo;
    }

    public static List<StaticInfo> getInfosByService(String serviceName) {
        List<StaticInfo> staticInfos = serviceMap.getOrDefault(serviceName, new ArrayList<>());
        return staticInfos;
    }

    public static ValueSpec[] getRootSets(ParcelableMethod method) {
        ValueSpec[] rootSets = rootSetsMap.get(method);
        if (null == rootSets) {
            return new ValueSpec[0];
        }
        return rootSets;
    }

    public static double getWeight(ParcelableMethod riskyMethod, ParcelableMethod method) {
//        Log.d(TAG, "getWeight: " + riskyMethod + "<-" + method + ": " + weightMap.get(riskyMethod).getOrDefault(method, -1.0));
        if (weightMap.containsKey(riskyMethod)) {
            return weightMap.get(riskyMethod).getOrDefault(method, 0.0);
        } else {
            LogUtils.failTo(TAG, "get weight for " + method);
            return 0.0;
        }
    }

    /*
     * -------------------------- Class fields ----------------------------------------
     */

    private ParcelableMethod method;
    private Map<ParamFieldSpec, List<ValueSpec>> scope;
    private RiskyMethod[] riskyMethods;
    private Map<ParcelableMethod, RiskyMethod> riskyMethodMap;

    private StaticInfo(ParcelableMethod method, Map<String, List<ValueSpec>> scope, RiskyMethod[] riskyMethods) {
        this.method = method;

        this.scope = new HashMap<ParamFieldSpec, List<ValueSpec>>();
        for (Map.Entry<String, List<ValueSpec>> entry: scope.entrySet()) {
            this.scope.put(new ParamFieldSpec(entry.getKey()), entry.getValue());
        }
        this.riskyMethods = riskyMethods;
        this.riskyMethodMap = new HashMap<>();
        for (RiskyMethod riskyMethod:riskyMethods){
            riskyMethodMap.put(riskyMethod,riskyMethod);
        }
    }

    public ParcelableMethod getMethod() {
        return method;
    }

    public String getClassName() {
        return method.className;
    }

    public String getMethodName() {
        return method.methodName;
    }

    public String[] getParamTypes() {
        return method.paramTypes;
    }

    public Map<ParamFieldSpec, List<ValueSpec>> getScope() {
        return scope;
    }

    public boolean hasScope(ParamFieldSpec spec) {
        return scope.containsKey(spec);
    }

    public RiskyMethod[] getRiskyMethods() { return riskyMethods; }

    public ParamFieldSpec[] getControlFlowSpecs(ParcelableMethod riskyMethod) {
        return riskyMethodMap.get(riskyMethod).controlFlowInputs;
    }

    public ParamFieldSpec[] getMemoryConsumptionSpecs(ParcelableMethod riskyMethod) {
        return riskyMethodMap.get(riskyMethod).memoryConsumptionInputs;
    }

    public boolean hasValues(ParamFieldSpec spec) {
        List<ValueSpec> values = scope.get(spec);
        return null != values && values.size() > 0;
    }

    /**
     * RiskyMethod
     */
    public static class RiskyMethod extends ParcelableMethod {

        public ValueSpec[] rootSets;
        public Map<ParcelableMethod, Double> weights;
        public ParamFieldSpec[] controlFlowInputs;
        public ParamFieldSpec[] memoryConsumptionInputs;

        private RiskyMethod(ParcelableMethod method, ValueSpec[] rootSets, Map<ParcelableMethod, Double> weights, String[] controlFlowInputs, String[] memoryConsumptionInputs) {
            this(method.className, method.methodName, method.paramTypes, rootSets, weights, controlFlowInputs, memoryConsumptionInputs);
        }

        private RiskyMethod(String className, String methodName, String[] paramTypes, ValueSpec[] rootSets, Map<ParcelableMethod, Double> weights, String[] controlFlowInputs, String[] memoryConsumptionInputs) {
            super(className, methodName, paramTypes, "");
            this.rootSets = rootSets;
            this.weights = weights;
            this.controlFlowInputs = new ParamFieldSpec[controlFlowInputs.length];
            for (int i = 0; i < controlFlowInputs.length; ++i) {
                ParamFieldSpec paramFieldSpec = new ParamFieldSpec(controlFlowInputs[i]);
                this.controlFlowInputs[i] = paramFieldSpec;
            }
            Arrays.sort(this.controlFlowInputs);
            this.memoryConsumptionInputs = new ParamFieldSpec[memoryConsumptionInputs.length];
            for (int i = 0; i < memoryConsumptionInputs.length; ++i) {
                ParamFieldSpec paramFieldSpec = new ParamFieldSpec(memoryConsumptionInputs[i]);
                this.memoryConsumptionInputs[i] = paramFieldSpec;
            }
            Arrays.sort(this.memoryConsumptionInputs);
        }
    }

    /**
     * Class to specify a parameter or parameter field
     */
    public static class ParamFieldSpec implements Comparable {
        private Field field;
        private int index;
        private boolean self;
        private String[] splits;
        private String spec;
        private int attr;

        private ParamFieldSpec(String spec) {
            splits = spec.split("\\.");
            index = Integer.valueOf(splits[0]);
            self = splits.length == 1;
            field = null;
            this.spec = spec;
            this.attr = attr;
        }

        public int getIndex() {
            return index;
        }

        public boolean isSelf() {
            return self;
        }

        public String getType(Object target) throws NoSuchFieldException {
            return getField(target).getType().getName();
        }

        public Object getFieldValue(Object target) {
            try {
                Field targetField = getField(target);
                // return self
                if (null == targetField) return target;
                targetField.setAccessible(true);
                return targetField.get(target);
            } catch (Exception e) {
                e.printStackTrace();
                return target;
            }
        }

        public void setFieldValue(Object target, Object value) {
            try {
                Field targetField = getField(target);
                // return self
                if (null == targetField) return;
                targetField.setAccessible(true);
                try {
                    targetField.set(target, value);
                } catch (IllegalAccessException e) {
                    e.printStackTrace();
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }

        private Field getField(Object target) throws NoSuchFieldException {
            if (null != field || self) return field;
            Field targetField = null;
            Class clazz = target.getClass();
            for (int i = 1; i < splits.length; ++i) {
                targetField = clazz.getDeclaredField(splits[i]);
                clazz = targetField.getClass();
            }
            field = targetField;
            // splits is useless
            splits = null;
            return targetField;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o instanceof String) {
                return spec.equals(o);
            }
            if (o == null || getClass() != o.getClass()) return false;
            ParamFieldSpec that = (ParamFieldSpec) o;
            return Objects.equals(spec, that.spec);
        }

        @Override
        public int hashCode() {
            return Objects.hash(spec);
        }

        @Override
        public int compareTo(Object o) {
            ParamFieldSpec that = (ParamFieldSpec) o;
            return that.spec.compareTo(this.spec);
        }
    }

    /**
     * Class to specify a value, or result of a serial of call and field access.
     */
    public static class ValueSpec {

        private Object value;
        private ValueSpecType type;
        private ValueSpec object;
        private ValueSpec[] params;

        enum ValueSpecType { PRIMITIVE, NULL, THIS, PREV, INDEX, INVOKE, CONSTRUCT, FIELD, CHAIN, UNKNOWN }

        public ValueSpec(Object value) {
            this.type = ValueSpecType.UNKNOWN;
            if (value instanceof JSONArray) {
                JSONArray arr = (JSONArray) value;
                boolean isChain = false;
                for (Object subValue: arr) {
                    if (subValue instanceof JSONArray) {
                        isChain = true;
                        break;
                    }
                }
                if (isChain) {
                    // [[], ...]: 表示一系列的调用或者field引用，每一个元素是一个列表，形式和函数调用或field引用相同
                    this.type = ValueSpecType.CHAIN;
                    // for convenient access.
                    this.params = new ValueSpec[arr.size()];
                    this.value = this.params;
                    this.object = null;
                    for (int i = 0; i < arr.size(); ++i) {
                        Array.set(this.value, i, new ValueSpec(arr.get(i)));
                    }
                } else {
                    Object subValue = ((JSONArray) value).get(0);
                    assert subValue instanceof String;
                    if (((String) subValue).startsWith("<")) {
                        // ["<com.android.server.DropBoxManagerService$2: boolean isTagEnabled(java.lang.String)>", object, param1, ...]:
                        //        表示调用函数，第一个元素是类似格式的字符串，第二个object为调用方法的对象，可以为"<null>", "<this>", "<prev>"中的任意一种，之后的param是参数表示方法与value相同，
                        // The value will be a method or constructor
                        ParcelableMethod method = ParcelableMethod.parseOne((String) subValue);
                        assert null != method;
                        if (method.isConstructor()) {
                            this.type = ValueSpecType.CONSTRUCT;
                            this.value = method.toConstructor();
                            if (null != this.value) {
                                ((Constructor) (this.value)).setAccessible(true);
                            }
                        } else {
                            this.type = ValueSpecType.INVOKE;
                            this.value = method.toMethod();
                            if (null != this.value) {
                                ((Method) (this.value)).setAccessible(true);
                            }
                        }
                        this.object = new ValueSpec(arr.get(1));
                        this.params = new ValueSpec[arr.size() - 2];
                        for (int i = 0; i < arr.size() - 2; ++i) {
                            this.params[i] = new ValueSpec(arr.get(i + 2));
                            assert this.params[i] != null;
                        }
                    } else {
                        // [className, fieldName, object]: 表示引用类或对象的field，第一个元素表示类名，第二个元素表示字段名，第三个元素表示获取field的object，可以为"<null>", "<this>", "<prev>"中的任意一种
                        assert ((JSONArray) value).size() == 3;
                        String className = (String) subValue;
                        String fieldName = (String) arr.get(1);
                        this.type = ValueSpecType.FIELD;
                        this.value = MyClassLoader.loadField(className, fieldName);
                        if (null != this.value) {
                            ((Field) (this.value)).setAccessible(true);
                        }
                        this.object = new ValueSpec(arr.get(2));
                        this.params = null;
                    }
                    assert null != this.object;
                }
                assert null != this.value;
            } else {
                assert !(value instanceof JSONObject);
                if (value instanceof String && ((String) value).startsWith("<") && ((String) value).endsWith(">")) {
                    switch ((String) value) {
                        case "<null>":
                            this.type = ValueSpecType.NULL;
                            this.value = null;
                            break;
                        case "<this>":
                        case "<self>":
                            this.type = ValueSpecType.THIS;
                            this.value = null;
                            break;
                        case "<prev>":
                            // "<prev>": Represent previous getValue result
                            this.type = ValueSpecType.PREV;
                            this.value = null;
                            break;
                        default:
                            try {
                                int index = Integer.valueOf(((String) value).substring(1, ((String) value).length() - 1));
                                this.type = ValueSpecType.INDEX;
                                this.value = index;
                            } catch (NumberFormatException e) {
                                this.type = ValueSpecType.PRIMITIVE;
                                this.value = value;
                            }
                            break;
                    }
                } else {
                    // 表示基本类型\
//                    Log.d(logTag, value.getClass() + " \"" + value  + "\" is PRIMITIVE?");
                    this.type = ValueSpecType.PRIMITIVE;
                    this.value = value;
                }
                this.object = null;
                this.params = null;
            }
        }

        public ValueSpecType getType() {
            return type;
        }

        public Optional<Object> getValueForceType(Object prevObject, Object thisObject, Class forceType) {
//            String errorMessage;
            Optional<Object> optVal = getValue(prevObject, thisObject);
            if (null == forceType || !optVal.isPresent() || null == optVal.get()) {
                return optVal;
            }
            Object val = optVal.get();
            if (forceType.isInstance(val)) {
                try {
                    return Optional.of(forceType.cast(val));
                } catch (Exception e) {
                }
            }
            if (val instanceof String) {
                String strVal = (String) val;
                try {
                    switch (forceType.getName()) {
                        case "boolean":
                        case "java.lang.Boolean":
                            try {
                                return Optional.of(Integer.parseInt(strVal) == 0 ? true : false);
                            } catch (Exception e) {
                            }
                            return Optional.of(Boolean.parseBoolean(strVal));
                        case "byte":
                        case "java.lang.Byte":
                            return Optional.of(Byte.parseByte(strVal));
                        case "char":
                        case "java.lang.Character":
                            return Optional.of((char) Byte.parseByte(strVal));
                        case "double":
                        case "java.lang.Double":
                            return Optional.of(Double.parseDouble(strVal));
                        case "float":
                        case "java.lang.Float":
                            return Optional.of(Float.parseFloat(strVal));
                        case "int":
                        case "java.lang.Integer":
                            return Optional.of(Integer.parseInt(strVal));
                        case "long":
                        case "java.lang.Long":
                            return Optional.of(Long.parseLong(strVal));
                        case "short":
                        case "java.lang.Short":
                            return Optional.of(Short.parseShort(strVal));
                        default:
                    }
                } catch (Exception e) { }
            }

            if (forceType.isPrimitive()) {
                try {
                    switch (forceType.getName()) {
                        case "boolean":
                            if (val.getClass() == Boolean.class) return optVal;
                            return Optional.of(((Number) val).intValue() != 0);
                        case "byte":
                            return Optional.of(((Number) val).byteValue());
                        case "char":
                            if (val.getClass() == Character.class) return optVal;
                            return Optional.of(Character.valueOf((char) ((Number) val).intValue()));
                        case "double":
                            return Optional.of(((Number) val).doubleValue());
                        case "float":
                            return Optional.of(((Number) val).floatValue());
                        case "int":
                            return Optional.of(((Number) val).intValue());
                        case "long":
                            return Optional.of(((Number) val).longValue());
                        case "short":
                            return Optional.of(((Number) val).shortValue());
                        default:
                    }
                } catch (Exception e) { }
            }

            return Optional.empty();
        }

        public Optional<Object> getValue(Object prevObject, Object thisObject) {
            return getValue(prevObject, thisObject, new Object[0]);
        }

        public Optional<Object> getValue(Object prevObject, Object thisObject, Object[] chain) {
            Object[] paramValues;
            Optional<Object> objectOpt;
            Object obj;
            switch (this.type) {
                case NULL:
                    return Optional.of(null);
                case PREV:
                    return Optional.of(prevObject);
                case THIS:
                    return Optional.of(thisObject);
                case INDEX:
                    return Optional.of(chain[(int)this.value]);
                case PRIMITIVE:
                    return Optional.of(value);
                case FIELD:
                    if (null == value) return Optional.empty();
                    objectOpt = object.getValue(prevObject, thisObject, chain);
                    if (!objectOpt.isPresent()) return Optional.empty();
                    obj = objectOpt.get();
                    try {
                        return Optional.of(((Field) value).get(obj));
                    } catch (IllegalAccessException e) {
                        LogUtils.failTo(TAG, "ValueSpec: get FIELD value " + value + ":" + e);
                        return Optional.empty();
                    }
                case INVOKE:
                case CONSTRUCT:
                    if (null == value) return Optional.empty();
                    paramValues = new Object[params.length];
                    for (int i = 0; i < paramValues.length; ++i) {
                        Optional paramOpt = params[i].getValue(prevObject, thisObject, chain);
                        if (!paramOpt.isPresent()) {
                            return Optional.empty();
                        }
                        paramValues[i] = paramOpt.get();
                    }
                    objectOpt = object.getValue(prevObject, thisObject, chain);
                    if (!objectOpt.isPresent()) return Optional.empty();
                    obj = objectOpt.get();
                    // invoke or construct
                    if (type.equals(ValueSpecType.INVOKE)) {
                        try {
                            return Optional.of(((Method) value).invoke(obj, paramValues));
                        } catch (InvocationTargetException | IllegalAccessException e) {
                            LogUtils.failTo(TAG, "ValueSpec: get INVOKE value " + value + ":" + e);
                            return Optional.empty();
                        }
                    } else {
                        try {
                            return Optional.of(((Constructor) value).newInstance(paramValues));
                        } catch (InvocationTargetException | IllegalAccessException | InstantiationException e) {
                            LogUtils.failTo(TAG, "ValueSpec: get CONSTRUCT value " + value + ":" + e);
                            return Optional.empty();
                        }
                    }
                case CHAIN:
                    Object chainPrevObject = prevObject;
                    Optional<Object> chainPrevObjectOpt;
                    Object[] newChain = new Object[params.length];
                    for (int i = 0; i < params.length; ++i) {
                        String errorMessage = null;
                        try {
                            chainPrevObjectOpt = params[i].getValue(chainPrevObject, thisObject, newChain);
                            if (!chainPrevObjectOpt.isPresent()) {
                                errorMessage = "empty";
                            } else {
                                chainPrevObject = chainPrevObjectOpt.get();
                                newChain[i] = chainPrevObject;
                            }
                        } catch (Exception e) {
                            errorMessage = e.toString();
                        }
                        if (null != errorMessage) {
                            LogUtils.failTo(TAG, "ValueSpec: get CHAIN value " + this + " at " + params[i] + ":" + errorMessage);
                            return Optional.empty();
                        }
                    }
                    return Optional.of(chainPrevObject);
                default:
                    LogUtils.failTo(TAG, "get valid type for " + this.toString());
                    return Optional.empty();
            }
        }

        @Override
        public String toString() {
            return "ValueSpec{" +
                    "value=" + value +
                    ", type=" + type +
                    ", object=" + object +
                    ", params=" + Arrays.toString(params) +
                    '}';
        }
    }
}
