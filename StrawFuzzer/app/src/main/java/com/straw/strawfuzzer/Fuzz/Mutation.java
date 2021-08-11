package com.straw.strawfuzzer.Fuzz;

import android.os.Parcel;
import android.os.Parcelable;
import android.util.Log;

import com.google.common.collect.BiMap;
import com.google.common.collect.ImmutableBiMap;
import com.straw.lib.reflection.ParcelableMethod;
import com.straw.lib.utils.LogUtils;
import com.straw.strawfuzzer.Hook.StaticInfo;
import com.straw.strawfuzzer.Input.InputGenerator;
import com.straw.lib.reflection.MyClassLoader;
import com.straw.lib.utils.Optional;

import java.lang.reflect.Array;
import java.lang.reflect.Field;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ThreadLocalRandom;

public class Mutation {

    private static final String TAG = "Straw_Mutation";

    private static ThreadLocalRandom random = ThreadLocalRandom.current();
    private static int chooseCount = 0;

    private static ObjectMutator exploitMutator = new ObjectMutator(MutationConfig.exploitConfig);
    private static ObjectMutator exploreMutator = new ObjectMutator(MutationConfig.exploreConfig);

    static Seed generateSeed(ParcelableMethod method, ParcelableMethod parcelableRiskyMethod) {
        // try retrieving parameter information
        StaticInfo staticInfo = StaticInfo.getInfo(method);
        if (null == staticInfo) return null;

        String[] paramTypes = method.paramTypes;
        Object[] paramValues = new Object[paramTypes.length];
        for (int i = 0; i < paramTypes.length; ++i) {
            paramValues[i] = null;
        }

        // generate by choosing from scope
        for (Map.Entry<StaticInfo.ParamFieldSpec, List<StaticInfo.ValueSpec>> entry: staticInfo.getScope().entrySet()) {
            StaticInfo.ParamFieldSpec spec = entry.getKey();
            int index = spec.getIndex();

            boolean choose = staticInfo.hasValues(spec)
                    && rollChoose(0.05, .1);
            if (choose) {
                // 70% chance to select from scope
                List<StaticInfo.ValueSpec> values = entry.getValue();
                Object chosenValue = Optional.empty();
                try {
                    chosenValue = chooseValueStrict(values, paramTypes[index]);
                } catch (Exception e) {
                    Log.d(TAG, "generation: choose fail " + e);
                }
                if (spec.isSelf()) {
                    paramValues[index] = chosenValue;
                } else {
                    spec.setFieldValue(paramValues[index], chosenValue);
                }
            }
        }

        for (int i = 0; i < paramTypes.length; ++i) {
            if (null == paramValues[i]) {
                paramValues[i] = InputGenerator.generateInput(paramTypes[i]);
                if (null == paramValues[i]) {
                    LogUtils.failTo(TAG, "generate the " + i + "th parameter, typed " + paramTypes[i], null);
                }
            }
        }

        return new Seed(staticInfo, parcelableRiskyMethod, paramValues);
    }

    static Seed mutateSeed(Seed parent) {
        String[] paramTypes = parent.getParamTypes();
        Object[] paramValues = parent.getParamValues();
        StaticInfo staticInfo = parent.getStaticInfo();

        ParcelableMethod parcelableRiskyMethod = parent.getParcelableRiskyMethod();

        Object[] newParamValues = Arrays.copyOf(paramValues, paramValues.length);
        // mutate all params that needs mutation
        boolean[] mutated = new boolean[paramValues.length];

        boolean toExploit = parent.isHit();

        // select from scope
        for (Map.Entry<StaticInfo.ParamFieldSpec, List<StaticInfo.ValueSpec>> entry: staticInfo.getScope().entrySet()) {
            StaticInfo.ParamFieldSpec spec = entry.getKey();
            List<StaticInfo.ValueSpec> values = entry.getValue();
            double confidence = 1.0 / values.size();
            int index = spec.getIndex();

            boolean choose = !mutated[index]
                    && staticInfo.hasValues(spec)
                    && rollChoose(Math.max(toExploit ? 0.05 : 0.1, confidence), Math.max(.25, confidence));
            if (choose) {
                mutated[index] = true;
                try {
                    newParamValues[index] = chooseValueStrict(values, paramTypes[index]);
                } catch (Exception e) {
                    LogUtils.failTo(TAG, "mutate choose", e);
                    mutated[index] = false;
                }
            }
        }

        final StaticInfo.ParamFieldSpec[] specs;
        if (toExploit) {
            specs = staticInfo.getMemoryConsumptionSpecs(parcelableRiskyMethod);
        } else {
            specs = staticInfo.getControlFlowSpecs(parcelableRiskyMethod);
        }

        for (StaticInfo.ParamFieldSpec spec: specs) {
            int index = spec.getIndex();

            Object value = newParamValues[index];
            Object newValue;
            if (spec.isSelf()) {
                if (mutated[index]) continue;
                if (toExploit) {
                    newValue = mutateForExploit(paramTypes[index], value);
                } else {
                    newValue = mutateForExplore(paramTypes[index], value);
                }
            } else {
//                assert value instanceof Parcelable;
                newValue = shallowClone((Parcelable) value);
                newParamValues[index] = newValue;
                Object specValue = spec.getFieldValue(newValue);
                String specValueType = specValue.getClass().getTypeName();
                Object newSpecValue;
                if (toExploit) {
                    newSpecValue = mutateForExploit(specValueType, specValue);
                } else {
                    newSpecValue = mutateForExplore(specValueType, specValue);
                }
                Log.d(TAG, "mutateSeed: " + newSpecValue);
                spec.setFieldValue(newValue, newSpecValue);
            }
            newParamValues[index] = newValue;
            mutated[index] = true;
        }
        Seed subSeed = new Seed(staticInfo, parcelableRiskyMethod, newParamValues);
//        Log.d(TAG, subSeed.debugDescribe());
        return subSeed;
    }

    private static boolean rollChoose(double minRate, double maxRate) {
        double rate = minRate + (maxRate - minRate) / (1 + Math.log10(1 + chooseCount));
        boolean choose = random.nextDouble() < rate;
        if (choose) chooseCount += 1;
        return choose;
    }

    private static Object handleNull(Optional<Object> chosenValue, String forceType) {
        if (chosenValue.isPresent() && null != chosenValue.get()) {
            return chosenValue.get();
        }

        boolean replaceNull = random.nextDouble() < 0.1;
        if (replaceNull) {
            return InputGenerator.generateInput(forceType);
        } else {
            return null;
        }
    }

    private static Object chooseValueStrict(List<StaticInfo.ValueSpec> values, String forceType) {
        Optional<Object> chosenValue = chooseValue(values, forceType);
        Object res = handleNull(chosenValue, forceType);
//        Log.d(TAG, "chooseValueStrict: " + res + " As " + forceType);
        return res;
    }

    private static Optional<Object> chooseValue(List<StaticInfo.ValueSpec> values, String forceType) {
        return chooseValue(values, MyClassLoader.loadClass(forceType));
    }

    private static Optional<Object> chooseValue(List<StaticInfo.ValueSpec> values, Class forceType) {
        StaticInfo.ValueSpec valueSpec = values.get(random.nextInt(values.size()));
        Optional<Object> res = valueSpec.getValueForceType(null, null, forceType);
//        Log.d(TAG, "chooseValue: " + (!res.isPresent() ? ("null") : ("" + res.get() + " " + res.get().getClass())) + " As " + forceType);
        return res;
    }

    static Object mutateForExplore(String paramType, Object value) {
        return exploreMutator.mutate(value, paramType);
    }

    static Object mutateForExploit(String paramType, Object value) {
        try {
            return exploitMutator.mutate(value, paramType);
        } catch (OutOfMemoryError e) {
            // Reduce chance of crashing app when run out of memory
            return value;
        }
    }

    private static <T extends Parcelable> T deepClone(T objectToClone) {
        Parcel parcel = null;
        try {
            parcel = Parcel.obtain();
            parcel.writeParcelable(objectToClone, 0);
            parcel.setDataPosition(0);
            return parcel.readParcelable(objectToClone.getClass().getClassLoader());
        } finally {
            if (parcel != null) {
                parcel.recycle();
            }
        }
    }

    private static Object shallowClone(Object objectToClone) {
        Object res = InputGenerator.generateSmallSeedByClass(objectToClone.getClass().getTypeName());
        if (null == res) return res; // fail
        for (Field field: objectToClone.getClass().getDeclaredFields()) {
            if (!field.isAccessible()) {
                field.setAccessible(true);
            }
            try {
                field.set(res, field.get(objectToClone));
            } catch (IllegalAccessException e) {
                assert false;
            }
        }
        return res;
    }

    /**
     * Class to serialize and deserialize during mutation
     */
    public static class ObjectMutator {
        private ThreadLocalRandom random = ThreadLocalRandom.current();

        private static final BiMap<String, String> typeIDMap = ImmutableBiMap.<String, String>builder()
                .put("int", "i")
                .put("long", "j")
                .put("float", "f")
                .put("boolean", "z")
                .put("char", "c")
                .put("double", "d")
                .put("byte", "b")
                .put("short", "s")
                .put("java.lang.Integer", "I")
                .put("java.lang.Long", "J")
                .put("java.lang.Float", "F")
                .put("java.lang.Boolean", "Z")
                .put("java.lang.Character", "C")
                .put("java.lang.Double", "D")
                .put("java.lang.Byte", "B")
                .put("java.lang.Short", "S")
                .put("java.lang.String", "St")
                /* arrays */
                .put("[I", "[i")
                .put("[J", "[j")
                .put("[F", "[f")
                .put("[Z", "[z")
                .put("[C", "[c")
                .put("[D", "[d")
                .put("[B", "[b")
                .put("[S", "[s")
                .put("[Ljava.lang.Integer;", "[I")
                .put("[Ljava.lang.Long;", "[J")
                .put("[Ljava.lang.Float;", "[F")
                .put("[Ljava.lang.Boolean;", "[Z")
                .put("[Ljava.lang.Character;", "[C")
                .put("[Ljava.lang.Double;", "[D")
                .put("[Ljava.lang.Byte;", "[B")
                .put("[Ljava.lang.Short;", "[S")
                .put("[Ljava.lang.String;", "[St")
                /* null */
                .put("null", "null")
                .build();

        public static String getID(String paramType) {
            return typeIDMap.getOrDefault(paramType, "");
        }

        public static boolean isSupported(String paramType) {
            return typeIDMap.containsValue(paramType) || typeIDMap.containsKey(paramType);
        }

        public static boolean isArray(String paramType) {
            return paramType.startsWith("[") || typeIDMap.getOrDefault(paramType, "").startsWith("[");
        }

        private MutationConfig config;

        public ObjectMutator(MutationConfig config) {
            this.config = config;
        }

        public Object mutate(Object obj) {
            String typeName = obj.getClass().getName();
            return mutate(obj, typeName);
        }

        public Object mutate(Object obj, long limit) {
            String typeName = obj.getClass().getName();
            return mutate(obj, typeName, limit);
        }

        public Object mutate(Object obj, String typeName) {
            return mutate(obj, typeName, config.MUTATE_LITERAL_LIMIT);
        }

        public Object mutate(Object obj, String typeName, long limit) {
            if (null == obj) {
                return InputGenerator.generateInput(typeName);
            }

            if (!isSupported(typeName)) {
                if (InputGenerator.isInterfaceType(typeName)) {
                    return obj;
                } else {
                    return InputGenerator.generateInput(typeName);
                }
            }

            String typeID = getID(typeName);
            if (isArray(typeID)) {
                return mutateArray(obj, typeID, limit);
            } else {
                return mutateBasic(obj, typeID, limit);
            }
        }

        private Object mutateArray(Object obj, String typeID, long limit) {
            return mutateArray(obj, limit);
        }

        private Object mutateBasic(Object obj, String typeID, long limit) {
            switch (typeID) {
                case "i":
                case "I":
                    return mutateInt((int) obj);
                case "j":
                case "J":
                    return mutateLong((long) obj);
                case "f":
                case "F":
                    return mutateFloat((float) obj);
                case "z":
                case "Z":
                    return mutateBool((boolean) obj);
                case "c":
                case "C":
                    return mutateChar((char) obj);
                case "d":
                case "D":
                    return mutateDouble((double) obj);
                case "b":
                case "B":
                    return mutateByte((byte) obj);
                case "s":
                case "S":
                    return mutateShort((short) obj);
                case "St":
                    return mutateString((String) obj, limit);
                default:
                    return null;
            }
        }

        private Object mutateArray(Object arr, long limit) {
            Class arrClass = arr.getClass();
            assert arrClass.isArray();
            Class componentType =  arrClass.getComponentType();
            Object newArr = randInsertDeleteFromArray(arr, componentType);
            int newLength = Array.getLength(newArr);
            if (newLength == 0) {
                return newArr;
            }
            if (config.MUTATE_ARRAY_ONLY_ONE_ELEMENT) {
                int mutateIndex = random.nextInt(newLength);
                Object mutatedObj = mutate(Array.get(newArr, mutateIndex), limit / Array.getLength(newArr));
                Array.set(newArr, mutateIndex, mutatedObj);
                return newArr;
            }
            double eleMutateRate = Math.log(newLength + 1) / (double) newLength;
            for (int i = 0; i < newLength; ++i) {
                if (random.nextDouble() < eleMutateRate) {
                    Object mutatedObj = mutate(Array.get(newArr, i), limit / Array.getLength(newArr));
                    Array.set(newArr, i, mutatedObj);
                }
            }
            return newArr;
        }

        private Object randInsertDeleteFromArray(Object arr, Class componentType) {
            int length = Array.getLength(arr);
            boolean delete = random.nextDouble() < config.MUTATE_ARRAY_DELETE_RATE && length >= 1;
            if (delete) {
                // delete
                Object newArr = Array.newInstance(componentType, length - 1);
                int delPos = random.nextInt(length);
                for (int i = 0; i < delPos; ++i) {
                    Array.set(newArr, i, Array.get(arr, i));
                }
                for (int i = delPos + 1; i < length; ++i) {
                    Array.set(newArr, i - 1, Array.get(arr, i));
                }
                return newArr;
            }
            boolean insert = random.nextDouble() < config.MUTATE_ARRAY_INSERT_RATE;
            if (insert) {
                // insert
                Object newArr = Array.newInstance(componentType, length + 1);
                int insPos = random.nextInt(length + 1);
                Array.set(newArr, insPos, InputGenerator.generateSeedByClass(componentType));
                for (int i = 0; i < insPos; ++i) {
                    Array.set(newArr, i, Array.get(arr, i));
                }
                for (int i = insPos; i < length; ++i) {
                    Array.set(newArr, i + 1, Array.get(arr, i));
                }
                return newArr;
            }
            // don't change array length
            return arr;
        }

        private int mutateInt(int val) {
            return (int) mutateLong(val);
        }

        private short mutateShort(short val) {
            return (short) mutateLong(val);
        }

        private long mutateLong(long val) {
            double needle = random.nextDouble();
            double threshold = config.MUTATE_INTEGER_ADD_RATE;
            if (needle < threshold) {
                // 60% chance for +
                return val + random.nextLong(Math.abs(val) + 1);
            }
            threshold += config.MUTATE_INTEGER_MUL_RATE;
            if (needle < threshold) {
                // 20% chance for *
                return val * random.nextLong((int) Math.log(Math.abs(val) + 1) + 1);
            }
            // Fall through 20% chance for -
            return val - random.nextLong(Math.abs(val) + 1);
        }

        private float mutateFloat(float val) {
            return (float) mutateDouble(val);
        }

        private double mutateDouble(double val) {
            if (random.nextBoolean()) {
                return val + random.nextDouble();
            } else {
                return val - random.nextDouble();
            }
        }

        private boolean mutateBool(boolean val) {
            return random.nextBoolean();
        }

        private char mutateChar(char val) {
            return (char) (val ^ (1 << random.nextInt(16)) ^ (1 << random.nextInt(8)));
        }

        private byte mutateByte(byte val) {
            return (byte) (val ^ (1 << random.nextInt(8)));
        }

        private String mutateString(String val, long limit) {
            if (val.isEmpty()) {
                // only append to a string if it's empty
                return InputGenerator.getRandomString(random.nextInt(1, 10));
            }

            int idx = random.nextInt(val.length());
            double needle = random.nextDouble();
            int changeSize;
            if (limit - val.length() < limit / 64) {
                // don't increase
                needle = random.nextDouble(config.MUTATE_STRING_INCREASE_THRESHOLD, 1.0);
                changeSize = val.length() / 3;
            } else {
                changeSize = random.nextInt((int) Math.min(val.length() + 1, limit - val.length()));
            }
            int sliceLen = Math.min(random.nextInt(Math.min(val.length(), val.length() - idx)), changeSize);

            double threshold = config.MUTATE_STRING_APPEND_RATE;
            if (needle < threshold) {
                return val + InputGenerator.getRandomString(changeSize);
            }
            threshold += config.MUTATE_STRING_INSERT_RATE;
            if (needle < threshold) {
                return val.substring(0, idx) + InputGenerator.getRandomString(changeSize) + val.substring(idx);
            }
            threshold += config.MUTATE_STRING_DUPLICATE_RATE;
            if (needle < threshold) {
                int insPos = random.nextInt(val.length());
                String slice = val.substring(idx, idx + sliceLen);
                return val.substring(0, insPos) + slice + val.substring(insPos);
            }
            threshold += config.MUTATE_STRING_REPLACE_RATE;
            if (needle < threshold) {
                return val.substring(0, idx) + InputGenerator.getRandomString(sliceLen) + val.substring(idx + sliceLen);
            }
            threshold += config.MUTATE_STRING_REMOVE_RATE;
            if (needle < threshold) {
                return val.substring(0, idx) + val.substring(idx + sliceLen);
            }
            // Fall through
//            threshold += config.MUTATE_STRING_SUBSTRING_RATE;
//            assert Math.abs(1.0 - threshold) < 0.000001;
            sliceLen = (int) (random.nextDouble(0.5, 1.0) * val.length());
            idx = random.nextInt(val.length() - sliceLen);
            return val.substring(idx, idx + sliceLen);
        }

    }

    public static class MutationConfig {
        public double MUTATE_ARRAY_DELETE_RATE;
        public double MUTATE_ARRAY_INSERT_RATE;
        public boolean MUTATE_ARRAY_ONLY_ONE_ELEMENT = true;

        public double MUTATE_INTEGER_ADD_RATE;
        public double MUTATE_INTEGER_MUL_RATE;
        public double MUTATE_INTEGER_SUB_RATE;

        public double MUTATE_STRING_APPEND_RATE;
        public double MUTATE_STRING_INSERT_RATE;
        public double MUTATE_STRING_DUPLICATE_RATE;
        public double MUTATE_STRING_REPLACE_RATE;
        public double MUTATE_STRING_REMOVE_RATE;
        public double MUTATE_STRING_SUBSTRING_RATE;
        public int MUTATE_LITERAL_LIMIT;
        public double MUTATE_STRING_INCREASE_THRESHOLD;

        public void updateCheck() {
            boolean valid = Math.abs(MUTATE_INTEGER_ADD_RATE + MUTATE_INTEGER_MUL_RATE + MUTATE_INTEGER_SUB_RATE - 1.0) < 0.00001
                    && Math.abs(MUTATE_STRING_APPEND_RATE + MUTATE_STRING_INSERT_RATE + MUTATE_STRING_DUPLICATE_RATE
                    + MUTATE_STRING_REPLACE_RATE + MUTATE_STRING_REMOVE_RATE + MUTATE_STRING_SUBSTRING_RATE - 1.0) < 0.00001;
            assert valid;
            MUTATE_STRING_INCREASE_THRESHOLD = MUTATE_STRING_APPEND_RATE + MUTATE_STRING_INSERT_RATE + MUTATE_STRING_DUPLICATE_RATE;
        }

        static final MutationConfig exploitConfig;
        static final MutationConfig exploreConfig;

        static {
            exploitConfig = new MutationConfig();
            exploitConfig.MUTATE_ARRAY_DELETE_RATE = 0.4;
            exploitConfig.MUTATE_ARRAY_INSERT_RATE = 0.8;
            exploitConfig.MUTATE_ARRAY_ONLY_ONE_ELEMENT = true;
            exploitConfig.MUTATE_INTEGER_ADD_RATE = 0.6;
            exploitConfig.MUTATE_INTEGER_MUL_RATE = 0.2;
            exploitConfig.MUTATE_INTEGER_SUB_RATE = 0.2;
            exploitConfig.MUTATE_STRING_APPEND_RATE = 0.3;
            exploitConfig.MUTATE_STRING_INSERT_RATE = 0.3;
            exploitConfig.MUTATE_STRING_DUPLICATE_RATE = 0.1;
            exploitConfig.MUTATE_STRING_REPLACE_RATE = 0.1;
            exploitConfig.MUTATE_STRING_REMOVE_RATE = 0.1;
            exploitConfig.MUTATE_STRING_SUBSTRING_RATE = 0.1;
            exploitConfig.MUTATE_LITERAL_LIMIT = 1024 * 16;
            exploitConfig.updateCheck();

            exploreConfig = new MutationConfig();
            exploreConfig.MUTATE_ARRAY_DELETE_RATE = 0.5;
            exploreConfig.MUTATE_ARRAY_INSERT_RATE = 0.4;
            exploreConfig.MUTATE_ARRAY_ONLY_ONE_ELEMENT = true;
            exploreConfig.MUTATE_INTEGER_ADD_RATE = 0.4;
            exploreConfig.MUTATE_INTEGER_MUL_RATE = 0.2;
            exploreConfig.MUTATE_INTEGER_SUB_RATE = 0.4;
            exploreConfig.MUTATE_STRING_APPEND_RATE = 0.2;
            exploreConfig.MUTATE_STRING_INSERT_RATE = 0.2;
            exploreConfig.MUTATE_STRING_DUPLICATE_RATE = 0.1;
            exploreConfig.MUTATE_STRING_REPLACE_RATE = 0.1;
            exploreConfig.MUTATE_STRING_REMOVE_RATE = 0.2;
            exploreConfig.MUTATE_STRING_SUBSTRING_RATE = 0.2;
            exploreConfig.MUTATE_LITERAL_LIMIT = 1024;
            exploreConfig.updateCheck();
        }
    }
}


