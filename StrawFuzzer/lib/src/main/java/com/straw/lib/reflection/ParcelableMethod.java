package com.straw.lib.reflection;

import android.os.Parcel;
import android.os.Parcelable;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.straw.lib.utils.ParcelUtils;

import java.lang.reflect.Constructor;
import java.lang.reflect.Member;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class ParcelableMethod implements Parcelable {

    public final String className;
    public final String methodName;
    public final String[] paramTypes;
    public final String returnType;
    private Member member = null;
    private List<Integer> nullables = null;

    private static Map<String, String> ARR_BASE_SIG_MAP = new HashMap<>();
    static {
        ARR_BASE_SIG_MAP.put("int", "I");
        ARR_BASE_SIG_MAP.put("long", "J");
        ARR_BASE_SIG_MAP.put("float", "F");
        ARR_BASE_SIG_MAP.put("boolean", "Z");
        ARR_BASE_SIG_MAP.put("char", "C");
        ARR_BASE_SIG_MAP.put("double", "D");
        ARR_BASE_SIG_MAP.put("byte", "B");
        ARR_BASE_SIG_MAP.put("short", "S");
    }

    private static final Pattern PATTERN = Pattern.compile("\\<(?<Class>[\\w\\.\\$]+)\\s*:\\s*(?<Ret>[\\w\\.\\$\\[\\]\\;]+)\\s*(?<Method>[\\w\\$\\<\\>]+)\\s*\\((?<Params>[\\w\\.\\$,\\s\\[\\]\\;]*)\\)\\s*\\>");

    public static ParcelableMethod parseOne(String text) {
        List<ParcelableMethod> methods = parse(text);
        if (methods.size() == 0) return null;
        return methods.get(0);
    }

    public static List<ParcelableMethod> parse(String text) {
        List<ParcelableMethod> methods = new ArrayList<>();
        Matcher m = PATTERN.matcher(text);
        // TODO handle constructors
        while (m.find()) {
            String className = m.group("Class");
//            String retType = m.group("Ret");
            String methodName = m.group("Method");
            String params = m.group("Params").replace(" ", "");
            String[] paramTypes;
            if (params.length() == 0) {
                paramTypes = new String[0];
            } else {
                paramTypes = params.split(",");
            }
            // handling array typename
            for (int i = 0; i < paramTypes.length; ++i) {
                String paramType = paramTypes[i];
                int idx = paramType.indexOf('[');
                int bracketCount = 0;
                for (int j = paramType.length() - 1; j >= 0; --j) {
                    char ch = paramType.charAt(j);
                    if (ch == '[') bracketCount += 1;
                    else if (ch == ']') continue;
                    else break;
                }
                if (bracketCount > 0) {
                    String basicType = paramType.substring(0, idx);
                    StringBuilder sigSB = new StringBuilder();
                    for (int j = 0; j < bracketCount; ++j) {
                        sigSB.append('[');
                    }
                    if (ARR_BASE_SIG_MAP.containsKey(basicType)) {
                        basicType = ARR_BASE_SIG_MAP.get(basicType);
                        sigSB.append(basicType);
                    } else {
                        sigSB.append("L").append(basicType).append(';');
                    }
                    paramTypes[i] = sigSB.toString();
                }
            }
            String returnType = m.group("Ret");
            ParcelableMethod method = new ParcelableMethod(className, methodName, paramTypes, returnType);
            methods.add(method);
        }
        return methods;
    }

    public ParcelableMethod(Method method) {
        className = method.getDeclaringClass().getName();
        methodName = method.getName();
        paramTypes = MyClassLoader.getStringParamTypesOfMethod(method);
        returnType = method.getReturnType().getTypeName();
        member = method;
    }

    /* Constructor is also supported */
    public ParcelableMethod(Constructor constructor) {
        className = constructor.getDeclaringClass().getName();
        methodName = constructor.getName();
        paramTypes = MyClassLoader.getStringParamTypesOfConstructor(constructor);
        returnType = className;
        member = constructor;
    }

    public ParcelableMethod(@NonNull String className, @NonNull String methodName,
                            @NonNull String[] paramTypes, String returnType) {
        this.className = className;
        this.methodName = methodName;
        this.paramTypes = paramTypes;
        this.returnType = returnType;
    }

    protected ParcelableMethod(Parcel in) {
        className = in.readString();
        methodName = in.readString();
        paramTypes = in.createStringArray();
        returnType = in.readString();
    }

    public boolean isConstructor() {
        return methodName.equals(className) || methodName.equals("<init>");
    }

    @Nullable
    public Method toMethod() {
        if (null == member) {
            member = MyClassLoader.loadMethod(className, methodName, paramTypes);
        }
        return (Method) member;
    }

    @Nullable
    public Constructor toConstructor() {
        if (null == member) {
            member = MyClassLoader.loadConstructor(className, paramTypes);
        }
        return (Constructor) member;
    }

    public static final Creator<ParcelableMethod> CREATOR = new Creator<ParcelableMethod>() {
        @Override
        public ParcelableMethod createFromParcel(Parcel in) {
            return new ParcelableMethod(in);
        }

        @Override
        public ParcelableMethod[] newArray(int size) {
            return new ParcelableMethod[size];
        }
    };

    @Override
    public int describeContents() {
        return 0;
    }

    @Override
    public void writeToParcel(Parcel out, int flags) {
        out.writeString(className);
        out.writeString(methodName);
        out.writeStringArray(paramTypes);
        out.writeString(returnType);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || !(o instanceof ParcelableMethod)) return false;
        ParcelableMethod method = (ParcelableMethod) o;
        if (method.isConstructor()) {
            return isConstructor() &&
                    className.equals(method.className) &&
                    Arrays.equals(paramTypes, method.paramTypes);
        }
        return className.equals(method.className) &&
                methodName.equals(method.methodName) &&
                Arrays.equals(paramTypes, method.paramTypes);
    }

    @Override
    public int hashCode() {
        int result = Objects.hash(className, isConstructor() ? "<init>": methodName);
        result = 31 * result + Arrays.hashCode(paramTypes);
        return result;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("<");
        sb.append(className);
        sb.append(": ");
        sb.append(returnType);
        sb.append(" ");
        sb.append(methodName);
        sb.append("(");
        if (paramTypes.length != 0) {
            sb.append(paramTypes[0]);
            for (int i = 1; i < paramTypes.length; ++i) {
                sb.append(", ");
                sb.append(paramTypes[i]);
            }
        }
        sb.append(")>");
        return sb.toString();
    }

    public void setNullables(List<Integer> nullables) {
        this.nullables = nullables;
    }

    public void writeParamValuesToParcel(Parcel in, Object[] paramValues) {
        assert paramValues.length == this.paramTypes.length;
        int nullableIdx = 0;
        int nullableLength = null != nullables ? nullables.size() : 0;
        for (int i = 0; i < paramTypes.length; ++i) {
            if (nullableIdx < nullableLength && i == nullables.get(nullableIdx++)) {
                in.writeInt(paramValues[i] == null ? 0 : 1);
            }
            ParcelUtils.writeToParcel(in, paramTypes[i], paramValues[i]);
        }
    }
}
