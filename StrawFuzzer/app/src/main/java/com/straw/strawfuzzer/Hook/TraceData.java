package com.straw.strawfuzzer.Hook;

import android.os.Parcel;
import android.os.Parcelable;

import androidx.core.util.Pools;

import com.straw.lib.reflection.ParcelableMethod;

import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

public class TraceData implements Parcelable {

    public static final int MAX_TRACE_LENGTH = 1024;

    public static int id = 0;
    public static List<ParcelableMethod> methodTable = new ArrayList<>(1000);
    public static final Map<ParcelableMethod, Integer> methodMap = new HashMap<>(1000);

    private static final TraceDataPool traceDataPool = new TraceDataPool(1);

    public List<Integer> trace; /* Execution trace. Each element is the id of a method */

    public boolean overTraced; /* If the trace size is too large, this field is set */

    public boolean dirty; /* If the trace is hybrid with other RPC call, the trace is dirty and this field is set */

    public static final Creator<TraceData> CREATOR = new Creator<TraceData>() {
        @Override
        public TraceData createFromParcel(Parcel in) {
            return new TraceData(in);
        }

        @Override
        public TraceData[] newArray(int size) {
            return new TraceData[size];
        }
    };

    private TraceData() {
        trace = new ArrayList<>(MAX_TRACE_LENGTH);
        overTraced = false;
        dirty = false;
    }

    protected TraceData(Parcel in) {
        int length = in.readInt();
        trace = new ArrayList<>(length);
        for (int i = 0; i < length; ++i) {
            trace.add(in.readInt());
        }
        overTraced = in.readInt() != 0;
        dirty = in.readInt() != 0;
    }

    /**
     * Reset a trace
     */
    public void reset() {
        trace.clear();
        overTraced = false;
        dirty = false;
    }

    /**
     * Save a trace
     * @param id method id of the traced method
     */
    public void traceAt(int id) {
        if (trace.size() >= MAX_TRACE_LENGTH) {
            overTraced = true;
        } else {
            trace.add(id);
        }
    }

    public boolean contains(ParcelableMethod method) {
        return trace.contains(methodMap.get(method));
    }

    public boolean contains(int methodId) {
        return trace.contains(methodId);
    }

    @Override
    public String toString() {
        boolean printIndex = methodTable.size() == 0;
        return toString(printIndex);
    }

    public String toString(boolean printIndex) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < trace.size(); ++i) {
            int id = trace.get(i);
            if (printIndex) {
                sb.append(id);
            } else {
                ParcelableMethod method = methodTable.get(id);
//                sb.append(method.className);
//                sb.append('.');
//                sb.append(method.methodName);
                sb.append(method.toString());
            }
            if (i + 1 == trace.size()) break;
            sb.append("->");
        }
        if (dirty) {
            sb.append("[dirty]");
        }
        return sb.toString();
    }

    /**
     * Require a trace data
     * @return trace data
     */
    public static TraceData acquire() {
        return new TraceData();
    }

    public static void registerMethod(Method method) {
        ParcelableMethod parcelableMethod = new ParcelableMethod(method);
        methodTable.add(parcelableMethod);
        methodMap.put(parcelableMethod, id);
        id++;
    }

    public static void registerConstructor(Constructor constructor) {
        ParcelableMethod parcelableMethod = new ParcelableMethod(constructor);
        methodTable.add(parcelableMethod);
        methodMap.put(parcelableMethod, id);
        id++;
    }

    public static void prepareWithMethodTable() {
        id = 0;
        for (ParcelableMethod method: methodTable) {
            methodMap.put(method, id);
            id++;
        }
    }

    @Override
    public int describeContents() {
        return 0;
    }

    @Override
    public void writeToParcel(Parcel out, int flags) {
        out.writeInt(trace.size());
        for (int id: trace) {
            out.writeInt(id);
        }
        out.writeInt(overTraced ? 1: 0);
        out.writeInt(dirty? 1: 0);
    }

    public Set<String> getCoveredMethods() {
        Set<String> methods = new HashSet<>();
        for (int idx: trace) {
            methods.add(methodTable.get(idx).toString());
        }
        return methods;
    }

    private static class TraceDataPool extends Pools.SynchronizedPool<TraceData> {

        /**
         * Creates a new instance.
         *
         * @param maxPoolSize The max pool size.
         * @throws IllegalArgumentException If the max pool size is less than zero.
         */
        public TraceDataPool(int maxPoolSize) {
            super(maxPoolSize);
        }

        @Override
        public TraceData acquire() {
            TraceData traceData = super.acquire();
            traceData.reset();
            return traceData;
        }
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        TraceData traceData = (TraceData) o;
        return trace.equals(traceData.trace);
    }

    @Override
    public int hashCode() {
        return Objects.hash(trace);
    }
}
