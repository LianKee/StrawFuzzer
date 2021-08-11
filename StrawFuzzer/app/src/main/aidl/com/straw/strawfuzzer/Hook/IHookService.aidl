// IHookService.aidl
package com.straw.strawfuzzer.Hook;

// Declare any non-default types here with import statements
import com.straw.strawfuzzer.Hook.TraceData;
import com.straw.lib.reflection.ParcelableMethod;
import com.straw.strawfuzzer.Fuzz.MemoryInfo;
import android.os.Debug;

interface IHookService {

    /* ------------------ *
     * Trace information
     * ------------------ */
    void traceAt(int id);

    double getWeight();

    void setup(in ParcelableMethod riskyMethod);

    void resetTrace();

    TraceData getTraceData();

    boolean isTraceReady();

    void setTraceReady();

    boolean isTraceStart();

    void setTraceStart(boolean traceStart);

    void markDirty();

    /* ------------------ *
     * RootSet information
     * ------------------ */
    int getRootSetSize();

    void postRootSetSize(int id, int rootSetSize);

    /* ------------------ *
     * Hook information
     * ------------------ */
    List<ParcelableMethod> getMethods(int start, int end);

    int getMethodCount();

    void postMethods(in List<ParcelableMethod> methods, int start);

    /* ------------------ *
     * Runtime information
     * ------------------ */
    MemoryInfo getMemoryInfo();

    void postMemoryInfo(in MemoryInfo memoryInfo);

    void postNullMemoryInfo();

    /* ------------------ *
     * Special
     * ------------------ */
    void reboot();
}
