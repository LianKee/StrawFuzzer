package com.straw.strawfuzzer.Hook;

import android.app.Service;
import android.content.Intent;
import android.os.IBinder;
import android.os.RemoteException;
import android.util.Log;

import androidx.annotation.Nullable;

import com.straw.lib.reflection.ParcelableMethod;
import com.straw.strawfuzzer.Fuzz.MemoryInfo;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class HookService extends Service {

    public static String TRACE_START_ACTION = "com.straw.strawfuzzer.Hook.XposedHook$TraceStartReceiver";
    public static String GET_MEMORY_INFO_ACTION = "com.straw.strawfuzzer.Hook.XposedHook$MemoryInfoReceiver";
    public static String REBOOT_ACTION = "com.straw.strawfuzzer.Hook.XposedHook$RebootReceiver";

    public static String CRASH_START_ACTION  = "com.straw.strawfuzzer.Fuzz.Fuzzer$CrashStartReceiver";
    public static String CRASH_HANDLED_ACTION = "com.straw.strawfuzzer.Hook.XposedHook$CrashHandledReceiver";

    public static final String STOP_FUZZING_ACTION = "com.straw.strawfuzzer.Fuzz$StopFuzzingReceiver";
    public static final String DATA_PRINT_ACTION = "com.straw.strawfuzzer.Fuzz$DataPrintReceiver";

    private static final String TAG = "Straw_HookService";

    @Nullable
    @Override
    public IBinder onBind(Intent intent) { return binder; }

    final IHookService.Stub binder = new IHookService.Stub() {

        private boolean traceStart = false; // The trace recorded only when this field is true

        private TraceData traceData = TraceData.acquire();
        private TraceData readyTraceData = null;
        private Map<Integer, Integer> traceCount = new HashMap<>();

        private ParcelableMethod riskyMethod = null;
        private Integer riskyMethodId = -1;

        private Double weight = .0;
        private int rootSetSize = -1;

        private MemoryInfo memoryInfo = null;

        @Override
        public void traceAt(int id) throws RemoteException {
            if (null == riskyMethod || null == TraceData.methodTable) return;
            ParcelableMethod method = TraceData.methodTable.get(id);
            double traceWeight = StaticInfo.getWeight(riskyMethod, method);
            synchronized (weight) {
                weight = Math.max(weight, traceWeight);
            }
//            traceData.traceAt(id);
//            Integer count = traceCount.getOrDefault(id, 0) + 1;
//            traceCount.put(id, count);
        }

        @Override
        public double getWeight() throws RemoteException {
            double res;
            synchronized (this) {
                res = weight;
                weight = .0;
            }
            return res;
        }

        @Override
        public void setup(ParcelableMethod riskyMethod) throws RemoteException {
            this.riskyMethod = riskyMethod;
            this.riskyMethodId = TraceData.methodMap.get(riskyMethod);
            if (null == riskyMethodId) {
                Log.d(TAG, "Warning: setup fail to find " + riskyMethod + " in table{len=" + TraceData.methodMap.size() + "} ");
                riskyMethodId = -1;
            }
        }

        @Override
        public void resetTrace() throws RemoteException {
//            traceData.reset();
//            readyTraceData = null;
            synchronized (this) {
                this.weight = .0;
            }
        }

        @Override
        public TraceData getTraceData() throws RemoteException {
            TraceData traceData = readyTraceData;
            this.readyTraceData = null;
            return traceData;
        }

        @Override
        public List<ParcelableMethod> getMethods(int start, int end) throws RemoteException {
            int methodCount = getMethodCount();
            if (start < 0 || start >= end || end > methodCount) {
                return new ArrayList<>();
            }
            return TraceData.methodTable.subList(start, end);
        }

        @Override
        public int getMethodCount() throws RemoteException {
            return TraceData.methodTable.size();
        }

        @Override
        public synchronized void postMethods(List<ParcelableMethod> methods, int start) throws RemoteException {
            if (start == TraceData.methodTable.size()) {
                TraceData.methodTable.addAll(methods);
                int i = 0;
                for (ParcelableMethod method: methods) {
                    TraceData.methodMap.put(method, start + i++);
                }
            }
        }

        @Deprecated
        @Override
        public boolean isTraceReady() throws RemoteException {
            return null == traceData;
        }

        @Override
        public void setTraceReady() throws RemoteException {
//            readyTraceData = traceData;
//            traceData = TraceData.acquire();
        }

        @Override
        public boolean isTraceStart() throws RemoteException {
            return traceStart;
        }

        @Override
        public void setTraceStart(boolean traceStart) throws RemoteException {
            Intent intent = new Intent(TRACE_START_ACTION);
            intent.putExtra("traceStart", traceStart);
            sendBroadcast(intent);
            this.traceStart = traceStart;
            resetTrace();
        }

        @Override
        public void markDirty() throws RemoteException {
            traceData.dirty = true;
        }

        @Override
        public int getRootSetSize() throws RemoteException {
            return rootSetSize;
        }

        @Override
        public synchronized void postRootSetSize(int id, int rootSetSize) throws RemoteException {
            if (id == riskyMethodId) {
                this.rootSetSize = rootSetSize;
            }
        }

        @Override
        public MemoryInfo getMemoryInfo() throws RemoteException {
            synchronized (this) {
                this.memoryInfo = null;
                Intent intent = new Intent(GET_MEMORY_INFO_ACTION);
                sendBroadcast(intent);
                try {
                    this.wait();
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
                return this.memoryInfo;
            }
        }

        @Override
        public void postMemoryInfo(MemoryInfo memoryInfo) throws RemoteException {
            synchronized (this) {
                this.memoryInfo = memoryInfo;
                this.notifyAll();
            }
        }

        @Override
        public void postNullMemoryInfo() throws RemoteException {
            synchronized (this) {
                this.memoryInfo = null;
                this.notifyAll();
            }
        }

        @Override
        public void reboot() throws RemoteException {
            Intent intent = new Intent(REBOOT_ACTION);
            sendBroadcast(intent);
        }
    };
}
