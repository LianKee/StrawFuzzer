package com.straw.strawfuzzer.Fuzz;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.os.RemoteException;
import android.util.Log;

import com.alibaba.fastjson.JSON;
import com.straw.lib.utils.LogUtils;
import com.straw.strawfuzzer.Hook.HookService;
import com.straw.strawfuzzer.Hook.IHookService;
import com.straw.lib.reflection.ParcelableMethod;
import com.straw.strawfuzzer.Hook.TraceData;
import com.straw.lib.system.SystemService;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.PriorityQueue;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorCompletionService;
import java.util.concurrent.Executors;

public class Fuzzer {

    private static final String TAG = "Straw_Fuzzer";

    private static final int MAX_MUTATE_TIMES = 50;
    private static final int EXPLOITATION_MUTATE_TIMES = 5;
    private static final int EXPLOITATION_SAMPLE_TIMES = 100;
    private static final long WAIT_TIMEOUT = 5000;
    private static final double MEMORY_BASE = EXPLOITATION_SAMPLE_TIMES * 1024 / 2;
    private static final double REF_COUNT_BASE = EXPLOITATION_SAMPLE_TIMES;
    public static final int SAMPLE_RATE = 100;
    private static final int THREAD_COUNT = 4;
    private static final long CRASH_MEM_THRESHOLD = 480 * 1024;
    private static final long CRASH_REF_THRESHOLD = 10000;

    private static IHookService hookService = null;
    private static boolean runFlag = false;
    private static List<ParcelableMethod> methods = null;

    private static MemoryInfo prevInfo = null;
    private static MemoryInfo currInfo;

    private static Integer explorationCount;
    private static Integer exploitationCount;
    private static int sampleCount = 0;
    private static Integer crashSniffCount = 0;
    private static int originRootSetSize = -2;
    private static int prevRootSetSize = -2;
    private static List<Double> consumptionScores;
    private static Map<String, Integer> exceptionMessages;
    private static int adaptCount;
    private static long startTime;

    private static double childrenContribution = .0;
    private static double childrenContributionCount = 0;

    private static ExecutorCompletionService pool = null;
    private static SeedQueue queue = null;
    private static SystemService service = null;
    private static Context context = null;

    public static boolean setUp(IHookService hookService, Context context) {
        Fuzzer.hookService = hookService;
        IntentFilter intentFilter = new IntentFilter(HookService.CRASH_START_ACTION);
        context.registerReceiver(new CrashStartReceiver(), intentFilter);
        intentFilter = new IntentFilter(HookService.STOP_FUZZING_ACTION);
        context.registerReceiver(new StopFuzzingReceiver(), intentFilter);
        intentFilter = new IntentFilter(HookService.DATA_PRINT_ACTION);
        context.registerReceiver(new DataPrintReceiver(), intentFilter);
        methods = TraceData.methodTable;
        Fuzzer.context = context;
        return true;
    }

    public static void setRunFlag(boolean runFlag) {
        Fuzzer.runFlag = runFlag;
        try {
            hookService.setTraceStart(runFlag);
        } catch (RemoteException | NullPointerException e) {
            Log.d(TAG, e.toString());
        }
    }

    public static void fuzzTargetHookless(final ParcelableMethod entryMethod, final ParcelableMethod riskyMethod) throws RemoteException {
        prepareFuzz(entryMethod, riskyMethod);

        Log.d(TAG, "Fuzzing loop start");
        startTime = System.currentTimeMillis();

        while (runFlag) {
            for (int i = 0; i < MAX_MUTATE_TIMES; ++i) {
                pool.submit(() -> {
                    Seed seed = Mutation.generateSeed(entryMethod, riskyMethod);
                    RunUtils.RunException runException = RunUtils.run(service, entryMethod.methodName, seed);
                    handleRunException(runException);
                    return null;
                });
            }
            for (int i = 0; i < MAX_MUTATE_TIMES; ++i) {
                try {
                    pool.take().get();
                } catch (ExecutionException | InterruptedException e) { }
            }
        }
    }

    public static void fuzzTargetFixedTime(final ParcelableMethod entryMethod, final ParcelableMethod riskyMethod,
                                           final boolean generate, final long exploreTime) throws RemoteException {
        prepareFuzz(entryMethod, riskyMethod);

        if (!waitForTraceStart(WAIT_TIMEOUT)) {
            Log.d(TAG, "Trace not started");
        }

        hookService.resetTrace();
        hookService.setup(riskyMethod);

        hookService.getMemoryInfo();
        Log.d(TAG, "Fuzzing loop start");
        startTime = System.currentTimeMillis();

        initSeeds(entryMethod, riskyMethod);

        // explore for fixed time
        while (runFlag && System.currentTimeMillis() - startTime < exploreTime) {
            Seed seed = queue.getSeed();
            seed.select();
            assert null != seed;

            int energy = seed.getEnergy(MAX_MUTATE_TIMES);
            Log.d(TAG, "Select " + seed.describe() + " with energy " + energy);

            for (int i = -1; i < energy; ++i) {
                if (!runFlag) return;
                boolean isParent = i == -1;
                Seed subSeed;
                if (isParent) {
                    subSeed = seed; // self
                    if (seed.isCFGScoreSet()) continue;
                } else {
                    if (generate) {
                        subSeed = Mutation.generateSeed(entryMethod, riskyMethod);
                    } else {
                        subSeed = Mutation.mutateSeed(seed);
                    }
                }
                explorationCount += 1;

                // First get the cfg score of a seed
                executeForCFGScore(subSeed, entryMethod);

                evaluateCFGScore(subSeed);

                boolean interesting = subSeed.getScoreWithPunish() > seed.getScoreWithPunish();
                if (interesting) {
                    Log.d(TAG, "Add an interesting seed " + subSeed.describe());
                    queue.add(subSeed);
                }
            }
        }

        // exploit
        while (runFlag) {
            Seed seed = queue.getSeed();
            assert null != seed;

            int energy = seed.getEnergy(EXPLOITATION_MUTATE_TIMES);
            Log.d(TAG, "Select " + seed.describe() + " with energy " + energy);

            for (int i = 0; i < energy; ++i) {
                if (!runFlag) return;
                Seed subSeed;
                if (generate) {
                    subSeed = Mutation.generateSeed(entryMethod, riskyMethod);
                } else {
                    subSeed = Mutation.mutateSeed(seed);
                }

                // Exploitation stage for a seed
                if (null == prevInfo) {
                    prevInfo = hookService.getMemoryInfo();
                }

                exploitationExecute(subSeed, entryMethod, riskyMethod, generate);

                evaluateConsumptionScore(seed, subSeed);

                // add interesting seed to queue
                boolean interesting = subSeed.getScoreWithPunish() > seed.getScoreWithPunish();
                if (interesting) {
                    subSeed.setCfgScore(seed.getCFGScore());
                    Log.d(TAG, "Add an interesting seed " + subSeed.describe());
                    queue.add(subSeed);
                }
            }
        }

    }

    public static void fuzzTarget(final ParcelableMethod entryMethod, final ParcelableMethod riskyMethod,
                                  final boolean generate) throws RemoteException {
        prepareFuzz(entryMethod, riskyMethod);

        if (!waitForTraceStart(WAIT_TIMEOUT)) {
            Log.d(TAG, "Trace not started");
        }

        hookService.resetTrace();
        hookService.setup(riskyMethod);

        hookService.getMemoryInfo();
        Log.d(TAG, "Fuzzing loop start");
        startTime = System.currentTimeMillis();

        boolean afterExplore = true;

        initSeeds(entryMethod, riskyMethod);

        while (runFlag) {
            Seed seed = queue.getSeed();
            assert null != seed;

            int energy = seed.getEnergy(seed.isHit() ? EXPLOITATION_MUTATE_TIMES : MAX_MUTATE_TIMES);
            Log.d(TAG, "Select " + seed.describe() + " with energy " + energy);

            for (int i = -1; i < energy; ++i) {
                if (!runFlag) return;
                boolean isParent = i == -1;
                Seed subSeed;
                if (isParent) {
                    subSeed = seed; // self
                    if (!seed.isCFGScoreSet()) explorationCount += 1;
                    else continue;
                } else {
                    if (generate) {
                        subSeed = Mutation.generateSeed(entryMethod, riskyMethod);
                    } else {
                        subSeed = Mutation.mutateSeed(seed);
                    }
                    if (!seed.isHit()) {
                        explorationCount += 1;
                    }
                }

                // First get the cfg score of a seed
                executeForCFGScore(subSeed, entryMethod);

                evaluateCFGScore(subSeed);

                // Exploitation stage for a seed
                if (subSeed.isHit() && !subSeed.isConsumptionScoreSet()) {
                    if (null == prevInfo) {
                        prevInfo = hookService.getMemoryInfo();
                    }

                    exploitationExecute(subSeed, entryMethod, riskyMethod, generate);

                    evaluateConsumptionScore(seed, subSeed);
                }
                if (seed.isHit()) {
                    if (afterExplore) {
                        // from explore to exploit
                        adaptCount += 1;
                        afterExplore = false;
                    }
                } else {
                    if (!afterExplore) {
                        // from exploit to explore
                        adaptCount += 1;
                        afterExplore = true;
                    }
                }

                // add interesting seed to queue
                boolean interesting = subSeed.getScoreWithPunish() > seed.getScoreWithPunish();
                if (interesting) {
                    Log.d(TAG, "Add an interesting seed " + subSeed.describe());
                    queue.add(subSeed);
                }
            }
        }
    }

    static void initSeeds(ParcelableMethod entryMethod, ParcelableMethod riskyMethod) {
        for (int i = 0; i < 3; ++i) {
            Seed initialSeed = Mutation.generateSeed(entryMethod, riskyMethod);
            assert null != initialSeed;
            queue.add(initialSeed);
        }
    }

    static void sniffCrash(boolean usePrevInfo) throws RemoteException {
        synchronized (crashSniffCount) {
            if (explorationCount + exploitationCount < EXPLOITATION_SAMPLE_TIMES * crashSniffCount)
                return;
            synchronized (crashSniffCount) {
                crashSniffCount += 1;
            }
        }
        MemoryInfo info = prevInfo;
        if (null == info || !usePrevInfo) {
            info = hookService.getMemoryInfo();
            if (null == info) {
                LogUtils.failTo(TAG, "get memory info in sniffCrash");
                return;
            }
        }
        // Crash detecting
        Log.d(TAG, "sniffCrash: " + info.heap + "(" + info.pss + ") <? " + CRASH_MEM_THRESHOLD);
        if (info.heap >= CRASH_MEM_THRESHOLD || info.deathRecipients >= CRASH_REF_THRESHOLD) {
            Log.d(TAG, "Flaw detected; stop fuzzing");
            Intent crashIntent = new Intent(HookService.CRASH_START_ACTION);
            context.sendBroadcast(crashIntent);
            return;
        }
    }

    static void evaluateCFGScore(Seed subSeed) throws RemoteException {
        if (!subSeed.isCFGScoreSet()) {
            double weight = hookService.getWeight();
            int rootSetSizeChange = getRootSetSizeChange();
            // retainability
            if (rootSetSizeChange == 0) {
                weight /= 2;
            }
            subSeed.setCfgScore(weight);
        }
    }

    static void evaluateConsumptionScore(Seed seed, Seed subSeed) throws RemoteException {
        currInfo = hookService.getMemoryInfo();
        double consumptionScore = calculateConsumptionScore(prevInfo, currInfo);
        prevInfo = currInfo;
        subSeed.setConsumptionScore(consumptionScore);
        synchronized (consumptionScores) {
            consumptionScores.add(consumptionScore);
        }
        childrenContribution += consumptionScore;
        childrenContributionCount += 1;

        // adjust parent's consumption score according to children's contribution
        if (childrenContributionCount > 0) {
            seed.setConsumptionScore((childrenContribution + seed.getConsumptionScore()) / (childrenContributionCount + 1));
        }
//        getRootSetSizeChange();
    }

    static void executeForCFGScore(Seed subSeed, ParcelableMethod entryMethod) throws RemoteException {
        if (!subSeed.isCFGScoreSet()) {
            RunUtils.RunException runException = RunUtils.run(service, entryMethod.methodName, subSeed);
            handleRunException(runException);
            sniffCrash(true);
        }
    }

    static int getRootSetSizeChange() throws RemoteException {
        // record root set size change
//        if (exploitationCount + explorationCount > sampleCount * SAMPLE_RATE) {
//            sampleCount++;
//            if (originRootSetSize < 0) originRootSetSize = hookService.getRootSetSize();
//            else {
//                sizeChange = Math.max(prevRootSetSize - originRootSetSize, sizeChange);
//            }
//        }
        int sizeChange = -1;
        if (originRootSetSize < 0) {
            if (originRootSetSize != -1) {
                originRootSetSize = hookService.getRootSetSize();
            } else {
                return sizeChange;
            }
        }
        else {
            int rootSetSize = hookService.getRootSetSize();
            sizeChange = rootSetSize - prevRootSetSize;
        }
        return sizeChange;
    }

    static int getTotalRootSetSizeChange() {
        if (prevRootSetSize < 0 || originRootSetSize < 0) return -1;
        return prevRootSetSize - originRootSetSize;
    }

    static void exploitationExecute(Seed subSeed, ParcelableMethod entryMethod, ParcelableMethod riskyMethod, boolean generate) throws RemoteException {
        // currently disable trace
        hookService.setTraceStart(false);
        // pretend to hit
        if (!subSeed.isCFGScoreSet()) subSeed.setCfgScore(1.0);

        Fuzzer.pool.submit(() -> {
            RunUtils.RunException runException = RunUtils.run(service, entryMethod.methodName, subSeed);
            handleRunException(runException);
            synchronized (exploitationCount) {
                exploitationCount += 1;
            }
            sniffCrash(false);
            return null;
        });
        final int executeCount = EXPLOITATION_SAMPLE_TIMES;
        for (int j = 0; j < executeCount; ++j) {
            if (!runFlag) return;
            Fuzzer.pool.submit(() -> {
                Seed testSeed;
                if (generate) {
                    testSeed = Mutation.generateSeed(entryMethod, riskyMethod);
                } else {
                    testSeed = Mutation.mutateSeed(subSeed);
                }
                RunUtils.RunException runException = RunUtils.run(service, entryMethod.methodName, testSeed);
                handleRunException(runException);
                synchronized (exploitationCount) {
                    exploitationCount += 1;
                }
                sniffCrash(false);
                return null;
            });
        }
        // Block and wait
        for (int j = 0; j < executeCount; ++j) {
            if (!runFlag) return;
            try {
                pool.take().get();
            } catch (InterruptedException | ExecutionException e) { }
        }

        // re-enable trace
        hookService.setTraceStart(true);
    }

    static void prepareFuzz(final ParcelableMethod entryMethod, final ParcelableMethod riskyMethod) {
        Fuzzer.explorationCount = 0;
        Fuzzer.exploitationCount = 0;
        Fuzzer.consumptionScores = new ArrayList<>();
        Fuzzer.exceptionMessages = new HashMap<>();
        Fuzzer.adaptCount = 0;

        pool = new ExecutorCompletionService(Executors.newFixedThreadPool(THREAD_COUNT));
        queue = new SeedQueue();

        String className = entryMethod.className;
        if (className.endsWith("$Proxy")) {
            service = SystemService.getSystemServiceByStubClassName(className.replace("$Proxy", ""));
        } else if (className.endsWith("$Stub")) {
            service = SystemService.getSystemServiceByStubClassName(className);
        } else {
            service = SystemService.getSystemServiceByServiceClassName(className);
        }
        if (null == service) {
            LogUtils.failTo(TAG, "get service . Ending");
            return;
        }
    }

    static boolean handleRunException(RunUtils.RunException runException) {
        if (null == runException) return false;
        // Save exception message
        synchronized (exceptionMessages) {
            if (exceptionMessages.size() < 16) {
                String exceptionMessage = runException.toString();
                exceptionMessages.put(
                        exceptionMessage,
                        exceptionMessages.getOrDefault(exceptionMessage, 0) + 1
                );
            }
        }
        return true;
    }

    static double calculateConsumptionScore(MemoryInfo prevInfo, MemoryInfo currInfo) {
        if (null == prevInfo || null == currInfo) return 0;
        double consumptionScore = (currInfo.heap - prevInfo.heap) / MEMORY_BASE +
                (currInfo.deathRecipients - prevInfo.deathRecipients) / REF_COUNT_BASE;
//        Log.d("Straw", "calculateConsumptionScore: " + consumptionScore);
        return consumptionScore;
    }

    private static TraceData waitForTraceData(long timeoutMillis) {
        long startTime = System.currentTimeMillis();
        try {
            TraceData traceData;
            do {
                traceData = hookService.getTraceData();
                if (System.currentTimeMillis() - startTime >= timeoutMillis || !runFlag) {
                    return null;
                }
            } while (null == traceData);
            Log.d("Straw", traceData.toString(true));
            return traceData;
        } catch (RemoteException e) {
            e.printStackTrace();
            return null;
        }
    }

    private static boolean waitForTraceStart(long timeoutMillis) {
        long startTime = System.currentTimeMillis();
        try {
            while (!hookService.isTraceStart()) {
                if (System.currentTimeMillis() - startTime >= timeoutMillis || !runFlag) {
                    return false;
                }
                try {
                    Thread.sleep(timeoutMillis / 100);
                } catch (InterruptedException e) {}
            }
            return true;
        } catch (RemoteException e) {
            e.printStackTrace();
            return false;
        }
    }

    public static String getFuzzData(boolean crashed, long duration) {
        synchronized (consumptionScores) {
            synchronized (exceptionMessages) {
                Map<String, Object> itemMap = new HashMap<>();
                itemMap.put("crashed", crashed);
                itemMap.put("duration", duration);
                itemMap.put("sizeChange", getTotalRootSetSizeChange());
                itemMap.put("adaptCount", adaptCount);
                itemMap.put("explorationCount", explorationCount);
                itemMap.put("exploitationCount", exploitationCount);
                itemMap.put("consumptionScores", consumptionScores);
                itemMap.put("exceptionMessages", exceptionMessages);
                return JSON.toJSONString(itemMap);
            }
        }
    }

    ///////////////////////////////////////////////////////////////
    // Following receiver is leveraged to save result of fuzzing //
    ///////////////////////////////////////////////////////////////

    private static class CrashStartReceiver extends BroadcastReceiver {

        @Override
        public void onReceive(Context context, Intent intent) {
            Log.d(TAG, "Printing fuzzing data");
            setRunFlag(false);
            long duration = System.currentTimeMillis() - startTime;
            String fuzzData = Fuzzer.getFuzzData(true, duration);
            for (int i = 0; i < fuzzData.length(); i += 2048) {
                Log.d(TAG, "Data for crashing: " + fuzzData.substring(i, Math.min(i + 2048, fuzzData.length())));
            }
            Log.d(TAG, "Data for crashing: !!!END");
            context.sendBroadcast(new Intent(HookService.CRASH_HANDLED_ACTION));
        }
    }

    private static class StopFuzzingReceiver extends BroadcastReceiver {

        @Override
        public void onReceive(Context context, Intent intent) {
            Log.d(TAG, "Printing fuzzing data");
            setRunFlag(false);
            long duration = System.currentTimeMillis() - startTime;
            String fuzzData = Fuzzer.getFuzzData(false, duration);
            for (int i = 0; i < fuzzData.length(); i += 2048) {
                Log.d(TAG, "Data for stopping: " + fuzzData.substring(i, Math.min(i + 2048, fuzzData.length())));
            }
            Log.d(TAG, "Data for stopping: !!!END");
        }
    }

    private static class DataPrintReceiver extends BroadcastReceiver {

        @Override
        public void onReceive(Context context, Intent intent) {
            Log.d(TAG, "Printing fuzzing data");
            long duration = System.currentTimeMillis() - startTime;
            String fuzzData = Fuzzer.getFuzzData(true, duration);
            for (int i = 0; i < fuzzData.length(); i += 2048) {
                Log.d(TAG, "Data for print: " + fuzzData.substring(i, Math.min(i + 2048, fuzzData.length())));
            }
            Log.d(TAG, "Data for print: !!!END");
            context.sendBroadcast(new Intent(HookService.CRASH_HANDLED_ACTION));
        }
    }

}
