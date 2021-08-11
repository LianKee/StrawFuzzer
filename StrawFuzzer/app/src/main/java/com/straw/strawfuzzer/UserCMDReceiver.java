package com.straw.strawfuzzer;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.util.Log;

import com.straw.lib.utils.LogUtils;
import com.straw.strawfuzzer.Fuzz.Fuzzer;
import com.straw.strawfuzzer.Hook.HookService;
import com.straw.strawfuzzer.Hook.HookServiceClientConnection;
import com.straw.strawfuzzer.Hook.IHookService;
import com.straw.lib.reflection.ParcelableMethod;
import com.straw.strawfuzzer.Hook.PreferenceUtils;

/**
 * UserCMDReceiver receives and handles command from broadcasts.
 * Command:
 * - SET_SERVICE
 *      Set target services
 *      Args:
 *          services -- target services, separated with comma
 *
 * - START_FUZZING
 *      Start fuzzing
 *      Args:
 *          hookless        -- If set, the fuzzer will not use any feature relying on
 *                             instrumentation, and will not use static analysis results
 *          generate        -- If set, the fuzzer will generate seeds instead of mutating ones
 *          entrySignature  -- A signature represent the entry method
 *          riskySignature  -- A signature represent the target method which is potentially
 *                             vulnerable to straw attack
 *
 * - STOP_FUZZING
 *      Stop fuzzing
 */
public class UserCMDReceiver extends BroadcastReceiver {
    public static final String SET_SERVICE = "com.straw.strawfuzzer.UserCMDReceiver.SET_SERVICE";
    public static final String START_FUZZING = "com.straw.strawfuzzer.UserCMDReceiver.START_FUZZING";
    public static final String STOP_FUZZING = "com.straw.strawfuzzer.UserCMDReceiver.STOP_FUZZING";
    public static final String SET_DISABLE_HOOK = "com.straw.strawfuzzer.UserCMDReceiver.SET_DISABLE_HOOK";
    public static final String SET_DISABLE_CRASH_HOOK = "com.straw.strawfuzzer.UserCMDReceiver.SET_DISABLE_CRASH_HOOK";

    private static final String TAG = "Straw_CMD";

    private IHookService hookService;
    private HookServiceClientConnection connection;

    public UserCMDReceiver(HookServiceClientConnection connection) {
        this.connection = connection;
    }

    @Override
    public void onReceive(Context context, Intent intent) {
        switch (intent.getAction()) {
            case SET_SERVICE:
                setService(context, intent);
                break;
            case START_FUZZING:
                startFuzzing(context, intent);
                break;
            case STOP_FUZZING:
                stopFuzzing(context, intent);
                break;
            case SET_DISABLE_HOOK:
                setDisableHook(context, intent);
                break;
            case SET_DISABLE_CRASH_HOOK:
                setDisableCrashHook(context, intent);
                break;
            default:
                break;
        }
    }

    public void setService(Context context, Intent intent) {
        final String key = "services";
        String val = intent.getStringExtra(key);
        if (null == val) {
            return;
        }
        SharedPreferences prefs = context.getSharedPreferences(PreferenceUtils.prefName, Context.MODE_PRIVATE);
        prefs.edit().putString(key, val).commit();
        Log.i(TAG, "Set " + key + " to " + val);
    }

    public void setDisableHook(Context context, Intent intent) {
        final String key = "disable_hook";
        boolean val = intent.getBooleanExtra(key, false);
        SharedPreferences prefs = context.getSharedPreferences(PreferenceUtils.prefName, Context.MODE_PRIVATE);
        prefs.edit().putBoolean(key, val).commit();
        Log.i(TAG, "Set " + key + " to " + val);
    }

    public void setDisableCrashHook(Context context, Intent intent) {
        final String key = "disable_crash_hook";
        boolean val = intent.getBooleanExtra(key, false);
        SharedPreferences prefs = context.getSharedPreferences(PreferenceUtils.prefName, Context.MODE_PRIVATE);
        prefs.edit().putBoolean(key, val).commit();
        Log.i(TAG, "Set " + key + " to " + val);
    }

    public void stopFuzzing(Context context, Intent intent) {
        Intent stopIntent = new Intent(HookService.STOP_FUZZING_ACTION);
        context.sendBroadcast(stopIntent);
    }

    public void startFuzzing(Context context, Intent intent) {
        boolean hookless = intent.getBooleanExtra("hookless", false);
        if (!hookless) {
            if (null == hookService) {
                hookService = connection.getHookService();
            }
            for (int i = 0; i < 10; ++i) {
                if (null != hookService) {
                    break;
                }
                try {
                    Thread.sleep(1000);
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
            }
            if (null == hookService) {
                Log.d(TAG, "HookService not ready");
                return;
            }
        }
        Fuzzer.setUp(hookService, context);
        String entrySignature = intent.getStringExtra("entrySignature");
        String riskySignature = intent.getStringExtra("riskySignature");
        boolean generate = intent.getBooleanExtra("generate", false);
        int exploreTime = intent.getIntExtra("exploreTime", -1);

        ParcelableMethod entryMethod = ParcelableMethod.parseOne(entrySignature);
        ParcelableMethod riskyMethod = ParcelableMethod.parseOne(riskySignature);
        String fuzzingMethod = hookless ? ("fuzzTargetHookless") : (exploreTime < 0 ? "fuzzTarget" : "fuzzTargetFixedTime");
        if (null == entryMethod || !hookless && null == riskyMethod) {
            LogUtils.failTo(TAG, "fuzz on " + entrySignature + " -- " + riskySignature + " with " + fuzzingMethod);
            return;
        } else {
            Log.i(TAG, "Start to fuzz on " + entrySignature + " -- " + riskySignature + " with " + fuzzingMethod);
        }

        try {
            Thread t = new Thread(() -> {
                try {
                    Fuzzer.setRunFlag(true);
                    if (hookless) {
                        Fuzzer.fuzzTargetHookless(entryMethod, riskyMethod);
                    } else {
                        if (exploreTime < 0) {
                            Fuzzer.fuzzTarget(entryMethod, riskyMethod, generate);
                        } else {
                            Fuzzer.fuzzTargetFixedTime(entryMethod, riskyMethod, generate, exploreTime * 1000/* millsecs */);
                        }
                    }
                } catch (Exception e) {
                    LogUtils.failTo(TAG, "continue fuzz", e);
                }
            });
            t.setDaemon(true);
            t.start();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
