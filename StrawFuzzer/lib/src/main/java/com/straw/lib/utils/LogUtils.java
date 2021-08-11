package com.straw.lib.utils;

import android.util.Log;

public class LogUtils {
    public static void failTo(String tag, String message, Exception exception) {
        failTo(tag, message);
        if (null == exception) return;
        for (String traceLine: Log.getStackTraceString(exception).split("\n")) {
            Log.w(tag, "Fail to: " + traceLine);
        }
    }

    public static void failTo(String tag, String message) {
        Log.w(tag, "Fail to: " + message);
    }
}
