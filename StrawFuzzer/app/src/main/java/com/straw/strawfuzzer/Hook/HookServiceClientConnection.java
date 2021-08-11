package com.straw.strawfuzzer.Hook;

import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.os.IBinder;
import android.os.RemoteException;
import android.util.Log;

import com.straw.lib.utils.LogUtils;

import java.util.ArrayList;

public class HookServiceClientConnection implements ServiceConnection {

    private static final String TAG = "Straw_Conn";

    private IHookService hookService = null;

    @Override
    public void onServiceConnected(ComponentName name, IBinder service) {
        hookService = IHookService.Stub.asInterface(service);
        try {
            int methodCount = hookService.getMethodCount();
            TraceData.methodTable = new ArrayList<>();
            for (int i = 0; i < methodCount; i += 500) {
                TraceData.methodTable.addAll(hookService.getMethods(i, Math.min(i + 500, methodCount)));
            }
            TraceData.prepareWithMethodTable();
            Log.i(TAG, "getMethods " + TraceData.methodTable.size() + "/" + methodCount);
        } catch (RemoteException e) {
            LogUtils.failTo(TAG, "getMethods");
        }
        Log.i(TAG, "HookService Client connected");
    }

    @Override
    public void onServiceDisconnected(ComponentName name) {
        hookService = null;
    }

    public IHookService getHookService() { return  hookService; }

    public static boolean establish(Context packageContext, ServiceConnection connection) {
        Intent intent = new Intent(packageContext, HookService.class);
//        boolean res = packageContext.startService(intent) != null;
        boolean res = packageContext.bindService(intent, connection, Context.BIND_IMPORTANT);
        if (!res) {
            Log.i(TAG, "HookService Client fail to connect");
        }
        return res;
    }
}
