package com.straw.strawfuzzer;

import android.os.Bundle;
import android.os.RemoteException;
import android.util.Log;
import android.widget.TextView;

import androidx.appcompat.app.AppCompatActivity;
import androidx.appcompat.widget.Toolbar;

import com.google.android.material.appbar.CollapsingToolbarLayout;
import com.google.android.material.floatingactionbutton.FloatingActionButton;
import com.straw.strawfuzzer.Hook.HookServiceClientConnection;
import com.straw.strawfuzzer.Hook.IHookService;
import com.straw.lib.reflection.ParcelableMethod;
import com.straw.strawfuzzer.Hook.TraceData;

import java.util.ArrayList;
import java.util.List;

public class HookedMethodsActivity extends AppCompatActivity {

    HookServiceClientConnection connection = new HookServiceClientConnection();

    @Override
    protected void onStart() {
        super.onStart();
        HookServiceClientConnection.establish(this, connection);
    }

    @Override
    protected void onStop() {
        super.onStop();
        unbindService(connection);
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_hooked_methods);
        Toolbar toolbar = findViewById(R.id.toolbar);
        setSupportActionBar(toolbar);
        CollapsingToolbarLayout toolBarLayout = findViewById(R.id.toolbar_layout);
        toolBarLayout.setTitle(getTitle());

        FloatingActionButton fab = findViewById(R.id.fab);
        fab.setOnClickListener((view) -> {
            TextView textView = findViewById(R.id.textview_hooked_methods);
            String content = getHookedMethodsPrintableString();
            textView.setText(content);
        });
    }

    private String getHookedMethodsPrintableString() {
        StringBuilder sb = new StringBuilder();
        try {
            Log.d("Straw", "Try to get methodTable from HookService");
            IHookService hookService = connection.getHookService();
            if (null == hookService) {
                return "Error: Fail to get HookService";
            }

            int methodCount = hookService.getMethodCount();
            TraceData.methodTable = new ArrayList<>();
            for (int i = 0; i < methodCount; i += 500) {
                TraceData.methodTable.addAll(hookService.getMethods(i, Math.min(i + 500, methodCount)));
            }
        } catch (RemoteException e) {
            e.printStackTrace();
        }
        List<ParcelableMethod> methods = TraceData.methodTable;
        for (int i = 0; i < methods.size(); ++i) {
            ParcelableMethod method = methods.get(i);
            sb.append(String.format("%-6d\n%s.%s (\n", i, method.className, method.methodName));
            int paramTypesLength = method.paramTypes.length;
            for (int j = 0; j < paramTypesLength; ++j) {
                sb.append("\t");
                sb.append(method.paramTypes[j]);
                if (j != paramTypesLength - 1) {
                    sb.append(",\n");
                }
            }
            sb.append(String.format("\n) -> %s\n", method.returnType));
        }
        return sb.toString();
    }
}
