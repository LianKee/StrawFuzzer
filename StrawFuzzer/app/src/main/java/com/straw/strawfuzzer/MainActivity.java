package com.straw.strawfuzzer;

import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.util.Log;
import android.view.Menu;
import android.view.MenuItem;

import androidx.annotation.NonNull;
import androidx.appcompat.app.AppCompatActivity;
import androidx.appcompat.widget.Toolbar;

import com.google.android.material.floatingactionbutton.FloatingActionButton;
import com.straw.lib.reflection.MyClassLoader;
import com.straw.lib.reflection.ParcelableMethod;
import com.straw.lib.system.Permissions;
import com.straw.strawfuzzer.Hook.HookServiceClientConnection;
import com.straw.strawfuzzer.Hook.PreferenceUtils;
import com.straw.strawfuzzer.Hook.StaticInfo;

import me.weishu.reflection.Reflection;

public class MainActivity extends AppCompatActivity {

    public static Context context;
    private SharedPreferences prefs = null;
    public static HookServiceClientConnection connection = new HookServiceClientConnection();

    @Override
    protected void onStart() {
        super.onStart();
        HookServiceClientConnection.establish(this, connection);
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        unbindService(connection);
        Log.d("Straw", "App onDestroy");
    }

    @Override
    protected void attachBaseContext(Context base) {
        super.attachBaseContext(base);
        Reflection.unseal(base);
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        context = getApplicationContext();
        MyClassLoader.setContext(context);
        MyClassLoader.setClassLoader(getClassLoader());

        // Permission Request
        Permissions.checkPermissions(this);

        // Register and setup UserCMDReceiver
        IntentFilter intentFilter = new IntentFilter();
        intentFilter.addAction(UserCMDReceiver.SET_SERVICE);
        intentFilter.addAction(UserCMDReceiver.START_FUZZING);
        intentFilter.addAction(UserCMDReceiver.STOP_FUZZING);
        intentFilter.addAction(UserCMDReceiver.SET_DISABLE_HOOK);
        intentFilter.addAction(UserCMDReceiver.SET_DISABLE_CRASH_HOOK);

        context.registerReceiver(new UserCMDReceiver(connection), intentFilter);
        Log.d("Straw", "Registered UserCMDReceiver");

        prefs = context.getSharedPreferences(PreferenceUtils.prefName, MODE_PRIVATE);

        setContentView(R.layout.activity_main);
        Toolbar toolbar = findViewById(R.id.toolbar);
        setSupportActionBar(toolbar);

        FloatingActionButton fab = findViewById(R.id.fab);
        fab.setOnClickListener((view) -> {});

        prefs.edit().putString("filterUID", String.valueOf(getApplicationInfo().uid)).commit();
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        getMenuInflater().inflate(R.menu.activity_menu, menu);
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(@NonNull MenuItem item) {
        Intent intent;
        switch (item.getItemId()) {
            case R.id.action_settings:
                intent = new Intent(MainActivity.this, SettingsActivity.class);
                startActivity(intent);
                return true;
            case R.id.action_hooked_methods:
                intent = new Intent(MainActivity.this, HookedMethodsActivity.class);
                startActivity(intent);
                return true;
            default:
                return super.onOptionsItemSelected(item);
        }
    }

}
