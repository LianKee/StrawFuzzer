package com.straw.lib.system;

import android.app.Activity;
import android.content.pm.PackageManager;

import androidx.core.app.ActivityCompat;
import androidx.core.content.ContextCompat;

import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;

public class Permissions {
    public static HashSet<String> allPermissions = new HashSet<>();

    public static HashSet<String> getAllPermissions(){
        if (allPermissions.size()>0)
            return allPermissions;

        try{
            Class clazz = Class.forName("android.Manifest$permission");
            for (Field field: clazz.getDeclaredFields()){
                allPermissions.add((String) field.get(null));
                System.out.println("<uses-permission android:name=\""+(String) field.get(null)+"\" />");
            }
        }catch (Exception e){
            e.printStackTrace();
        }
        return allPermissions;
    }

    public static void checkPermissions(Activity activity) {
        List<String> listPermissionsNeeded = new ArrayList<>();
        for (String p : getAllPermissions()) {
            if (ContextCompat.checkSelfPermission(activity.getApplicationContext(),p) != PackageManager.PERMISSION_GRANTED) {
                listPermissionsNeeded.add(p);
            }
        }
        if (!listPermissionsNeeded.isEmpty()) {
            ActivityCompat.requestPermissions(activity, listPermissionsNeeded.toArray(new String[listPermissionsNeeded.size()]),1);
        }
    }

}
