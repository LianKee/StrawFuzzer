package com.straw.lib.utils;

import android.os.Build;
import android.os.Bundle;
import android.os.Parcel;
import android.os.Parcelable;

import java.util.Arrays;
import java.util.List;
import java.util.Map;

public class ParcelUtils {
    public static void writeToParcel(Parcel in, String paramType, Object target){
        if ("int".equals(paramType)) {
            in.writeInt((int) target);
        } else if ("long".equals(paramType)) {
            in.writeLong((long) target);
        } else if ("float".equals(paramType)) {
            in.writeFloat((float) target);
        } else if ("double".equals(paramType)) {
            in.writeDouble((double) target);
        } else if ("byte".equals(paramType)) {
            in.writeByte((byte) target);
        } else if ("java.lang.String".equals(paramType)) {
            in.writeString((String) target);
        } else if ("boolean".equals(paramType)) {
            boolean tmp = (boolean) target;
            if (tmp)
                in.writeInt(1);
            else
                in.writeInt(0);
        } else if (target instanceof List) { //TODO: List List<IBinder>
            in.writeList((List) target);
        } else if ("java.util.Map".equals(paramType)) {
            in.writeMap((Map) target);
        } else if ("[Z".equals(paramType)) {
            in.writeBooleanArray((boolean[]) target);
        } else if ("[B".equals(paramType)) {
            in.writeByteArray((byte[]) target);
        } else if ("[C".equals(paramType)) {
            in.writeCharArray((char[]) target);
        } else if ("[I".equals(paramType)) {
            in.writeIntArray((int[]) target);
        } else if ("[J".equals(paramType)) {
            in.writeLongArray((long[]) target);
        } else if ("[F".equals(paramType)) {
            in.writeFloatArray((float[]) target);
        } else if ("[D".equals(paramType)) {
            in.writeDoubleArray((double[]) target);
//        } else if ("[Ljava.lang.String;".equals(paramType)) {
//            in.writeStringArray((String[]) InputGenerator.generateSeedByClass(paramType));
        } else if ("[Ljava.lang.String;".equals(paramType) || "java.lang.String[]".equals(paramType)) {
            in.writeStringArray((String[]) target);
        } else if (paramType.equals("android.os.Bundle")) {
            in.writeBundle((Bundle) target);
        } else {
            // writeArray invoke writeValue for each element
//            in.writeValue(target);
            if (target.getClass().isArray()){
                in.writeParcelableArray((Parcelable[]) target,0);
            } else if(target instanceof List) {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                    in.writeParcelableList(Arrays.asList((Parcelable[]) target),0);
                } else {
                    in.writeValue(target);
                }
            } else {
                in.writeTypedObject((Parcelable) target,0);
            }
        }
    }
}
