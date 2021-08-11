package com.straw.lib.reflection;

import java.lang.reflect.Field;

public class ReflectionUtils {

    public static Object getField(Object obj, Class<?> cl, String field)
            throws NoSuchFieldException, IllegalArgumentException, IllegalAccessException {
        Field localField = cl.getDeclaredField(field);
        localField.setAccessible(true);
        return localField.get(obj);
    }

    public static void setField(Object obj, Class<?> cl, String field, Object value)
            throws NoSuchFieldException, IllegalArgumentException, IllegalAccessException {
        Field localField = cl.getDeclaredField(field);
        localField.setAccessible(true);
        localField.set(obj, value);
    }

    public static Boolean isInterfaceType(String paramType) {
        String[] strArr = paramType.split("\\.");
        if (strArr[strArr.length - 1].startsWith("I") && Character.isUpperCase(strArr[strArr.length - 1].charAt(1))) {
            return true;
        } else {
            return false;
        }
    }
}
