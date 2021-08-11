package com.straw.lib.reflection;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

public class ClassDependencyInfo {

    public static String[] getDependencyOf(String className) {
        return dependencies.get(className);
    }

    private static Map<String, String[]> dependencies = new HashMap<>();

    private static String[][] raw_deps = new String[][] {
            {"com.android.server.DropBoxManagerService", "android.provider.Settings"}
    };

    static {
        for(String[] raw_dep: raw_deps) {
            dependencies.put(raw_dep[0], Arrays.copyOfRange(raw_dep, 1, raw_dep.length));
        }
    }
}
