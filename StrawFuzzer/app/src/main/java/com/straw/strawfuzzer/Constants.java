package com.straw.strawfuzzer;

import java.util.Arrays;
import java.util.HashSet;

public class Constants {
    // Basic param types
    public static HashSet<String> typicalParamType = new HashSet<String>(){{addAll(
            Arrays.asList(new String[]{
                    "int","long","float","boolean","char","double","byte","short","java.lang.String",
                    "java.lang.CharSequence"

            }));}};

}

