package com.straw.strawfuzzer.Info;

import com.straw.strawfuzzer.Hook.StaticInfo;

import org.junit.Test;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;

public class StaticInfoTest {

    String text = "";

    @Test
    public void test() throws IOException {
        InputStream is = new FileInputStream(new File("/data/data/com.straw.strawfuzzer/static_info.json"));
        StaticInfo.init(is);
        is.close();
    }
}
