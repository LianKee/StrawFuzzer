package com.straw.strawfuzzer.Fuzz;

import com.straw.strawfuzzer.Hook.StaticInfo;

import static org.junit.Assert.*;
import org.junit.Test;

public class StaticInfoTest {

    @Test
    public void valueSpecTest() {

        assertEquals("1234", new StaticInfo.ValueSpec("1234").getValueForceType(null, null, String.class).get());
        assertEquals(1234, new StaticInfo.ValueSpec("1234").getValueForceType(null, null, int.class).get());
    }
}
