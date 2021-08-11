package com.straw.strawfuzzer.Fuzz;

import org.junit.Test;

import java.lang.reflect.Array;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;

public class FuzzingObjectMutatorTest {

    @Test
    public void mutateExplore() {
        Mutation.ObjectMutator mutator = new Mutation.ObjectMutator(Mutation.MutationConfig.exploreConfig);
        mutateTest(mutator);
    }

    @Test
    public void mutateExploit() {
        Mutation.ObjectMutator mutator = new Mutation.ObjectMutator(Mutation.MutationConfig.exploitConfig);
        mutateTest(mutator);
    }

    public void mutateTest(Mutation.ObjectMutator mutator) {
        Object val;
        val = mutator.mutate(-32);
        val = mutator.mutate(4294967297l);
        val = mutator.mutate((short) 4096);
        val = mutator.mutate(3.1444444444444444444444444444444333333333333333333333333333333f);
        val = mutator.mutate(3.1444444444444444444444444444444333333333333333333333333333333);
        val = mutator.mutate(true);
        val = mutator.mutate('我');
        val = mutator.mutate((byte) 77);
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 21894; ++i) {
            sb.append('a');
        }
        for (int i = 0; i < 100; ++i) {
            val = mutator.mutate(sb.toString());
            assertNotEquals(sb.toString(), val);
        }
        val = mutator.mutate(new int[]{1, 3, 5, 7});
        val = mutator.mutate(new long[]{4294967297l, 4294967299l});
        val = mutator.mutate(new float[]{3.1444444444444444444444444444444333333333333333333333333333333f, .0f});
        val = mutator.mutate(new double[]{3.12394120341823421, -.3});
        val = mutator.mutate(new boolean[]{true, false});
        val = mutator.mutate(new byte[]{(byte)127, (byte)-3});
        val = mutator.mutate(new char[]{(char)99, 'c', '\n'});
        val = mutator.mutate(new short[]{(short)4096, (short)(-255 * 100)});
        val = mutator.mutate(new Integer[]{Integer.valueOf(-32), Integer.valueOf(9981)});
        val = mutator.mutate(new Long[]{Long.valueOf(4294967297l), Long.valueOf(3)});
        val = mutator.mutate(new Float[]{Float.valueOf(3.1444444444444444444444444444444333333333333333333333333333333f)});
        val = mutator.mutate(new Double[]{Double.valueOf(3.1444444444444444444444444444444333333333333333333333333333333)});
        val = mutator.mutate(new Boolean[]{Boolean.valueOf(true), false});
        val = mutator.mutate(new Byte[]{Byte.valueOf((byte)127)});
        val = mutator.mutate(new Character[]{Character.valueOf((char)99)});
        val = mutator.mutate(new Short[]{Short.valueOf((short)4096)});
        val = mutator.mutate(new String[]{"Hello\n^%+_-\0dsa", "3123412"});
        val = mutator.mutate(new String[]{"Hello\n^%+_-\0dsa", "ddd"});
    }

    private Object[] getObjectArray(Object val) {
        if (val instanceof Object[]) {
            return (Object[]) val;
        }
        int arrLength = Array.getLength(val);
        Object[] outputArray = new Object[arrLength];
        for(int i = 0; i < arrLength; ++i){
            outputArray[i] = Array.get(val, i);
        }
        return outputArray;
    }

}
