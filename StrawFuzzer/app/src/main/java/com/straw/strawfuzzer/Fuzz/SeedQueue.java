package com.straw.strawfuzzer.Fuzz;

import android.util.Log;

import java.util.ArrayList;
import java.util.List;
import java.util.PriorityQueue;

public class SeedQueue extends PriorityQueue<Seed> {

    private static int MAX_SEED = 200;
    private static int SHRINK_SIZE = MAX_SEED / 2;

    @Override
    public synchronized Seed peek() {
        Seed seed = super.peek();
        return seed;
    }

    @Override
    public synchronized Seed poll() {
        Seed seed = super.poll();
        return seed;
    }

    @Override
    public synchronized boolean add(Seed seed) {
        if (size() >= MAX_SEED) {
            shrink();
        }
        return super.add(seed);
    }

    public synchronized Seed getSeed() {
        if (isEmpty()) return null;
        Seed seed = poll();
//        seed.select();
        add(seed);
        return seed;
    }

    /**
     * shrink to reduce the size of queue
     */
    protected synchronized void shrink() {
        Log.d("Straw_Fuzzer", "Shrink SeedQueue");
        int shrinkSize = Math.min(size(), SHRINK_SIZE);
        List<Seed> tmpList = new ArrayList<>();
        for (int i = 0; i < shrinkSize; ++i) {
            tmpList.add(poll());
        }
        clear();
        super.addAll(tmpList);
    }
}
