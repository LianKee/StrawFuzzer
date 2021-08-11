package com.straw.strawfuzzer.Fuzz;

import android.os.Debug;
import android.os.Parcel;
import android.os.Parcelable;

public class MemoryInfo implements Parcelable {

    public long heap = 0;
    public long pss = 0;
    public int deathRecipients = 0;

    private static Debug.MemoryInfo dMemoryInfo = new Debug.MemoryInfo();

    public static MemoryInfo getCurrentMemoryInfo() {
        Debug.getMemoryInfo(dMemoryInfo);
        MemoryInfo memoryInfo = new MemoryInfo();
        memoryInfo.heap = dMemoryInfo.dalvikPrivateDirty + dMemoryInfo.nativePrivateDirty;
        memoryInfo.pss = dMemoryInfo.getTotalPss();
//        memoryInfo.pss = dMemoryInfo.getTotalPss();
        memoryInfo.deathRecipients = Debug.getBinderDeathObjectCount();
        return memoryInfo;
    }

    public MemoryInfo() { }

    protected MemoryInfo(Parcel in) {
        heap = in.readLong();
        pss = in.readLong();
        deathRecipients = in.readInt();
    }

    public static final Creator<MemoryInfo> CREATOR = new Creator<MemoryInfo>() {
        @Override
        public MemoryInfo createFromParcel(Parcel in) {
            return new MemoryInfo(in);
        }

        @Override
        public MemoryInfo[] newArray(int size) {
            return new MemoryInfo[size];
        }
    };

    @Override
    public int describeContents() {
        return 0;
    }

    @Override
    public void writeToParcel(Parcel dest, int flags) {
        dest.writeLong(heap);
        dest.writeLong(pss);
        dest.writeInt(deathRecipients);
    }
}
