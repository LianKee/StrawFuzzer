#!/bin/sh
DATADIR="/data/data/com.straw.strawfuzzer"
SCRIPTDIR=`dirname $0`
adb shell su -c "chmod a+x $DATADIR"
adb shell su -c "chmod a+x $DATADIR/shared_prefs"
adb shell su -c "chmod a+r $DATADIR/shared_prefs/com.straw.strawfuzzer_preferences.xml"
adb shell su -c "chmod a+r $DATADIR/static_info.json"

mkdir -p "$SCRIPTDIR/../data/fuzzLog"

adb shell su -c "killall zygote"

# Wait for device to reboot
adb wait-for-device

A=$(adb shell getprop init.svc.bootanim | tr -d '\r')
while [ "$A" != "stopped" ]; do
        sleep 2
        A=$(adb shell getprop init.svc.bootanim 2>&1 | tr -d '\r')
done

A=$(adb shell getprop sys.boot_completed | tr -d '\r')
while [ "$A" != "1" ]; do
        sleep 2
        A=$(adb shell getprop sys.boot_completed | tr -d '\r')
done

adb wait-for-device
adb logcat -G 100M
