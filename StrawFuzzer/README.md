# StrawFuzzer

## Introduction

StrawFuzzer is a tool to detect and verify Straw vulnerabilities in **Android System Server**. 


## Requirements

1. A rooted Android device for fuzz testing.
2. Make sure [Xposed](https://repo.xposed.info/module/de.robv.android.xposed.installer) is successfully installed on the device.
3. Build environment including [Android Studio](https://developer.android.com/studio) and Android SDK.


## Usage

1.  Import this project into  Android Studio.
2.  Build and install the fuzzer with **app** configuration.
3.  Enable the StrawFuzzer module in Xposed Manager.
4.  Generate static analysis result with our static analyzer.
5.  Edit fuzzing configurations in `data/config.json`.
6.  Start fuzzing by running `script/client.py`.
7.  Analyze the fuzzing result with the help of `script/analyze.py`

## Result

There are 4 parts of output that can be utilized for further analysis：

- `data/log`: The log printed by `scripts/client.py`
- `data/summary.json`: The summary of `data/fuzzLog/*.log`, or rather, the summary of fuzzing statistic result
- `data/fuzzLog/*.log`: json format fuzzing result for each pair, the file name is formatted as `"{}-{}-{}.log".format(type, entry, risky)`。
- `data/fuzzLog/*.logcat`: The Android system logcat produced when fuzzing each pair。
