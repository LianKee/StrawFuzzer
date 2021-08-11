#!env python3
import sys
import os
import re
import time
import json, yaml
import subprocess
import threading
import codecs
import traceback
import string
import xml.etree.ElementTree as ET
from datetime import datetime
from queue import Queue, Empty

SCRIPT_PATH = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(SCRIPT_PATH, "../data/config.json")
STATIC_INFO_PATH = os.path.join(SCRIPT_PATH, "../data/static_info.json")
SERVICE_INFO_PATH = os.path.join(SCRIPT_PATH, "../data/service_info.json")
SUMMARY_PATH = os.path.join(SCRIPT_PATH, "../data/summary.json")
VULN_PATH = os.path.join(SCRIPT_PATH, "../data/vuln.yaml")
TMP_LOGCAT_PATH = '/sdcard/fuzzLogcat/tmp.logcat'
ON_POSIX = 'posix' in sys.builtin_module_names
PACKAGE_NAME = 'com.straw.strawfuzzer'
SYSTEM_CRASH_NEEDLEs = [
    '*** FATAL EXCEPTION IN SYSTEM PROCESS',
    '>>>>>> START com.android.internal.os.ZygoteInit uid 0 <<<<<<',
    'libc    : Fatal signal 6 (SIGABRT), code -1 (SI_QUEUE)',
    ]
CRASH_NEEDLE = 'Data for crashing: '
STOP_NEEDLE = 'Data for stopping: '
PRINT_NEEDLE = 'Data for print: '
END_NEEDLE = 'Data for '

RUN_SUCCESS = 0
RUN_SUCCESS_CRASH = 1
RUN_FAIL = 2
RUN_INIT = RUN_FAIL
RUN_SKIP = 3
RUN_FAIL_APP_CRASH = 4

SKIP_NO = 0
SKIP_TO = 1
SKIP_SOME = 2
SKIP_ONLY = 3
SKIP_EXIST = 4
SKIP_DUP = 5
SKIP_VULN = 6

CONFIG = None

class MemInfo(object):
    @classmethod
    def get_meminfo(cls):
        selector = get_device_selector()
        execute_res = execute_wait(f"adb {selector} shell dumpsys meminfo system")
        if not execute_res:
            return None
        raw_info = codecs.decode(execute_res[0], 'utf-8', errors="ignore")
        return cls.parse_meminfo(raw_info)

    @classmethod
    def parse_meminfo(cls, raw_info):
        def get_number_next_to(text, needle):
            needle_idx = text.find(needle)
            if needle_idx < 0:
                return -1
            start_idx = needle_idx + len(needle)
            while text[start_idx] not in string.digits: start_idx += 1
            end_idx = start_idx
            while text[end_idx] in string.digits: end_idx += 1
            return int(text[start_idx: end_idx])
        pss = get_number_next_to(raw_info, 'TOTAL:')
        if -1 == pss:
            pss = get_number_next_to(raw_info, 'TOTAL PSS:')
        refs = get_number_next_to(raw_info, 'Death Recipients:')
        meminfo = MemInfo(pss, refs)
        return meminfo

    def __init__(self, pss, refs):
        self.pss = pss
        self.refs = refs

    def to_dict(self):
        return {
            'pss': self.pss,
            'refs': self.refs
        }


class MyLogger(object):
    def __init__(self):
        self.terminal = sys.stdout
        self.log_path = os.path.join(SCRIPT_PATH, "../data/log")
        self.log = open(self.log_path, 'a+')
        self.lprint(f"-----------{datetime.now().strftime('%Y-%M-%D-%H:%M:%S')}-----------")

    def flush(self):
        self.terminal.flush()
        self.log.flush()

    def lprint(self, *args, **kwargs):
        if 'file' in kwargs:
            print(*args, **kwargs)
        else:
            kwargs['file'] = self.terminal
            print(*args, **kwargs)
            kwargs['file'] = self.log
            print(*args, **kwargs)
            self.log.flush()

L = MyLogger()


class LogP(object):
    def __init__(self):
        self.initialize()

    def initialize(self):
        self.selector = get_device_selector()
        self.lines = []
        self.fail_to = set()
        self.logAll = False
        self.closed = False
        self.no_clean = False
        self.q = Queue()
        self.start_logcat()
        self.start_thread()

    def clean(self):
        self.clean_logcat()
        self.clean_buf()

    def start_thread(self):
        self.t = threading.Thread(target=self._enqueue_output)
        self.t.daemon = True
        self.t.start()

    def start_logcat(self):
        self.p = subprocess.Popen(
            [f"adb {self.selector} logcat "],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=True)

    def restart_logcat(self):
        self.p.kill()
        self.p.wait()
        self.start_logcat()

    def _enqueue_output(self):
        may_conflict = False
        lineset = None
        while not self.closed:
            try:
                line = self.p.stdout.readline()
                line = codecs.decode(line, "utf-8", errors="ignore")
                line = line.strip()
                if not line:
                    err_line = self.p.stderr.readline()
                    err_line = codecs.decode(err_line, "utf-8", errors="ignore")
                    err_line = err_line.strip()
                    if err_line:
                        L.lprint("[!] Logcat error " + err_line)
                        # restart the adb log
                        self.clean_logcat()
                        self.restart_logcat()
                        may_conflict = True
                        lineset = set(self.lines)
                    continue
                # L.lprint(line, flush=True)
                # if not self.logAll and suggest_system_crash(line):
                #     self.logAll = True
                if may_conflict:
                    if line in lineset:
                        continue
                    else:
                        may_conflict = False
                        lineset = None
                if self.logAll or 'Straw' in line or suggest_system_crash(line):
                    self.q.put(line)
                    self.lines.append(line)
            except Exception as e:
                L.lprint(e)

    def wait_for(self, message, timeout=-1):
        self.no_clean = True
        start_time = time.time()
        while timeout <= 0 or time.time() - start_time < timeout:
            line = self.readline()
            if not line:
                continue
            if message in line:
                self.no_clean = False
                return True
        self.no_clean = False
        return False

    def wait_for_all(self, messages, timeout=-1):
        self.no_clean = True
        start_time = time.time()
        occurs = [False for _ in messages]
        while timeout <= 0 or time.time() - start_time < timeout:
            line = self.readline()
            if not line:
                continue
            for i in range(len(messages)):
                if messages[i] in line:
                    occurs[i] = True
            if all(occurs):
                self.no_clean = False
                return True
        self.no_clean = False
        return False

    def wait_for_one(self, messages, timeout=-1):
        self.no_clean = True
        start_time = time.time()
        while timeout <= 0 or time.time() - start_time < timeout:
            line = self.readline()
            if not line:
                continue
            for i in range(len(messages)):
                if messages[i] in line:
                    self.no_clean = False
                    return i
        self.no_clean = False
        return -1

    def readline(self):
        try:
            line = self.q.get_nowait()
            self.handle_fail_to(line)
        except Empty:
            return None
        return line

    def handle_fail_to(self, line):
        if not line: return
        idx = line.find('Straw')
        if idx >= 0:
            if 'Fail to' in line:
                fail_to_msg = line[idx:].strip()
                if fail_to_msg not in self.fail_to:
                    L.lprint(fail_to_msg)
                    self.fail_to.add(fail_to_msg)

    def dumpLogcat(self, path, timeout=-1):
        start_time = time.time()
        while timeout <= 0 or time.time() - start_time < timeout:
            dt = self.get_dt(self.lines)
            if dt and get_dt_secs(dt) > start_time:
                break
            time.sleep(0.5)
        with open(path, 'w+') as f:
            f.write('\n'.join(self.lines))

    def dumpLog(self, path, timeout=-1):
        start_time = time.time()
        prev_size = 0
        fuzzLog = ''
        while timeout <= 0 or time.time() - start_time < timeout:
            dt = self.get_dt(self.lines)
            if dt and get_dt_secs(dt) > start_time:
                break
            time.sleep(0.5)
        for line in self.lines:
            if '!!!END' in line and (CRASH_NEEDLE in line or STOP_NEEDLE in line or PRINT_NEEDLE in line):
                break
            if CRASH_NEEDLE in line:
                fuzzLog += line[line.find(CRASH_NEEDLE) + len(CRASH_NEEDLE): ]
            elif STOP_NEEDLE in line:
                fuzzLog += line[line.find(STOP_NEEDLE) + len(STOP_NEEDLE): ]
            elif PRINT_NEEDLE in line:
                fuzzLog += line[line.find(PRINT_NEEDLE) + len(PRINT_NEEDLE): ]
        # time.sleep(3)
        with open(path, 'w+') as f:
            f.write(fuzzLog)

    @staticmethod
    def get_dt(lines):
        #09-16 14:38:30.640
        for i in range(len(lines)-1, -1, -1):
            line = lines[i]
            time_str = ' '.join(line.split(maxsplit=2)[:2]).split('.')[0]
            time_str = f'{datetime.now().year}-{time_str}'
            try:
                t = datetime.strptime(time_str, "%Y-%m-%d %H:%M:%S")
                return t
            except:
                continue
        return None

    def clean_logcat(self):
        if self.no_clean:
            return
        L.lprint("cleaning logcat")
        while True:
            cleanP = subprocess.Popen([f"adb {self.selector} logcat -c "], shell=True, stderr=subprocess.PIPE)
            cleanP.wait()
            err = codecs.decode(cleanP.communicate()[1], "utf-8", errors="ignore")
            for line in err.split('\n'):
                if 'failed to clear' in line:
                    continue
            break

    def clean_buf(self):
        self.lines.clear()
        self.fail_to.clear()
        for i in range(self.q.qsize()):
            self.q.get_nowait()

    def close(self):
        self.closed = True
        self.t.join()


def get_device_selector():
    config: dict = get_config()
    udid = config.get("udid", "") if config else ""
    selector = f'-s {udid}' if udid else ""
    return selector


def suggest_system_crash(s):
    for system_crash_needle in SYSTEM_CRASH_NEEDLEs:
        if system_crash_needle in s:
            return True
    return False


def sh_str_escape(s):
    return "'" + s.replace("(","\\(").replace(")","\\)").replace("<", "\\<").replace(">", "\\>").replace(" ", "\\ ").replace("$", "\\$").replace("*", "\\*") + "'"


def broadcast(action, kvs):
    count = 0
    while count < 3:
        es_lst = []
        for k, v in kvs.items():
            if isinstance(v, str):
                es_lst.append("--es")
                es_lst.append(k)
                es_lst.append(sh_str_escape(v))
            elif isinstance(v, bool):
                es_lst.append("--ez")
                es_lst.append(k)
                es_lst.append('true' if v else 'false')
            elif isinstance(v, int):
                es_lst.append("--ei")
                es_lst.append(k)
                es_lst.append(str(v))
        selector = get_device_selector()
        cmd = ' '.join(
            [f"adb {selector} shell am broadcast -a", sh_str_escape(action)] + es_lst
        )
        # L.lprint(cmd)
        try:
            res = subprocess.check_output([cmd], shell=True)
        except Exception:
            break
        if b'Broadcasting' in res:
            break
        else:
            time.sleep(0.5)
        count += 1


def get_dt_secs(dt):
    return (dt - datetime(1970, 1, 1)).total_seconds()


def get_curr_package():
    # Run #0: ActivityRecord{38d89a0 u0 com.android.quicksearchbox/.SearchActivity t216}
    selector = get_device_selector()
    cmd = f'adb {selector} shell dumpsys activity activities|grep -E ' + '"Run #|Hist #"'
    lines = codecs.decode(execute_wait(cmd)[0], 'utf-8', errors='ignore').split('\n')
    # lines = os.popen(cmd).readlines()
    if lines:
        for item in lines[0].strip().split():
            if '/' in item:
                packageName = item.split('/')[0]
                return packageName
    return ""


def start_app(logp=None, hookless=False, pkg=PACKAGE_NAME):
    selector = get_device_selector()
    while get_curr_package() == pkg:
        if hookless: break
        execute_wait(f'adb {selector} shell am force-stop {pkg}')
        time.sleep(1.0)
    while get_curr_package() != pkg:
        execute_wait(f"adb {selector} shell am start -n {pkg}/.MainActivity")
        time.sleep(2.0)
    if not hookless and logp:
        logp.wait_for("HookService Client connected", timeout=5.0)


def reboot(udid=""):
    broadcast("com.straw.strawfuzzer.Hook.XposedHook$RebootReceiver", {}, udid=udid)


def soft_reboot():
    selector = get_device_selector()
    execute_wait(f'adb {selector} shell su -c "killall zygote"')


def set_services(services):
    if isinstance(services, list):
        services = ','.join(services)
    kvs = {
        "services": services
    }
    broadcast("com.straw.strawfuzzer.UserCMDReceiver.SET_SERVICE", kvs)


def ensure_set_services(services, logp):
    while True:
        start_app(logp, True)
        set_services(services)
        if logp.wait_for("Set services to", timeout=5.0):
            break
        logp.restart_logcat()
    L.lprint("[+] Set services to " + services)


def get_services():
    selector = get_device_selector()
    xml_str = subprocess.check_output(f'adb {selector} shell su -c "cat /data/data/com.straw.strawfuzzer/shared_prefs/com.straw.strawfuzzer_preferences.xml"', shell=True)
    tree = ET.fromstring(xml_str)
    for ch in tree:
        if ch.tag == 'string' and ch.get('name') == 'services':
            return ch.text.split(',')
    return []


def fuzz(entrySignature, riskySignature, config):
    kvs = {
        "entrySignature": entrySignature,
        "riskySignature": riskySignature,
        "timeout": config['timeout'],
        "exploreTime": config['exploreTime'],
        "generate": config['generate'],
        "hookless": config['hookless']
    }

    broadcast('com.straw.strawfuzzer.UserCMDReceiver.START_FUZZING', kvs)


def ensure_fuzz(entrySignature, riskySignature, logp, config):
    status = True
    blocking_count = 0
    while True:
        logp.clean_logcat()
        if get_curr_package() != "com.straw.strawfuzzer":
            L.lprint("[.] Restarting app")
            start_app(logp, config['hookless'])
        fuzz(entrySignature, riskySignature, config)

        blocking_count += 1
        if blocking_count >= 7:
            L.lprint("[!] Fail to start fuzz")
            status = False
            break

        idx = logp.wait_for_one(['Start to fuzz on', 'Fail to fuzz on', 'HookService not ready'], timeout=10)
        if idx == 0:
            L.lprint("[+] Fuzzing started")
            break
        elif idx == 1:\
            L.lprint("[-] The signature can't be parsed")
        elif idx == 2:
            L.lprint("[-] HookService not ready")
            continue
        elif idx < 0:
            continue
    blocking_count = 0
    while status:
        L.lprint("[.] Waiting for fuzzing loop")
        blocking_count += 1
        if blocking_count >= 3:
            status = False
            L.lprint("[-] Fail to enter fuzzing loop")
            break
        if logp.wait_for('Fuzzing loop start', timeout=60):
            L.lprint("[+] Fuzzing loop started")
            break
    return status


def set_disable_hook(disable_hook):
    kvs = {"disable_hook": disable_hook}
    broadcast("com.straw.strawfuzzer.UserCMDReceiver.SET_DISABLE_HOOK", kvs)


def ensure_set_disable_hook(disable_hook, logp):
    while True:
        start_app(logp, True)
        set_disable_hook(disable_hook)
        if logp.wait_for("Set disable_hook to", timeout=5.0):
            break
    L.lprint(f"[+] Set disable_hook to {disable_hook}")


def set_disable_crash_hook(disable_crash_hook):
    kvs = {"disable_crash_hook": disable_crash_hook}
    broadcast("com.straw.strawfuzzer.UserCMDReceiver.SET_DISABLE_CRASH_HOOK", kvs)


def ensure_set_disable_crash_hook(disable_crash_hook, logp):
    while True:
        start_app(logp, True)
        set_disable_crash_hook(disable_crash_hook)
        if logp.wait_for("Set disable_hook to", timeout=5.0):
            break
    L.lprint(f"[+] Set disable_crash_hook to {disable_crash_hook}")


def stop():
    broadcast('com.straw.strawfuzzer.UserCMDReceiver.STOP_FUZZING', {})


def crash():
    broadcast('com.straw.strawfuzzer.Fuzz.Fuzzer$CrashStartReceiver', {})


def doprint():
    broadcast('com.straw.strawfuzzer.Fuzz.Fuzzer$DataPrintReceiver', {})


def prepare_fuzzing(logp=None, hookless=False):
    if hookless:
        return
    with open(os.path.join(SCRIPT_PATH, "prepare_fuzzing.sh"), 'r') as f:
        script = f.read()
    script = script.replace("adb ", f"adb {get_device_selector()} ")
    while True:
        # cmd = os.path.join(SCRIPT_PATH, "prepare_fuzzing.sh")
        execute_wait(script)
        # subprocess.check_output(cmd)
        # p = subprocess.Popen([cmd], shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        # p.wait()
        # if not logp or logp.wait_for("Registered CrashHandledReceiver", timeout=60.0):
        #     break
        if logp:
            logp.clean()
        break


def load_summary(path=SUMMARY_PATH):
    get_config()
    summary = {}
    try:
        with open(path) as f:
            summary = json.load(f)
    except IOError:
        pass
    for v in summary.values():
        scores = v['consumptionScores']
        for i, score in enumerate(scores):
            if score is None:
                scores[i] = 0
            elif type(score) == str:
                scores[i] = float(score)
    return summary


def execute_wait(cmd, timeout=60):
    p = subprocess.Popen([cmd], shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
    try:
        p.wait(timeout=timeout)
    except:
        return None
    return p.communicate(timeout=timeout)


def prepare_static_info(static_info_path):
    selector = get_device_selector()
    execute_wait(f'adb {selector} push {static_info_path} /sdcard')
    static_info_file_name = os.path.basename(static_info_path)
    execute_wait(f'adb {selector} shell su -c "mv /sdcard/{static_info_file_name} /sdcard/static_info.json"')
    execute_wait(f'adb {selector} shell su -c "mv /sdcard/static_info.json /data/data/com.straw.strawfuzzer/static_info.json"')
    execute_wait(f'adb {selector} shell su -c "chmod a+r /data/data/com.straw.strawfuzzer/static_info.json"')


def get_config(path=CONFIG_PATH):
    global CONFIG
    if CONFIG: return CONFIG
    return load_config(path=path)


def load_config(path=CONFIG_PATH):
    global CONFIG, SUMMARY_PATH
    with open(path, 'r') as config_file:
        config = json.load(config_file)
    config['skip_exist'] = config.get('skip_exist', False)
    config['skip_vuln'] = config.get('skip_vuln', False)
    config['skip_to'] = (lambda e: (e[0], e[1]) if e else None)(config.get('skip_to'))
    config['skip_some'] = set(map(lambda e: (e[0], e[1]), config.get('skip_some', [])))
    config['only_some'] = set(map(lambda e: (e[0], e[1]), config.get('only_some', [])))

    summary_path = config.get('summary')
    if summary_path:
        SUMMARY_PATH = summary_path

    only_some = config.get('only_some')

    # Only test different serivices of different os version
    difference_infos = config.get('difference_infos')
    if difference_infos:
        run_pairs = load_difference(difference_infos[0])
        only_some.update(run_pairs)

    only_interesting = config.get('only_interesting', False)
    if only_interesting:
        config['skip_exist'] = False
        config['skip_to'] = None
        interesting = load_interesting(load_summary(), config['timeout'])
        config['only_some'] = interesting
        L.lprint("[+] There are {} interesting pairs".format(len(interesting)))
        if not interesting:
            return
    config['hookless'] = config.get('hookless', False)
    config['generate'] = config.get('generate', False)
    config['exploreTime'] = config.get('exploreTime', -1)

    CONFIG = config
    return config


def load_all_static_info(static_info_paths=None):
    if not static_info_paths:
        static_info_paths = load_config()['static_infos']
    static_info_paths = get_static_info_paths(static_info_paths)
    all_static_info = []
    for static_info_path in static_info_paths:
        static_info = load_static_info(static_info_path)
        all_static_info.extend(static_info)
    return all_static_info

def load_static_info(static_info_path):
    try:
        with open(static_info_path, 'r') as f:
            static_info = json.load(f)
        return static_info
    except IOError:
        return {}
    except json.JSONDecodeError as e:
        L.lprint(f"[!] Fail to load static_info {static_info_path} " + ' '.join(e.args))
        exit(0)


def load_real_vuln():
    try:
        with open(VULN_PATH, 'r') as f:
            return yaml.load(f)
    except IOError:
        return {}


def load_service_info():
    with open(SERVICE_INFO_PATH, 'r') as f:
        service_info_raw = json.load(f)
    service_info = {}
    for service_info_raw_one in service_info_raw:
        service_info[service_info_raw_one[0]] = service_info_raw_one
        service_info[service_info_raw_one[1]] = service_info_raw_one
        service_info[service_info_raw_one[2]] = service_info_raw_one
    return service_info


def get_service_name(method, service_info):
    className = method['Class']
    if className.endswith("$Proxy"):
        className = className.replace("$Proxy", "")
    if className in service_info:
        serviceName = service_info[className][0]
    else:
        serviceName = ""
    return serviceName


def get_service_method_map(static_info, service_info):
    service_method_map = {}
    for entry_method in static_info:
        entryMethod = parse_signature(entry_method['signature'])
        serviceName = get_service_name(entry_method, service_info)
        if serviceName:
            if serviceName not in service_method_map:
                service_method_map[serviceName] = []
            service_method_map[serviceName].append(entry_method)
        else:
            L.lprint("[!] Fail to find corresponding service for " + entryMethod['Class'] + ": " + entryMethod['Method'], flush=True)
            continue

    return service_method_map


def monitor_fuzz(logp, timeout):
    start_time = time.time()
    crashed = False
    prev_spent = 0
    prev_spent_for_app_crashed = 0
    app_crashed = False
    waiting_for_block = 0
    going_to_crash = False
    while True:
        spent = time.time() - start_time
        if spent >= timeout:
            break
        if spent - prev_spent > 0.5:
            prev_spent = spent
            L.lprint('\r({:.2f}/{}) '.format(spent, timeout), end='', file=sys.stdout)
        if spent - prev_spent_for_app_crashed > 3.0:
            prev_spent_for_app_crashed = spent
            if app_crashed:
                break
            if get_curr_package() != PACKAGE_NAME:
                # The app crashed
                if going_to_crash:
                    crashed = True
                app_crashed = True

        line = logp.readline()
        if not line:
            time.sleep(0.3)
            continue
        if 'JNI ERROR (app bug)' in line:
            crashed = True
            crash()
        elif 'Waiting for a blocking GC Alloc' in line:
            waiting_for_block += 1
        elif CRASH_NEEDLE in line:
            crashed = True
            break
        elif '----------------Before' in line:
            crashed = True
            crash()
        # currently disable this optimization
        # else:
        #     if waiting_for_block > 5:
        #         going_to_crash = True
        #         doprint()
        #     else:
        #         waiting_for_block = 0

    if not crashed and not app_crashed:
        stop()
    sys.stdout.write('\n')
    sys.stdout.flush()
    if not app_crashed:
        idx = logp.wait_for_one([PRINT_NEEDLE, STOP_NEEDLE, CRASH_NEEDLE], timeout=timeout/10)
    L.lprint("[+] End, crashed: {}, app_crashed: {} ... Dumping logs".format(crashed, app_crashed), flush=True)
    # Add to VULNS

    return crashed, app_crashed


def dump_check(logp, target_type, entrySignature, riskySignature, summary, meminfo_before, meminfo_after):
    entryMethod = parse_signature(entrySignature)
    riskyMethod = parse_signature(riskySignature)
    def getMethodStr(method):
        return method['Class'].replace('$', '.') + '.' + method['Method'].replace('$', '.') if method else 'unknown'
    basename = target_type + "-" + getMethodStr(entryMethod) + '-' + getMethodStr(riskyMethod)
    fuzzLogDir = os.path.join(SCRIPT_PATH, "../data/fuzzLog") 
    if not os.path.exists(fuzzLogDir):
        os.mkdir(fuzzLogDir)
    fuzzLogcatPath = os.path.join(fuzzLogDir, basename + ".logcat")
    fuzzLogPath = os.path.join(fuzzLogDir, basename + ".log")
    fuzzLogDevicePath = os.path.join("/sdcard/fuzzLog", basename + ".log")

    logp.dumpLog(fuzzLogPath, timeout=10.0)
    logp.dumpLogcat(fuzzLogcatPath, timeout=5.0)

    time.sleep(1)
    if not os.path.exists(fuzzLogcatPath):
        L.lprint("[!] logcat not saved " + fuzzLogcatPath, flush=True)
    else:
        with open(fuzzLogcatPath, 'r') as f:
            if not f.read().strip():
                L.lprint("[!] logcat is empty " + fuzzLogcatPath, flush=True)
    if not os.path.exists(fuzzLogPath):
        L.lprint("[!] log not saved " + fuzzLogPath, flush=True)
    else:
        with open(fuzzLogPath, 'r') as f:
            s = f.read().strip()
            if not s:
                L.lprint("[!] log is empty " + fuzzLogPath, flush=True)
                return False
            else:
                try:
                    fuzzData = json.loads(s)
                    fuzzData['entry'] = entrySignature
                    fuzzData['risky'] = riskySignature
                    if meminfo_before and meminfo_after:
                        fuzzData['meminfo_before'] = meminfo_before.to_dict()
                        fuzzData['meminfo_after'] = meminfo_after.to_dict()
                    pair = (entrySignature, riskySignature)
                    entry_name = get_entry_name(target_type, pair)
                    summary[entry_name] = fuzzData
                except:
                    L.lprint("[!] log is invalid " + fuzzLogPath, flush=True)
                with open(SUMMARY_PATH, 'w+') as sf:
                    json.dump(summary, sf)
    return True


def initialize_service(service, logp, first_reboot, hookless):
    # initialize service
    logp.clean()

    # force reboot at the first time
    if not first_reboot or service not in get_services():
        ensure_set_services(service, logp)
        ensure_set_disable_hook(hookless, logp)
        prepare_fuzzing(logp, hookless)
        start_app(logp, hookless)
        # Reduce reboot overhead
    else:
        L.lprint("[+] Detected service " + service)
    L.lprint("[+] Start fuzzing service " + service)


def run_one(config, count, entrySignature, riskySignature, logp, summary):

    logp.clean()

    L.lprint("[{}] Fuzz on {} -- {} ... ".format(count, entrySignature, riskySignature), flush=True)

    # loop to confirm the fuzzing started
    status = ensure_fuzz(entrySignature, riskySignature, logp, config)
    meminfo_before = MemInfo.get_meminfo()
    if not status:
        return RUN_SKIP

    # Monitor fuzzing
    crashed, app_crashed = monitor_fuzz(logp, config['timeout'])
    meminfo_after = MemInfo.get_meminfo()

    dump_success = dump_check(logp, config['type'], entrySignature, riskySignature, summary, meminfo_before, meminfo_after)
    if dump_success:
        if crashed:
            VULNS.add(riskySignature)
            CRASHED.add((entrySignature, riskySignature))
            return RUN_SUCCESS_CRASH
        return RUN_SUCCESS
    elif app_crashed:
        return RUN_FAIL_APP_CRASH
    else:
        return RUN_FAIL


def parse_signatures(signatures):
    regex = "\\<(?P<Class>[\\w\\.\\$]+)\\s*:\\s*(?P<Ret>[\\w\\.\\$\\[\\]]+)\\s*(?P<Method>[\\w\\$\\<\\>]+)\\s*\\((?P<Params>[\\w\\.\\$,\\s\\[\\]]*)\\)\\s*\\>"
    res = []
    sigs = []
    for m in re.finditer(regex, signatures.strip()):
        if not m:
            return None
        e = {}
        e['Class'] = m.group('Class')
        e['Ret'] = m.group('Ret')
        e['Method'] = m.group('Method')
        e['Params'] = m.group('Params')
        res.append(e)
        sigs.append(m.group())
    return sigs, res


def parse_signature(signature):
    _, res = parse_signatures(signature)
    if res:
        return res[0]
    return None


warned_is_potential = False
def is_potential(v, use_lingress=True):
    global warned_is_potential
    avgScore = get_avg_score(v)
    consumptionScores = v['consumptionScores']
    result_potential = False
    var_score = get_var_score(v)
    result_potential = var_score > 40
    rootset_potential = 'changeSize' in v and v['sizeChange'] > 50

    score_potential = False
    lingress_not_supported = False
    if len(consumptionScores) > 2:
        if use_lingress:
            try:
                score_potential = get_consumption_slope(v) > 0.1
            except Exception as e:
                lingress_not_supported = True
                if not warned_is_potential:
                    print("[!] Warning: scipy not installed, use simple check")
                    warned_is_potential = True
        if not use_lingress or lingress_not_supported:
            score_potential = avgScore > 0.1 and len(consumptionScores) >= 10
    return score_potential or rootset_potential or result_potential


def get_consumption_slope(v):
    import scipy
    import scipy.stats as st
    # get relative memory usage
    consumptionScores = v['consumptionScores']
    y = [0]
    for score in consumptionScores:
        y.append(y[-1] + score)

    # remove outliers
    # new_y = [0]
    # ref = 0
    # for i in range(1, len(y)):
    #     if abs(y[i] - ref) > 100:
    #         continue
    #     else:
    #         new_y.append(y[i])
    #         ref = y[i]
    # y = new_y
    # if len(y) < 2:
    #     return 0

    x = scipy.arange(len(y))
    slope, intercept, r_value, p_value, std_err = st.linregress(x, y)
    return slope


def get_var_score(v):
    if 'meminfo_before' not in v or 'meminfo_after' not in v:
        return 0.0
    ma = v['meminfo_after']
    mb = v['meminfo_before']
    score = (ma['pss'] - mb['pss']) / 512 + (ma['refs'] - mb['refs']) / 100
    return score


def get_avg_score(v):
    consumptionScores = v['consumptionScores']
    if not consumptionScores:
        return 0
    sumScore = get_sum_score(v)
    avgScore = sumScore / len(consumptionScores)
    return avgScore


def get_sum_score(v):
    consumptionScores = v['consumptionScores']
    sumScore = 0
    for consumptionScore in consumptionScores:
        sumScore += consumptionScore if consumptionScore else 0
    return sumScore


VULNS = set()
def load_vulns(summary, force=False):
    if not force and VULNS:
        return VULNS
    for k, v in summary.items():
        if v['crashed']:
            if v['exploitationCount'] < sum(v['consumptionScores']) / 10:
                continue
            else:
                risky = v['risky']
                VULNS.add(risky)
    return VULNS

CRASHED = set()
def load_crashed(summary, force=False):
    if not force and CRASHED:
        return CRASHED
    for k, v in summary.items():
        if v['crashed']:
            pair = (v['entry'], v['risky'])
            CRASHED.add(pair)
    return CRASHED


def load_interesting(summary, timeout):
    interesting = set()
    for k, v in summary.items():
        crashed = v['crashed']
        if not crashed and is_potential(v):
            # if v['duration'] < timeout * 5 * 1000:
                interesting.add((v['entry'], v['risky']))
    return interesting


def get_entry_name(prefix, pair):
    return "{}-{}-{}".format(prefix, pair[0], pair[1])


skip_to_already = False
def should_skip(config, pair, summary, visited):
    global skip_to_already
    skip_to = config['skip_to']
    skip_some = config['skip_some']
    only_some = config['only_some']
    skip_exist = config['skip_exist']
    skip_vuln = config['skip_vuln']

    wild_entry_pair = ('*', pair[1])
    wild_risky_pair = (pair[0], '*')
    if pair in visited:
        return SKIP_DUP
    if not skip_to_already:
        if skip_to and pair != skip_to and wild_entry_pair != skip_to and wild_risky_pair != skip_to:
            return SKIP_TO
        else:
            skip_to_already = True
    if skip_some and ((pair in skip_some) or (wild_entry_pair in skip_some) or (wild_risky_pair in skip_some)):
        return SKIP_SOME
    if only_some and ((pair not in only_some) and (wild_entry_pair not in only_some) and (wild_risky_pair not in only_some)):
        return SKIP_ONLY
    if skip_exist:
        entry_name = get_entry_name(config['type'], (pair[0], pair[1]))
        if entry_name in summary:
            return SKIP_EXIST
    if skip_vuln and pair[1] in load_vulns(summary):
        return SKIP_VULN
    return SKIP_NO


def run_pair(config, entrySignature, riskySignature, logp, count, summary):
    MAX_FAIL_COUNT = 3
    fail_count = 0
    runStat = RUN_INIT
    while runStat == RUN_INIT or runStat == RUN_FAIL:
        try:
            if fail_count >= MAX_FAIL_COUNT:
                print("[-] Fail and drop")
                break
            runStat = run_one(config, count, entrySignature, riskySignature, logp, summary)
            if runStat == RUN_FAIL or runStat == RUN_FAIL_APP_CRASH:
                if runStat == RUN_FAIL_APP_CRASH:
                    soft_reboot()
                start_app(logp, config['hookless'])
                fail_count += 1
                continue
        except KeyboardInterrupt:
            exc_type, exc_value, exc_traceback = sys.exc_info()
            traceback.print_exception(exc_type, exc_value, exc_traceback)
            sys.exit()
        except Exception as e:
            print("[-] during fuzzing " + str(e))
            fail_count += 1
            continue
        break
    return runStat


def get_static_info_paths(raw_static_info_paths):
    static_info_paths = []
    for static_info_path in raw_static_info_paths:
        try:
            if static_info_path.endswith('*'):
                static_info_path = static_info_path.replace('*', '')
                for filename in os.listdir(static_info_path):
                    if filename.endswith('.json'):
                        static_info_paths.append(os.path.join(static_info_path, filename))
            else:
                static_info_paths.append(static_info_path)
        except: pass
    static_info_paths = list(map(os.path.realpath, static_info_paths))
    static_info_paths.sort()
    return static_info_paths


def get_pair_risky_set(static_info_path):
    pair_set = set()
    risky_set = set()
    static_info = load_static_info(static_info_path)
    for entry in static_info:
        if 'riskyMethods' not in entry:
            pair_set.add((entry['signature'], entry['signature']))
            risky_set.add(entry['signature'])
            continue
        for risky in entry['riskyMethods']:
            pair = (entry['signature'], risky['signature'])
            pair_set.add(pair)
            risky_set.add(risky['signature'])
    return pair_set, risky_set


def print_static_info_summary(static_info_path, visited):
    pair_set, risky_set = get_pair_risky_set(static_info_path)
    pair_set = pair_set - visited
    print("[+] There are {} new pairs and {} risky methods in {}".format(len(pair_set), len(risky_set), static_info_path))


def print_static_infos_summary(static_info_paths, service_info):
    pair_set = set()
    risky_set = set()
    for static_info_path in static_info_paths:
        sub_pair_set, sub_risky_set = get_pair_risky_set(static_info_path)
        pair_set.update(sub_pair_set)
        risky_set.update(sub_risky_set)
    print("[+] There are {} pairs and {} risky methods in total".format(len(pair_set), len(risky_set)))


def auto_run(config):
    service_info = load_service_info()

    summary = load_summary()
    count = 0
    logp = LogP()

    static_info_paths = get_static_info_paths(config['static_infos'])
    print_static_infos_summary(static_info_paths, service_info)

    visited = set()
    for static_info_path in static_info_paths:
        static_info_parepared = False
        first_reboot = False
        static_info = load_static_info(static_info_path)
        service_method_map = get_service_method_map(static_info, service_info)

        print_static_info_summary(static_info_path, visited)

        for service, entry_method_entries in service_method_map.items():
            service_initialized = False
            # Fuzzing on each interface method
            for entry_method_entry in entry_method_entries:
                entrySignature = entry_method_entry['signature']
                if not entry_method_entry.get('riskyMethods'):
                    riskySignatures = ['*']
                else:
                    riskySignatures = list(map(lambda e: e['signature'], entry_method_entry['riskyMethods']))
                for riskySignature in riskySignatures:
                    # check skip
                    pair = (entrySignature, riskySignature)
                    if not should_skip(config, pair, summary, visited):
                        if not static_info_parepared:
                            prepare_static_info(static_info_path)
                            static_info_parepared = True
                        if not service_initialized and not config['hookless']:
                            initialize_service(service, logp, first_reboot, False)
                            first_reboot = True
                            service_initialized = True
                        runStatus = run_pair(config, entrySignature, riskySignature, logp, count, summary)
                        # Force reboot because the crash may no be really triggered
                        if runStatus == RUN_SUCCESS_CRASH:
                            service_initialized = False
                    count += 1
                    visited.add(pair)


def load_difference(difference_info_file):
    new_pairs = set()
    with open(difference_info_file, 'r') as diff_info_file:
        diff_info = json.load(diff_info_file)
        all_diff_pairs = diff_info["AllNewPairs"]
        for risky_method in all_diff_pairs.keys():
            for interface in all_diff_pairs[risky_method]:
                new_pairs.add((interface,risky_method))
    return new_pairs


def main():
    config = load_config()

    only_interesting = config['only_interesting']
    if only_interesting:
        config['timeout'] *= 10
        interesting = config['only_some']
        if not interesting:
            return
        L.lprint("[+] There are {} interesting pairs".format(len(interesting)))

    auto_run(config)


if __name__ == '__main__':
    main()
