import os
import sys
import subprocess
import platform
import datetime
import time
import winreg
import hashlib
import re
import psutil
import ctypes
import threading
import json
import math
import struct
import binascii
import shutil
import sqlite3
import collections
from concurrent.futures import ThreadPoolExecutor

class ForensicConfig:
    VERSION = "8.0.0-SENTINEL-ULTIMATE"
    REPORT_NAME = f"FORENSIC_VERDICT_{int(time.time())}.json"
    SCAN_ID = hashlib.sha256(str(time.time()).encode()).hexdigest()[:24].upper()
    
    THRESHOLD_BAN = 180
    THRESHOLD_SUSPECT = 65
    
    TARGET_KEYWORDS = [
        "vape", "drip", "entropy", "karma", "phantom", "itami", "raven", "koid", 
        "astolfo", "sigma", "wurst", "liquidbounce", "meteor", "tenacity", "rise",
        "flux", "vmulti", "intercept", "reach", "autoclicker", "velocity", 
        "selfdestruct", "destruct", "cheat", "hack", "injector", "mapped", "manualmap",
        "dllinject", "processhacker", "cheatengine", "x64dbg", "wireshark", "processhollowing",
        "scylla", "dnspy", "hacker", "aimbot", "esp", "clicker", "doubleclick", "macros",
        "razersynapse", "logitechg", "blatant", "ghostclient", "internal", "external", 
        "overlay", "bypass", "anticheat", "cleaner", "slayer", "pixelclicker", "hitbox",
        "knockback", "antikb", "killaura", "fastplace", "scaffold", "fly", "speed",
        "bhop", "noslow", "autoarmor", "inventorywalk", "cheststealer", "fucker",
        "hidhide", "vjoy", "aimassist", "backtrack", "silentaim", "fakefat", "spoofer"
    ]
    
    PATHS_TO_SCAN = [
        os.path.join(os.environ.get('TEMP', 'C:\\Windows\\Temp')),
        os.path.join(os.environ.get('USERPROFILE', 'C:'), 'Downloads'),
        os.path.join(os.environ.get('USERPROFILE', 'C:'), 'Desktop'),
        os.path.join(os.environ.get('APPDATA', 'C:'), '.minecraft'),
        os.path.join(os.environ.get('LOCALAPPDATA', 'C:'), 'Temp'),
        os.path.join(os.environ.get('USERPROFILE', 'C:'), 'AppData', 'Roaming', 'Microsoft', 'Windows', 'Recent'),
        os.path.join(os.environ.get('USERPROFILE', 'C:'), 'AppData', 'Local', 'Microsoft', 'Windows', 'History'),
        "C:\\Windows\\Prefetch", "C:\\Windows\\debug", "C:\\ProgramData", "C:\\Windows\\System32\\drivers"
    ]

    S_INFO, S_LOW, S_MED, S_HIGH, S_CRIT = "INFO", "LOW", "MED", "HIGH", "CRITICAL"

class Utils:
    @staticmethod
    def file_time_to_dt(filetime):
        if not filetime or filetime == 0: return None
        try:
            if filetime > 100000000000000000:
                return datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=filetime // 10)
            return datetime.datetime.fromtimestamp(filetime)
        except: return None

    @staticmethod
    def rot13(s):
        return s.translate(str.maketrans(
            "ABCDEFGHIJKLMabcdefghijklmNOPQRSTUVWXYZnopqrstuvwxyz",
            "NOPQRSTUVWXYZnopqrstuvwxyzABCDEFGHIJKLMabcdefghijklm"))

    @staticmethod
    def get_file_entropy(path):
        try:
            if os.path.getsize(path) > 10 * 1024 * 1024: return 0
            with open(path, 'rb') as f:
                data = f.read()
                if not data: return 0
                occ = collections.Counter(data)
                ent = 0
                for count in occ.values():
                    p_x = count / len(data)
                    ent += - p_x * math.log(p_x, 2)
                return ent
        except: return 0

    @staticmethod
    def get_file_hashes(path):
        sha256_hash = hashlib.sha256()
        try:
            with open(path, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except: return None

class UI:
    R, G, Y, C, M, B, W = '\033[91m', '\033[92m', '\033[93m', '\033[96m', '\033[95m', '\033[1m', '\033[0m'
    
    @staticmethod
    def banner():
        print(f"{UI.C}{UI.B}═"*110)
        print(f" SENTINEL-FORENSIC v{ForensicConfig.VERSION} | HEURISTIC ANALYSIS & DECISION ENGINE")
        print(f" SESSION_ID: {ForensicConfig.SCAN_ID}")
        print("═"*110 + f"{UI.W}")

class TimelineManager:
    def __init__(self):
        self.events = []
        self.entities = collections.defaultdict(list)
        self.total_score = 0
        self.verdict_evidences = []
        self.lock = threading.Lock()

    def add_event(self, source, entity_name, timestamp, description, severity, weight, reliability=1):
        with self.lock:
            event = {
                "source": source, "entity": entity_name, "timestamp": str(timestamp),
                "dt_obj": timestamp if isinstance(timestamp, datetime.datetime) else None,
                "description": description, "severity": severity, "weight": weight, "reliability": reliability
            }
            self.events.append(event)
            self.entities[entity_name.lower()].append(event)
            self.total_score += (weight * reliability)

class FilesystemEngine:
    def __init__(self, timeline):
        self.timeline = timeline

    def scan(self):
        for base in ForensicConfig.PATHS_TO_SCAN:
            if not os.path.exists(base): continue
            for root, _, files in os.walk(base):
                for f in files:
                    fp = os.path.join(root, f)
                    try:
                        st = os.stat(fp)
                        m, c, a = [datetime.datetime.fromtimestamp(x) for x in [st.st_mtime, st.st_ctime, st.st_atime]]
                        
                        if any(k in f.lower() for k in ForensicConfig.TARGET_KEYWORDS):
                            ent = Utils.get_file_entropy(fp)
                            h = Utils.get_file_hashes(fp)
                            sev = ForensicConfig.S_CRIT if ent > 7.75 else ForensicConfig.S_HIGH
                            self.timeline.add_event("FS_STATIC", f, m, f"Keyword match: {f} (Entropy: {ent:.2f}, Hash: {h[:16]}...)", sev, 30, 1.5)
                        
                        if c > m + datetime.timedelta(seconds=5):
                            self.timeline.add_event("ANTI-FORENSIC", f, c, "Inconsistent Timestamp: Timestomping Sign (C > M)", ForensicConfig.S_HIGH, 45, 2)
                        
                        if abs((m-c).total_seconds()) < 0.1 and abs((m-a).total_seconds()) < 0.1:
                             self.timeline.add_event("ANTI-FORENSIC", f, m, "Precision Timestamp Match (M=C=A): Forensic Erasure Tool Sign", ForensicConfig.S_CRIT, 50, 2)
                             
                    except: continue

class RegistryEngine:
    def __init__(self, timeline):
        self.timeline = timeline

    def scan(self):
        
        hives = [
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist", "USERASSIST"),
            (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\bam\UserSettings", "BAM"),
            (winreg.HKEY_CURRENT_USER, r"Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache", "MUICACHE"),
            (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache", "SHIMCACHE"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options", "IFEO")
        ]
        for root, path, label in hives:
            try:
                with winreg.OpenKey(root, path) as key:
                    if "UserAssist" in path:
                        for i in range(winreg.QueryInfoKey(key)[0]):
                            sk_n = winreg.EnumKey(key, i)
                            with winreg.OpenKey(key, f"{sk_n}\\Count") as sk:
                                for j in range(winreg.QueryInfoKey(sk)[1]):
                                    n, d, _ = winreg.EnumValue(sk, j)
                                    dn = Utils.rot13(n)
                                    if any(k in dn.lower() for k in ForensicConfig.TARGET_KEYWORDS):
                                        ts = Utils.file_time_to_dt(struct.unpack("<Q", d[60:68])[0])
                                        self.timeline.add_event("REG_EXEC", dn, ts, f"Execution identified in {label}", ForensicConfig.S_CRIT, 55, 2)
                    else:
                        try:
                            for i in range(winreg.QueryInfoKey(key)[1]):
                                n, v, _ = winreg.EnumValue(key, i)
                                if any(k in str(n).lower() or k in str(v).lower() for k in ForensicConfig.TARGET_KEYWORDS):
                                    self.timeline.add_event("REG_PERSIST", str(n), None, f"Configuration match in {label}", ForensicConfig.S_HIGH, 25, 1.2)
                        except: pass
            except: pass

class MemoryEngine:
    def __init__(self, timeline):
        self.timeline = timeline

    def scan(self):
        
        for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline', 'status', 'username']):
            try:
                p = proc.info
                if p['exe'] and p['name'].lower() not in p['exe'].lower():
                    self.timeline.add_event("PROC_BEHAVIOR", p['name'], None, f"Process Masquerading: Name '{p['name']}' != File '{p['exe']}'", ForensicConfig.S_CRIT, 70, 2)
                
                if p['username'] == 'SYSTEM' and 'Users' in str(p['exe']):
                    self.timeline.add_event("PROC_PRIVILEGE", p['name'], None, "System-level process running from user path", ForensicConfig.S_CRIT, 80, 2)

                if "java" in p['name'].lower():
                    cmd = " ".join(p['cmdline']) if p['cmdline'] else ""
                    if any(x in cmd.lower() for x in ["-javaagent", "-cp", "-Djava.library.path"]):
                        if any(k in cmd.lower() for k in ForensicConfig.TARGET_KEYWORDS):
                            self.timeline.add_event("PROC_JAVA", p['name'], None, f"Injection/Agent identified in JVM: {cmd[:60]}", ForensicConfig.S_CRIT, 90, 2)
                
                try:
                    for m in proc.memory_maps():
                        if any(k in m.path.lower() for k in ForensicConfig.TARGET_KEYWORDS):
                             self.timeline.add_event("PROC_MEM", p['name'], None, f"Unsigned/Cheat module mapped: {m.path}", ForensicConfig.S_CRIT, 100, 2)
                except: pass

            except: continue

class EventLogEngine:
    def __init__(self, timeline):
        self.timeline = timeline

    def scan(self):
        try:
            cmd = 'wevtutil qe Security /q:"*[System[(EventID=1102)]]" /f:text /c:1'
            if "1102" in subprocess.check_output(cmd, shell=True).decode(errors='ignore'):
                self.timeline.add_event("ANTI-FORENSIC", "Security Logs", None, "Critical Audit Log Clearing detected", ForensicConfig.S_CRIT, 120, 2)
            
            cmd_sys = 'wevtutil qe System /q:"*[System[(EventID=7045)]]" /f:text /c:10'
            sys_out = subprocess.check_output(cmd_sys, shell=True).decode(errors='ignore')
            for k in ForensicConfig.TARGET_KEYWORDS:
                if k in sys_out.lower():
                    self.timeline.add_event("SYSTEM_EVENT", "Kernel Service", None, f"Suspicious Service Installation: {k}", ForensicConfig.S_HIGH, 60, 1.5)
        except: pass

class DecisionEngine:
    def __init__(self, timeline):
        self.timeline = timeline

    def evaluate(self):
        for ent, evts in self.timeline.entities.items():
            sources = set(e['source'] for e in evts)
            count = len(sources)
            if count >= 3:
                self.timeline.total_score += 250
                self.timeline.verdict_evidences.append(f"IRREFUTABLE PROOF: {ent.upper()} present in {count} independent sources ({', '.join(sources)})")
            elif count >= 2:
                self.timeline.total_score += 100
                self.timeline.verdict_evidences.append(f"CROSS-CORRELATION: {ent.upper()} detected in {sources}")

        final_score = self.timeline.total_score
        if final_score >= ForensicConfig.THRESHOLD_BAN:
            verdict = "DA BANNARE"
            color = UI.R
        elif final_score >= ForensicConfig.THRESHOLD_SUSPECT:
            verdict = "SOSPETTO"
            color = UI.Y
        else:
            verdict = "CLEAN"
            color = UI.G
            
        return verdict, color, final_score

class CoreOrchestrator:
    def __init__(self):
        self.tm = TimelineManager()

    def run(self):
        UI.banner()
        fs, reg, mem, ev = FilesystemEngine(self.tm), RegistryEngine(self.tm), MemoryEngine(self.tm), EventLogEngine(self.tm)
        
        with ThreadPoolExecutor(max_workers=8) as ex:
            ex.submit(fs.scan); ex.submit(reg.scan); ex.submit(mem.scan); ex.submit(ev.scan)

        de = DecisionEngine(self.tm)
        verdict, color, score = de.evaluate()

        print(f"\n{UI.B}╔" + "═"*50 + "╗")
        print(f"║ {f'FINAL VERDICT: {verdict}':^48} ║")
        print(f"║ {f'TOTAL SCORE: {int(score)}':^48} ║")
        print(f"╚" + "═"*50 + f"╝{UI.W}")
        
        if self.tm.verdict_evidences:
            print(f"\n{UI.M}{UI.B}[!] EVIDENCE SUMMARY:{UI.W}")
            for e in sorted(set(self.tm.verdict_evidences)):
                print(f" {UI.R}»{UI.W} {e}")
        
        report = {
            "metadata": {
                "scan_id": ForensicConfig.SCAN_ID,
                "timestamp": str(datetime.datetime.now()),
                "verdict": verdict,
                "score": score
            },
            "summary": self.tm.verdict_evidences,
            "timeline": self.tm.events
        }
        with open(ForensicConfig.REPORT_NAME, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=4)

if __name__ == "__main__":
    if not ctypes.windll.shell32.IsUserAnAdmin():
        sys.exit(1)
    CoreOrchestrator().run()
