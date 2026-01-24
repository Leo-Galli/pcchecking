import os
import sys
import subprocess
import platform
import datetime
import time
import hashlib
import re
import psutil
import ctypes
import threading
import json
import math
import collections
import shutil
from concurrent.futures import ThreadPoolExecutor

try:
    import winreg
except ImportError:
    winreg = None

class ForensicConfig:
    VERSION = "6.0.0-SCREENSHARE"
    SCAN_ID = hashlib.sha384(str(time.time()).encode()).hexdigest()[:32].upper()
    REPORT_NAME = f"Forensic_Intel_{SCAN_ID}.json"
    DUMP_DIR = f"Forensic_Evidence_{SCAN_ID}"
    T_CONFIRMED = 1300
    T_SUSPICIOUS = 750
    T_INCONCLUSIVE = 450
    ENTROPY_THRESHOLD = 7.75
    KEYWORDS = list(set([
        "vape", "v4pe", "v_ape", "drip", "dr1p", "phantom", "ph4ntom", "itami", "raven", "koid", "astolfo", "sigma", "5igma", "wurst", "liquidbounce", 
        "tenacity", "rise", "flux", "future", "impact", "huzuni", "aristois", "metis", "rusherhack", "salhack", "novoline", "skura", "viamcp", 
        "hypixel", "antikb", "killaura", "esp", "aimbot", "triggerbot", "hitboxes", "ch34t", "1nj3ct0r", "h4ck", "byp455", "loader", "mapper", 
        "manualmap", "dllinject", "stub", "payload", "stealth", "ghost", "shadow", "mirror", "bypass", "kernel", "driver", "sys", "vdm", 
        "capcom", "ghidra", "ida", "binary", "reversing", "hook", "detour", "trampoline", "shellcode", "reflect", "atom", "bomb", "thread", 
        "hijack", "stack", "rop", "gadget", "obf", "xor", "aes", "crypt", "dropper", "stager", "beacon", "cobalt", "strike", "metasploit",
        "amsi", "etw", "pacing", "jitter", "clancy", "murmur", "viking", "exodus", "entropy", "kdmapper", "drvmap", "processhacker", 
        "cheatengine", "x64dbg", "scylla", "dnspy", "hidhide", "vjoy", "jnativehook", "reaper", "autoclicker", "macro", "mousekey",
        "auto_clicker", "fastclick", "trigger_bot", "aim_assist", "silent_aim", "wallhack", "noclip", "fly", "speedhack", "teleport", 
        "packet_editor", "wireshark", "fiddler", "charles", "burp", "proxifier", "hide_process", "stealth_inject", "kernel_cheat", 
        "ring0", "ring3", "driver_manual_map", "service_bypass", "av_killer", "defender_control", "runas_system"
    ]))
    WHITELIST_ENTITIES = ["logitech", "lghub", "corsair", "icue", "razer", "synapse", "wireshark", "fiddler", "npcap", "pcap"]
    WIN_PATHS = [
        os.path.join(os.environ.get('TEMP', 'C:\\Windows\\Temp')),
        os.path.join(os.environ.get('USERPROFILE', 'C:'), 'Downloads'),
        os.path.join(os.environ.get('LOCALAPPDATA', 'C:'), 'Temp'),
        "C:\\Windows\\Prefetch", "C:\\Windows\\debug", "C:\\ProgramData", "C:\\Users\\Public"
    ]
    LNX_PATHS = ["/tmp", "/var/tmp", "/dev/shm", "/opt", "/usr/local/bin"]

class AnalysisEngine:
    @staticmethod
    def get_entropy(data):
        if not data: return 0
        counts = collections.Counter(data)
        entropy = 0
        l = len(data)
        for count in counts.values():
            p_x = count / l
            entropy -= p_x * math.log(p_x, 2)
        return entropy

    @staticmethod
    def calculate_hash(filepath):
        sha256_hash = hashlib.sha256()
        try:
            if os.path.getsize(filepath) > 50 * 1024 * 1024: return None
            with open(filepath, "rb") as f:
                for byte_block in iter(lambda: f.read(65536), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except: return None

    @staticmethod
    def normalize(s):
        s = s.lower()
        m = {'4':'a','3':'e','1':'i','0':'o','7':'t','5':'s','8':'b','_':'','-':'',' ':'','!':'i','@':'a'}
        return "".join(m.get(c, c) for c in s)

    @staticmethod
    def levenshtein(s1, s2):
        if len(s1) < 4: return 99
        if len(s1) < len(s2): return AnalysisEngine.levenshtein(s2, s1)
        if len(s2) == 0: return len(s1)
        prev_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            curr_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = prev_row[j + 1] + 1
                deletions = curr_row[j] + 1
                substitutions = prev_row[j] + (c1 != c2)
                curr_row.append(min(insertions, deletions, substitutions))
            prev_row = curr_row
        return prev_row[-1]

class AdaptiveOrchestrator:
    def __init__(self, ref_time=None):
        self.os_type = platform.system()
        self.is_admin = self._check_privs()
        self.timeline = []
        self._lock = threading.Lock()
        self._seen = set()
        self.ref_time = ref_time if ref_time else time.time()
        self.rename_chains = {}
        self.score = 0
        self.mitigations = []
        self.correlations = []
        self.intel = collections.defaultdict(list)
        self.layer_counts = collections.defaultdict(int)
        if not os.path.exists(ForensicConfig.DUMP_DIR):
            try: os.makedirs(ForensicConfig.DUMP_DIR)
            except: pass

    def _check_privs(self):
        try:
            if self.os_type == "Windows": return ctypes.windll.shell32.IsUserAnAdmin() != 0
            return os.getuid() == 0
        except: return False

    def add_event(self, layer, entity, desc, weight, reliability, ts=None, fingerprint=None):
        ent_lower = str(entity).lower()
        if any(w in ent_lower for w in ForensicConfig.WHITELIST_ENTITIES):
            weight *= 0.2
            reliability *= 0.5
        event_key = f"{layer}|{ent_lower}|{desc}"
        with self._lock:
            if event_key in self._seen: return
            self._seen.add(event_key)
            event_ts = ts if ts else time.time()
            decay = math.exp(-abs(event_ts - self.ref_time) / 172800)
            adj_weight = weight * decay
            self.layer_counts[layer] += 1
            self.timeline.append({
                "layer": layer, "entity": str(entity), "description": desc,
                "weight": float(adj_weight), "reliability": float(reliability),
                "timestamp": event_ts, "fingerprint": fingerprint
            })

    def run(self):
        print(f"[*] Avvio {ForensicConfig.VERSION} - ID: {ForensicConfig.SCAN_ID}")
        tasks = []
        with ThreadPoolExecutor(max_workers=16) as executor:
            tasks.append(executor.submit(self._audit_processes))
            tasks.append(executor.submit(self._audit_filesystem))
            if self.os_type == "Windows":
                tasks.append(executor.submit(self._win_registry_audit))
                tasks.append(executor.submit(self._win_journal_audit))
                tasks.append(executor.submit(self._win_antiforensic_check))
                tasks.append(executor.submit(self._win_driver_audit))
        for t in tasks:
            try: t.result()
            except: pass
        report_path = self._finalize()
        self._open_report(report_path)

    def _audit_processes(self):
        
        for proc in psutil.process_iter(['pid', 'name', 'exe', 'ppid', 'create_time']):
            try:
                p = proc.info
                pname = p['name'] or "Unknown"
                pexe = p['exe'] or ""
                h = AnalysisEngine.calculate_hash(pexe) if pexe else None
                fp = hashlib.md5(f"{pname}{h}".encode()).hexdigest() if h else "mem_only"
                if not pexe and p['pid'] > 4:
                    self.add_event("PROCESS", pname, "In-Memory execution", 500, 0.95, fingerprint=fp)
                norm_name = AnalysisEngine.normalize(pname)
                for kw in ForensicConfig.KEYWORDS:
                    if kw in norm_name:
                        self.add_event("PROCESS", pname, f"Keyword match: {kw}", 200, 0.85, fingerprint=fp)
                    elif len(kw) >= 4 and AnalysisEngine.levenshtein(kw, norm_name) <= 1:
                        self.add_event("PROCESS", pname, f"Fuzzy match: {kw}", 150, 0.7, fingerprint=fp)
            except (psutil.NoSuchProcess, psutil.AccessDenied): continue

    def _audit_filesystem(self):
        
        paths = ForensicConfig.WIN_PATHS if self.os_type == "Windows" else ForensicConfig.LNX_PATHS
        for b_path in paths:
            if not os.path.exists(b_path): continue
            for root, _, files in os.walk(b_path):
                for f in files:
                    fpath = os.path.join(root, f)
                    try:
                        st = os.stat(fpath)
                        h = AnalysisEngine.calculate_hash(fpath)
                        if h:
                            if h not in self.rename_chains: self.rename_chains[h] = set()
                            self.rename_chains[h].add(fpath)
                        if st.st_size > 0 and st.st_size < 5 * 1024 * 1024:
                            with open(fpath, 'rb') as fd:
                                data = fd.read(65536)
                                ent = AnalysisEngine.get_entropy(data)
                                if ent > ForensicConfig.ENTROPY_THRESHOLD:
                                    self.add_event("FILESYSTEM", f, f"High Entropy: {ent:.2f}", 300, 0.75, fingerprint=h)
                    except: continue

    def _win_journal_audit(self):
        if self.os_type != "Windows" or not self.is_admin: return
        try:
            raw = subprocess.check_output("fsutil usn readjournal C: csv", shell=True, stderr=subprocess.DEVNULL).decode(errors='ignore')
            for line in raw.splitlines()[-1000:]:
                parts = line.split(',')
                if len(parts) > 3 and any(kw in parts[0].lower() for kw in ForensicConfig.KEYWORDS):
                    self.add_event("JOURNAL", parts[0].strip(), "USN Keyword Match", 250, 0.8)
        except: pass

    def _win_driver_audit(self):
        if self.os_type != "Windows": return
        try:
            raw = subprocess.check_output("driverquery /v /fo csv", shell=True, stderr=subprocess.DEVNULL).decode(errors='ignore')
            for line in raw.splitlines():
                if any(kw in line.lower() for kw in ForensicConfig.KEYWORDS):
                    self.add_event("DRIVER", "Kernel", f"Suspicious Driver: {line[:50]}", 450, 0.9)
        except: pass

    def _win_registry_audit(self):
        if not winreg or self.os_type != "Windows": return
        targets = [
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run")
        ]
        for root, path in targets:
            try:
                with winreg.OpenKey(root, path) as key:
                    for i in range(winreg.QueryInfoKey(key)[1]):
                        n, v, _ = winreg.EnumValue(key, i)
                        if any(kw in str(v).lower() for kw in ForensicConfig.KEYWORDS):
                            self.add_event("REGISTRY", n, "Persistence Match", 200, 0.85)
            except: pass

    def _win_antiforensic_check(self):
        if self.os_type != "Windows": return
        try:
            if os.path.exists("C:\\Windows\\Prefetch") and len(os.listdir("C:\\Windows\\Prefetch")) < 5:
                self.add_event("ANTIFORENSIC", "Prefetch", "Prefetch Wipe Detected", 300, 0.9)
        except: pass

    def _finalize(self):
        fp_map = collections.defaultdict(list)
        for e in self.timeline:
            self.score += e['weight'] * e['reliability']
            if e['fingerprint']: fp_map[e['fingerprint']].append(e)
        for fp, evs in fp_map.items():
            layers = {ev['layer'] for ev in evs}
            if len(layers) >= 2:
                self.score += 300
                self.correlations.append(f"Correlation [{fp}]: {layers}")
        verdict = "CLEAN"
        if self.score >= ForensicConfig.T_CONFIRMED: verdict = "CONFIRMED"
        elif self.score >= ForensicConfig.T_SUSPICIOUS: verdict = "SUSPICIOUS"
        elif self.score >= ForensicConfig.T_INCONCLUSIVE: verdict = "INCONCLUSIVE"
        report = {
            "metadata": {"score": int(self.score), "verdict": verdict, "scan_id": ForensicConfig.SCAN_ID},
            "metrics": dict(self.layer_counts),
            "correlations": self.correlations,
            "timeline": self.timeline
        }
        p = os.path.abspath(ForensicConfig.REPORT_NAME)
        with open(p, "w") as f: json.dump(report, f, indent=4)
        print(f"[!] Report: {p}\n[!] Verdict: {verdict}")
        return p

    def _open_report(self, path):
        try:
            if self.os_type == "Windows": os.startfile(path)
            else: subprocess.call(["xdg-open", path])
        except: pass

if __name__ == "__main__":
    orch = AdaptiveOrchestrator()
    orch.run()
