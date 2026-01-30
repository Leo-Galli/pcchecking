import os
import sys
import time
import json
import shutil
import sqlite3
import threading
import subprocess
import collections
import tempfile
import platform
import ctypes
import logging
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

VERSION = "v2.1"
WEBHOOK_URL = "https://discord.com/api/webhooks/1464939014787436741/W_vdUtu_JZTETx0GYz4iyZoOTnMKYyH6RU6oZnGbzz5rEAQOhuKLqyzX6QlRr-oPgsxx"
SCORE_PULITO = 200
SCORE_SOSPETTO = 500
MAX_FILES_SCAN = 50000
MAX_WORKERS = 8
OS_TYPE = platform.system()

logging.basicConfig(
    filename='screenshare_debug.log',
    level=logging.ERROR,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def _bootstrap():
    deps = ["psutil", "requests", "colorama", "readchar"]
    for d in deps:
        try:
            __import__(d)
        except ImportError:
            subprocess.check_call([sys.executable, "-m", "pip", "install", d, "--quiet"])

_bootstrap()

import psutil
import requests
import colorama
import readchar

colorama.init(autoreset=True)

class Style:
    MAIN = colorama.Fore.CYAN
    ACCENT = colorama.Fore.LIGHTBLUE_EX
    CLEAN = colorama.Fore.GREEN
    SUSP = colorama.Fore.YELLOW
    CRIT = colorama.Fore.RED
    GRAY = colorama.Style.DIM + colorama.Fore.WHITE
    BOLD = colorama.Style.BRIGHT
    RESET = colorama.Style.RESET_ALL
    CLEAR = "\033[2J\033[H"
    HIDE = "\033[?25l"
    SHOW = "\033[?25h"

class Engine:
    def __init__(self):
        self.score = 0
        self.findings = []
        self.stats = collections.defaultdict(lambda: {"score": 0, "count": 0, "time": 0.0})
        self.lock = threading.Lock()
        self.keywords = {
            "cheat": ["vape", "drip", "killaura", "aimbot", "reach", "velocity", "wurst", "sigma", "entropy", "destiny", "kurium", "phantom", "cheat", "hack", "bypass", "inject", "clicker", "macro", "esp", "xray", "wallhack", "speedhack", "fly", "triggerbot", "silentaim"],
            "tools": ["processhacker", "process_hacker", "ph.exe", "ph64.exe", "everything.exe", "voidtools", "scylla", "x64dbg", "ollydbg", "ida.exe", "cheatengine", "fiddler", "charles", "wireshark"],
            "system": ["jni", "hook", "driver", "spoofer", "hwid", "self-destruct", "blackout", "ahk", "ring0", "dllinject", "kdmapper"],
            "minecraft": ["altmanager", "launcher_profiles.json", "accounts.json", "authlib", "multimc", "tlauncher"]
        }
        self._flat_keys = {k for v in self.keywords.values() for k in v}

    def add_finding(self, target, module, reason, pts, meta=None):
        with self.lock:
            self.score += pts
            self.stats[module]["score"] += pts
            self.stats[module]["count"] += 1
            self.findings.append({
                "target": target, "module": module, "reason": reason,
                "pts": pts, "ts": datetime.now().isoformat(), "meta": meta
            })

class UI:
    @staticmethod
    def get_width():
        return shutil.get_terminal_size((80, 24)).columns

    @staticmethod
    def center(text, col=""):
        width = UI.get_width()
        clean = text
        for s in [Style.MAIN, Style.ACCENT, Style.CLEAN, Style.SUSP, Style.CRIT, Style.GRAY, Style.BOLD, Style.RESET]:
            clean = clean.replace(s, "")
        pad = max(0, (width - len(clean)) // 2)
        return " " * pad + col + text + Style.RESET

    @staticmethod
    def progress_bar(curr, total, label, score):
        width = UI.get_width()
        percent = (curr / max(total, 1)) * 100
        bar_len = max(10, width // 5)
        filled = int((percent / 100) * bar_len)
        color = Style.CLEAN if score < SCORE_PULITO else Style.SUSP if score < SCORE_SOSPETTO else Style.CRIT
        bar = f"{color}{'█'*filled}{Style.GRAY}{'░'*(bar_len-filled)}{Style.RESET}"
        output = f"{Style.BOLD}{label:<15} {bar} {percent:>5.1f}%"
        sys.stdout.write(f"\r{UI.center(output)}")
        sys.stdout.flush()

class Menu:
    def __init__(self, options):
        self.options = ["Esegui Tutto"] + options
        self.selected = [False] * len(self.options)
        self.cursor = 0

    def draw(self, engine=None):
        sys.stdout.write(Style.CLEAR + Style.HIDE)
        print("\n" + UI.center(f"{Style.MAIN}╔{'═'*50}╗"))
        print(UI.center(f"║{Style.BOLD} ScreenShare {VERSION} - Audit System {Style.RESET}{Style.MAIN}║"))
        print(UI.center(f"╚{'═'*50}╝") + "\n")
        for i, opt in enumerate(self.options):
            pref = f"{Style.ACCENT} > " if i == self.cursor else "   "
            box = f"{Style.CLEAN}[▣]" if self.selected[i] else f"{Style.GRAY}[ ]"
            res = ""
            if engine and opt in engine.stats:
                c = engine.stats[opt]["count"]
                res = f" {Style.CRIT}({c}!)" if c > 0 else f" {Style.CLEAN}(OK)"
            print(UI.center(f"{pref}{box} {opt:<20}{res}"))
        print("\n" + UI.center(f"{Style.GRAY}[↑↓] Naviga  [SPAZIO] Seleziona  [INVIO] Avvia"))

    def run(self):
        while True:
            self.draw()
            k = readchar.readkey()
            if k == readchar.key.UP: self.cursor = (self.cursor - 1) % len(self.options)
            elif k == readchar.key.DOWN: self.cursor = (self.cursor + 1) % len(self.options)
            elif k == ' ':
                if self.cursor == 0:
                    v = not self.selected[0]
                    self.selected = [v] * len(self.options)
                else:
                    self.selected[self.cursor] = not self.selected[self.cursor]
            elif k == readchar.key.ENTER:
                indices = [i-1 for i, v in enumerate(self.selected[1:]) if v]
                return indices if indices else list(range(len(self.options)-1))

class Scanner:
    def __init__(self, engine):
        self.engine = engine
        self._fs_counter = 0

    def processes(self):
        start = time.time()
        procs = list(psutil.process_iter(['name', 'cmdline', 'exe']))
        total = len(procs)
        for i, p in enumerate(procs):
            if i % 10 == 0: UI.progress_bar(i+1, total, "Processi", self.engine.score)
            try:
                pinfo = p.info
                name, cmd, exe = (pinfo['name'] or ""), (pinfo['cmdline'] or []), (pinfo['exe'] or "")
                full_str = f"{name} {' '.join(cmd)} {exe}".lower()
                for kw in self.engine._flat_keys:
                    if kw in full_str: self.engine.add_finding(name, "Processi", f"Keyword: {kw}", 120)
                if exe and not os.path.exists(exe):
                    self.engine.add_finding(name, "Processi", "Hidden/Removed Executable", 150)
            except (psutil.NoSuchProcess, psutil.AccessDenied): continue
        self.engine.stats["Processi"]["time"] = time.time() - start
        print()

    def filesystem(self):
        start = time.time()
        paths = [os.environ.get(x) for x in ['TEMP', 'APPDATA', 'LOCALAPPDATA', 'USERPROFILE']] if OS_TYPE == "Windows" else ['/tmp', os.path.expanduser('~')]
        scan_list = []
        
        for p in [x for x in paths if x and os.path.exists(x)]:
            if len(scan_list) >= MAX_FILES_SCAN: break
            try:
                for root, _, files in os.walk(p):
                    if any(x in root for x in ['.git', 'node_modules', 'Windows\\System32']): continue
                    for f in files:
                        scan_list.append(os.path.join(root, f))
                        if len(scan_list) >= MAX_FILES_SCAN: break
                    if len(scan_list) >= MAX_FILES_SCAN: break
            except Exception as e: logging.error(f"FS Walk: {e}")

        self._fs_counter = 0
        total = len(scan_list)
        
        def _task(f_path):
            try:
                name = os.path.basename(f_path).lower()
                for kw in self.engine._flat_keys:
                    if kw in name: self.engine.add_finding(f_path, "Filesystem", f"Match: {kw}", 90)
            finally:
                with self.engine.lock:
                    self._fs_counter += 1
                    if self._fs_counter % 100 == 0 or self._fs_counter == total:
                        UI.progress_bar(self._fs_counter, total, "Filesystem", self.engine.score)

        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
            list(ex.map(_task, scan_list))
            
        self.engine.stats["Filesystem"]["time"] = time.time() - start
        print()

    def bam(self):
        if OS_TYPE != "Windows": return
        start = time.time()
        
        try:
            import winreg
            r_path = r"SYSTEM\CurrentControlSet\Services\bam\State\UserSettings"
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r_path) as k:
                for i in range(winreg.QueryInfoKey(k)[0]):
                    sid = winreg.EnumKey(k, i)
                    try:
                        with winreg.OpenKey(k, sid) as sk:
                            for j in range(winreg.QueryInfoKey(sk)[1]):
                                name, _, _ = winreg.EnumValue(sk, j)
                                ln = name.lower()
                                for kw in self.engine._flat_keys:
                                    if kw in ln: self.engine.add_finding("BAM_Entry", "BAM", f"Entry: {kw}", 110)
                    except PermissionError: continue
        except Exception as e: logging.error(f"BAM: {e}")
        self.engine.stats["BAM"]["time"] = time.time() - start
        UI.progress_bar(1, 1, "BAM Registry", self.engine.score)
        print()

    def browsers(self):
        start = time.time()
        home = os.path.expanduser("~")
        profiles = []
        if OS_TYPE == "Windows":
            loc = os.environ.get('LOCALAPPDATA', '')
            targets = [
                (os.path.join(loc, "Google/Chrome/User Data"), "Chrome"),
                (os.path.join(loc, "Microsoft/Edge/User Data"), "Edge"),
                (os.path.join(loc, "BraveSoftware/Brave-Browser/User Data"), "Brave")
            ]
        elif OS_TYPE == "Darwin":
            targets = [(os.path.join(home, "Library/Application Support/Google/Chrome"), "Chrome")]
        else:
            targets = [(os.path.join(home, ".config/google-chrome"), "Chrome"), (os.path.join(home, ".mozilla/firefox"), "Firefox")]

        for base, name in targets:
            if not os.path.exists(base): continue
            for root, _, files in os.walk(base):
                if "History" in files or "places.sqlite" in files:
                    profiles.append((os.path.join(root, "History" if "History" in files else "places.sqlite"), name))

        for hp, bn in profiles:
            temp_db = os.path.join(tempfile.gettempdir(), f"ss_{bn}_{os.getpid()}")
            conn = None
            try:
                shutil.copy2(hp, temp_db)
                conn = sqlite3.connect(temp_db)
                cur = conn.cursor()
                table = "urls" if "History" in hp else "moz_places"
                cur.execute(f"SELECT url, title FROM {table}")
                rows = cur.fetchall()
                total_rows = len(rows)
                for idx, (url, title) in enumerate(rows):
                    if idx % 100 == 0: UI.progress_bar(idx+1, total_rows, f"Browser ({bn})", self.engine.score)
                    data = f"{url} {title}".lower()
                    for kw in self.engine._flat_keys:
                        if kw in data: self.engine.add_finding(bn, "Browsers", f"History: {kw}", 75)
                print()
            except Exception as e: logging.error(f"Browser {bn}: {e}")
            finally:
                if conn: conn.close()
                if os.path.exists(temp_db): os.remove(temp_db)
        self.engine.stats["Browsers"]["time"] = time.time() - start

def main():
    is_admin = False
    if OS_TYPE == "Windows":
        is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
        if not is_admin:
            print(f"\n{Style.SUSP}" + UI.center("AVVISO: Esecuzione senza privilegi Admin. Alcune scansioni (BAM) saranno limitate."))
            time.sleep(2)

    eng = Engine()
    m_list = ["Processi", "Filesystem", "Browsers"]
    if OS_TYPE == "Windows": m_list.append("BAM")
    
    sel = Menu(m_list).run()
    sys.stdout.write(Style.CLEAR + Style.HIDE)
    
    scn = Scanner(eng)
    mmap = {"Processi": scn.processes, "Filesystem": scn.filesystem, "BAM": scn.bam, "Browsers": scn.browsers}

    start_t = time.time()
    for i in sel: mmap[m_list[i]]()
    duration = time.time() - start_t

    verdict = "PULITO" if eng.score < SCORE_PULITO else "SOSPETTO" if eng.score < SCORE_SOSPETTO else "CRITICO"
    v_col = Style.CLEAN if verdict == "PULITO" else Style.SUSP if verdict == "SOSPETTO" else Style.CRIT

    report_path = "screenshare_report.json"
    report_data = {
        "meta": {"score": eng.score, "verdict": verdict, "os": OS_TYPE, "duration": duration, "ts": datetime.now().isoformat()},
        "findings": eng.findings
    }
    with open(report_path, "w") as f: json.dump(report_data, f, indent=4)

    # Webhook Discord Robust
    try:
        embed_color = 0x2ecc71 if verdict == "PULITO" else 0xf1c40f if verdict == "SOSPETTO" else 0xe74c3c
        content = "@everyone **ALERT CRITICO RILEVATO**" if verdict == "CRITICO" else "Audit Completato"
        
        embed = {
            "title": f"ScreenShare {VERSION} Audit - {verdict}",
            "color": embed_color,
            "fields": [
                {"name": "Punteggio", "value": f"`{eng.score}`", "inline": True},
                {"name": "OS", "value": f"`{OS_TYPE}`", "inline": True},
                {"name": "Durata", "value": f"`{duration:.2f}s`", "inline": True}
            ],
            "footer": {"text": f"Scansionato il: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"}
        }
        
        # Multipart request: JSON Payload + File
        with open(report_path, "rb") as f:
            requests.post(
                WEBHOOK_URL,
                data={"payload_json": json.dumps({"content": content, "embeds": [embed]})},
                files={"file": (report_path, f)},
                timeout=15
            )
    except Exception as e: logging.error(f"Webhook: {e}")

    sys.stdout.write(Style.SHOW)
    print("\n" + UI.center(f"{Style.BOLD}AUDIT COMPLETATO"))
    print(UI.center(f"Verdetto: {v_col}{verdict}"))
    print(UI.center(f"Tempo: {duration:.2f}s | Punteggio: {eng.score}"))
    input("\n" + UI.center("Premi INVIO per uscire..."))

if __name__ == "__main__":
    main()
