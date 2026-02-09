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
import re
import gzip
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

# --- CONFIGURAZIONE AVANZATA ---
VERSION = "v3.0 - ELITE TITANIUM"
WEBHOOK_URL = "https://discord.com/api/webhooks/1464939014787436741/W_vdUtu_JZTETx0GYz4iyZoOTnMKYyH6RU6oZnGbzz5rEAQOhuKLqyzX6QlRr-oPgsxx"
SCORE_PULITO = 200
SCORE_SOSPETTO = 500
MAX_FILES_SCAN = 80000  # Aumentato per scansione profonda
MAX_WORKERS = 12        # Ottimizzato per CPU moderne
OS_TYPE = platform.system()

logging.basicConfig(
    filename='screenshare_debug.log',
    level=logging.ERROR,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def _bootstrap():
    """Installa le dipendenze mancanti in modo silenzioso."""
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
    PRI = colorama.Fore.LIGHTCYAN_EX
    SEC = colorama.Fore.WHITE
    DIM = colorama.Style.DIM + colorama.Fore.WHITE
    OK = colorama.Fore.LIGHTGREEN_EX
    WARN = colorama.Fore.LIGHTYELLOW_EX
    ERR = colorama.Fore.LIGHTRED_EX
    BOLD = colorama.Style.BRIGHT
    RESET = colorama.Style.RESET_ALL
    HIDE = "\033[?25l"
    SHOW = "\033[?25h"
    CLEAR = "\033[2J\033[H"

class UI:
    @staticmethod
    def get_width():
        return max(60, shutil.get_terminal_size((80, 24)).columns)

    @staticmethod
    def center(text, color=""):
        width = UI.get_width()
        clean = text
        for s in [Style.PRI, Style.SEC, Style.DIM, Style.OK, Style.WARN, Style.ERR, Style.BOLD, Style.RESET]:
            clean = clean.replace(s, "")
        pad = max(0, (width - len(clean)) // 2)
        return " " * pad + color + text + Style.RESET

    @staticmethod
    def header():
        title_raw = f"                S C R E E N S H A R E  -  {VERSION}                "
        subtitle_raw = "Official Forensic Tool - CoralMC"
        box_width = len(title_raw) + 4
        line = "━" * box_width
        padding_sub = (box_width - len(subtitle_raw)) // 2
        space_left = " " * padding_sub
        space_right = " " * (box_width - len(subtitle_raw) - padding_sub)

        sys.stdout.write(Style.CLEAR + Style.HIDE)
        print("\n" + UI.center(f"┏{line}┓", Style.PRI))
        print(UI.center(f"┃  {Style.BOLD}{title_raw}{Style.RESET}{Style.PRI}  ┃", Style.PRI))
        print(UI.center(f"┃{space_left}{Style.BOLD}{subtitle_raw}{Style.RESET}{Style.PRI}{space_right}┃", Style.PRI))
        print(UI.center(f"┗{line}┛", Style.PRI))
        print(UI.center(f"{Style.DIM}OS: {OS_TYPE} | Arch: {platform.machine()} | Staffer: LeoGalli"))
        print("")

    @staticmethod
    def bar(curr, total, label, score):
        width = UI.get_width()
        bar_w = 30
        percent = (curr / max(total, 1)) * 100
        filled = int((percent / 100) * bar_w)
        c = Style.OK if score < SCORE_PULITO else Style.WARN if score < SCORE_SOSPETTO else Style.ERR
        bar = f"{c}{'━' * filled}{Style.DIM}{'─' * (bar_w - filled)}"
        info = f"{Style.SEC}{label:<20} {bar} {Style.BOLD}{percent:>5.1f}%"
        sys.stdout.write(f"\r{UI.center(info)}")
        sys.stdout.flush()

class ExitMenu:
    def __init__(self):
        self.options = ["Torna al Menu", "Conferma Uscita"]
        self.cursor = 0

    def draw(self):
        UI.header()
        print(UI.center(f"{Style.WARN}{Style.BOLD}ATTENZIONE: L'USCITA VERRÀ LOGGATA COME RIFIUTO SS"))
        print("")
        for i, opt in enumerate(self.options):
            is_cur = i == self.cursor
            ptr = f"  >  " if is_cur else "     "
            label_col = Style.BOLD + Style.PRI if is_cur else Style.SEC
            print(UI.center(f"{ptr}{label_col}{opt:<20}"))
        print("\n" + UI.center(f"{Style.DIM}↑↓ Naviga  •  Invio Conferma"))

    def run(self):
        while True:
            self.draw()
            k = readchar.readkey()
            if k == readchar.key.UP: self.cursor = (self.cursor - 1) % len(self.options)
            elif k == readchar.key.DOWN: self.cursor = (self.cursor + 1) % len(self.options)
            elif k == readchar.key.ENTER: return self.cursor == 1

class Engine:
    def __init__(self):
        self.score = 0
        self.findings = []
        self.stats = collections.defaultdict(lambda: {"score": 0, "count": 0, "time": 0.0})
        self.lock = threading.Lock()
        self.keywords = {
            "cheat": ["vape", "drip", "killaura", "aimbot", "reach", "velocity", "wurst", "sigma", "entropy", "destiny", "kurium", "phantom", "cheat", "hack", "bypass", "inject", "clicker", "macro", "esp", "xray", "wallhack", "speedhack", "fly", "triggerbot", "silentaim", "itami", "akari", "slap", "echo"],
            "tools": ["processhacker", "process_hacker", "ph.exe", "ph64.exe", "everything.exe", "voidtools", "scylla", "x64dbg", "ollydbg", "ida.exe", "cheatengine", "fiddler", "charles", "wireshark", "dnspy", "ilspy"],
            "system": ["jni", "hook", "driver", "spoofer", "hwid", "self-destruct", "blackout", "ahk", "ring0", "dllinject", "kdmapper", "lsass", "cryptsvc"]
        }
        self._flat_keys = {k for v in self.keywords.values() for k in v}

    def reset(self):
        self.score = 0
        self.findings = []
        self.stats.clear()

    def add_finding(self, target, module, reason, pts, meta=None):
        with self.lock:
            self.score += pts
            self.stats[module]["score"] += pts
            self.stats[module]["count"] += 1
            self.findings.append({"target": target, "module": module, "reason": reason, "pts": pts, "ts": datetime.now().isoformat(), "meta": meta})

class Scanner:
    def __init__(self, engine):
        self.engine = engine
        self._fs_c = 0

    def processes(self):
        s_t = time.time()
        p_list = list(psutil.process_iter(['name', 'cmdline', 'exe', 'username']))
        tot = len(p_list)
        for i, p in enumerate(p_list):
            if i % 5 == 0: UI.bar(i+1, tot, "PROCESSI (DEEP)", self.engine.score)
            try:
                inf = p.info
                blob = f"{inf['name']} {inf['cmdline']} {inf['exe']}".lower()
                for kw in self.engine._flat_keys:
                    if kw in blob: self.engine.add_finding(inf['name'], "Processi", f"Flag: {kw}", 125)
                # Verifica processi "nascosti" o senza eseguibile su disco
                if inf['exe'] and not os.path.exists(inf['exe']):
                    self.engine.add_finding(inf['name'], "Processi", "Ghost Process (Memory Only)", 180)
            except: continue
        self.engine.stats["Processi"]["time"] = time.time() - s_t
        print()

    def prefetch(self):
        """Analisi dei file .pf (Prefetch) per trovare tracce di programmi passati."""
        if OS_TYPE != "Windows": return
        s_t = time.time()
        pf_path = r"C:\Windows\Prefetch"
        if not os.path.exists(pf_path): return
        
        try:
            files = os.listdir(pf_path)
            tot = len(files)
            for i, f in enumerate(files):
                if i % 20 == 0: UI.bar(i+1, tot, "PREFETCH ANALYSIS", self.engine.score)
                name = f.lower()
                for kw in self.engine._flat_keys:
                    if kw in name:
                        self.engine.add_finding(f, "Prefetch", f"Traccia storica: {kw}", 110)
        except: pass
        self.engine.stats["Prefetch"] = {"time": time.time() - s_t}
        print()

    def dns_cache(self):
        """Controlla la cache DNS per connessioni a siti di cheat."""
        s_t = time.time()
        try:
            output = subprocess.check_output("ipconfig /displaydns", shell=True).decode('cp850', errors='ignore').lower()
            for kw in self.engine._flat_keys:
                if kw in output:
                    self.engine.add_finding("DNS Cache", "Network", f"Sito sospetto risolto: {kw}", 95)
            UI.bar(1, 1, "DNS CACHE DUMP", self.engine.score)
        except: pass
        self.engine.stats["Network"] = {"time": time.time() - s_t}
        print()

    def filesystem(self):
        s_t = time.time()
        roots = [os.environ.get(x) for x in ['TEMP', 'APPDATA', 'LOCALAPPDATA', 'USERPROFILE', 'DOWNLOADS']] 
        if OS_TYPE != "Windows": roots = ['/tmp', os.path.expanduser('~')]
        
        queue = []
        for r in [x for x in roots if x and os.path.exists(x)]:
            try:
                for root, _, files in os.walk(r):
                    if any(x in root for x in ['.git', 'node_modules', 'Windows\\System32', 'AppData\\Local\\Microsoft']): continue
                    for f in files:
                        queue.append(os.path.join(root, f))
                        if len(queue) >= MAX_FILES_SCAN: break
                    if len(queue) >= MAX_FILES_SCAN: break
            except: continue

        self._fs_c = 0
        tot = len(queue)
        def _task(path):
            try:
                n = os.path.basename(path).lower()
                # Verifica estensioni sospette
                if n.endswith(('.exe', '.dll', '.jar', '.ahk', '.py')):
                    for kw in self.engine._flat_keys:
                        if kw in n: self.engine.add_finding(path, "Filesystem", f"Match: {kw}", 100)
            finally:
                with self.lock:
                    self._fs_c += 1
                    if self._fs_c % 500 == 0 or self._fs_c == tot: 
                        UI.bar(self._fs_c, tot, "FILESYSTEM (TITANIUM)", self.engine.score)
        
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
            list(ex.map(_task, queue))
        self.engine.stats["Filesystem"]["time"] = time.time() - s_t
        print()

    def bam(self):
        if OS_TYPE != "Windows": return
        s_t = time.time()
        try:
            import winreg
            path = r"SYSTEM\CurrentControlSet\Services\bam\State\UserSettings"
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path) as k:
                for i in range(winreg.QueryInfoKey(k)[0]):
                    sid = winreg.EnumKey(k, i)
                    try:
                        with winreg.OpenKey(k, sid) as sk:
                            for j in range(winreg.QueryInfoKey(sk)[1]):
                                name, _, _ = winreg.EnumValue(sk, j)
                                if any(kw in name.lower() for kw in self.engine._flat_keys):
                                    self.engine.add_finding(name, "BAM", "Esecuzione rilevata nel Registro", 130)
                    except: continue
        except: pass
        UI.bar(1, 1, "BAM REGISTRY", self.engine.score)
        self.engine.stats["BAM"]["time"] = time.time() - s_t
        print()

    def browsers(self):
        s_t = time.time()
        home = os.path.expanduser("~")
        profs = []
        if OS_TYPE == "Windows":
            loc = os.environ.get('LOCALAPPDATA', '')
            t = [(os.path.join(loc, "Google/Chrome/User Data"), "Chrome"), 
                 (os.path.join(loc, "Microsoft/Edge/User Data"), "Edge"), 
                 (os.path.join(loc, "BraveSoftware/Brave-Browser/User Data"), "Brave")]
        else:
            t = [(os.path.join(home, ".config/google-chrome"), "Chrome"), (os.path.join(home, ".mozilla/firefox"), "Firefox")]
            
        for b, n in t:
            if not os.path.exists(b): continue
            for root, _, files in os.walk(b):
                if "History" in files or "places.sqlite" in files: 
                    profs.append((os.path.join(root, "History" if "History" in files else "places.sqlite"), n))
        
        for hp, bn in profs:
            tdb = os.path.join(tempfile.gettempdir(), f"ss_{bn}_{os.getpid()}")
            conn = None
            try:
                shutil.copy2(hp, tdb)
                conn = sqlite3.connect(tdb)
                cur = conn.cursor()
                tbl = "urls" if "History" in hp else "moz_places"
                cur.execute(f"SELECT url, title FROM {tbl} ORDER BY last_visit_time DESC LIMIT 5000")
                rows = cur.fetchall()
                for idx, (u, t) in enumerate(rows):
                    if idx % 200 == 0: UI.bar(idx+1, len(rows), f"BROWSER ({bn})", self.engine.score)
                    blob = f"{u} {t}".lower()
                    for kw in self.engine._flat_keys:
                        if kw in blob: self.engine.add_finding(bn, "Browsers", f"History: {kw}", 85)
            except: continue
            finally:
                if conn: conn.close()
                if os.path.exists(tdb): os.remove(tdb)
        self.engine.stats["Browsers"]["time"] = time.time() - s_t
        print()

    def recycle_bin(self):
        """Controlla file sospetti eliminati di recente nel Cestino."""
        if OS_TYPE != "Windows": return
        s_t = time.time()
        try:
            # Scansione profonda delle directory del Cestino di sistema
            out = subprocess.check_output("dir /s /b C:\\$Recycle.Bin", shell=True, stderr=subprocess.DEVNULL).decode('cp850', errors='ignore').lower()
            for kw in self.engine._flat_keys:
                if kw in out:
                    self.engine.add_finding("Recycle Bin", "Filesystem", f"File sospetto eliminato: {kw}", 140)
        except: pass
        UI.bar(1, 1, "RECYCLE BIN", self.engine.score)
        self.engine.stats["RecycleBin"] = {"time": time.time() - s_t}
        print()
        
    def multi_account_minecraft(self):
        s_t = time.time()
        mc_path = os.path.join(os.environ.get("APPDATA", ""), ".minecraft") if OS_TYPE == "Windows" else os.path.expanduser("~/.minecraft")
        found_nicks = set()
        
        json_files = ["launcher_profiles.json", "launcher_accounts.json", "launcher_accounts_microsoft_store.json"]
        for f_name in json_files:
            f_path = os.path.join(mc_path, f_name)
            if os.path.exists(f_path):
                try:
                    with open(f_path, 'r', encoding='utf-8', errors='ignore') as f:
                        data = f.read()
                        names = re.findall(r'"name"\s*:\s*"([^"]+)"| "displayName"\s*:\s*"([^"]+)"', data)
                        for match in names:
                            for name in match:
                                if name and len(name) > 2: found_nicks.add(name)
                except: continue

        log_dir = os.path.join(mc_path, "logs")
        if os.path.exists(log_dir):
            logs = [f for f in os.listdir(log_dir) if f.endswith(('.log', '.gz'))]
            for i, log_f in enumerate(logs):
                if i % 10 == 0: UI.bar(i+1, len(logs), "DEEP LOG SCAN", self.engine.score)
                full_p = os.path.join(log_dir, log_f)
                try:
                    if log_f.endswith(".gz"):
                        with gzip.open(full_p, 'rt', errors='ignore') as f: content = f.read()
                    else:
                        with open(full_p, 'r', errors='ignore') as f: content = f.read()
                    matches = re.findall(r'Setting user: ([a-zA-Z0-9_]{3,16})', content)
                    for n in matches: found_nicks.add(n)
                except: continue

        lunar = os.path.join(os.path.expanduser("~"), ".lunarclient", "settings", "game", "accounts.json")
        if os.path.exists(lunar):
            try:
                with open(lunar, 'r') as f:
                    data = json.load(f)
                    for acc in data.get("accounts", []): found_nicks.add(acc.get("username"))
            except: pass

        if len(found_nicks) > 1:
            self.engine.add_finding("Minecraft Forensic", "MultiAccount", f"Nicks: {', '.join(found_nicks)}", 150)
        
        UI.bar(1, 1, "MC ACCOUNTS", self.engine.score)
        self.engine.stats["MultiAccount"]["time"] = time.time() - s_t
        print()


class Menu:
    def __init__(self, options):
        self.raw_options = options
        self.options = ["Seleziona Tutto"] + options
        self.selected = [False] * len(self.options)
        self.cursor = 0

    def draw(self, error=""):
        UI.header()
        for i, opt in enumerate(self.options):
            is_cur = i == self.cursor
            is_sel = self.selected[i]
            ptr = f"  >  " if is_cur else "     "
            box = f"{Style.PRI}●{Style.RESET}" if is_sel else f"{Style.DIM}○{Style.RESET}"
            label_col = Style.BOLD + Style.PRI if is_cur else Style.SEC
            line = f"{ptr}{box} {label_col}{opt:<25}"
            print(UI.center(line))
        if error: print("\n" + UI.center(error, Style.ERR))
        print("\n" + UI.center(f"{Style.DIM}↑↓ Naviga  •  Spazio Seleziona  •  Invio Avvia  •  ESC Esci"))

    def run(self):
        err_msg = ""
        while True:
            self.draw(err_msg)
            k = readchar.readkey()
            err_msg = ""
            if k == readchar.key.ESC:
                if ExitMenu().run():
                    sys.stdout.write(Style.SHOW + Style.CLEAR)
                    sys.exit(0)
                continue
            if k == readchar.key.UP: self.cursor = (self.cursor - 1) % len(self.options)
            elif k == readchar.key.DOWN: self.cursor = (self.cursor + 1) % len(self.options)
            elif k == ' ':
                if self.cursor == 0:
                    val = not self.selected[0]
                    self.selected = [val] * len(self.options)
                else:
                    self.selected[self.cursor] = not self.selected[self.cursor]
                    self.selected[0] = all(self.selected[1:])
            elif k == readchar.key.ENTER:
                chosen = [self.options[i] for i, v in enumerate(self.selected) if v and i != 0]
                if not chosen:
                    err_msg = "ERRORE: SELEZIONA ALMENO UN MODULO"
                    continue
                return chosen

def main():
    if OS_TYPE == "Windows" and not ctypes.windll.shell32.IsUserAnAdmin():
        UI.header()
        print(UI.center(f"{Style.ERR}{Style.BOLD}RICHIESTI PRIVILEGI DI AMMINISTRATORE"))
        print(UI.center(f"{Style.SEC}Riavvia il terminale come amministratore per una scansione forense completa."))
        time.sleep(4); sys.exit()

    eng = Engine()
    mlist = ["Processi", "Filesystem", "BAM Registry", "Prefetch Analysis", "DNS Cache", "Browser History", "Multi Account Minecraft", "Recycle Bin Scan"]
    menu = Menu(mlist)

    while True:
        eng.reset()
        selected_names = menu.run()
        UI.header()
        scn = Scanner(eng)
        
        mmap = {
            "Processi": scn.processes,
            "Filesystem": scn.filesystem,
            "BAM Registry": scn.bam,
            "Prefetch Analysis": scn.prefetch,
            "DNS Cache": scn.dns_cache,
            "Browser History": scn.browsers,
            "Multi Account Minecraft": scn.multi_account_minecraft,
            "Recycle Bin Scan": scn.recycle_bin  # <--- Aggiungi questa riga
        }
        
        st_t = time.time()
        for name in selected_names:
            if name in mmap: mmap[name]()
        dur = time.time() - st_t

        verdict = "PULITO" if eng.score < SCORE_PULITO else "SOSPETTO" if eng.score < SCORE_SOSPETTO else "CRITICO"
        
        # Estrae i nomi trovati dai findings per il report
        # Cerca in tutti i findings se esiste una traccia di account
        multi_acc_findings = [f['reason'].replace("Nicks: ", "") for f in eng.findings if "MultiAccount" in f['module']]
        acc_list = multi_acc_findings[0] if multi_acc_findings else "Nessun Multi-Account rilevato"
        
        report_data = {
            "meta": {
                "score": eng.score, 
                "verdict": verdict, 
                "os": OS_TYPE, 
                "duration": dur, 
                "staffer": "LeoGalli",
                "accounts_found": acc_list
            }, 
            "findings": eng.findings
        }
        
        with open("screenshare_report.json", "w") as f: 
            json.dump(report_data, f, indent=4)

        try:
            col = 0x2ecc71 if verdict == "PULITO" else 0xf1c40f if verdict == "SOSPETTO" else 0xe74c3c
            emb = {
                "title": f"ScreenShare {VERSION} - {verdict}",
                "color": col,
                "fields": [
                    {"name": "Staffer", "value": "`LeoGalli`", "inline": True},
                    {"name": "Score", "value": f"`{eng.score}`", "inline": True},
                    {"name": "Durata", "value": f"`{dur:.2f}s`", "inline": True},
                    {"name": "Account Rilevati", "value": f"```arm\n{acc_list}```", "inline": False},
                    {"name": "Tracce Totali", "value": f"Trovate `{len(eng.findings)}` anomalie.", "inline": False}
                ],
                "footer": {"text": "CoralMC Security - Titanium Forensic Engine"}
            }
            with open("screenshare_report.json", "rb") as f:
                requests.post(WEBHOOK_URL, data={"payload_json": json.dumps({"content": f"**Audit terminato per l'utente.** Esito: {verdict}", "embeds": [emb]})}, files={"file": ("report.json", f)}, timeout=10)
        except: pass

        UI.header()
        print(UI.center(f"{Style.BOLD}SCANSIONE TERMINATA"))
        print(UI.center(f"Esito Finale: {Style.PRI}{verdict} ({eng.score} pts)"))
        print("\n" + UI.center(f"{Style.SEC}Le informazioni sono state inviate allo staff di CoralMC."))
        print(UI.center(f"{Style.SEC}Ogni tentativo di manomissione è stato registrato."))
        print(UI.center(f"Tempo impiegato: {Style.PRI}{dur:.2f}s"))
        print("\n" + UI.center(f"{Style.OK}Grazie per la collaborazione. Buona permanenza su CoralMC."))
        sys.stdout.write(Style.SHOW)
        print("\n" + UI.center(f"{Style.DIM}Premi INVIO per chiudere..."))
        input()

if __name__ == "__main__":
    main()
