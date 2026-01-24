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
    VERSION = "70.0.0-FORENSIC-DASHBOARD-PRO"
    SCAN_ID = hashlib.sha384(str(time.time()).encode()).hexdigest()[:32].upper()
    REPORT_NAME = f"Forensic_Report_{SCAN_ID}.html"
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
        self.layer_counts = collections.defaultdict(int)
        self.anomalies_temp = []
        self.correlations = []

    def _check_privs(self):
        try:
            if self.os_type == "Windows": return ctypes.windll.shell32.IsUserAnAdmin() != 0
            return os.getuid() == 0
        except: return False

    def add_event(self, layer, entity, desc, weight, reliability, ts=None, fingerprint=None):
        ent_lower = str(entity).lower()
        if any(w in ent_lower for w in ForensicConfig.WHITELIST_ENTITIES):
            weight *= 0.1
            reliability *= 0.5
        event_key = f"{layer}|{ent_lower}|{desc}"
        with self._lock:
            if event_key in self._seen: return
            self._seen.add(event_key)
            event_ts = ts if ts else time.time()
            self.layer_counts[layer] += 1
            self.timeline.append({
                "layer": layer, "entity": str(entity), "description": desc,
                "weight": float(weight), "reliability": float(reliability),
                "timestamp": event_ts, "fingerprint": fingerprint
            })

    def run(self):
        print(f"[*] Analisi Forense in corso (ID: {ForensicConfig.SCAN_ID})...")
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
        self._generate_dashboard()

    def _audit_processes(self):
        
        for proc in psutil.process_iter(['pid', 'name', 'exe', 'ppid', 'create_time', 'cmdline']):
            try:
                p = proc.info
                pname = p['name'] or "Unknown"
                pexe = p['exe'] or ""
                h = AnalysisEngine.calculate_hash(pexe) if pexe else None
                fp = hashlib.md5(f"{pname}{h}".encode()).hexdigest() if h else "mem_only"
                
                if not pexe and p['pid'] > 4:
                    self.add_event("PROCESS", pname, "Esecuzione 'Ghost': il processo non ha un file fisico su disco. Tipico di iniezioni di memoria (Process Hollowing/Reflective Loading).", 600, 0.95, fingerprint=fp)
                
                norm_name = AnalysisEngine.normalize(pname)
                for kw in ForensicConfig.KEYWORDS:
                    if kw in norm_name:
                        self.add_event("PROCESS", pname, f"Keyword Match: '{kw}'. Nome processo associato a strumenti di cheat o hacking noti.", 300, 0.9, fingerprint=fp)
                    elif len(kw) >= 4 and AnalysisEngine.levenshtein(kw, norm_name) <= 1:
                        self.add_event("PROCESS", pname, f"Fuzzy Match: '{kw}'. Il nome sembra una variazione camuffata di un software proibito.", 200, 0.75, fingerprint=fp)
            except: continue

    def _audit_filesystem(self):
        
        paths = ForensicConfig.WIN_PATHS if self.os_type == "Windows" else ["/tmp", "/var/tmp"]
        for b_path in paths:
            if not os.path.exists(b_path): continue
            for root, _, files in os.walk(b_path):
                for f in files:
                    fpath = os.path.join(root, f)
                    try:
                        st = os.stat(fpath)
                        h = AnalysisEngine.calculate_hash(fpath)
                        
                        if h:
                            if h not in self.rename_chains: self.rename_chains[h] = []
                            if fpath not in self.rename_chains[h]: self.rename_chains[h].append(fpath)

                        if abs(st.st_mtime - st.st_ctime) > 86400 * 30:
                            self.anomalies_temp.append({
                                "file": f, "desc": "Timestomp: Data creazione e modifica troppo distanti o incoerenti. Possibile alterazione manuale dei log temporali."
                            })

                        if 0 < st.st_size < 10 * 1024 * 1024:
                            with open(fpath, 'rb') as fd:
                                data = fd.read(131072)
                                ent = AnalysisEngine.get_entropy(data)
                                if ent > ForensicConfig.ENTROPY_THRESHOLD:
                                    self.add_event("FILESYSTEM", f, f"Alta Entropia ({ent:.2f}): Il file è cifrato o compresso con un packer. Tecnica usata per nascondere il codice reale agli antivirus.", 350, 0.8, fingerprint=h)
                    except: continue

    def _win_journal_audit(self):
        if self.os_type != "Windows" or not self.is_admin: return
        try:
            raw = subprocess.check_output("fsutil usn readjournal C: csv", shell=True, stderr=subprocess.DEVNULL).decode(errors='ignore')
            for line in raw.splitlines()[-1000:]:
                parts = line.split(',')
                if len(parts) > 3:
                    fname = parts[0].strip()
                    if any(kw in fname.lower() for kw in ForensicConfig.KEYWORDS):
                        self.add_event("JOURNAL", fname, "Traccia Journal: Il filesystem registra attività recente legata a file con nomi sospetti, anche se cancellati.", 250, 0.85)
        except: pass

    def _win_driver_audit(self):
        if self.os_type != "Windows": return
        try:
            raw = subprocess.check_output("driverquery /v /fo csv", shell=True).decode(errors='ignore')
            for line in raw.splitlines():
                if any(kw in line.lower() for kw in ForensicConfig.KEYWORDS):
                    self.add_event("DRIVER", "Kernel", f"Driver Sospetto: '{line.split(',')[0]}'. I driver kernel possono bypassare le protezioni di sistema e i giochi.", 500, 0.95)
        except: pass

    def _win_registry_audit(self):
        if not winreg: return
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run") as k:
                for i in range(winreg.QueryInfoKey(k)[1]):
                    n, v, _ = winreg.EnumValue(k, i)
                    if any(kw in str(v).lower() for kw in ForensicConfig.KEYWORDS):
                        self.add_event("REGISTRY", n, "Esecuzione Automatica: Il software si avvia col sistema. Comune in cheat persistenti o malware.", 300, 0.9)
        except: pass

    def _win_antiforensic_check(self):
        if self.os_type != "Windows": return
        try:
            log_c = subprocess.check_output('wevtutil qe Security /q:"*[System[(EventID=1102)]]" /c:1', shell=True)
            if log_c: self.add_event("ANTIFORENSIC", "Log Eventi", "Cancellazione Log: È stato rilevato il comando di svuotamento dei log di sicurezza. Tentativo di nascondere tracce.", 450, 1.0)
        except: pass

    def _generate_dashboard(self):
        fp_data = collections.defaultdict(lambda: {"score": 0, "events": [], "name": ""})
        for e in self.timeline:
            if e['fingerprint']:
                fp_data[e['fingerprint']]["score"] += e['weight'] * e['reliability']
                fp_data[e['fingerprint']]["events"].append(e)
                fp_data[e['fingerprint']]["name"] = e['entity']
            self.score += e['weight'] * e['reliability']

        sorted_cheats = sorted(fp_data.items(), key=lambda x: x[1]['score'], reverse=True)
        
        verdict = "CLEAN"
        v_class = "v-green"
        if self.score >= ForensicConfig.T_CONFIRMED: verdict, v_class = "CONFIRMED", "v-red"
        elif self.score >= ForensicConfig.T_SUSPICIOUS: verdict, v_class = "SUSPICIOUS", "v-orange"

        html_tpl = f"""
        <!DOCTYPE html>
        <html lang="it">
        <head>
            <meta charset="UTF-8">
            <style>
                :root {{ --red: #e74c3c; --orange: #f39c12; --green: #27ae60; --dark: #2c3e50; --light: #ecf0f1; }}
                body {{ font-family: 'Segoe UI', system-ui, sans-serif; background: #f0f2f5; color: var(--dark); margin: 0; line-height: 1.6; }}
                .container {{ max-width: 1200px; margin: 20px auto; padding: 0 20px; }}
                .dashboard-header {{ background: white; padding: 30px; border-radius: 15px; box-shadow: 0 4px 20px rgba(0,0,0,0.08); display: flex; justify-content: space-between; align-items: center; margin-bottom: 25px; }}
                .verdict-badge {{ padding: 15px 40px; border-radius: 50px; font-weight: 800; font-size: 1.4em; color: white; text-transform: uppercase; }}
                .v-red {{ background: var(--red); box-shadow: 0 4px 15px rgba(231, 76, 60, 0.4); }}
                .v-orange {{ background: var(--orange); box-shadow: 0 4px 15px rgba(243, 156, 18, 0.4); }}
                .v-green {{ background: var(--green); box-shadow: 0 4px 15px rgba(39, 174, 96, 0.4); }}
                .section {{ background: white; padding: 25px; border-radius: 15px; margin-bottom: 25px; box-shadow: 0 2px 10px rgba(0,0,0,0.05); }}
                h2 {{ border-bottom: 2px solid #eee; padding-bottom: 10px; margin-top: 0; display: flex; align-items: center; }}
                .cheat-card {{ border-left: 5px solid var(--red); background: #fff9f9; padding: 15px; margin-bottom: 10px; border-radius: 5px; }}
                .badge {{ padding: 4px 10px; border-radius: 4px; font-size: 0.85em; font-weight: bold; color: white; }}
                .b-red {{ background: var(--red); }} .b-orange {{ background: var(--orange); }} .b-blue {{ background: #3498db; }}
                table {{ width: 100%; border-collapse: collapse; }}
                th {{ text-align: left; background: #f8f9fa; padding: 12px; border-bottom: 2px solid #dee2e6; }}
                td {{ padding: 12px; border-bottom: 1px solid #eee; }}
                .timeline-item {{ border-left: 3px solid #ddd; padding-left: 20px; margin-bottom: 20px; position: relative; }}
                .timeline-item::before {{ content: ''; width: 12px; height: 12px; background: #3498db; position: absolute; left: -8px; border-radius: 50%; }}
                .legenda {{ display: flex; gap: 20px; flex-wrap: wrap; font-size: 0.9em; }}
                .legenda-item {{ background: #eee; padding: 10px; border-radius: 8px; flex: 1; min-width: 200px; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="dashboard-header">
                    <div>
                        <h1 style="margin:0">Forensic Intel Dashboard</h1>
                        <p style="color:#7f8c8d; margin:5px 0">ID Scansione: {ForensicConfig.SCAN_ID} | Ver: {ForensicConfig.VERSION}</p>
                        <p><strong>OS:</strong> {self.os_type} | <strong>Data:</strong> {datetime.datetime.now().strftime('%d/%m/%Y %H:%M')}</p>
                    </div>
                    <div class="verdict-badge {v_class}">{verdict}</div>
                </div>

                <div class="section">
                    <h2 style="color:var(--red)">🚨 TOP INDICATORI DI RISCHIO (CHEAT/BYPASS)</h2>
                    <p>Queste sono le entità che hanno accumulato il punteggio più alto durante la scansione.</p>
                    {"".join([f'''
                    <div class="cheat-card">
                        <div style="display:flex; justify-content:space-between">
                            <strong>{v['name']}</strong>
                            <span class="badge b-red">Score: {int(v['score'])}</span>
                        </div>
                        <p style="margin:5px 0; font-size:0.9em"><strong>Fingerprint:</strong> {k}</p>
                        <ul style="font-size:0.9em">
                            {"".join([f"<li>{ev['description']}</li>" for ev in v['events']])}
                        </ul>
                    </div>''' for k, v in sorted_cheats[:5] if v['score'] > 0])}
                </div>

                <div class="grid" style="display:grid; grid-template-columns: 1fr 1fr; gap: 25px;">
                    <div class="section">
                        <h2>🕒 ANOMALIE TEMPORALI</h2>
                        <p style="font-size:0.9em; color:#666">L'alterazione dei timestamp (Timestomping) è usata per far apparire file recenti come vecchi file di sistema.</p>
                        {"".join([f"<div style='margin-bottom:10px;'><strong>{a['file']}</strong><br><small>{a['desc']}</small></div>" for a in self.anomalies_temp])}
                    </div>
                    <div class="section">
                        <h2>🔗 RENAME CHAINS</h2>
                        <p style="font-size:0.9em; color:#666">File con lo stesso contenuto (Hash) ma nomi diversi in percorsi sospetti.</p>
                        {"".join([f"<div style='margin-bottom:10px;'><strong>Hash: {h[:12]}...</strong><br><small>{' ➔ '.join([os.path.basename(p) for p in paths])}</small></div>" for h, paths in self.rename_chains.items() if len(paths) > 1])}
                    </div>
                </div>

                <div class="section">
                    <h2>📘 LEGENDA E TERMINI</h2>
                    <div class="legenda">
                        <div class="legenda-item"><strong>Peso:</strong> Indica la gravità potenziale di un evento specifico.</div>
                        <div class="legenda-item"><strong>Entropia:</strong> Misura il disordine dei dati. Valori > 7.7 indicano spesso file cifrati (cheat).</div>
                        <div class="legenda-item"><strong>Fingerprint:</strong> Identificativo unico basato sul contenuto del file (Hash).</div>
                        <div class="legenda-item"><strong>Fuzzy Match:</strong> Rilevamento di nomi che tentano di imitare software legittimi (es. "L0gitech").</div>
                    </div>
                </div>

                <div class="section">
                    <h2>Timeline Forense Ordinata</h2>
                    <div style="margin-bottom:20px">
                        <button onclick="filterLayer('all')" style="padding:5px 15px">Tutti</button>
                        <button onclick="filterLayer('PROCESS')" style="padding:5px 15px">Processi</button>
                        <button onclick="filterLayer('FILESYSTEM')" style="padding:5px 15px">File</button>
                    </div>
                    <div id="timeline-container">
                    {"".join([f'''
                    <div class="timeline-item" data-layer="{e['layer']}">
                        <div style="display:flex; justify-content:space-between">
                            <strong>{e['entity']}</strong>
                            <span class="badge {'b-red' if e['weight']>400 else 'b-orange' if e['weight']>200 else 'b-blue'}">{e['layer']}</span>
                        </div>
                        <p style="margin:5px 0">{e['description']}</p>
                        <small style="color:#7f8c8d">Rilevato il: {datetime.datetime.fromtimestamp(e['timestamp']).strftime('%H:%M:%S')} | Affidabilità: {int(e['reliability']*100)}%</small>
                    </div>''' for e in sorted(self.timeline, key=lambda x: x['timestamp'])])}
                    </div>
                </div>

                <div class="section" style="background:var(--dark); color:white">
                    <h2>Riassunto Finale</h2>
                    <p>L'analisi ha concluso un verdetto di <strong>{verdict}</strong> con un punteggio totale di {int(self.score)}.</p>
                    <p>I fattori determinanti sono stati: {", ".join(list(self.layer_counts.keys()))}. Si consiglia di ispezionare manualmente le entità nella sezione "Top Indicatori".</p>
                </div>
            </div>
            <script>
                function filterLayer(layer) {{
                    document.querySelectorAll('.timeline-item').forEach(el => {{
                        el.style.display = (layer === 'all' || el.getAttribute('data-layer') === layer) ? 'block' : 'none';
                    }});
                }}
            </script>
        </body>
        </html>
        """
        with open(ForensicConfig.REPORT_NAME, "w", encoding='utf-8') as f: f.write(html_tpl)
        print(f"\n[!] REPORT GENERATO: {os.path.abspath(ForensicConfig.REPORT_NAME)}")
        if self.os_type == "Windows": os.startfile(ForensicConfig.REPORT_NAME)

if __name__ == "__main__":
    orch = AdaptiveOrchestrator()
    orch.run()
