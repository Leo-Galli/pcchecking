import os, subprocess, platform, time, hashlib, psutil, math, collections, webbrowser
import csv, zipfile, json, statistics, logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

try:
    import winreg
except ImportError:
    winreg = None

try:
    import ctypes
    user32 = ctypes.windll.user32
except:
    user32 = None

# -------------------------
# CONFIG
# -------------------------
class ForensicConfig:
    VERSION = "900.2.0-EDR-FORENSIC-PRO-ULTIMATE"
    SCAN_ID = hashlib.sha256(str(time.time()).encode()).hexdigest()[:12].upper()
    REPORT_HTML = f"EDR_Report_{SCAN_ID}.html"
    REPORT_JSON = f"EDR_Report_{SCAN_ID}.json"

    ENTROPY_CRITICAL = 7.8
    PREFETCH_DAYS = 7
    INPUT_SAMPLE_SECONDS = 20
    MAX_FILES_PER_DIR = 500
    MAX_ZIP_FILES = 200
    MAX_THREADS = 16

    WEIGHTS = {
        "RWX": 35,
        "GHOST": 30,
        "RENAME": 20,
        "ENTROPY": 15,
        "PREFETCH": 15,
        "PERSIST": 15,
        "KERNEL": 40,
        "INPUT": 30,
        "RESOURCE": 25
    }

    SAFE_EXTS = {
        ".png",".jpg",".jpeg",".gif",".mp3",".mp4",".wav",".ogg",".svg",".ico",
        ".webp",".css",".json",".log",".txt",".xml",".pdf",".docx",".zip",
        ".rar",".msi",".ttf",".otf"
    }

    WHITELIST = [
        "microsoft","nvidia","amd","intel","steam","valve","discord",
        "google","mozilla","adobe","oracle","asus","msi","gigabyte",
        "corsair","logitech","razer","mojang","java"
    ]

logging.basicConfig(
    filename=f"EDR_{ForensicConfig.SCAN_ID}.log",
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

# -------------------------
# ANALYSIS UTILITIES
# -------------------------
class Analysis:
    @staticmethod
    def entropy(data):
        if len(data) < 2048:
            return 0
        c = collections.Counter(data)
        l = len(data)
        return -sum((v/l) * math.log(v/l, 2) for v in c.values())

    @staticmethod
    def sha256(path):
        try:
            if not os.path.exists(path):
                return None
            if os.path.splitext(path)[1].lower() in ForensicConfig.SAFE_EXTS:
                return None
            h = hashlib.sha256()
            with open(path, "rb") as f:
                for c in iter(lambda: f.read(131072), b""):
                    h.update(c)
            return h.hexdigest()
        except Exception as e:
            logging.warning(f"SHA256 failed for {path}: {e}")
            return None

    @staticmethod
    def whitelisted(path):
        p = str(path).lower()
        if any(w in p for w in ForensicConfig.WHITELIST):
            return True
        if "windows\\system32" in p and "drivers" not in p:
            return True
        return False

# -------------------------
# EDR CORE
# -------------------------
class EDR:
    def __init__(self):
        self.events = collections.defaultdict(list)
        self.rename = collections.defaultdict(list)
        self.layer_stats = collections.defaultdict(int)
        self.start = time.time()

    def add(self, pivot, layer, score, desc, explain):
        if not pivot or (isinstance(pivot,str) and Analysis.whitelisted(pivot)):
            return
        self.events[pivot].append({
            "time": datetime.now().isoformat(timespec="seconds"),
            "layer": layer,
            "score": score,
            "desc": desc,
            "explain": explain
        })
        self.layer_stats[layer] += score
        logging.info(f"{pivot} | {layer} | {desc}")

    # -------------------------
    # RUN ALL CHECKS
    # -------------------------
    def run(self):
        logging.info("EDR Scan started")
        tasks = []
        with ThreadPoolExecutor(max_workers=ForensicConfig.MAX_THREADS) as t:
            tasks.append(t.submit(self.memory))
            tasks.append(t.submit(self.filesystem))
            tasks.append(t.submit(self.input_analysis))
            if platform.system() == "Windows":
                tasks.append(t.submit(self.prefetch))
                tasks.append(t.submit(self.kernel))
                tasks.append(t.submit(self.persistence))
                tasks.append(t.submit(self.resourcepacks))
            for _ in as_completed(tasks):
                pass
        self.finalize()
        logging.info("EDR Scan completed")

    # -------------------------
    # MEMORY CHECK
    # -------------------------
    def memory(self):
        for p in psutil.process_iter(["pid","exe"]):
            try:
                rwx = False
                for m in p.memory_maps(grouped=False):
                    if "x" in m.perms and "w" in m.perms and not m.path:
                        rwx = True
                        self.add(
                            p.pid, "MEMORY",
                            ForensicConfig.WEIGHTS["RWX"],
                            "Anonymous RWX memory region",
                            "Executable + writable memory without file backing → manual injection"
                        )
                if rwx and not p.exe():
                    self.add(
                        p.pid, "PROCESS",
                        ForensicConfig.WEIGHTS["GHOST"],
                        "Hidden process",
                        "Process has RWX memory but no executable on disk"
                    )
            except Exception as e:
                logging.warning(f"Memory check failed for PID {p.pid}: {e}")

    # -------------------------
    # FILESYSTEM CHECK
    # -------------------------
    def filesystem(self):
        bases = [os.environ.get(x) for x in ["TEMP","APPDATA","LOCALAPPDATA"] if os.environ.get(x)]
        for base in bases:
            for root, _, files in os.walk(base):
                if Analysis.whitelisted(root):
                    continue
                for f in files[:ForensicConfig.MAX_FILES_PER_DIR]:
                    p = os.path.join(root, f)
                    ext = os.path.splitext(f)[1].lower()
                    if ext in ForensicConfig.SAFE_EXTS:
                        continue
                    h = Analysis.sha256(p)
                    if not h:
                        continue
                    self.rename[h].append(p)
                    if len(self.rename[h]) > 1:
                        self.add(
                            h, "FILESYSTEM",
                            ForensicConfig.WEIGHTS["RENAME"],
                            "Binary renamed multiple times",
                            "Same hash with different filenames → evasion attempt"
                        )
                    try:
                        with open(p,"rb") as fd:
                            e = Analysis.entropy(fd.read(65536))
                            if e > ForensicConfig.ENTROPY_CRITICAL:
                                self.add(
                                    h, "FILESYSTEM",
                                    ForensicConfig.WEIGHTS["ENTROPY"],
                                    "High entropy executable",
                                    "Packed/encrypted binary often used by loaders"
                                )
                    except Exception as ex:
                        logging.warning(f"Entropy check failed for {p}: {ex}")

    # -------------------------
    # INPUT / MACRO CHECK
    # -------------------------
    def input_analysis(self):
        if not user32:
            return
        clicks = []
        last = None
        start = time.time()
        while time.time()-start < ForensicConfig.INPUT_SAMPLE_SECONDS:
            for key in [0x01, 0x02, 0x04]:  # sinistro, destro, medio
                if user32.GetAsyncKeyState(key) & 0x8000:
                    now = time.time()
                    if last:
                        clicks.append(now-last)
                    last = now
            time.sleep(0.004)
        if len(clicks) > 25:
            jitter = statistics.pstdev(clicks)
            if jitter < 0.008:
                self.add(
                    "INPUT","INPUT",
                    ForensicConfig.WEIGHTS["INPUT"],
                    "Unnaturally stable click pattern",
                    "Low jitter → possible macro/autoclicker"
                )

    # -------------------------
    # RESOURCE PACK CHECK
    # -------------------------
    def resourcepacks(self):
        rp = os.path.join(os.environ.get("APPDATA",""),".minecraft","resourcepacks")
        if not os.path.exists(rp):
            return
        for f in os.listdir(rp)[:ForensicConfig.MAX_ZIP_FILES]:
            if not f.lower().endswith(".zip"):
                continue
            zp = os.path.join(rp,f)
            try:
                with zipfile.ZipFile(zp) as z:
                    models = [n for n in z.namelist() if "models" in n and n.endswith(".json")]
                    if len(models) > 80:
                        self.add(
                            zp, "RESOURCEPACK",
                            ForensicConfig.WEIGHTS["RESOURCE"],
                            "Abnormal model density",
                            "XRAY packs inflate block models to force visibility"
                        )
            except Exception as e:
                logging.warning(f"Resource pack check failed for {zp}: {e}")

    # -------------------------
    # PREFETCH CHECK
    # -------------------------
    def prefetch(self):
        path = r"C:\Windows\Prefetch"
        if not os.path.exists(path):
            return
        now = time.time()
        for f in os.listdir(path):
            try:
                if not f.lower().endswith(".pf"):
                    continue
                age = (now - os.path.getmtime(os.path.join(path,f)))/86400
                if age < ForensicConfig.PREFETCH_DAYS:
                    self.add(
                        f.split("-")[0], "PREFETCH",
                        ForensicConfig.WEIGHTS["PREFETCH"],
                        "Recent execution trace",
                        "Executable ran recently"
                    )
            except Exception as e:
                logging.warning(f"Prefetch check failed for {f}: {e}")

    # -------------------------
    # KERNEL DRIVER CHECK
    # -------------------------
    def kernel(self):
        try:
            out = subprocess.check_output("driverquery /v /fo csv", shell=True)
            r = csv.reader(out.decode(errors="ignore").splitlines())
            next(r)
            for row in r:
                try:
                    p = row[10].lower()
                    if "system32\\drivers" not in p and not Analysis.whitelisted(p):
                        self.add(
                            "KERNEL","DRIVER",
                            ForensicConfig.WEIGHTS["KERNEL"],
                            "Unsigned / non-standard driver",
                            "Kernel driver outside trusted path → ring-0 bypass potential"
                        )
                except: continue
        except Exception as e:
            logging.warning(f"Kernel check failed: {e}")

    # -------------------------
    # PERSISTENCE CHECK
    # -------------------------
    def persistence(self):
        if not winreg:
            return
        for root,path in [
            (winreg.HKEY_CURRENT_USER,r"Software\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_LOCAL_MACHINE,r"Software\Microsoft\Windows\CurrentVersion\Run")
        ]:
            try:
                with winreg.OpenKey(root,path) as k:
                    for i in range(winreg.QueryInfoKey(k)[1]):
                        _,v,_ = winreg.EnumValue(k,i)
                        exe = v.split(" ")[0].replace('"',"")
                        h = Analysis.sha256(exe)
                        if h:
                            self.add(
                                h,"REGISTRY",
                                ForensicConfig.WEIGHTS["PERSIST"],
                                "Auto-start persistence",
                                "Executable configured to start with Windows"
                            )
            except Exception as e:
                logging.warning(f"Persistence check failed: {e}")

    # -------------------------
    # FINALIZATION & REPORT
    # -------------------------
    def finalize(self):
        results = []
        for pivot,ev in self.events.items():
            total = sum(e["score"] for e in ev)
            confidence = min(100,total)
            level = "CONFIRMED" if confidence>=70 else "LIKELY" if confidence>=40 else "INFO"
            results.append((pivot,level,confidence,ev))
        self.render(results)

    def render(self, data):
        dur = round(time.time()-self.start,2)
        html = f"<html><body style='background:#0d1117;color:#c9d1d9;font-family:Segoe UI;padding:40px'>"
        html += f"<h1>EDR Forensic Report</h1><p>ID {ForensicConfig.SCAN_ID} | v{ForensicConfig.VERSION} | {dur}s</p>"
        html += "<h2>Layer Summary:</h2><ul>"
        for layer,score in self.layer_stats.items():
            html += f"<li>{layer}: {score}</li>"
        html += "</ul>"

        # Event details
        for p,l,c,ev in sorted(data,key=lambda x:x[2],reverse=True):
            color = {"CONFIRMED":"#f85149","LIKELY":"#d29922","INFO":"#58a6ff"}[l]
            html += f"<div style='background:#161b22;border-left:6px solid {color};padding:20px;margin:20px;border-radius:10px'>"
            html += f"<h3>{p}</h3><b>{l}</b> | Confidence {c}%"
            for e in ev:
                html += f"<div><b>[{e['layer']}]</b> {e['desc']}<br><small>{e['explain']} | {e['time']}</small></div>"
            html += "</div>"
        html += "</body></html>"

        # Save reports
        with open(ForensicConfig.REPORT_HTML,"w",encoding="utf-8") as f:
            f.write(html)
        with open(ForensicConfig.REPORT_JSON,"w",encoding="utf-8") as f:
            json.dump([{"pivot":p,"level":l,"confidence":c,"events":ev} for p,l,c,ev in data], f, indent=2)

        webbrowser.open(os.path.abspath(ForensicConfig.REPORT_HTML))
        logging.info(f"Reports generated: HTML + JSON")

# -------------------------
# RUN
# -------------------------
if __name__=="__main__":
    if platform.system()=="Windows":
        EDR().run()