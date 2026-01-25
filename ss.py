import os, subprocess, platform, time, hashlib, psutil, math, collections, webbrowser
import csv, zipfile, json, statistics, logging, socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

try:
    import winreg
except:
    winreg = None

try:
    import ctypes
    user32 = ctypes.windll.user32
except:
    user32 = None

# =========================
# CONFIG
# =========================
class ForensicConfig:
    VERSION = "1.0.0-EDR-FORENSIC-PRO-STABLE"
    SCAN_ID = hashlib.sha256(str(time.time()).encode()).hexdigest()[:10]

    REPORT_HTML = f"EDR_{SCAN_ID}.html"
    REPORT_JSON = f"EDR_{SCAN_ID}.json"
    REPORT_CSV  = f"EDR_{SCAN_ID}.csv"

    ENTROPY_HIGH = 7.8
    INPUT_SECONDS = 30
    PREFETCH_DAYS = 5

    MAX_THREADS = 12
    FILE_THREADS = 6
    MAX_FILES_PER_DIR = 250

    MIN_SCORE_TO_LOG = 20

    SAFE_EXT = {
        ".png",".jpg",".jpeg",".gif",".mp3",".mp4",".wav",".ogg",".svg",".ico",
        ".webp",".css",".json",".log",".txt",".xml",".pdf",".docx",".zip",".rar",
        ".ttf",".otf",".md",".yml",".ini"
    }

    TRUSTED = [
        "microsoft","windows","nvidia","amd","intel","steam","valve",
        "discord","google","mozilla","oracle","java","mojang",
        "corsair","logitech","razer","asus","msi","gigabyte"
    ]

    WEIGHTS = {
        "RWX": 40,
        "GHOST": 35,
        "ENTROPY": 20,
        "RENAME": 20,
        "PREFETCH": 15,
        "PERSIST": 20,
        "KERNEL": 45,
        "INPUT": 30,
        "RESOURCE": 25,
        "NETWORK": 25
    }

logging.basicConfig(
    filename=f"EDR_{ForensicConfig.SCAN_ID}.log",
    level=logging.INFO,
    format="%(asctime)s | %(message)s"
)

# =========================
# UTIL
# =========================
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
            if not os.path.exists(path): return None
            if os.path.splitext(path)[1].lower() in ForensicConfig.SAFE_EXT:
                return None
            h = hashlib.sha256()
            with open(path,"rb") as f:
                for b in iter(lambda:f.read(131072),b""):
                    h.update(b)
            return h.hexdigest()
        except:
            return None

    @staticmethod
    def whitelisted(path):
        p = str(path).lower()
        return any(x in p for x in ForensicConfig.TRUSTED)

# =========================
# EDR CORE
# =========================
class EDR:
    def __init__(self):
        self.events = collections.defaultdict(list)
        self.start = time.time()

    def add(self,pivot,layer,score,desc,why):
        if score < ForensicConfig.MIN_SCORE_TO_LOG:
            return
        if isinstance(pivot,str) and Analysis.whitelisted(pivot):
            return
        self.events[pivot].append({
            "layer":layer,
            "score":score,
            "desc":desc,
            "why":why,
            "time":datetime.now().isoformat(timespec="seconds")
        })

    # =========================
    # RUN
    # =========================
    def run(self):
        print("[+] EDR Scan started...")
        with ThreadPoolExecutor(max_workers=ForensicConfig.MAX_THREADS) as t:
            tasks = [
                t.submit(self.memory),
                t.submit(self.filesystem),
                t.submit(self.input_check),
                t.submit(self.network)
            ]
            if platform.system()=="Windows":
                tasks += [
                    t.submit(self.prefetch),
                    t.submit(self.kernel),
                    t.submit(self.persistence),
                    t.submit(self.resourcepacks)
                ]
            for _ in as_completed(tasks):
                pass
        self.report()

    # =========================
    # MEMORY
    # =========================
    def memory(self):
        for p in psutil.process_iter(["pid","exe"]):
            try:
                rwx=False
                for m in p.memory_maps(grouped=False):
                    if "x" in m.perms and "w" in m.perms and not m.path:
                        rwx=True
                if rwx:
                    self.add(p.pid,"MEMORY",ForensicConfig.WEIGHTS["RWX"],
                             "RWX memory region",
                             "Writable + Executable anonymous memory")
                    if not p.exe():
                        self.add(p.pid,"PROCESS",ForensicConfig.WEIGHTS["GHOST"],
                                 "Ghost process","No executable on disk")
            except:
                pass

    # =========================
    # FILESYSTEM
    # =========================
    def filesystem(self):
        bases = [os.environ.get(x) for x in ["TEMP","APPDATA","LOCALAPPDATA"] if os.environ.get(x)]
        hashes = collections.defaultdict(list)
        for base in bases:
            for root,_,files in os.walk(base):
                if Analysis.whitelisted(root): continue
                for f in files[:ForensicConfig.MAX_FILES_PER_DIR]:
                    p=os.path.join(root,f)
                    if os.path.splitext(p)[1].lower() in ForensicConfig.SAFE_EXT:
                        continue
                    h=Analysis.sha256(p)
                    if not h: continue
                    hashes[h].append(p)
                    try:
                        with open(p,"rb") as fd:
                            e=Analysis.entropy(fd.read(65536))
                            if e>ForensicConfig.ENTROPY_HIGH:
                                self.add(h,"FILESYSTEM",ForensicConfig.WEIGHTS["ENTROPY"],
                                         "High entropy binary","Packed or encrypted")
                    except:
                        pass
        for h,paths in hashes.items():
            if len(paths)>1:
                self.add(h,"FILESYSTEM",ForensicConfig.WEIGHTS["RENAME"],
                         "Rename chain","Same hash, multiple names")

    # =========================
    # INPUT
    # =========================
    def input_check(self):
        if not user32: return
        clicks=[]
        last=None
        start=time.time()
        while time.time()-start<ForensicConfig.INPUT_SECONDS:
            if user32.GetAsyncKeyState(0x01)&0x8000:
                now=time.time()
                if last: clicks.append(now-last)
                last=now
            time.sleep(0.004)
        if len(clicks)>30:
            if statistics.pstdev(clicks)<0.008:
                self.add("INPUT","INPUT",ForensicConfig.WEIGHTS["INPUT"],
                         "Autoclicker pattern","Very low click jitter")

    # =========================
    # NETWORK
    # =========================
    def network(self):
        for c in psutil.net_connections(kind="inet"):
            if c.status=="ESTABLISHED" and c.raddr:
                ip=c.raddr.ip if hasattr(c.raddr,"ip") else c.raddr[0]
                if not ip.startswith(("10.","192.168","172.")):
                    self.add(ip,"NETWORK",ForensicConfig.WEIGHTS["NETWORK"],
                             "External connection","Non-local active connection")

    # =========================
    # PREFETCH
    # =========================
    def prefetch(self):
        path=r"C:\Windows\Prefetch"
        if not os.path.exists(path): return
        now=time.time()
        for f in os.listdir(path):
            if f.lower().endswith(".pf"):
                age=(now-os.path.getmtime(os.path.join(path,f)))/86400
                if age<ForensicConfig.PREFETCH_DAYS:
                    self.add(f,"PREFETCH",ForensicConfig.WEIGHTS["PREFETCH"],
                             "Recent execution","Recently run executable")

    # =========================
    # KERNEL
    # =========================
    def kernel(self):
        try:
            out=subprocess.check_output("driverquery /v /fo csv",shell=True)
            r=csv.reader(out.decode(errors="ignore").splitlines())
            next(r)
            for row in r:
                p=row[10].lower()
                if "system32\\drivers" not in p and not Analysis.whitelisted(p):
                    self.add(p,"KERNEL",ForensicConfig.WEIGHTS["KERNEL"],
                             "Suspicious driver","Kernel driver outside trusted path")
        except:
            pass

    # =========================
    # PERSISTENCE
    # =========================
    def persistence(self):
        if not winreg: return
        for root,path in [
            (winreg.HKEY_CURRENT_USER,r"Software\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_LOCAL_MACHINE,r"Software\Microsoft\Windows\CurrentVersion\Run")
        ]:
            try:
                with winreg.OpenKey(root,path) as k:
                    for i in range(winreg.QueryInfoKey(k)[1]):
                        _,v,_=winreg.EnumValue(k,i)
                        h=Analysis.sha256(v.split(" ")[0].replace('"',""))
                        if h:
                            self.add(h,"REGISTRY",ForensicConfig.WEIGHTS["PERSIST"],
                                     "Startup persistence","Runs at boot")
            except:
                pass

    # =========================
    # RESOURCEPACKS
    # =========================
    def resourcepacks(self):
        rp=os.path.join(os.environ.get("APPDATA",""),".minecraft","resourcepacks")
        if not os.path.exists(rp): return
        for f in os.listdir(rp):
            if f.lower().endswith(".zip"):
                try:
                    with zipfile.ZipFile(os.path.join(rp,f)) as z:
                        models=[n for n in z.namelist() if "models" in n]
                        if len(models)>80:
                            self.add(f,"RESOURCEPACK",ForensicConfig.WEIGHTS["RESOURCE"],
                                     "Xray resourcepack","Abnormal model density")
                except:
                    pass

    # =========================
    # REPORT
    # =========================
    def report(self):
        results=[]
        for p,ev in self.events.items():
            score=sum(e["score"] for e in ev)
            lvl="CONFIRMED" if score>=70 else "SUSPICIOUS" if score>=40 else "INFO"
            results.append((p,lvl,score,ev))

        html="<html><body style='background:#0d1117;color:#c9d1d9;font-family:Segoe UI;padding:30px'>"
        html+=f"<h1>EDR Report</h1><p>Scan {ForensicConfig.SCAN_ID}</p>"
        for p,l,s,ev in sorted(results,key=lambda x:x[2],reverse=True):
            html+=f"<details><summary><b>{p}</b> | {l} | {s}</summary>"
            for e in ev:
                html+=f"<div>[{e['layer']}] {e['desc']} – {e['why']}</div>"
            html+="</details>"
        html+="</body></html>"

        with open(ForensicConfig.REPORT_HTML,"w",encoding="utf-8") as f: f.write(html)
        with open(ForensicConfig.REPORT_JSON,"w",encoding="utf-8") as f:
            json.dump(results,f,indent=2)

        webbrowser.open(os.path.abspath(ForensicConfig.REPORT_HTML))
        print("[+] Scan complete. Report opened.")

# =========================
# MAIN
# =========================
if __name__=="__main__":
    if platform.system()=="Windows":
        EDR().run()