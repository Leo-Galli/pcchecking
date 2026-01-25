import os, platform, time, hashlib, psutil, math, collections, webbrowser, json, csv, logging, subprocess
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

# ---------------- CONFIG ----------------
class CFG:
    VERSION = "1.0.0-STABLE-FORENSIC"
    SCAN_ID = hashlib.sha1(str(time.time()).encode()).hexdigest()[:10].upper()

    HTML = f"EDR_{SCAN_ID}.html"
    JSON = f"EDR_{SCAN_ID}.json"
    LOG  = f"EDR_{SCAN_ID}.log"

    MAX_THREADS = 8
    ENTROPY_CRITICAL = 7.9
    MIN_SCORE_TO_LOG = 25   # <— anti spam
    CONFIRMED_SCORE  = 70

    SAFE_EXT = {".png",".jpg",".jpeg",".gif",".mp3",".mp4",".txt",".json",".log",".pdf",".zip",".rar",".css"}
    TRUSTED = ["windows","microsoft","intel","amd","nvidia","steam","discord","google","mozilla","java"]

    MALWARE_HASHES = {
        # esempio
        "e3b0c44298fc1c149afbf4c8996fb924": "Known test malware"
    }

logging.basicConfig(
    filename=CFG.LOG,
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s"
)

# ---------------- UTILS ----------------
def entropy(data):
    if len(data) < 2048:
        return 0
    c = collections.Counter(data)
    l = len(data)
    return -sum((v/l)*math.log(v/l,2) for v in c.values())

def whitelisted(path):
    p = path.lower()
    return any(t in p for t in CFG.TRUSTED)

def sha256(path):
    try:
        h = hashlib.sha256()
        with open(path,"rb") as f:
            for b in iter(lambda:f.read(65536),b""):
                h.update(b)
        return h.hexdigest()
    except:
        return None

# ---------------- CORE ----------------
class EDR:
    def __init__(self):
        self.events = collections.defaultdict(list)
        self.inventory = {}
        self.start = time.time()

    def add(self, path, layer, score, desc, reason):
        if score < CFG.MIN_SCORE_TO_LOG:
            return
        if path and whitelisted(path):
            return
        self.events[path].append({
            "layer":layer,
            "score":score,
            "desc":desc,
            "reason":reason,
            "time":datetime.now().isoformat(timespec="seconds"),
            "path":path
        })
        logging.info(f"{layer} | {path} | {desc}")

    # -------- INVENTORY --------
    def system_inventory(self):
        self.inventory = {
            "OS": platform.platform(),
            "CPU": platform.processor(),
            "RAM_GB": round(psutil.virtual_memory().total/(1024**3),1),
            "Processes":[]
        }
        for p in psutil.process_iter(["name","exe"]):
            try:
                if p.info["exe"] and whitelisted(p.info["exe"]):
                    self.inventory["Processes"].append(p.info["name"])
            except:
                pass

    # -------- FILESYSTEM --------
    def filesystem(self):
        bases = [os.environ.get(x) for x in ["TEMP","APPDATA","LOCALAPPDATA"] if os.environ.get(x)]
        for base in bases:
            for root,_,files in os.walk(base):
                if whitelisted(root):
                    continue
                for f in files[:200]:
                    p = os.path.join(root,f)
                    ext = os.path.splitext(p)[1].lower()
                    if ext in CFG.SAFE_EXT:
                        continue

                    h = sha256(p)
                    if not h:
                        continue

                    # HASH CERTO
                    if h in CFG.MALWARE_HASHES:
                        self.add(
                            p,"MALWARE",100,
                            f"Known malware: {CFG.MALWARE_HASHES[h]}",
                            "Exact hash match"
                        )
                        continue

                    # ENTROPY SOLO COME SUPPORTO
                    try:
                        with open(p,"rb") as fd:
                            e = entropy(fd.read(65536))
                        if e > CFG.ENTROPY_CRITICAL:
                            self.add(
                                p,"FILESYSTEM",30,
                                "High entropy executable",
                                "Packed binary (needs correlation)"
                            )
                    except:
                        pass

    # -------- PERSISTENCE --------
    def persistence(self):
        try:
            import winreg
            keys=[
                (winreg.HKEY_CURRENT_USER,r"Software\Microsoft\Windows\CurrentVersion\Run"),
                (winreg.HKEY_LOCAL_MACHINE,r"Software\Microsoft\Windows\CurrentVersion\Run")
            ]
            for root,path in keys:
                with winreg.OpenKey(root,path) as k:
                    for i in range(winreg.QueryInfoKey(k)[1]):
                        _,v,_ = winreg.EnumValue(k,i)
                        exe = v.split(" ")[0].replace('"',"")
                        if exe and not whitelisted(exe):
                            self.add(
                                exe,"PERSISTENCE",60,
                                "Suspicious autostart entry",
                                "Runs at boot outside trusted vendors"
                            )
        except:
            pass

    # -------- KERNEL --------
    def kernel(self):
        try:
            out = subprocess.check_output("driverquery /fo csv",shell=True)
            r = csv.reader(out.decode(errors="ignore").splitlines())
            next(r)
            for row in r:
                p = row[-1].lower()
                if p and "system32\\drivers" not in p:
                    self.add(
                        p,"KERNEL",80,
                        "Non standard kernel driver",
                        "Driver outside system path"
                    )
        except:
            pass

    # -------- RUN --------
    def run(self):
        self.system_inventory()
        with ThreadPoolExecutor(max_workers=CFG.MAX_THREADS) as t:
            t.submit(self.filesystem)
            t.submit(self.persistence)
            t.submit(self.kernel)

        self.render()

    # -------- REPORT --------
    def render(self):
        results=[]
        for p,ev in self.events.items():
            score=sum(e["score"] for e in ev)
            level="CONFIRMED" if score>=CFG.CONFIRMED_SCORE else "SUSPICIOUS"
            results.append((p,level,score,ev))

        # JSON
        with open(CFG.JSON,"w",encoding="utf-8") as f:
            json.dump({
                "scan_id":CFG.SCAN_ID,
                "inventory":self.inventory,
                "findings":[
                    {"path":p,"level":l,"score":s,"events":ev}
                    for p,l,s,ev in results
                ]
            },f,indent=2)

        # HTML
        html=f"""
        <html><body style="background:#0d1117;color:#c9d1d9;font-family:Segoe UI;padding:30px">
        <h1>EDR Forensic Report</h1>
        <small>ID {CFG.SCAN_ID} | v{CFG.VERSION}</small>

        <h2>🧾 System</h2>
        <pre>{json.dumps(self.inventory,indent=2)}</pre>

        <h2>🚨 Findings</h2>
        """
        for p,l,s,ev in sorted(results,key=lambda x:x[2],reverse=True):
            html+=f"<div style='border-left:6px solid {'#f85149' if l=='CONFIRMED' else '#d29922'};padding:10px;margin:10px'>"
            html+=f"<b>{p}</b> | {l} | Score {s}<br>"
            for e in ev:
                html+=f"<small>[{e['layer']}] {e['desc']} — {e['reason']}</small><br>"
            html+="</div>"
        html+="</body></html>"

        with open(CFG.HTML,"w",encoding="utf-8") as f:
            f.write(html)

        # OPEN EVERYTHING
        webbrowser.open(os.path.abspath(CFG.HTML))
        webbrowser.open(os.path.abspath(CFG.JSON))
        webbrowser.open(os.path.abspath(CFG.LOG))


# ---------------- RUN ----------------
if __name__=="__main__":
    if platform.system()=="Windows":
        EDR().run()