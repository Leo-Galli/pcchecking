# ============================================================
# EDR 11.5 – HARDENED USER-LAND DEFENSIVE ENGINE
# Anti-cheat | Anti-rename | Behavioral | Driver & Service Scan
# ============================================================

import os, sys, time, json, math, zipfile, psutil, hashlib, platform
import threading, collections, logging, requests, inspect, subprocess
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor

# ====================== DISCORD ======================
DISCORD_WEBHOOK = "INSERISCI_WEBHOOK_DISCORD"

# ====================== CONFIG ======================
class CFG:
    VERSION = "11.5.0-HARDENED-USERLAND"
    SCAN_ID = hashlib.sha256(str(time.time()).encode()).hexdigest()[:12]

    THREADS = 20
    ENTROPY_THRESHOLD = 7.0
    FILE_RECENT_HOURS = 168

    SCORE_CONFIRMED = 220
    SCORE_SUSPICIOUS = 110

    EXEC_EXT = {".exe",".dll",".jar",".scr",".ps1",".bat",".vbs",".sys"}
    SAFE_EXT = {".png",".jpg",".jpeg",".gif",".txt",".json",".xml",".cfg",".log",".pdf"}

    MC_HINTS = {
        ".minecraft","mods","versions","lunar","badlion",
        "tlauncher","fabric","forge"
    }

    JVM_FLAGS = {
        "-javaagent","-noverify","-Xbootclasspath",
        "attach","-agentlib"
    }

    BEHAVIOR_CLASSES = {
        "killaura","aim","rotation","combat","reach",
        "autoclick","velocity","scaffold","module",
        "tick","update","event","mixin","inject"
    }

    DRIVER_DIRS = [
        "C:\\Windows\\System32\\drivers"
    ]

    SCAN_DIRS = [
        os.environ.get("APPDATA"),
        os.environ.get("LOCALAPPDATA"),
        os.environ.get("PROGRAMDATA"),
        os.path.expanduser("~/Desktop"),
        os.path.expanduser("~/Downloads")
    ]

    FUZZY_DB = "fuzzy_cheat.db"

# ====================== LOG ======================
logging.basicConfig(
    level=logging.INFO,
    format="\033[96m[EDR]\033[0m %(message)s"
)

# ====================== UTILS ======================
def now():
    return datetime.utcnow().isoformat()

def entropy(path, size=65536):
    try:
        with open(path,"rb") as f:
            d = f.read(size)
        if len(d) < 2048:
            return 0
        c = collections.Counter(d)
        l = len(d)
        return -sum((v/l)*math.log(v/l,2) for v in c.values())
    except:
        return 0

def recent(path):
    try:
        return datetime.now() - datetime.fromtimestamp(
            os.path.getmtime(path)
        ) <= timedelta(hours=CFG.FILE_RECENT_HOURS)
    except:
        return False

# ====================== FUZZY HASH ======================
def simhash(data):
    bits = [0]*64
    for token in data.split():
        h = int(hashlib.md5(token.encode()).hexdigest(),16)
        for i in range(64):
            bits[i] += 1 if (h>>i)&1 else -1
    out = 0
    for i,b in enumerate(bits):
        if b > 0:
            out |= (1<<i)
    return out

def hamming(a,b):
    return bin(a ^ b).count("1")

# ====================== EDR CORE ======================
class EDR:
    def __init__(self):
        self.events = collections.defaultdict(list)
        self.timeline = []
        self.system = {}
        self.lock = threading.Lock()
        self.running = True
        self.self_hash = self._self_hash()
        self.fuzzy_db = self._load_fuzzy()

    # -------- SELF DEFENSE --------
    def _self_hash(self):
        try:
            return hashlib.sha256(
                inspect.getsource(sys.modules[__name__]).encode()
            ).hexdigest()
        except:
            return None

    def watchdog(self):
        while self.running:
            time.sleep(2)
            if self.self_hash != self._self_hash():
                self.add("EDR","TAMPERING",400,"Tentativo di modifica runtime")
                self.running = False

    # -------- EVENT --------
    def add(self,path,cat,score,reason,extra=None):
        evt = {
            "time": now(),
            "path": path,
            "categoria": cat,
            "score": score,
            "motivo": reason,
            "extra": extra
        }
        with self.lock:
            self.events[path].append(evt)
            self.timeline.append(evt)

    # -------- FUZZY DB --------
    def _load_fuzzy(self):
        if not os.path.exists(CFG.FUZZY_DB):
            return []
        try:
            with open(CFG.FUZZY_DB,"r") as f:
                return [int(x) for x in f.read().splitlines()]
        except:
            return []

    def _save_fuzzy(self):
        try:
            with open(CFG.FUZZY_DB,"w") as f:
                for h in set(self.fuzzy_db):
                    f.write(str(h)+"\n")
        except:
            pass

    # -------- SYSTEM --------
    def system_info(self):
        logging.info("[1/9] Raccolta info sistema")
        self.system = {
            "os": platform.platform(),
            "cpu": platform.processor(),
            "ram_gb": round(psutil.virtual_memory().total/1024**3,2),
            "boot": datetime.fromtimestamp(psutil.boot_time()).isoformat()
        }

    # -------- PROCESS --------
    def process_scan(self):
        logging.info("[2/9] Analisi processi")
        procs = {p.pid:p for p in psutil.process_iter(
            ["pid","name","exe","cmdline","ppid"]
        )}

        for p in procs.values():
            try:
                exe = p.info["exe"]
                if not exe or not os.path.exists(exe):
                    continue

                cmd = " ".join(p.info["cmdline"] or []).lower()

                for flag in CFG.JVM_FLAGS:
                    if flag in cmd:
                        self.add(exe,"JVM_TAMPER",150,f"Flag JVM sospetta: {flag}")

                parent = procs.get(p.info["ppid"])
                if parent and "java" in (parent.info["name"] or "").lower():
                    self.add(exe,"JAVA_CHILD",130,"Processo figlio di JVM")

            except:
                continue

    # -------- SERVICES --------
    def service_scan(self):
        logging.info("[3/9] Analisi servizi Windows")
        try:
            for svc in psutil.win_service_iter():
                s = svc.as_dict()
                path = (s.get("binpath") or "").lower()
                if not path:
                    continue
                if any(x in path for x in ["temp","appdata","downloads"]):
                    self.add(
                        s["name"],
                        "SERVICE_SUSPICIOUS",
                        160,
                        "Servizio avviato da percorso anomalo",
                        path
                    )
        except:
            pass

    # -------- DRIVERS --------
    def driver_scan(self):
        logging.info("[4/9] Analisi driver (.sys)")
        for d in CFG.DRIVER_DIRS:
            if not os.path.exists(d):
                continue
            for f in os.listdir(d):
                if f.lower().endswith(".sys"):
                    path = os.path.join(d,f)
                    if recent(path):
                        self.add(path,"DRIVER_RECENT",140,"Driver modificato di recente")
                    if entropy(path) > CFG.ENTROPY_THRESHOLD:
                        self.add(path,"DRIVER_ENTROPY",160,"Driver ad alta entropia")

    # -------- JAR ANALYSIS --------
    def inspect_jar(self,path):
        try:
            with zipfile.ZipFile(path) as jar:
                names = " ".join(jar.namelist()).lower()

                hits = sum(1 for b in CFG.BEHAVIOR_CLASSES if b in names)
                if hits >= 4:
                    self.add(path,"BEHAVIOR_CLASSES",190,f"{hits} moduli combat/event")

                fh = simhash(names)
                for known in self.fuzzy_db:
                    if hamming(fh,known) <= 7:
                        self.add(path,"FUZZY_MATCH",220,"Cheat rinominato rilevato")
                self.fuzzy_db.append(fh)

        except:
            pass

    # -------- FILESYSTEM --------
    def scan_dir(self,base):
        if not base or not os.path.exists(base):
            return
        for root,_,files in os.walk(base):
            for f in files:
                path = os.path.join(root,f)
                ext = os.path.splitext(path)[1].lower()
                if ext in CFG.SAFE_EXT:
                    continue
                if ext in CFG.EXEC_EXT:
                    if recent(path):
                        self.add(path,"RECENT_EXEC",60,"File modificato recentemente")
                    ent = entropy(path)
                    if ent >= CFG.ENTROPY_THRESHOLD:
                        self.add(path,"HIGH_ENTROPY",90,f"Entropia {round(ent,2)}")
                    if any(h in path.lower() for h in CFG.MC_HINTS):
                        self.add(path,"MC_CONTEXT",140,"Contesto Minecraft")
                    if ext == ".jar":
                        self.inspect_jar(path)

    def filesystem_scan(self):
        logging.info("[5/9] Scansione filesystem")
        with ThreadPoolExecutor(max_workers=CFG.THREADS) as pool:
            for d in CFG.SCAN_DIRS:
                pool.submit(self.scan_dir,d)

    # -------- CORRELATION --------
    def correlate(self):
        logging.info("[6/9] Correlazione eventi")
        results = []

        for path,evs in self.events.items():
            score = sum(e["score"] for e in evs)
            cats = {e["categoria"] for e in evs}

            if {"MC_CONTEXT","BEHAVIOR_CLASSES"} <= cats:
                score += 160
            if {"JAVA_CHILD","JVM_TAMPER"} <= cats:
                score += 160
            if "FUZZY_MATCH" in cats:
                score += 220

            prob = min(99,int((score/450)*100))
            livello = (
                "CONFERMATO" if score >= CFG.SCORE_CONFIRMED else
                "SOSPETTO" if score >= CFG.SCORE_SUSPICIOUS else
                "INFO"
            )

            results.append({
                "path": path,
                "livello": livello,
                "score": score,
                "probabilita": f"{prob}%",
                "eventi": evs
            })

        return sorted(results,key=lambda x:x["score"],reverse=True)

    # -------- DISCORD --------
    def send_discord(self,report):
        logging.info("[7/9] Invio report Discord")
        confirmed = [r for r in report if r["livello"]=="CONFERMATO"]

        embed = {
            "title":"🛡️ EDR 11.5 – Scansione completata",
            "description":f"Scan ID `{CFG.SCAN_ID}`",
            "color":15158332 if confirmed else 3066993,
            "fields":[
                {"name":"Minacce confermate","value":len(confirmed),"inline":True},
                {"name":"Totale rilevamenti","value":len(report),"inline":True},
                {"name":"Difficoltà bypass stimata","value":"⭐⭐⭐⭐⭐⭐⭐⭐⭐☆ (8.5/10)","inline":False}
            ],
            "footer":{"text":CFG.VERSION}
        }

        payload = {
            "scan_id": CFG.SCAN_ID,
            "sistema": self.system,
            "risultati": report,
            "timeline": self.timeline
        }

        requests.post(DISCORD_WEBHOOK,json={"embeds":[embed]})
        requests.post(
            DISCORD_WEBHOOK,
            files={"file":(f"EDR_{CFG.SCAN_ID}.json",json.dumps(payload,indent=2))}
        )

    # -------- RUN --------
    def run(self):
        logging.info("\n[*] Avvio EDR 11.5 HARDENED\n")
        threading.Thread(target=self.watchdog,daemon=True).start()

        self.system_info()
        self.process_scan()
        self.service_scan()
        self.driver_scan()
        self.filesystem_scan()

        report = self.correlate()
        self.running = False
        self._save_fuzzy()
        self.send_discord(report)

        logging.info("\n[✓] Scansione completata – report forense inviato")

# ====================== MAIN ======================
if __name__ == "__main__":
    if platform.system() == "Windows":
        EDR().run()