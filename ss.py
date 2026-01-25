# ============================================================
# EDR 12.0 – HARDENED USER-LAND DETECTION
# ============================================================

import os, sys, time, json, math, zipfile, psutil, hashlib, platform
import threading, collections, inspect, requests
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor

# ====================== DISCORD ======================
DISCORD_WEBHOOK = "https://discord.com/api/webhooks/XXXXXXXX"

# ====================== LOGGING ======================
class Log:
    @staticmethod
    def phase(t): print(f"\n\033[96m[▶] {t}\033[0m")
    @staticmethod
    def ok(t): print(f"\033[92m[✓] {t}\033[0m")
    @staticmethod
    def warn(t): print(f"\033[93m[!] {t}\033[0m")
    @staticmethod
    def bad(t): print(f"\033[91m[✗] {t}\033[0m")
    @staticmethod
    def info(t): print(f"\033[94m[i] {t}\033[0m")

# ====================== CONFIG ======================
class CFG:
    VERSION = "12.0.0-HARDENED"
    SCAN_ID = hashlib.sha256(str(time.time()).encode()).hexdigest()[:10]

    THREADS = 12
    ENTROPY_HIGH = 7.2
    RECENT_HOURS = 168

    SCORE_CONFIRMED = 250
    SCORE_SUSPICIOUS = 120

    EXEC_EXT = {".exe",".dll",".jar",".scr",".ps1",".bat",".vbs"}
    SAFE_EXT = {".txt",".png",".jpg",".json",".xml",".cfg",".log"}

    JVM_FLAGS = {"-javaagent","-noverify","-Xbootclasspath","attach"}

    CHEAT_SIGNATURES = {
        "liquidbounce": [
            "net/ccbluex/liquidbounce",
            "liquidbounce",
            "killaura",
            "autoclicker",
            "reach"
        ],
        "wurst": ["net/wurstclient","wurst","flight","aimassist"],
        "impact": ["impactclient","baritone","aimassist"],
        "sigma": ["sigma","monsoon","elytrafly"]
    }

    MC_HINTS = {".minecraft","mods","versions","lunar","badlion","tlauncher"}

    SCAN_DIRS = [
        os.environ.get("APPDATA"),
        os.environ.get("LOCALAPPDATA"),
        os.environ.get("PROGRAMDATA"),
        os.path.expanduser("~/Downloads"),
        os.path.expanduser("~/Desktop")
    ]

# ====================== UTILS ======================
def now(): return datetime.utcnow().isoformat()

def entropy(path, size=65536):
    try:
        with open(path,"rb") as f:
            data = f.read(size)
        if len(data) < 2048: return 0
        freq = collections.Counter(data)
        l = len(data)
        return -sum((v/l)*math.log(v/l,2) for v in freq.values())
    except:
        return 0

def recent(path):
    try:
        return datetime.now() - datetime.fromtimestamp(os.path.getmtime(path)) < timedelta(hours=CFG.RECENT_HOURS)
    except:
        return False

def is_valid_exe(path):
    try:
        with open(path,"rb") as f:
            return f.read(2) == b"MZ"
    except:
        return False

# ====================== CORE ======================
class EDR:
    def __init__(self):
        self.events = collections.defaultdict(list)
        self.timeline = []
        self.system = {}
        self.lock = threading.Lock()
        self.self_hash = self._hash_self()
        self.running = True

    def _hash_self(self):
        try:
            return hashlib.sha256(inspect.getsource(sys.modules[__name__]).encode()).hexdigest()
        except:
            return None

    def add(self, target, cat, score, reason):
        e = {
            "time": now(),
            "target": target,
            "category": cat,
            "score": score,
            "reason": reason
        }
        with self.lock:
            self.events[target].append(e)
            self.timeline.append(e)

    # ================= SYSTEM =================
    def system_info(self):
        Log.phase("Raccolta informazioni sistema")
        self.system = {
            "os": platform.platform(),
            "cpu": platform.processor(),
            "ram_gb": round(psutil.virtual_memory().total/1024**3,2),
            "boot": datetime.fromtimestamp(psutil.boot_time()).isoformat()
        }
        Log.ok("Sistema analizzato")

    # ================= PROCESS =================
    def process_scan(self):
        Log.phase("Analisi processi")
        for p in psutil.process_iter(["name","exe","cmdline","ppid"]):
            try:
                name = (p.info["name"] or "").lower()
                cmd = " ".join(p.info["cmdline"] or []).lower()

                if "java" in name:
                    for f in CFG.JVM_FLAGS:
                        if f in cmd:
                            self.add(name,"JVM_TAMPER",180,f"Flag JVM sospetto: {f}")

                if p.info["exe"] and p.info["exe"].lower().endswith(".exe"):
                    if not is_valid_exe(p.info["exe"]):
                        self.add(p.info["exe"],"FAKE_EXE",250,"EXE non valido")

            except:
                continue
        Log.ok("Processi completati")

    # ================= JAR =================
    def inspect_jar(self, path):
        try:
            with zipfile.ZipFile(path) as jar:
                names = " ".join(jar.namelist()).lower()
                for cheat, sigs in CFG.CHEAT_SIGNATURES.items():
                    hits = sum(1 for s in sigs if s in names)
                    if hits >= 2:
                        self.add(path,"CHEAT_CONFIRMED",320,f"{cheat} ({hits} firme)")
        except:
            pass

    # ================= FILESYSTEM =================
    def scan_dir(self, base):
        if not base or not os.path.exists(base): return
        for root,_,files in os.walk(base):
            for f in files:
                path = os.path.join(root,f)
                ext = os.path.splitext(path)[1].lower()

                if ext in CFG.SAFE_EXT:
                    continue

                if ext in CFG.EXEC_EXT:
                    if recent(path):
                        self.add(path,"RECENT_EXEC",40,"File recente")

                    ent = entropy(path)
                    if ent >= CFG.ENTROPY_HIGH:
                        self.add(path,"HIGH_ENTROPY",90,f"Entropy {round(ent,2)}")

                    if any(h in path.lower() for h in CFG.MC_HINTS):
                        self.add(path,"MC_CONTEXT",120,"Ambiente Minecraft")

                    if ext == ".jar":
                        self.inspect_jar(path)

    def filesystem_scan(self):
        Log.phase("Scansione filesystem")
        with ThreadPoolExecutor(max_workers=CFG.THREADS) as exe:
            for d in CFG.SCAN_DIRS:
                exe.submit(self.scan_dir,d)
        Log.ok("Filesystem completato")

    # ================= CORRELATION =================
    def correlate(self):
        Log.phase("Correlazione eventi")
        results=[]
        for t, evs in self.events.items():
            score = sum(e["score"] for e in evs)
            if score < 80:
                continue
            lvl = "CONFIRMED" if score >= CFG.SCORE_CONFIRMED else "SUSPICIOUS"
            prob = min(99, int((score/400)*100))
            results.append({
                "target": t,
                "livello": lvl,
                "score": score,
                "probabilita": f"{prob}%",
                "eventi": evs
            })
        Log.ok(f"{len(results)} rilevamenti rilevanti")
        return sorted(results,key=lambda x:x["score"],reverse=True)

    # ================= DISCORD =================
    def send_discord(self, report):
        Log.phase("Invio report Discord")
        embed = {
            "title":"🛡️ EDR 12.0 – Scansione completata",
            "description":f"Scan ID `{CFG.SCAN_ID}`",
            "color":15158332 if any(r["livello"]=="CONFIRMED" for r in report) else 3066993,
            "fields":[
                {"name":"Totale rilevamenti","value":str(len(report)),"inline":True},
                {"name":"Confermati","value":str(sum(1 for r in report if r["livello"]=="CONFIRMED")),"inline":True}
            ],
            "footer":{"text":CFG.VERSION}
        }

        payload = {
            "scan_id": CFG.SCAN_ID,
            "system": self.system,
            "results": report,
            "timeline": self.timeline
        }

        requests.post(DISCORD_WEBHOOK, json={"embeds":[embed]})
        requests.post(
            DISCORD_WEBHOOK,
            files={"file":(f"EDR_{CFG.SCAN_ID}.json", json.dumps(payload,indent=2))}
        )
        Log.ok("Report inviato")

    # ================= RUN =================
    def run(self):
        Log.phase("Avvio EDR")
        self.system_info()
        self.process_scan()
        self.filesystem_scan()
        report = self.correlate()
        self.send_discord(report)
        Log.ok("Scansione terminata")

# ====================== MAIN ======================
if __name__ == "__main__":
    if platform.system() == "Windows":
        EDR().run()
    else:
        print("Solo Windows")