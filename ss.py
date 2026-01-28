
# ============================================================
# SCREENSHARE – Audit Tool (Terminal Edition)
# Versione: v3.0.0
# Server: CoralMC | Staff: CoralMC Staff
# Developed by: LeoGalli
# ============================================================

import os, sys, time, math, json, platform, ctypes, hashlib, threading, collections
from datetime import datetime, timedelta, timezone
from concurrent.futures import ThreadPoolExecutor

# ====================== DISCORD ======================
DISCORD_WEBHOOK = "https://discord.com/api/webhooks/1464939014787436741/W_vdUtu_JZTETx0GYz4iyZoOTnMKYyH6RU6oZnGbzz5rEAQOhuKLqyzX6QlRr-oPgsxx"

# ====================== COLORS ======================
class C:
    RESET="\033[0m"; BOLD="\033[1m"
    CYAN="\033[96m"; BLUE="\033[94m"
    GRAY="\033[90m"; GREEN="\033[92m"
    YELLOW="\033[93m"; RED="\033[91m"

# ====================== CONFIG ======================
class CFG:
    THREADS = 16
    ENTROPY_HIGH = 7.1
    RECENT_HOURS = 168

    EXEC_EXT = {".exe",".dll",".jar",".ps1",".bat",".scr",".sys"}
    SAFE_EXT = {".txt",".log",".json",".xml",".cfg",".png",".jpg",".jpeg",".md"}

    # Keyword intelligence (estesa)
    KEYWORDS = {
        # generic
        "cheat","hack","hacked","bypass","inject","injection","loader","mapper",
        # combat
        "killaura","aim","aimbot","trigger","reach","velocity","noslow",
        # macro / click
        "autoclick","auto_click","clicker","macro","doubleclick",
        # ghost
        "ghost","assist","legit","humanizer",
        # clients / mods
        "wurst","impact","meteor","aristois","sigma","rusherhack",
        "lunar","badlion","feather","liquid","rise","novoline",
        # technical
        "dll","overlay","hook","driver","agent","bootstrap","reflect","jni"
    }

    SCAN_DIRS = [
        os.environ.get("APPDATA"),
        os.environ.get("LOCALAPPDATA"),
        os.environ.get("TEMP"),
        "C:\\Windows\\Temp",
        "C:\\Windows\\Prefetch",
        os.path.expanduser("~\\.minecraft")
    ]

    SCORE_LEVELS = {
        "CLEAN": 0,
        "LOW_RISK": 60,
        "SUSPICIOUS": 150,
        "HIGH_RISK": 280,
        "CRITICAL": 420
    }

    # Hash whitelist (estratto – esempio). Se NON verificabile → flag.
    # In produzione: amplia con hash ufficiali verificati.
    SAFE_HASHES = {
        # Windows system (esempi)
        "f2c7bb8acc97f92e987a2d4087d021b1a4d8d2c98f1b1d6d1a8e9b9f0c4c9a1a",
        "9b0a2a9c6b9f6a4f0f7d1e3c2b9d4a8f6e1c2b7a9d0e4f6b8c1a2e3d4f5",
        # Java (esempi)
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        # Launcher noti (esempi)
        "3a7bd3e2360a3d80a6d2c6c8b8c5f9e7a6b5c4d3e2f1a0b9c8d7e6f5a4b3"
    }

# ====================== UI ======================
def clear(): os.system("cls" if os.name=="nt" else "clear")

def box(title, subtitle):
    w=88
    print("╔"+"═"*w+"╗")
    print("║"+title.center(w)+"║")
    print("║"+subtitle.center(w)+"║")
    print("╚"+"═"*w+"╝")

def sep(): print(f"{C.GRAY}{'─'*92}{C.RESET}")
def section(t):
    sep()
    print(f"{C.CYAN}{C.BOLD}▶ {t}{C.RESET}")
    sep()

def ok(t): print(f"{C.GREEN}✔ {t}{C.RESET}")
def warn(t): print(f"{C.YELLOW}⚠ {t}{C.RESET}")
def info(t): print(f"{C.BLUE}ℹ {t}{C.RESET}")
def err(t): print(f"{C.RED}✖ {t}{C.RESET}")
def wait(s=0.2): time.sleep(s)

# ====================== UTILS ======================
def entropy(path, size=65536):
    try:
        with open(path,"rb") as f: data=f.read(size)
        if len(data)<2048: return 0
        freq=collections.Counter(data); l=len(data)
        return -sum((v/l)*math.log(v/l,2) for v in freq.values())
    except: return 0

def recent(path):
    try:
        return datetime.now(timezone.utc) - datetime.fromtimestamp(
            os.path.getmtime(path), tz=timezone.utc
        ) < timedelta(hours=CFG.RECENT_HOURS)
    except: return False

def is_admin():
    try: return ctypes.windll.shell32.IsUserAnAdmin()
    except: return False

def risk_level(score):
    lvl="CLEAN"
    for k,v in CFG.SCORE_LEVELS.items():
        if score>=v: lvl=k
    return lvl

def sha256(path):
    try:
        h=hashlib.sha256()
        with open(path,"rb") as f:
            for b in iter(lambda:f.read(8192), b""): h.update(b)
        return h.hexdigest()
    except: return None

def deps_check():
    missing=[]
    try: import psutil
    except: missing.append("psutil")
    try: import requests
    except: missing.append("requests")
    return missing

# ====================== CORE ======================
class ScreenShare:
    def __init__(self):
        self.targets={}
        self.timeline=[]
        self.lock=threading.Lock()
        self.started=datetime.now(timezone.utc)

    def _init(self,t):
        if t not in self.targets:
            self.targets[t]={
                "score":0,
                "flags":0,
                "hits":collections.Counter(),
                "categories":set(),
                "events":[],
                "level":"CLEAN"
            }

    def add(self,target,cat,reason,score):
        with self.lock:
            self._init(target)
            tgt=self.targets[target]
            tgt["hits"][cat]+=1
            key=(cat,reason)
            if key not in {(e["category"],e["reason"]) for e in tgt["events"]}:
                evt={
                    "time":datetime.now(timezone.utc).isoformat(),
                    "category":cat,
                    "reason":reason,
                    "score":score
                }
                tgt["events"].append(evt)
                self.timeline.append({"target":target,**evt})
                tgt["categories"].add(cat)
            tgt["score"]+=score
            tgt["flags"]+=1
            tgt["level"]=risk_level(tgt["score"])

    # ---------------- PROCESS ----------------
    def process_scan(self):
        section("Process & JVM Scan")
        try: import psutil
        except:
            err("Dipendenza mancante: psutil"); return

        for p in psutil.process_iter(["name","exe","cmdline"]):
            try:
                name=(p.info.get("name") or "").lower()
                exe=p.info.get("exe") or "unknown"
                cmd=" ".join(p.info.get("cmdline") or []).lower()

                # JVM args sospetti
                if "java" in name and any(x in cmd for x in ("-javaagent","-xbootclasspath","-agentlib")):
                    self.add(exe,"JVM_ARG","Parametro JVM non standard",120)

                # Keyword intelligence
                hay=(name+" "+cmd)
                for k in CFG.KEYWORDS:
                    if k in hay:
                        self.add(exe,"PROCESS_KEYWORD",f"Keyword: {k}",70)
                        break
            except: pass

        ok("Process scan completato"); wait()

    # ---------------- FILESYSTEM ----------------
    def scan_dir(self,base):
        try:
            for entry in os.scandir(base):
                if entry.is_dir(follow_symlinks=False):
                    self.scan_dir(entry.path)
                else:
                    ext=os.path.splitext(entry.name)[1].lower()
                    if ext in CFG.SAFE_EXT: continue

                    low=entry.name.lower()
                    for k in CFG.KEYWORDS:
                        if k in low:
                            self.add(entry.path,"FILENAME_KEYWORD",f"Nome contiene '{k}'",60)
                            break

                    if ext in CFG.EXEC_EXT:
                        # Hash verification
                        h=sha256(entry.path)
                        if h:
                            if h in CFG.SAFE_HASHES:
                                pass  # verificato
                            else:
                                self.add(entry.path,"HASH_UNKNOWN","Hash non verificato",80)

                        self.add(entry.path,"EXECUTABLE","File eseguibile",25)
                        if recent(entry.path):
                            self.add(entry.path,"RECENT","File recente",40)
                        if entropy(entry.path)>=CFG.ENTROPY_HIGH:
                            self.add(entry.path,"ENTROPY","Entropy elevata",80)
        except: pass

    def filesystem_scan(self):
        section("Filesystem / Prefetch / Temp Scan")
        with ThreadPoolExecutor(CFG.THREADS) as ex:
            for d in CFG.SCAN_DIRS:
                if d and os.path.exists(d):
                    ex.submit(self.scan_dir,d)
        ok("Filesystem scan completato"); wait()

    # ---------------- MINECRAFT ----------------
    def minecraft_scan(self):
        section("Minecraft Scan")
        mc=os.path.expanduser("~\\.minecraft")
        if not os.path.exists(mc):
            info("Cartella .minecraft non trovata"); return
        for root,_,files in os.walk(mc):
            for f in files:
                low=f.lower()
                if f.endswith(".jar") and any(k in low for k in CFG.KEYWORDS):
                    self.add(os.path.join(root,f),"MC_MOD","Jar sospetto",100)
        ok("Minecraft scan completato"); wait()

    # ---------------- DISCORD ----------------
    def send_discord(self):
        if not DISCORD_WEBHOOK or "INSERISCI" in DISCORD_WEBHOOK:
            warn("Webhook Discord non configurato"); return
        try:
            import requests
            payload={
                "meta":{
                    "version":"3.0.0",
                    "started":self.started.isoformat(),
                    "ended":datetime.now(timezone.utc).isoformat()
                },
                "system":{
                    "os":platform.platform(),
                    "admin":is_admin()
                },
                "summary":{
                    "targets":len(self.targets),
                    "levels":collections.Counter(v["level"] for v in self.targets.values())
                },
                "targets":{
                    k:{**v,"categories":list(v["categories"]),
                       "hits":dict(v["hits"])}
                    for k,v in self.targets.items()
                },
                "timeline":self.timeline
            }

            requests.post(DISCORD_WEBHOOK,json={
                "embeds":[{
                    "title":"🛡️ SCREENSHARE – Audit Report",
                    "description":"Report completo (verdetto non mostrato all’utente)",
                    "color":5763719,
                    "fields":[
                        {"name":"Target analizzati","value":str(len(self.targets)),"inline":True},
                        {"name":"Admin","value":str(is_admin()),"inline":True}
                    ],
                    "footer":{"text":"CoralMC • Staff Audit • v3.0"}
                }]
            },timeout=5)

            requests.post(
                DISCORD_WEBHOOK,
                files={"file":("audit_report.json",
                json.dumps(payload,indent=2,ensure_ascii=False))}
            )
            ok("Report inviato a Discord")
        except:
            warn("Invio Discord fallito")

    # ---------------- RUN ----------------
    def run(self):
        self.process_scan()
        self.filesystem_scan()
        self.minecraft_scan()
        self.send_discord()
        section("Completato")
        info("Analisi terminata. Attendere indicazioni dello staff.")

# ====================== MAIN ======================
def main():
    clear()
    box("SCREENSHARE", "CoralMC • Staff Audit Tool v3.0")
    sep()

    missing=deps_check()
    if missing:
        warn(f"Dipendenze mancanti: {', '.join(missing)}")
        warn("Installa le dipendenze e riavvia.")
        return

    print(f"{C.GRAY}Comandi: start | whoami | checkadmin | exit{C.RESET}")
    sep()

    ss=None
    while True:
        cmd=input("> ").strip().lower()
        if cmd=="start":
            ss=ScreenShare()
            ss.run()
        elif cmd=="whoami":
            print(os.getlogin())
        elif cmd=="checkadmin":
            print("Admin" if is_admin() else "User")
        elif cmd=="exit":
            break
        time.sleep(0.3)

if __name__=="__main__":
    if platform.system()!="Windows":
        print("Solo Windows"); sys.exit(0)
    main()