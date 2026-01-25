import os, platform, time, hashlib, psutil, math, collections, json, logging, subprocess, csv, requests
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

# ================= DISCORD =================
DISCORD_WEBHOOK = "https://discord.com/api/webhooks/1464939014787436741/W_vdUtu_JZTETx0GYz4iyZoOTnMKYyH6RU6oZnGbzz5rEAQOhuKLqyzX6QlRr-oPgsxx"

# ================= CONFIG =================
class CFG:
    VERSION = "2.6.0-FORENSIC-EDR-STABLE"
    SCAN_ID = hashlib.sha256(str(time.time()).encode()).hexdigest()[:12]

    THREADS = 8
    ENTROPY_HIGH = 7.6
    SCORE_CONFIRMED = 80
    SCORE_SUSPICIOUS = 40

    SAFE_EXT = {
        ".png",".jpg",".jpeg",".gif",".txt",".json",".log",
        ".xml",".css",".pdf",".mp3",".mp4",".ttf",".woff"
    }

    TRUSTED_VENDORS = [
        "microsoft","windows","intel","amd","nvidia",
        "discord","google","mozilla","oracle","java",
        "steam","logitech","razer","corsair"
    ]

    MINECRAFT_PATHS = [
        ".minecraft",
        "minecraft launcher",
        "tlauncher"
    ]

    CHEAT_KEYWORDS = [
        "liquidbounce","wurst","meteor","impact","sigma",
        "novoline","fdp","vape","rise","astolfo",
        "autoclicker","aimassist","reach","killaura"
    ]

# ================= LOG =================
logging.basicConfig(level=logging.INFO, format="%(message)s")

# ================= UTILS =================
def entropy(data):
    if len(data) < 2048:
        return 0
    c = collections.Counter(data)
    l = len(data)
    return -sum((v/l)*math.log(v/l,2) for v in c.values())

def sha256(path):
    try:
        h = hashlib.sha256()
        with open(path,"rb") as f:
            for b in iter(lambda:f.read(65536),b""):
                h.update(b)
        return h.hexdigest()
    except:
        return None

def whitelisted(path):
    p = path.lower()
    return any(v in p for v in CFG.TRUSTED_VENDORS)

# ================= EDR CORE =================
class EDR:
    def __init__(self):
        self.system = {}
        self.software = set()
        self.findings = collections.defaultdict(list)

    def add(self, path, category, score, reason):
        self.findings[path].append({
            "category": category,
            "score": score,
            "reason": reason
        })

    # ---------- SYSTEM ----------
    def system_info(self):
        self.system = {
            "os": platform.platform(),
            "cpu": platform.processor(),
            "ram_gb": round(psutil.virtual_memory().total/1024**3,2),
            "boot_time": datetime.fromtimestamp(psutil.boot_time()).isoformat()
        }

    # ---------- INSTALLED SOFTWARE ----------
    def installed_software(self):
        try:
            import winreg
            keys = [
                r"Software\Microsoft\Windows\CurrentVersion\Uninstall",
                r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
            ]
            for root in [winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER]:
                for path in keys:
                    try:
                        with winreg.OpenKey(root,path) as k:
                            for i in range(winreg.QueryInfoKey(k)[0]):
                                sk = winreg.OpenKey(k, winreg.EnumKey(k,i))
                                try:
                                    name,_ = winreg.QueryValueEx(sk,"DisplayName")
                                    self.software.add(name)
                                except: pass
                    except: pass
        except: pass

    # ---------- PROCESS SCAN ----------
    def process_scan(self):
        for p in psutil.process_iter(["name","exe","cmdline"]):
            try:
                exe = p.info["exe"]
                name = (p.info["name"] or "").lower()
                cmd = " ".join(p.info["cmdline"] or []).lower()

                if not exe or not os.path.exists(exe):
                    continue

                if "java" in name:
                    for kw in CFG.CHEAT_KEYWORDS:
                        if kw in cmd:
                            self.add(
                                exe,
                                "JAVA_PROCESS",
                                60,
                                f"Java process references cheat keyword: {kw}"
                            )
            except:
                pass

    # ---------- FILESYSTEM ----------
    def filesystem(self):
        roots = [
            os.environ.get("APPDATA"),
            os.environ.get("LOCALAPPDATA")
        ]

        for r in roots:
            if not r: continue
            for root,_,files in os.walk(r):
                if whitelisted(root):
                    continue

                for f in files[:400]:
                    p = os.path.join(root,f)
                    ext = os.path.splitext(p)[1].lower()
                    name = f.lower()

                    if ext in CFG.SAFE_EXT:
                        continue

                    for kw in CFG.CHEAT_KEYWORDS:
                        if kw in name:
                            self.add(
                                p,
                                "FILENAME",
                                45,
                                f"Cheat keyword in filename: {kw}"
                            )

                    if ext in {".exe",".jar"}:
                        try:
                            with open(p,"rb") as fd:
                                e = entropy(fd.read(65536))
                            if e > CFG.ENTROPY_HIGH and not whitelisted(p):
                                self.add(
                                    p,
                                    "ENTROPY",
                                    35,
                                    f"High entropy binary ({round(e,2)})"
                                )
                        except:
                            pass

                    for mc in CFG.MINECRAFT_PATHS:
                        if mc in p.lower() and ext == ".jar":
                            self.add(
                                p,
                                "MINECRAFT_MOD",
                                40,
                                "Jar inside Minecraft directory"
                            )

    # ---------- CORRELATION ----------
    def correlate(self):
        results = []
        for path, ev in self.findings.items():
            score = sum(e["score"] for e in ev)
            level = (
                "CONFIRMED" if score >= CFG.SCORE_CONFIRMED else
                "SUSPICIOUS" if score >= CFG.SCORE_SUSPICIOUS else
                "INFO"
            )
            results.append({
                "path": path,
                "level": level,
                "score": score,
                "evidence": ev
            })
        return sorted(results, key=lambda x:x["score"], reverse=True)

    # ---------- DISCORD ----------
    def send_discord(self, report):
        confirmed = [r for r in report if r["level"]=="CONFIRMED"]
        suspicious = [r for r in report if r["level"]=="SUSPICIOUS"]

        embed = {
            "title": "EDR Forensic Scan Completed",
            "description": f"Scan ID `{CFG.SCAN_ID}`",
            "color": 15158332 if confirmed else 3066993,
            "fields": [
                {"name":"Confirmed","value":len(confirmed),"inline":True},
                {"name":"Suspicious","value":len(suspicious),"inline":True},
                {"name":"Installed software","value":len(self.software),"inline":True}
            ],
            "footer":{"text":CFG.VERSION}
        }

        requests.post(DISCORD_WEBHOOK, json={"embeds":[embed]})

        requests.post(
            DISCORD_WEBHOOK,
            files={
                "file":(
                    f"EDR_{CFG.SCAN_ID}.json",
                    json.dumps({
                        "system": self.system,
                        "software": sorted(self.software),
                        "results": report
                    }, indent=2)
                )
            }
        )

    # ---------- RUN ----------
    def run(self):
        logging.info("[*] EDR scan started")
        self.system_info()
        self.installed_software()
        self.process_scan()
        self.filesystem()
        report = self.correlate()
        self.send_discord(report)
        logging.info("[+] Scan completed")

# ================= RUN =================
if __name__ == "__main__":
    if platform.system() == "Windows":
        EDR().run()