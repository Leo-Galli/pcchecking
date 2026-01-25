import os, platform, time, hashlib, psutil, math, collections, json, logging, subprocess, csv, requests
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

DISCORD_WEBHOOK = "https://discord.com/api/webhooks/1464939014787436741/W_vdUtu_JZTETx0GYz4iyZoOTnMKYyH6RU6oZnGbzz5rEAQOhuKLqyzX6QlRr-oPgsxx"

# ================= CONFIG =================
class CFG:
    VERSION = "2.0.0-FORENSIC-EDR-FINAL"
    SCAN_ID = hashlib.sha256(str(time.time()).encode()).hexdigest()[:12]

    ENTROPY_HIGH = 7.6
    THREADS = 8

    SAFE_EXT = {".png",".jpg",".jpeg",".gif",".txt",".json",".log",".xml",".css",".pdf"}
    TRUSTED_VENDORS = [
        "microsoft","windows","intel","amd","nvidia",
        "discord","google","mozilla","oracle","java","steam"
    ]

    CHEAT_KEYWORDS = [
        "liquidbounce","wurst","meteor","impact","sigma",
        "novoline","fdp","vape","autoclicker","aimassist"
    ]

# ================= LOG =================
logging.basicConfig(level=logging.INFO, format="%(message)s")

# ================= UTILS =================
def entropy(data):
    if len(data) < 2048: return 0
    c = collections.Counter(data)
    l = len(data)
    return -sum((v/l)*math.log(v/l,2) for v in c.values())

def sha256(p):
    try:
        h = hashlib.sha256()
        with open(p,"rb") as f:
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
        self.events = []
        self.system = {}
        self.software = []
        self.executables = []

    def add(self, level, category, path, reason, details):
        self.events.append({
            "level": level,
            "category": category,
            "path": path,
            "reason": reason,
            "details": details
        })

    # ---------- SYSTEM ----------
    def system_info(self):
        self.system = {
            "OS": platform.platform(),
            "CPU": platform.processor(),
            "RAM_GB": round(psutil.virtual_memory().total/1024**3,2),
            "BOOT_TIME": datetime.fromtimestamp(psutil.boot_time()).isoformat()
        }

    # ---------- INSTALLED SOFTWARE ----------
    def installed_software(self):
        try:
            import winreg
            paths = [
                r"Software\Microsoft\Windows\CurrentVersion\Uninstall",
                r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
            ]
            for root in [winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER]:
                for p in paths:
                    try:
                        with winreg.OpenKey(root,p) as k:
                            for i in range(winreg.QueryInfoKey(k)[0]):
                                sk = winreg.OpenKey(k, winreg.EnumKey(k,i))
                                try:
                                    name,_ = winreg.QueryValueEx(sk,"DisplayName")
                                    self.software.append(name)
                                except: pass
                    except: pass
        except: pass

    # ---------- EXECUTABLE VERIFICATION ----------
    def verify_executables(self):
        for p in psutil.process_iter(["pid","name","exe"]):
            try:
                exe = p.info["exe"]
                if not exe or not os.path.exists(exe): continue

                name = os.path.basename(exe).lower()
                h = sha256(exe)
                e = entropy(open(exe,"rb").read(65536))

                legit = whitelisted(exe) and e < CFG.ENTROPY_HIGH

                self.executables.append({
                    "name": name,
                    "path": exe,
                    "entropy": round(e,2),
                    "hash": h,
                    "legit": legit
                })

                if not legit and e > CFG.ENTROPY_HIGH:
                    self.add(
                        "LIKELY","EXECUTABLE",exe,
                        "Executable does not match expected legitimacy",
                        f"Entropy={e}"
                    )
            except: pass

    # ---------- FILESYSTEM ----------
    def filesystem(self):
        roots = [os.environ.get("APPDATA"), os.environ.get("LOCALAPPDATA")]
        for r in roots:
            if not r: continue
            for root,_,files in os.walk(r):
                if whitelisted(root): continue
                for f in files[:300]:
                    p = os.path.join(root,f)
                    ext = os.path.splitext(p)[1].lower()
                    name = f.lower()

                    for kw in CFG.CHEAT_KEYWORDS:
                        if kw in name:
                            self.add(
                                "CONFIRMED","CHEAT",p,
                                f"Cheat detected: {kw}",
                                "Known Minecraft cheat signature"
                            )

                    if ext in {".exe",".jar"}:
                        h = sha256(p)
                        if not h: continue
                        try:
                            e = entropy(open(p,"rb").read(65536))
                            if e > CFG.ENTROPY_HIGH:
                                self.add(
                                    "LIKELY","FILESYSTEM",p,
                                    "High entropy binary",
                                    f"Entropy={e}"
                                )
                        except: pass

    # ---------- REPORT ----------
    def build_report(self):
        return {
            "scan_id": CFG.SCAN_ID,
            "version": CFG.VERSION,
            "system": self.system,
            "installed_software": sorted(set(self.software)),
            "executables": self.executables,
            "events": self.events
        }

    # ---------- DISCORD ----------
    def send_discord(self, report):
        summary = {
            "CONFIRMED": len([e for e in self.events if e["level"]=="CONFIRMED"]),
            "LIKELY": len([e for e in self.events if e["level"]=="LIKELY"]),
            "INFO": len([e for e in self.events if e["level"]=="INFO"])
        }

        embed = {
            "title": "EDR Forensic Report",
            "description": f"Scan ID `{CFG.SCAN_ID}`",
            "color": 16711680,
            "fields": [
                {"name":"Confirmed","value":summary["CONFIRMED"],"inline":True},
                {"name":"Likely","value":summary["LIKELY"],"inline":True},
                {"name":"Info","value":summary["INFO"],"inline":True}
            ]
        }

        requests.post(DISCORD_WEBHOOK, json={"embeds":[embed]})

        requests.post(
            DISCORD_WEBHOOK,
            files={"file":("report.json", json.dumps(report,indent=2))}
        )

    # ---------- RUN ----------
    def run(self):
        logging.info("[+] EDR scan started")
        self.system_info()
        self.installed_software()
        self.verify_executables()
        self.filesystem()

        report = self.build_report()
        self.send_discord(report)
        logging.info("[+] Report sent to Discord")

# ================= RUN =================
if __name__ == "__main__":
    if platform.system() == "Windows":
        EDR().run()
