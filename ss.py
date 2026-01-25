import os, platform, time, hashlib, psutil, math, collections, json, requests, webbrowser
from datetime import datetime

DISCORD_WEBHOOK = "https://discord.com/api/webhooks/1464939014787436741/W_vdUtu_JZTETx0GYz4iyZoOTnMKYyH6RU6oZnGbzz5rEAQOhuKLqyzX6QlRr-oPgsxx"
HEADER_IMAGE_URL = "https://coralmc.it/_next/static/media/logo.acbad3a9.png"

# ================= CONFIG =================
class CFG:
    VERSION = "2.1.0-FORENSIC-EDR-PRO"
    SCAN_ID = hashlib.sha256(str(time.time()).encode()).hexdigest()[:12]

    ENTROPY_HIGH = 7.6

    TRUSTED_VENDORS = [
        "microsoft","windows","intel","amd","nvidia",
        "discord","google","mozilla","oracle","java","steam"
    ]

    CONFIRMED_CHEATS = {
        "liquidbounce": ["liquidbounce", "lb.jar"],
        "wurst": ["wurst"],
        "meteor": ["meteor-client"],
        "impact": ["impact"],
        "sigma": ["sigma"],
        "fdp": ["fdpclient"],
        "novoline": ["novoline"],
        "vape": ["vape", "vapev4"]
    }

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
        self.confirmed = []
        self.suspicious = []
        self.system = {}

    def system_info(self):
        self.system = {
            "OS": platform.platform(),
            "BOOT": datetime.fromtimestamp(psutil.boot_time()).isoformat()
        }

    def minecraft_scan(self):
        mc = os.path.join(os.environ.get("APPDATA",""),".minecraft")
        if not os.path.exists(mc):
            return

        for root,_,files in os.walk(mc):
            low = root.lower()
            for cheat,patterns in CFG.CONFIRMED_CHEATS.items():
                if any(p in low for p in patterns):
                    self.confirmed.append({
                        "name": cheat,
                        "path": root,
                        "reason": "Known Minecraft cheat directory signature"
                    })

            for f in files:
                fl = f.lower()
                for cheat,patterns in CFG.CONFIRMED_CHEATS.items():
                    if any(p in fl for p in patterns):
                        self.confirmed.append({
                            "name": cheat,
                            "path": os.path.join(root,f),
                            "reason": "Known Minecraft cheat binary"
                        })

    def process_scan(self):
        for p in psutil.process_iter(["name","exe"]):
            try:
                exe = p.info["exe"]
                if not exe or not os.path.exists(exe): continue
                if whitelisted(exe): continue

                e = entropy(open(exe,"rb").read(65536))
                if e > CFG.ENTROPY_HIGH:
                    self.suspicious.append({
                        "path": exe,
                        "reason": f"High entropy executable ({round(e,2)})"
                    })
            except: pass

    def report(self):
        return {
            "scan_id": CFG.SCAN_ID,
            "version": CFG.VERSION,
            "system": self.system,
            "confirmed_cheats": self.confirmed,
            "suspicious": self.suspicious
        }

    def discord(self, report):
        if self.confirmed:
            fields = [{
                "name": c["name"].upper(),
                "value": f"{c['path']}\n{c['reason']}",
                "inline": False
            } for c in self.confirmed]
        else:
            fields = [{
                "name":"No confirmed cheats",
                "value":"System appears clean",
                "inline":False
            }]

        embed = {
            "title":"EDR Forensic Result",
            "description":f"Scan ID `{CFG.SCAN_ID}`",
            "color": 15158332 if self.confirmed else 3066993,
            "fields": fields
        }

        requests.post(DISCORD_WEBHOOK, json={"embeds":[embed]})
        requests.post(
            DISCORD_WEBHOOK,
            files={"file":("report.json", json.dumps(report,indent=2))}
        )

    def thank_you_html(self):
        html = f"""
        <html>
        <body style="background:#0d1117;color:#c9d1d9;font-family:Segoe UI;text-align:center;padding:40px">
            <img src="{HEADER_IMAGE_URL}" style="max-width:90%;border-radius:12px"><br><br>
            <h1>Grazie per la pazienza</h1>
            <p>L’esito del controllo è ora in fase di visualizzazione da parte dello staff.</p>
        </body>
        </html>
        """
        path = os.path.abspath("scan_completed.html")
        with open(path,"w",encoding="utf-8") as f:
            f.write(html)
        webbrowser.open(path)

    def run(self):
        print("[+] Scan started")
        self.system_info()
        self.minecraft_scan()
        self.process_scan()

        report = self.report()
        self.discord(report)

        if self.confirmed:
            print("[!] Confirmed detections found")

        self.thank_you_html()
        print("[+] Scan completed")

# ================= RUN =================
if __name__ == "__main__":
    if platform.system() == "Windows":
        EDR().run()
