import os, json, zipfile, psutil, winreg, tempfile, requests, hashlib
from datetime import datetime

# ================= CONFIG =================
DISCORD_WEBHOOK = "INSERISCI_WEBHOOK"
USER_HTML_IMAGE = "INSERISCI_IMMAGINE"

SCAN_ID = hashlib.sha1(str(datetime.now()).encode()).hexdigest()[:10]

# ====== DATABASE CHEAT CERTI ======
CHEAT_SOFTWARE = {
    "liquidbounce": "Minecraft cheat client (LiquidBounce)",
    "fdp": "Minecraft cheat client (FDP)",
    "rise": "Minecraft cheat client (Rise)",
    "novoline": "Minecraft cheat client (Novoline)",
    "vape": "Minecraft ghost client (Vape)",
    "wurst": "Minecraft hack client",
    "impact": "Minecraft hack client",
    "meteor": "Minecraft hack client",
    "aristois": "Minecraft hack client",
    "sigma": "Minecraft hack client",
    "horion": "Minecraft Bedrock cheat",
    "cheat engine": "Memory editor",
    "process hacker": "Advanced process inspector",
    "x64dbg": "Debugger",
    "extreme injector": "DLL Injector",
    "xenos": "DLL Injector",
    "autoclicker": "Autoclicker software",
    "op auto clicker": "Autoclicker",
    "gs auto clicker": "Autoclicker"
}

LB_NAMESPACES = [
    "net/ccbluex/liquidbounce",
    "liquidbounce/injection",
    "liquidbounce/utils",
    "liquidbounce/event"
]

# ================= CORE =================
class EDRScanner:
    def __init__(self):
        self.findings = []
        self.logs = []

    def log(self, msg):
        self.logs.append(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}")

    # ---------- INSTALLED SOFTWARE ----------
    def scan_installed(self):
        self.log("Scan software installati")
        paths = [
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
            r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
        ]
        for p in paths:
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, p) as k:
                    for i in range(winreg.QueryInfoKey(k)[0]):
                        try:
                            sk = winreg.OpenKey(k, winreg.EnumKey(k, i))
                            name, _ = winreg.QueryValueEx(sk, "DisplayName")
                            lname = name.lower()
                            for key, desc in CHEAT_SOFTWARE.items():
                                if key in lname:
                                    self.findings.append({
                                        "type": "Installed software",
                                        "name": name,
                                        "description": desc,
                                        "certainty": "100%"
                                    })
                        except:
                            pass
            except:
                pass

    # ---------- PROCESSI ATTIVI ----------
    def scan_processes(self):
        self.log("Scan processi attivi")
        for p in psutil.process_iter(['name', 'exe']):
            try:
                n = (p.info['name'] or "").lower()
                e = (p.info['exe'] or "").lower()
                for key, desc in CHEAT_SOFTWARE.items():
                    if key in n or key in e:
                        self.findings.append({
                            "type": "Running process",
                            "name": p.info['name'],
                            "path": p.info['exe'],
                            "description": desc,
                            "certainty": "100%"
                        })
            except:
                pass

    # ---------- MINECRAFT MODS ----------
    def scan_minecraft(self):
        self.log("Scan Minecraft mods")
        mods = os.path.join(os.environ.get("APPDATA",""), ".minecraft", "mods")
        if not os.path.isdir(mods):
            return
        for f in os.listdir(mods):
            if not f.lower().endswith(".jar"):
                continue
            try:
                with zipfile.ZipFile(os.path.join(mods, f)) as z:
                    names = [n.lower() for n in z.namelist()]
                    for ns in LB_NAMESPACES:
                        if any(ns in n for n in names):
                            self.findings.append({
                                "type": "Minecraft mod",
                                "name": "LiquidBounce",
                                "file": f,
                                "description": "LiquidBounce namespace rilevato",
                                "certainty": "100%"
                            })
            except:
                pass

    # ---------- REPORT ----------
    def build_reports(self):
        tmp = tempfile.gettempdir()
        log_path = os.path.join(tmp, f"scan_{SCAN_ID}.log")
        json_path = os.path.join(tmp, f"scan_{SCAN_ID}.json")
        html_path = os.path.join(tmp, f"scan_{SCAN_ID}.html")
        user_html = os.path.join(tmp, f"user_{SCAN_ID}.html")

        open(log_path, "w", encoding="utf-8").write(
            "\n".join(self.logs) + "\n\n" + json.dumps(self.findings, indent=2)
        )
        open(json_path, "w", encoding="utf-8").write(
            json.dumps(self.findings, indent=2)
        )

        # DASHBOARD STAFF
        html = f"""
        <html>
        <head>
        <style>
        body {{ background:#0d1117;color:#c9d1d9;font-family:Segoe UI;padding:30px }}
        .card {{ background:#161b22;padding:20px;margin:15px;border-radius:10px }}
        .red {{ border-left:6px solid #f85149 }}
        </style>
        </head>
        <body>
        <h1>EDR Forensic Dashboard</h1>
        <p>Scan ID: {SCAN_ID}</p>
        """

        for f in self.findings:
            html += f"""
            <div class="card red">
            <b>{f['name']}</b><br>
            Tipo: {f['type']}<br>
            Descrizione: {f['description']}<br>
            Certezza: {f['certainty']}
            </div>
            """

        html += "</body></html>"
        open(html_path, "w", encoding="utf-8").write(html)

        # HTML UTENTE
        open(user_html, "w", encoding="utf-8").write(f"""
        <html>
        <body style="background:#0b0b0b;color:white;text-align:center;font-family:Segoe UI">
        <img src="{USER_HTML_IMAGE}" style="width:90%;margin-top:20px">
        <h1>Grazie per la pazienza</h1>
        <p>Il controllo è stato completato.<br>
        L’esito è ora in visualizzazione dello staff.</p>
        </body>
        </html>
        """)

        return log_path, json_path, html_path, user_html

    # ---------- DISCORD ----------
    def send_discord(self, files):
        if not self.findings:
            return
        embeds = []
        for f in self.findings:
            embeds.append({
                "title": f["name"],
                "description": f"{f['description']}\nCertezza: {f['certainty']}",
                "color": 16711680
            })

        requests.post(DISCORD_WEBHOOK, json={
            "content": "@everyone **SCAN COMPLETATA – CHEAT CERTI RILEVATI**",
            "embeds": embeds[:10]
        })

        for f in files[:-1]:
            requests.post(DISCORD_WEBHOOK, files={"file": open(f, "rb")})

    # ---------- RUN ----------
    def run(self):
        self.scan_installed()
        self.scan_processes()
        self.scan_minecraft()
        files = self.build_reports()
        self.send_discord(files)
        os.startfile(files[-1])

# ================= START =================
EDRScanner().run()