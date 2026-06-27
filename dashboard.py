import json, os, time
from collections import Counter
from datetime import datetime
from colorama import Fore, init
init(autoreset=True)
LOG = "logs/honeypot_log.json"
ALR = "logs/alerts.json"

def logs():
    if not os.path.exists(LOG): return []
    with open(LOG) as f: return [json.loads(l) for l in f if l.strip()]

def alerts():
    if not os.path.exists(ALR): return []
    with open(ALR) as f: return json.load(f)

def run():
    try:
        while True:
            os.system("clear")
            lg = logs()
            al = alerts()
            ips = Counter(e["source_ip"] for e in lg)
            usr = Counter(e["username"] for e in lg)
            hi = [a for a in al if a.get("severity")=="HIGH"]
            print(Fore.CYAN + "="*50)
            print(Fore.CYAN + "  CYBERSECURITY DASHBOARD")
            print(Fore.CYAN + "="*50)
            print(Fore.WHITE + "  Total attempts : " + Fore.RED + str(len(lg)))
            print(Fore.WHITE + "  Unique IPs     : " + Fore.YELLOW + str(len(ips)))
            print(Fore.WHITE + "  HIGH alerts    : " + Fore.RED + str(len(hi)))
            print(Fore.WHITE + "  Total alerts   : " + Fore.YELLOW + str(len(al)))
            print(Fore.WHITE + "  TOP IPs")
            for ip,c in ips.most_common(5):
                print(Fore.RED + "  " + ip + Fore.YELLOW + " " + str(c))
            print(Fore.WHITE + "  TOP USERNAMES")
            for u,c in usr.most_common(5):
                print(Fore.CYAN + "  " + u + Fore.WHITE + " " + str(c))
            print(Fore.CYAN + "="*50)
            print(Fore.WHITE + "  Ctrl+C to stop")
            time.sleep(5)
    except KeyboardInterrupt:
        print("Dashboard stopped.")

run()
