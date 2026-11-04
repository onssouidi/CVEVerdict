import json, os, time, urllib.request
from dotenv import load_dotenv

CVES = ["CVE-2024-23647", "CVE-2006-2916", "CVE-2023-4863"]
load_dotenv()
KEY = os.environ.get("NVD_API_KEY")

for cve in CVES:
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve}"
    req = urllib.request.Request(url)
    if KEY:
        req.add_header("apiKey", KEY)
    with urllib.request.urlopen(req, timeout=30) as r:
        data = json.load(r)
    with open(f"fixtures/{cve}.json", "w") as f:
        json.dump(data, f, indent=2)
    time.sleep(7)  