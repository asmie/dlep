"""Fail closed if dependency changes invalidate the time advisory exception.

Input: cargo metadata --locked --all-features --format-version 1
"""

import json
import sys

metadata = json.load(sys.stdin)
packages = {package["id"]: package for package in metadata["packages"]}
time_packages = [package for package in packages.values() if package["name"] == "time"]
if len(time_packages) != 1 or time_packages[0]["version"] != "0.3.45":
    sys.exit("Review/remove the time exception in .cargo/audit.toml: its version changed")

time_id = time_packages[0]["id"]
for node in metadata["resolve"]["nodes"]:
    if node["id"] == time_id and not set(node["features"]) <= {"alloc", "std"}:
        sys.exit("time gained features outside the audited scope; its parser must remain disabled")
    if time_id in node["dependencies"] and packages[node["id"]]["name"] not in {"rcgen", "yasna"}:
        sys.exit("time gained a consumer outside certificate generation; review the audit exception")

print("time exception verified: 0.3.45, no parsing, certificate-generator dependencies only")
