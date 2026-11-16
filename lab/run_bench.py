"""Run OMEGA fusion against the lab target and dump findings (accuracy bench)."""
import os
import sys
REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)
import json
from omega.scanning.fusion import fuse

out = fuse('http://127.0.0.1:8899', budget=400, allowlist=True)
fnd = out.get('findings') or []
print("ran:", len(out.get('ran') or []), "| findings:", len(fnd))
for f in fnd:
    print(f"  [{f.get('severity','?'):8}] ({f.get('verification','?'):10}) "
          f"{f.get('title','?')[:75]} @ {str(f.get('location','?'))[:45]}")
json.dump(out, open('/tmp/omega-fusion-lab.json', 'w'), default=str)
print("saved /tmp/omega-fusion-lab.json")
