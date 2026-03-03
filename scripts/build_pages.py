#!/usr/bin/env python3
import os, json

ROOT = os.path.dirname(os.path.dirname(__file__))
DATA = os.path.join(ROOT, "data", "latest.json")
DOCS = os.path.join(ROOT, "docs")
DATA_OUT = os.path.join(DOCS, "_data")
os.makedirs(DATA_OUT, exist_ok=True)

def main():
    try:
        with open(DATA, "r", encoding="utf-8") as f:
            latest = json.load(f)
    except Exception:
        latest = {"generated_at": "", "items": []}

    with open(os.path.join(DATA_OUT, "latest.json"), "w", encoding="utf-8") as f:
        json.dump(latest, f, indent=2, ensure_ascii=False)

    print("[pages] Wrote docs/_data/latest.json for Jekyll")

if __name__ == "__main__":
    main()
