#!/usr/bin/env python3
"""Reveal the next staged commit.

Reads .pipeline/manifest.json (an ordered list of steps).  Pops the first
step, materialises its files from .pipeline/blobs/ into their real paths, and
writes .pipeline/last_msg.txt with the commit message for the workflow to use.
When the manifest is empty it does nothing (workflow makes no commit).
"""
import json, os, shutil, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PIPE = os.path.join(ROOT, ".pipeline")
MAN  = os.path.join(PIPE, "manifest.json")
MSG  = os.path.join(PIPE, "last_msg.txt")


def main():
    with open(MAN, encoding="utf-8") as f:
        steps = json.load(f)
    if not steps:
        if os.path.exists(MSG):
            os.remove(MSG)
        print("pipeline empty")
        return
    step = steps.pop(0)
    if step.get("cleanup"):
        # final step: remove the drip machinery entirely
        shutil.rmtree(PIPE, ignore_errors=True)
        wf = os.path.join(ROOT, ".github", "workflows", "drip.yml")
        if os.path.exists(wf):
            os.remove(wf)
        os.makedirs(PIPE, exist_ok=True)
        with open(MSG, "w", encoding="utf-8") as f:
            f.write(step["msg"])
        return
    for item in step["files"]:
        src = os.path.join(PIPE, "blobs", item["blob"])
        dst = os.path.join(ROOT, item["path"])
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        shutil.copyfile(src, dst)
        os.remove(src)
    with open(MAN, "w", encoding="utf-8") as f:
        json.dump(steps, f, indent=2)
    with open(MSG, "w", encoding="utf-8") as f:
        f.write(step["msg"])
    print("revealed:", step["msg"])


if __name__ == "__main__":
    main()
