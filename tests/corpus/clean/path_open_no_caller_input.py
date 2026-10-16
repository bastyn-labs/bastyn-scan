"""Files opened at a joined or interpolated path where no non-literal part
of the path can be supplied by a caller: a loop variable over a directory
listing, a generated name, a value read from a local settings file, and
instance state. BAS-LLM10-012 reports nothing for these."""

import json
import os
import uuid

OUTPUT_DIR = os.getcwd()


def summarize_reports() -> int:
    total = 0
    for name in sorted(os.listdir(OUTPUT_DIR)):
        if not name.endswith(".json"):
            continue
        with open(os.path.join(OUTPUT_DIR, name)) as handle:
            total += len(json.load(handle))
    return total


def write_scratch_file(payload: str) -> str:
    scratch = f"scratch-{uuid.uuid4().hex}.txt"
    with open(os.path.join(OUTPUT_DIR, scratch), "w") as handle:
        handle.write(payload)
    return scratch


def read_from_configured_dir() -> str:
    with open("settings.json") as settings_file:
        settings = json.load(settings_file)
    with open(os.path.join(settings["data_dir"], "index.txt")) as handle:
        return handle.read()


class Archive:
    def __init__(self) -> None:
        self.root = os.getcwd()

    def read_index(self) -> str:
        with open(os.path.join(self.root, "index.txt")) as handle:
            return handle.read()
