"""eval/exec and yaml.load on text that traces to input this file does not control."""

import requests
import yaml


def run_snippet(snippet: str):
    return exec(compile(snippet.strip(), "<snippet>", "exec"))


def run_downloaded(url: str):
    body = requests.get(url).text
    exec(body)


def parse_settings(text: str):
    return yaml.load(text.strip())


def parse_settings_unsafe_loader(text: str):
    return yaml.load(text, Loader=yaml.UnsafeLoader)
