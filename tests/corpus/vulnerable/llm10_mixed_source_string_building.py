"""A value built by string building keeps the provenance of every segment.

Each function builds a string from a traced external value (a model reply or a
fetched page) plus an untraced parameter. The traced segment survives the
building, so the finding is reported against the traced source.
"""

import sqlite3

import requests
from openai import OpenAI

client = OpenAI()
cursor = sqlite3.connect("incidents.db").cursor()


def ask(prompt):
    return client.chat.completions.create(model="m", max_tokens=100, messages=[{"role": "user", "content": prompt}])


def sql_percent_format(ticket, flag):
    """BAS-LLM10-003: a model reply and a parameter, joined by `%`, run as SQL."""
    reply = ask(ticket)
    query = "SELECT * FROM t WHERE a = '%s' AND b = '%s'" % (reply, flag)
    cursor.execute(query)


def sql_str_format(ticket, flag):
    """BAS-LLM10-003: a model reply and a parameter, joined by `.format`, run as SQL."""
    reply = ask(ticket)
    query = "SELECT * FROM t WHERE a = '{}' AND b = '{}'".format(reply, flag)
    cursor.execute(query)


def prompt_from_fetched_page(flag):
    """BAS-ZT4-001: a fetched page and a parameter, joined by f-strings, in instructions."""
    doc = requests.get("http://example.invalid/page").text
    note = f"{doc} {flag}"
    system_prompt = f"You are a bot. {note} and {flag}"
    return system_prompt
