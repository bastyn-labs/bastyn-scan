"""Near-misses for string building that keeps a model reply's provenance.

An either-or choice between literals, a bound parameter and a prompt made only of
constants are not a model reply inside the built string.
"""

import sqlite3

from openai import OpenAI

ROLE = "an on-call assistant"
TONE = "concise"
SQL_A = "SELECT * FROM t WHERE a = 1"
SQL_B = "SELECT * FROM t WHERE a = 2"

client = OpenAI()
cursor = sqlite3.connect("incidents.db").cursor()


def ask(prompt):
    return client.chat.completions.create(model="m", max_tokens=100, messages=[{"role": "user", "content": prompt}])


def sql_either_or(flag):
    query = SQL_A if flag else SQL_B
    cursor.execute(query)


def sql_parameterised(ticket, flag):
    reply = ask(ticket)
    cursor.execute("SELECT * FROM t WHERE a = ? AND b = ?", (reply, flag))


def prompt_from_constants():
    system_prompt = f"You are a bot. {ROLE} and {TONE}"
    return system_prompt
