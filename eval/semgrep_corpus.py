"""
Positive-match corpus for the eight custom Semgrep rules in `.semgrep/rules.yml`.

This file MUST trigger every rule when scanned. The
`tests/test_semgrep_rules.py` test runs Semgrep against this file and asserts
the expected rule IDs fire. If you add a new rule, add a fixture here.

NOTHING IN THIS FILE IS EVER IMPORTED OR EXECUTED at runtime — these are
deliberately-broken patterns used only as a SAST corpus.
"""

import hashlib
import os
import pickle
import subprocess
import yaml
import requests


# Rule 1: ali-hardcoded-secret-assignment
API_KEY = "sk_live_AbCdEfGhIjKlMnOpQrStUvWx12345678"          # noqa
AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"   # noqa
client_secret = "abcdef0123456789abcdef0123456789"            # noqa


# Rule 2: ali-sql-injection-string-build
def vulnerable_sql_lookup(cursor, name):
    cursor.execute(f"SELECT * FROM users WHERE name = '{name}'")          # noqa
    cursor.executemany(f"INSERT INTO log VALUES ('{name}')", [])           # noqa
    cursor.execute("SELECT * FROM t WHERE x = '{}'".format(name))          # noqa


# Rule 3: ali-insecure-deserialisation
def insecure_deserialise(data, path):
    pickle.loads(data)              # noqa
    yaml.load(data)                 # noqa  (no Loader)
    yaml.load(open(path))           # noqa


# Rule 4: ali-web-framework-debug-enabled
DEBUG = True                        # noqa


def insecure_flask_run(app):
    app.run(host="0.0.0.0", debug=True)   # noqa


# Rule 5: ali-weak-password-hash
def weak_pw_hash(password):
    return hashlib.md5(password.encode()).hexdigest()    # noqa


def weak_pw_hash_sha1(password):
    return hashlib.sha1(password.encode()).hexdigest()   # noqa


# Rule 6: ali-ssrf-fstring-in-url
def fetch_user_avatar(host):
    return requests.get(f"http://{host}/avatar")          # noqa


# Rule 7: ali-command-injection
def shell_out(user_input):
    subprocess.run(f"echo {user_input}", shell=True)      # noqa
    os.system(f"ls {user_input}")                         # noqa


# Rule 8: ali-dynamic-code-evaluation
def evaluate_user_expr(expr):
    return eval(expr)                                     # noqa
