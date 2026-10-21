#!/usr/bin/env python3
"""Access register for scheduled AI agents: what each one can read, write, send, and reach.

Reads the permission config a fleet of scheduled Claude Code agents actually runs
under, reads each agent's instructions, and diffs the result against a written
acceptable-use policy.

Every capability carries one of two labels:

    declared   it is in permission config: an allow rule, a per-task approval,
               the task's working directory, its permission mode
    inferred   it was read out of free text: the task's SKILL.md, or a script
               that SKILL.md tells the agent to run (one hop, no further)

When the config names a source of run records, a just-in-time pass
(jit_pass.py) adds a third, observed: what each agent's runs actually used,
read from their transcripts, sorted into grants every run uses and grants only
some runs use.

Three rules hold everywhere below:

    1. Unknown stays unknown. An unreadable file is never an empty one, and
       "nothing detected" is never "nothing there".
    2. A warning is not the offense. "Do not post to Slack" is recorded as a
       prohibition the instructions make, not as a Slack capability.
    3. No secret value is ever printed. Secret-shaped strings are reported by
       file, line, and length only, and are masked wherever rule text is shown.

Usage:
    access_register.py --config register.config.json            write the page named in config
    access_register.py --config ... --out page.html --json r.json
    access_register.py --config ... --no-runs                  skip the just-in-time pass
    access_register.py --render-policy policy/acceptable-use.json   rewrite the .md beside it

Exit codes: 0 nothing config allows that policy forbids; 1 at least one such
finding; 2 an input couldn't be read, so the register is incomplete.
"""

import argparse
import fnmatch
import glob as globmod
import html
import json
import os
import re
import shlex
import sys
from datetime import datetime

HERE = os.path.dirname(os.path.abspath(__file__))

DECLARED, INFERRED = "declared", "inferred"

DEFAULT_CONFIG = {
    "home": "~",
    "user_settings": ["~/.claude/settings.json"],
    "registry": "registry.json",
    "tasks_roots": ["~/.claude/scheduled-tasks"],
    "skills_root": "~/.claude/skills",
    "policy": os.path.join(HERE, "policy", "acceptable-use.json"),
    "exceptions": {},
    "credential_stores": [],
    "send_helpers": [],
    "mcp_servers": {},
    "hosts": {"discord.com": "discord", "ntfy.sh": "ntfy", "slack.com": "slack",
              "api.telegram.org": "telegram"},
    "cli_credentials": {"sf": "salesforce-cli", "sfdx": "salesforce-cli", "gh": "github-cli",
                        "ssh": "ssh-keys", "scp": "ssh-keys", "rsync": "ssh-keys",
                        "sftp": "ssh-keys"},
    "title": "Agent access register",
    "out": None,
    # run records for the just-in-time pass: {"sessions": glob, "transcripts_root": dir, "window_days": 30}
    "runs": None,
}

# Scripts bigger than this aren't scanned; the hop is reported as unread instead.
MAX_SCRIPT_BYTES = 400000


# --------------------------------------------------------------------------
# environment: every "~" goes through here, so tests and the demo can use a fake home
# --------------------------------------------------------------------------

class Env:
    def __init__(self, home):
        self.home = os.path.abspath(os.path.expanduser(home))

    def expand(self, path):
        if path is None:
            return None
        if path == "~":
            return self.home
        if path.startswith("~/"):
            return os.path.join(self.home, path[2:])
        return path

    def tilde(self, path):
        if not path:
            return path
        if path == self.home:
            return "~"
        if path.startswith(self.home + "/"):
            return "~" + path[len(self.home):]
        return path


def load_config(path):
    """Defaults overlaid by a JSON config. Relative paths resolve against the config's folder."""
    cfg = json.loads(json.dumps(DEFAULT_CONFIG))
    base = os.getcwd()
    if path:
        with open(path) as fh:
            user = json.load(fh)
        for key in ("hosts", "cli_credentials"):   # these extend the defaults instead of replacing them
            if key in user:
                user[key] = dict(cfg[key], **user[key])
        cfg.update(user)
        base = os.path.dirname(os.path.abspath(path))
    home = cfg["home"]
    if not home.startswith("~") and not os.path.isabs(home):
        home = os.path.normpath(os.path.join(base, home))
    env = Env(home)

    def res(p):
        if p is None:
            return None
        p = env.expand(p)
        return p if os.path.isabs(p) else os.path.normpath(os.path.join(base, p))

    cfg["user_settings"] = [res(p) for p in cfg["user_settings"]]
    cfg["tasks_roots"] = [res(p) for p in cfg["tasks_roots"]]
    for key in ("registry", "policy", "skills_root", "out"):
        cfg[key] = res(cfg[key])
    for store in cfg["credential_stores"]:
        store["path"] = res(store["path"])
    if cfg.get("runs"):
        for key in ("sessions", "transcripts_root"):
            if cfg["runs"].get(key):
                cfg["runs"][key] = res(cfg["runs"][key])
    return cfg, env


# --------------------------------------------------------------------------
# secrets: found by shape, reported by location, never printed
# --------------------------------------------------------------------------

_UUID = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
_VAL = r"[A-Za-z0-9_\-+/=.~%]"
_TOKEN = re.compile(r"(?<![A-Za-z0-9_\-+.])[A-Za-z0-9_\-+.]{16,}={0,2}(?![A-Za-z0-9_\-+.])")
# base64 with slashes in it: the plain token pattern stops at "/", so this one doesn't
_B64 = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{24,}={0,2}(?![A-Za-z0-9+/])")
_KNOWN_PREFIX = re.compile(r"\b(?:ghp_|gho_|ghs_|github_pat_|sk-|xox[abprs]-|AKIA)[A-Za-z0-9_\-]{12,}")
_SECRET_NAME = (r"(api[_-]?key|apikey|application[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|"
                r"token|secret|password|passwd|pwd|key|sig|signature)")
# name=value: the name is the evidence, so the value is masked whatever it looks like
_ASSIGN = re.compile(r"(?i)(?<![A-Za-z0-9])" + _SECRET_NAME + r"\s*=\s*[\"']?(" + _VAL + r"+)")
_PATHLIKE = re.compile(r"^(~/|/Users/|/home/|/tmp/|/private/|\./|https?:)")
# Below this length a masked value isn't reported as a finding. It is still masked: an allow
# rule can hold the first few characters of a key followed by a wildcard.
REPORT_MIN = 6
# name: value reads like prose more often, so the value has to look like a value
_COLON = re.compile(r"(?i)(?<![A-Za-z0-9])" + _SECRET_NAME + r"\s*:\s*[\"']?(" + _VAL + r"{8,})")
_SCHEME = re.compile(r"(?i)\b(bearer|bot|basic)\s+[\"']?(" + _VAL + r"{8,})")
_FILE_EXT = re.compile(r"\.(py|sh|json|jsonl|md|html|txt|csv|xlsx|pdf|js|ts|yml|yaml|plist|log|"
                       r"app|com|net|org|io|dev|ai|bak|png|jpg|zip)$", re.IGNORECASE)


def _mixed(s):
    """Has a digit, or both cases: what separates a value from a word."""
    return bool(re.search(r"\d", s) or (re.search(r"[a-z]", s) and re.search(r"[A-Z]", s)))


def _secret_shaped(tok):
    """True for a string that looks like a credential: long, mixed, not a name or a file."""
    if _UUID.search(tok) or "__" in tok:
        return False
    tok = _FILE_EXT.sub("", tok)   # an extension doesn't make the stem a name: "<token>.json" is still a token
    # Judge the pieces, not the whole: "Senior-Support-Manager_R12345" is long and
    # mixed but every piece is a word or a short id. A credential has at least one
    # long run that mixes letters and digits.
    for piece in re.split(r"[-_.+=/]", tok):
        digit = re.search(r"\d", piece)
        lower = re.search(r"[a-z]", piece)
        upper = re.search(r"[A-Z]", piece)
        if len(piece) >= 20 and digit and (lower or upper):
            return True
        if len(piece) >= 16 and digit and lower and upper:
            return True
    return False


def secret_spans(text):
    """(start, end, kind) for each secret-shaped stretch of text. Values stay in the caller.

    Errs toward masking. A masked filename costs a reader nothing; a printed token
    is the one mistake this tool can't take back.
    """
    spans = []
    for m in _KNOWN_PREFIX.finditer(text):
        spans.append((m.start(), m.end(), "known key prefix"))
    for m in _ASSIGN.finditer(text):
        val = m.group(2)
        if not _UUID.fullmatch(val) and not _PATHLIKE.match(val):
            spans.append((m.start(2), m.end(2), "value assigned to %s" % m.group(1).lower()))
    for m in _COLON.finditer(text):
        val = m.group(2)
        if (_mixed(val) or len(val) >= 20) and not _UUID.fullmatch(val) and not _FILE_EXT.search(val) \
                and not _PATHLIKE.match(val):
            spans.append((m.start(2), m.end(2), "value after %s:" % m.group(1).lower()))
    for m in _SCHEME.finditer(text):
        val = m.group(2)
        auth = "authorization" in text[max(0, m.start() - 24):m.start()].lower()
        if auth or (len(val) >= 16 and _mixed(val)):
            spans.append((m.start(2), m.end(2), "value after %s" % m.group(1).lower()))
    for m in _TOKEN.finditer(text):
        if _secret_shaped(m.group(0)):
            spans.append((m.start(), m.end(), "long mixed string"))
    for m in _B64.finditer(text):
        tok = m.group(0)
        if "/" in tok and not tok.startswith("/") and _secret_shaped(tok):
            spans.append((m.start(), m.end(), "long mixed string"))
    spans.sort()
    merged = []
    for s in spans:
        if merged and s[0] < merged[-1][1]:
            if s[1] > merged[-1][1]:
                merged[-1] = (merged[-1][0], s[1], merged[-1][2])
            continue
        merged.append(s)
    return merged


def mask(text):
    """Text with every secret-shaped stretch replaced. Nothing else is changed."""
    text = str(text)
    out, last = [], 0
    for start, end, _ in secret_spans(text):
        out.append(text[last:start])
        out.append("[masked %d chars]" % (end - start))
        last = end
    out.append(text[last:])
    return "".join(out)


def safe(text, limit=150):
    """Text fit to show: secrets masked first, then whitespace collapsed and long text cut."""
    text = " ".join(mask(text).split())
    return text if len(text) <= limit else text[:limit - 1] + "…"


# --------------------------------------------------------------------------
# permission rules
# --------------------------------------------------------------------------

_RULE = re.compile(r"^([A-Za-z_][\w\-]*)(?:\((.*)\))?$", re.S)
_INTERPRETERS = re.compile(r"^(python[\d.]*|node|bash|sh|zsh|osascript|perl|ruby|deno|bun|npx|"
                           r"uvx?|env|xargs|eval|sudo|pwsh|php|npm|pnpm|yarn)$")
_INLINE_CODE_FLAGS = ("-c", "-e", "-lc", "--eval", "-p", "--print", "-")
_RUNNER_WORDS = ("run", "exec", "x", "dlx")


def parse_rule(rule):
    """'Tool(content)' -> (tool, content). content is None for a bare tool name."""
    m = _RULE.match(rule.strip()) if isinstance(rule, str) else None
    if not m:
        return None, None
    return m.group(1), m.group(2)


def split_commands(text):
    """Split shell text at command separators, leaving quoted stretches whole.

    `grep -v "^| *|*$"` is one command; the pipes are inside a string. An
    unbalanced quote keeps everything after it together.
    """
    parts, buf, quote, i = [], [], None, 0
    while i < len(text):
        ch = text[i]
        if quote:
            buf.append(ch)
            if ch == "\\" and quote == '"' and i + 1 < len(text):
                buf.append(text[i + 1])
                i += 1
            elif ch == quote:
                quote = None
            i += 1
            continue
        if ch in "'\"":
            quote = ch
            buf.append(ch)
            i += 1
            continue
        m = _SPLIT.match(text, i)
        if m:
            parts.append("".join(buf))
            buf = []
            i = m.end()
            continue
        buf.append(ch)
        i += 1
    parts.append("".join(buf))
    return parts


def shell_tokens(segment):
    """One command segment as tokens, env assignments dropped. Falls back when quotes don't balance."""
    try:
        toks = shlex.split(segment)
    except ValueError:
        toks = segment.split()
    while toks and _ENV_ASSIGN.match(toks[0]):
        toks = toks[1:]
    return toks


def is_broad_exec(content):
    """A Bash rule that amounts to arbitrary code.

    Blanket rules, a bare * as any part of a compound rule, and an interpreter
    or package runner whose wildcard isn't pinned behind a named script:
    `python3 *`, `python3:*`, `python3 -c ' *`, `python3 -m *`, `uv run *`.
    `python3 ~/bin/send.py *` is not one; the wildcard there is arguments.
    """
    if content is None:
        return True
    if content.strip() in ("", "*", ":*"):
        return True
    for seg in split_commands(content):
        seg = seg.strip()
        if seg in ("*", ":*"):
            return True
        if "*" not in seg:
            continue          # a literal command is one fixed program, whatever it runs
        toks = shell_tokens(seg)
        if not toks:
            continue
        first = toks[0]
        head = os.path.basename(first).split(":")[0].rstrip("*")
        if not _INTERPRETERS.match(head):
            continue
        if first.endswith("*"):
            return True       # python3*, python3:*
        rest = toks[1:]
        if any(t in _INLINE_CODE_FLAGS for t in rest):
            return True
        named = [t for t in rest if not t.startswith("-") and t.strip("'\"*: ") and t not in _RUNNER_WORDS]
        if not named:
            return True
    return False


def glob_to_re(pattern):
    out, i = [], 0
    while i < len(pattern):
        if pattern.startswith("**/", i):
            out.append("(?:.*/)?")
            i += 3
        elif pattern.startswith("**", i):
            out.append(".*")
            i += 2
        elif pattern[i] == "*":
            out.append("[^/]*")
            i += 1
        elif pattern[i] == "?":
            out.append("[^/]")
            i += 1
        else:
            out.append(re.escape(pattern[i]))
            i += 1
    return re.compile("^" + "".join(out) + "$")


def pattern_covers(pattern, path):
    """Does an anchored gitignore-style pattern reach this path?

    A pattern that matches a directory covers everything under it, which is how
    gitignore reads it. That is the wider reading, and the wider reading is the
    one a register should take.
    """
    if not pattern:
        return False
    rx = glob_to_re(pattern.rstrip("/") or "/")
    p = path
    while True:
        if rx.match(p):
            return True
        parent = os.path.dirname(p)
        if parent == p:
            return False
        p = parent


def anchor(content, settings_dir, cwd, env):
    """Resolve a Read/Edit rule path to (absolute pattern or None, anchor kind)."""
    if content.startswith("//"):
        return content[1:], "absolute"
    if content == "~" or content.startswith("~/"):
        return env.expand(content), "home"
    if content.startswith("/"):
        return os.path.join(settings_dir, content[1:]), "settings-relative"
    rel = content[2:] if content.startswith("./") else content
    if not cwd:
        return None, "cwd-relative"
    if "/" not in rel:
        return os.path.join(cwd, "**", rel), "cwd-relative"
    return os.path.join(cwd, rel), "cwd-relative"


def static_prefix(pattern):
    """The directory part of a pattern before its first wildcard."""
    cut = len(pattern)
    for ch in "*?[":
        i = pattern.find(ch)
        if i >= 0:
            cut = min(cut, i)
    head = pattern[:cut]
    return head if cut == len(pattern) else os.path.dirname(head)


# --------------------------------------------------------------------------
# capabilities
# --------------------------------------------------------------------------

def cap(key, evidence, source, detail="", **extra):
    # Keys can carry a path or a redirect target lifted from rule text, so they're masked here,
    # at the one place capabilities are made.
    c = {"key": mask(key), "evidence": evidence, "source": source, "detail": detail}
    c.update(extra)
    return c


def column(key):
    """Which of the page's columns a capability key belongs in."""
    head = key.split(":", 1)[0]
    if head in ("send", "draft", "publish"):
        return "send"
    if head == "cred":
        return "cred"
    if head in ("write", "delete", "modify"):
        return "write"
    if head in ("read", "net", "web"):
        return "read"
    if head == "data":
        return "write" if key.endswith((":write", ":any")) else "read"
    return "other"


_MCP = re.compile(r"mcp__([A-Za-z0-9_\-]+?)__([A-Za-z0-9_\-]+)")
_BROWSER_SERVERS = re.compile(r"(?i)chrome|browser|computer-use|computer_use|playwright|puppeteer")
_MCP_VERBS = [
    ("send", re.compile(r"(?:^|_)(send|reply|forward|post|respond)(?:_|$)")),
    ("draft", re.compile(r"(?:^|_)(create|update)_draft")),
    ("delete", re.compile(r"(?:^|_)(delete|trash|remove|archive|purge)(?:_|$)")),
    ("modify", re.compile(r"(?:^|_)(create|update|label|unlabel|apply|mark|unmark|edit|upload|"
                          r"share|copy|save|set|write|add|move|run|generate|untrash)(?:_|$)")),
    ("read", re.compile(r"(?:^|_)(get|list|search|read|fetch|describe|query|lookup|info|"
                        r"volumes|report|cases|export|download|suggest)(?:_|$)")),
]


def mcp_label(server, servers):
    if server in servers:
        return servers[server]
    return server[:8] if _UUID.fullmatch(server) else server


def classify_mcp(name, servers):
    """An MCP tool name -> capability key. The verb comes from the tool's own name."""
    m = _MCP.fullmatch(name)
    if not m:
        return "mcp:%s" % name
    server, tool = m.group(1), m.group(2)
    label = mcp_label(server, servers)
    if _BROWSER_SERVERS.search(server):
        low = server.lower()
        return "browser:%s" % ("chrome" if "chrome" in low else "computer-use" if "computer" in low else label)
    low = tool.lower()
    for verb, rx in _MCP_VERBS:
        if rx.search(low):
            return "%s:%s" % (verb, label)
    return "mcp:%s:%s" % (label, tool)


_URL = re.compile(r"https?://([A-Za-z0-9.\-]+\.[A-Za-z]{2,})")
_METHOD = r"[\"']?(?:POST|PUT|PATCH|DELETE)\b"
# curl: a body flag alone or inside a cluster (-sSd, -sSX POST), or an explicit write method
_CURL_SEND = re.compile(r"(?:^|\s)(?:-[A-Za-z]*[dFT]\b|--data\S*|--form\S*|--upload-file\b|--json\b|"
                        r"(?:-[A-Za-z]*X|--request)[= ]?\s*" + _METHOD + ")")
_WGET_SEND = re.compile(r"(?:^|\s)(?:--post-data\S*|--post-file\S*|--body-data\S*|--body-file\S*|"
                        r"--method[= ]\s*" + _METHOD + ")")
_HTTPIE_SEND = re.compile(r"(?:^|\s)(?:POST|PUT|PATCH|DELETE)\b|(?:^|\s)(?:-f|--form|--multipart)\b|\s\S+:?=\S")
# && || ; | |& newline, and a lone & (background), but not the & in >&, &>, 2>&1
_SPLIT = re.compile(r"&&|\|\||;|\|&?|\n|(?<![>&\d])&(?![>&])")
_ENV_ASSIGN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=.*$", re.S)
_SF_WRITE = re.compile(r"\bsf(?:dx)?\s+(?:data\s+(?:update|create|delete|upsert|import|resume)|apex\s+run|"
                       r"project\s+deploy|org\s+(?:delete|create)|force:data:(?:record:(?:update|create|delete)|bulk))")
_SF_READ = re.compile(r"\bsf(?:dx)?\s+(?:data\s+(?:query|get|search|export)|sobject\s+(?:describe|list)|"
                      r"org\s+(?:list|display)|force:data:soql)")
_GH_API_WRITE = re.compile(r"(?:^|\s)(?:(?:-X|--method)[= ]?\s*" + _METHOD + r"|-f\b|-F\b|--field\b|--raw-field\b|--input\b)")
_GH_READ_VERBS = ("view", "list", "status", "diff", "checks", "watch")
_GH_READ_TOPS = ("search", "browse", "status")
_REDIRECT = re.compile(r"(?<![0-9&\-=<>])>>?\s*[\"']?([~$/.\w*][^\s;&|)\"']*)")
_WRITERS = ("tee", "cp", "mv", "install", "ln", "touch", "mkdir", "chmod", "chown", "truncate", "dd")
_SCRIPT_EXT = r"\.(?:py|sh|js|mjs)"
# an interpreter, any flags, then a script: by path, by ~ or $HOME, or by bare name
_SCRIPT_CALL = re.compile(r"(?:^|[\s`(\"'/])(?:python[\d.]*|bash|sh|zsh|node)(?:\s+-[\w\-]+)*\s+"
                          r"((?:~|\$HOME|\$\{HOME\}|\.{0,2}/|[\w.\-]+/)?[\w.\-/~${}]*" + _SCRIPT_EXT + r")\b")
_SCRIPT_DIRECT = re.compile(r"(?:^|[\s`])((?:~|\$HOME|\$\{HOME\}|/Users/[\w.\-]+|/home/[\w.\-]+)/[\w.\-/]+\.sh)\b")
_PATH = re.compile(r"(?:~|\$HOME|\$\{HOME\}|/Users/[\w.\-]+|/home/[\w.\-]+)/[\w.\-/@+*<>\[\]%]+")


def norm_path(raw):
    """A path as written in text -> ~/ form. Any /Users/<name>/ is read as the home folder."""
    p = re.sub(r"^(?:\$HOME|\$\{HOME\}|/Users/[\w.\-]+|/home/[\w.\-]+)/", "~/", raw)
    return p.rstrip(".,;:)]>*").rstrip("/") or "~"


def _pathish(tok):
    return tok.startswith(("~", "/", "$", ".")) or "/" in tok


class Classifier:
    """Turns command text into capability keys, using the config's helpers, hosts, and stores."""

    def __init__(self, cfg, env):
        self.env = env
        self.helpers = cfg["send_helpers"]
        self.hosts = cfg["hosts"]
        self.servers = cfg["mcp_servers"]
        self.cli_creds = cfg["cli_credentials"]
        self.stores = cfg["credential_stores"]
        # A store is recognised in text by its path under home, however home is spelled.
        self._store_tails = []
        for s in self.stores:
            tail = env.tilde(s["path"])
            tail = tail[2:] if tail.startswith("~/") else tail
            if len(tail) >= 6:
                self._store_tails.append((tail, s["id"]))

    def channel(self, host):
        host = host.lower()
        for known, name in self.hosts.items():
            if host == known or host.endswith("." + known):
                return name
        return None

    def text_wide(self, text):
        """Capabilities any text can show, command or not: helpers, store paths, MCP tool names.

        Returns (key, detail, position of the thing in text).
        """
        keys = []
        for h in self.helpers:
            pos = text.find(h["match"])
            if pos < 0:
                continue
            keys.append(("send:%s" % h["channel"], "helper %s" % h["match"], pos))
            if h.get("credential"):
                keys.append(("cred:%s" % h["credential"], "helper %s" % h["match"], pos))
        for tail, sid in self._store_tails:
            pos = text.find(tail)
            if pos >= 0:
                keys.append(("cred:%s" % sid, "names the store's path", pos))
        for m in _MCP.finditer(text):
            keys.append((classify_mcp(m.group(0), self.servers),
                         "tool %s__%s" % (mcp_label(m.group(1), self.servers), m.group(2)), m.start()))
        return keys

    def command(self, text, wild=False):
        """Capability (key, detail) pairs for shell command text.

        wild=True is for allow rules: a * in the rule is read the wide way, since
        the rule permits whatever the wildcard can stand for. Where a command
        can't be pinned to a read, it's reported as the wider thing.
        """
        keys = [(k, d) for k, d, _ in self.text_wide(text)]
        for seg in split_commands(text):
            toks = shell_tokens(seg.strip())
            if not toks:
                continue
            head = os.path.basename(toks[0].strip("\"'`")).split(":")[0].rstrip("*")
            body = " ".join(toks)
            args = [t for t in toks[1:] if not t.startswith("-")]
            open_ended = wild and "*" in body
            if len(toks) == 2 and toks[1] in ("--version", "-v", "--help", "-h", "version", "help"):
                continue   # asking a tool what it is touches nothing
            if head in ("curl", "wget", "http", "https"):
                send_rx = {"curl": _CURL_SEND, "wget": _WGET_SEND}.get(head, _HTTPIE_SEND)
                explicit = bool(send_rx.search(body))
                sends = explicit or open_ended
                hosts = _URL.findall(body)
                if not hosts:
                    keys.append(("send:http:any" if sends else "net:any",
                                 "%s with no fixed host" % head))
                for host in hosts:
                    ch = self.channel(host)
                    if sends:
                        why = "request body or write method" if explicit else "wildcard leaves room for a request body"
                        keys.append(("send:%s" % (ch or "http:" + host.lower()), "%s, %s" % (head, why)))
                    else:
                        keys.append(("net:%s" % host.lower(), "%s, no request body" % head))
            elif head in ("sf", "sfdx"):
                if _SF_WRITE.search(body):
                    keys.append(("data:salesforce:write", "sf write command"))
                elif _SF_READ.search(body) and not open_ended:
                    keys.append(("data:salesforce:read", "sf read command"))
                else:
                    keys.append(("data:salesforce:any", "sf command not limited to reads"))
            elif head == "gh":
                top = args[0] if args else None
                verb = args[1] if len(args) > 1 else None
                if top == "api":
                    reads = not _GH_API_WRITE.search(body) and not open_ended
                elif top in _GH_READ_TOPS:
                    reads = True
                elif top == "auth":
                    reads = verb in ("status",)
                else:
                    # only a named read verb is a read; a wildcard in the verb's place could be any verb
                    reads = verb in _GH_READ_VERBS
                keys.append(("read:github", "gh read command") if reads
                            else ("publish:github", "gh command that can write"))
            elif head == "git":
                rest, i = toks[1:], 0
                while i < len(rest) and rest[i].startswith("-"):
                    i += 2 if rest[i] in ("-C", "-c", "--git-dir", "--work-tree") else 1
                sub = rest[i] if i < len(rest) else None
                if sub == "push" or (open_ended and (sub is None or "*" in sub)):
                    keys.append(("publish:git-push", "git push" if sub == "push"
                                 else "wildcard sits where the git subcommand goes"))
            elif head in ("ssh", "scp", "rsync", "sftp"):
                keys.append(("exec:remote", "%s to another machine" % head))
            elif head == "osascript":
                keys.append(("exec:osascript", "AppleScript can drive any app"))
            elif head == "security":
                if re.search(r"find-(generic|internet)-password|dump-keychain|export", body) or \
                        (open_ended and (not args or "*" in args[0])):
                    keys.append(("cred:keychain", "security command that reads the keychain"))
            elif head == "launchctl":
                keys.append(("control:launchctl", "launchctl"))
            elif head == "sudo":
                keys.append(("exec:sudo", "sudo"))
            elif head in ("rm", "rmdir", "trash", "unlink", "shred"):
                sweeping = ("*" in body or "$" in body or len(args) != 1
                            or any(re.match(r"^-\w*[rR]", t) or t == "--recursive" for t in toks[1:]))
                keys.append(("delete:files" if sweeping else "delete:named-file",
                             "%s, %s" % (head, "recursive, wildcard, or several paths" if sweeping else "one named path")))
            elif head == "find":
                if re.search(r"(?:^|\s)-delete\b|-exec(?:dir)?\s+(?:rm|unlink|shred)\b", body):
                    keys.append(("delete:files", "find that deletes what it matches"))
            elif head in _WRITERS or (head == "sed" and any(re.match(r"^-\w*i", t) or t.startswith("--in-place")
                                                            for t in toks[1:])):
                target = args[-1] if args else None
                if target is None or "*" in target:
                    keys.append(("write:any", "%s, target not fixed" % head))
                elif _pathish(target):
                    keys.append(("write:%s" % norm_path(target), head))
                else:
                    keys.append(("write:%s" % target, "%s, relative to the working directory" % head))
            elif head == "open":
                keys.append(("exec:open", "open launches apps and URLs"))
            elif head == "claude":
                keys.append(("exec:agent", "starts another agent session"))
            elif _INTERPRETERS.match(head) and any(t in _INLINE_CODE_FLAGS for t in toks[1:3]):
                keys.append(("exec:interpreter", "%s with inline code" % head))
            if head in self.cli_creds:
                keys.append(("cred:%s" % self.cli_creds[head], "%s uses its stored login" % head))
            for m in _REDIRECT.finditer(seg):
                target = m.group(1)
                if target.startswith("/dev/") or target in ("&1", "&2"):
                    continue
                if target.startswith("*"):
                    keys.append(("write:any", "shell redirect to a wildcard"))
                elif _pathish(target) or "." in target:
                    keys.append(("write:%s" % (norm_path(target) if _PATH.match(target) else target),
                                 "shell redirect"))
        return keys


# --------------------------------------------------------------------------
# reading SKILL.md: instructions, prohibitions, and the scripts they point at
# --------------------------------------------------------------------------

_NEG = re.compile(r"(?i)\b(not|never|don't|dont|doesn't|avoid|without|instead of|rather than|"
                  r"cannot|can't|won't)\b|^\s*(?:[-*+]\s+)?no\b")
_LIST_ITEM = re.compile(r"^\s*([-*+]|\d+[.)])\s")
_SPAN = re.compile(r"`([^`\n]+)`")
# Where one statement ends and the next begins. Commas are handled apart, in negated_at.
_HARD = re.compile(r"[;!?()—–]|[.:](?=\s|$)| but | instead | otherwise | then ", re.IGNORECASE)

_WRITE_VERB = re.compile(r"(?i)\b(write|writes|written|save|saves|append|appends|update|updates|"
                         r"create|creates|overwrite|rewrite|log|logs|record|records|edit|render|"
                         r"renders|output|move|copy|back ?up|stamp|stamps|store|add|adds|put)\b")
_READ_VERB = re.compile(r"(?i)\b(read|reads|load|loads|open|check|list|scan|parse|look|from|"
                        r"see|consult|review|compare|fetch|pull)\b")

_PROSE = [
    ("send:email", re.compile(r"(?i)\b(gmail|e-?mail)\b"), re.compile(r"(?i)\b(send|sends|sending|forward|forwards)\b")),
    ("draft:email", re.compile(r"(?i)\b(gmail|e-?mail)\b"), re.compile(r"(?i)\bdrafts?\b")),
    ("read:email", re.compile(r"(?i)\b(inbox|gmail|e-?mails?|threads?)\b"),
     re.compile(r"(?i)\b(search|read|scan|check|find|pull|look|triage|sweep)\b")),
    ("delete:mail", re.compile(r"(?i)\b(delete|deletes|trash|trashes)\b"),
     re.compile(r"(?i)\b(messages?|threads?|e-?mails?|mail|drafts?)\b")),
    ("send:imessage", re.compile(r"(?i)\bimessage\b"), None),
    ("send:slack", re.compile(r"(?i)\bslack\b"), re.compile(r"(?i)\b(send|sends|post|posts|dm|message)\b")),
    ("send:discord", re.compile(r"(?i)\bdiscord\b"), re.compile(r"(?i)\b(send|sends|post|posts|reply|message)\b")),
    # naming a system isn't touching it: the sentence has to say what's done to it
    ("data:salesforce:any", re.compile(r"(?i)\bsalesforce\b"),
     re.compile(r"(?i)\b(query|queries|pull|pulls|fetch|look up|update|updates|close|closes|reassign|soql)\b")),
    ("data:salesforce:any", re.compile(r"(?i)\bsoql\b"), None),
    ("browser:chrome", re.compile(r"(?i)claude[- ]in[- ]chrome|chrome (extension|tab|browser)"), None),
    ("browser:computer-use", re.compile(r"(?i)computer[- ]use"), None),
    ("web:fetch", re.compile(r"\bWebFetch\b|(?i:fetch (the|each|that) (page|url|article|feed))"), None),
    ("web:search", re.compile(r"\bWebSearch\b|(?i:web search|search the web)"), None),
    ("read:calendar", re.compile(r"(?i)\bcalendar\b"), re.compile(r"(?i)\b(read|check|search|list|pull|look)\b")),
]
_SKILL_REF = re.compile(r"(?i)\b(?:run|invoke|use|follow|call)\s+(?:the\s+)?([`\"']?)([a-z][\w:\-]{2,})[`\"']?\s+skill\b")


_DOUBLE = re.compile(r"(?i)^\s*(?:to\s+)?(?:\w+\s+)?(forget|forgetting|skip|skipping|omit|neglect|fail|stop|finish|"
                     r"end|leave|exit|quit|proceed|continue|move on|wrap up)\b")
_CONDITIONAL = re.compile(r"(?i)^\W*(if|when|unless|once|after|before|while|in case)\b")


def governs(part):
    """Does a negation in this stretch of text prohibit what comes after it?

    One plain negation does. These don't, because they are requirements written
    with a negative: "don't forget to post", "do not stop until you've posted",
    "never end the run without posting", "without a post the run is incomplete".
    When it's a toss-up the answer is no, so the thing is kept as a capability.
    """
    negs = list(_NEG.finditer(part))
    if not negs:
        return False
    if len(negs) >= 2:
        return False                      # never ... without ...
    m = negs[0]
    if _DOUBLE.match(part[m.end():]):
        return False                      # don't forget / do not stop / never skip
    if m.group(0).strip().lower() == "without" and not part[:m.start()].strip():
        return False                      # "Without X, the run is incomplete"
    return True


def is_negated_lead(lead):
    """A line that introduces what follows as things not to do: "Do NOT:", "Never:", "Things to avoid:".

    The negation has to be what the colon is about. "Don't skip this step:" and
    "If the helper doesn't answer:" both contain one and introduce instructions.
    """
    lead = lead.strip().lstrip("#>*-_ ").rstrip("*_ ")
    if not lead.endswith(":"):
        return False
    body = lead[:-1]
    if _CONDITIONAL.match(body) or len(body.split()) > 8:
        return False
    return governs(body)


def negated_at(text, pos):
    """Is the thing at text[pos] being prohibited rather than instructed?

    A negation counts only when it comes before the hit inside the same
    statement: "send via the helper, not a hand-built curl" prohibits the curl
    and instructs the helper. Across a comma, a negation carries only through a
    list ("do not use loops, `$(...)`, or curl"), which is how warnings are
    written. `text` should have code spans blanked so their punctuation doesn't
    split statements.
    """
    prev, start, boundary = 0, 0, None
    for m in _HARD.finditer(text):
        if m.start() >= pos:
            break
        prev, start, boundary = start, m.end(), m
    # "Do NOT: post to Slack", all on one line
    if boundary is not None and boundary.group(0).startswith(":") \
            and is_negated_lead(text[prev:boundary.start()] + ":"):
        return True
    nxt = _HARD.search(text, pos)
    tail = text[pos:nxt.start() if nxt else len(text)]
    # the hit is an item in an "a, b, or c" list if an "or" closes the list after it
    in_list = bool(re.search(r",\s*(or|nor)\b|^\s*\S+\s+(or|nor)\b", tail, re.IGNORECASE))
    parts = text[start:pos].split(",")
    k = len(parts) - 1
    while k >= 0:
        part = parts[k]
        if _NEG.search(part):
            return governs(part)
        conj = bool(re.match(r"\s*(or|nor|and)\b", part, re.IGNORECASE))
        in_list = in_list or conj
        # Walk back across a comma only while this still reads as one list: a blank
        # item, an "or ..." item, or (inside a list) a short item like the "stop" in
        # "never archive, stop, or delete". A part with its own verb phrase, as in
        # "don't skip this, run X", starts a new instruction.
        if k > 0 and (not part.strip() or conj or (in_list and len(part.split()) <= 3)):
            k -= 1
            continue
        return False
    return False


def lead_in_negated(lines, i):
    """True when line i sits under a 'Do NOT:' style lead-in rather than an instruction.

    Two shapes: the previous non-blank line, or the line that opens the bullet
    list this line belongs to. A negation in some earlier sentence that isn't
    introducing this line doesn't count. Dropping a real capability because a
    nearby sentence said "not" would be guessing toward safe.
    """
    j = i - 1
    while j >= 0 and not lines[j].strip():
        j -= 1
    if j < 0:
        return False
    if _LIST_ITEM.match(lines[i]):
        while j >= 0 and (_LIST_ITEM.match(lines[j]) or not lines[j].strip() or lines[j].startswith("  ")):
            j -= 1
        if j < 0:
            return False
    return is_negated_lead(lines[j])


def split_frontmatter(text):
    """(frontmatter dict of simple keys, body line offset)."""
    meta = {}
    if text.startswith("---"):
        end = text.find("\n---", 3)
        if end > 0:
            for line in text[3:end].splitlines():
                m = re.match(r"^([A-Za-z_\-]+):\s*(.*)$", line)
                if m:
                    meta[m.group(1)] = m.group(2).strip().strip("\"'")
    return meta


def scan_instructions(text, clf, label):
    """Read instruction text. Returns (capabilities, prohibitions, script refs, skill refs, secrets).

    Code (fenced, indented, backtick spans) is classified as commands. Prose is
    matched by phrase and marked as such. A hit the instructions are warning
    against is returned as a prohibition instead of a capability. If the same
    thing is both instructed somewhere and prohibited somewhere else, the
    capability stands: the caller keeps both lists.
    """
    caps, prohibited, scripts, skills, secrets = [], [], [], [], []
    lines = text.splitlines()
    fenced = False
    for i, line in enumerate(lines):
        where = "%s line %d" % (label, i + 1)
        for start, end, kind in secret_spans(line):
            if end - start >= REPORT_MIN:
                secrets.append({"where": where, "length": end - start, "kind": kind})
        if line.lstrip().startswith("```"):
            fenced = not fenced
            continue
        indented = line.startswith("    ") and not _LIST_ITEM.match(line)
        in_block = fenced or indented
        # prose view of the line: code spans blanked, same length, so positions line up
        prose = line if in_block else _SPAN.sub(lambda m: " " * len(m.group(0)), line)
        lead_neg = (not fenced) and lead_in_negated(lines, i)

        def emit(key, detail, pos, confidence):
            # Inside a fenced block there is no sentence to carry a negation; only a
            # "Do NOT:" lead-in above an unfenced line can prohibit a block line.
            neg = lead_neg or (not in_block and negated_at(prose, pos))
            item = cap(key, INFERRED, where, detail, confidence=confidence)
            (prohibited if neg else caps).append(item)

        if in_block:
            for key, detail in clf.command(line):
                emit(key, detail, 0, "command")
        else:
            for m in _SPAN.finditer(line):
                for key, detail in clf.command(m.group(1)):
                    emit(key, detail, m.start(), "command")
            for key, detail, pos in clf.text_wide(prose):
                emit(key, detail, pos, "token")
            for key, topic, verb in _PROSE:
                for m in topic.finditer(prose):
                    start = 0
                    for c in _HARD.finditer(prose):
                        if c.start() >= m.start():
                            break
                        start = c.end()
                    nxt = _HARD.search(prose, m.end())
                    clause = prose[start:nxt.start() if nxt else len(prose)]
                    if verb is None or verb.search(clause):
                        emit(key, "prose: “%s”" % safe(clause.strip(), 70), m.start(), "prose")
                        break
        for m in _SCRIPT_CALL.finditer(line):
            scripts.append((m.group(1), i + 1))
        for m in _SCRIPT_DIRECT.finditer(line):
            scripts.append((m.group(1), i + 1))
        for m in _SKILL_REF.finditer(line):
            skills.append((m.group(2), bool(m.group(1)), i + 1))
        runs_script = bool(_SCRIPT_CALL.search(line) or _SCRIPT_DIRECT.search(line))
        for m in _PATH.finditer(line):
            path = norm_path(m.group(0))
            if runs_script and re.search(r"\.(py|sh|js|mjs)$", path):
                continue
            start = 0
            for c in _HARD.finditer(line):
                if c.start() >= m.start():
                    break
                start = c.end()
            # The verb nearest before the path decides the direction. No verb: direction unknown.
            before = line[start:m.start()]
            w = [v.end() for v in _WRITE_VERB.finditer(before)]
            r = [v.end() for v in _READ_VERB.finditer(before)]
            if not w and not r:
                kind = "ref"
            else:
                kind = "write" if (w and (not r or w[-1] > r[-1])) else "read"
            emit("%s:%s" % (kind, path), "path in instructions", m.start(), "prose")
    return caps, prohibited, scripts, skills, secrets


_SCRIPT_CLI = [
    ("data:salesforce:write", re.compile(r"\bsf\W+data\W+(update|create|delete|upsert|import)|\bsf\W+apex\W+run")),
    ("data:salesforce:read", re.compile(r"\bsf\W+data\W+(query|get|search)|\bsf\W+org\W+(list|display)")),
    ("publish:github", re.compile(r"\bgh\W+(pr|issue|release|repo)\W+(create|edit|merge|delete|comment)|\bgh\W+api\b.*(POST|PUT|PATCH|DELETE)")),
    ("publish:git-push", re.compile(r"\bgit\b[^#\n]{0,60}\bpush\b")),
    ("exec:remote", re.compile(r"[\"'](ssh|scp|rsync)[\"']|\b(ssh|scp|rsync)\s+-")),
    ("exec:osascript", re.compile(r"\bosascript\b")),
    ("cred:keychain", re.compile(r"find-generic-password|find-internet-password|\bkeyring\.")),
    ("send:email", re.compile(r"\bsmtplib\b|\bsendmail\b")),
    ("exec:agent", re.compile(r"[\"']claude[\"']\s*,\s*[\"']-p[\"']|\bclaude\s+-p\b")),
    ("delete:files", re.compile(r"\bshutil\.rmtree\b|\bos\.(remove|unlink|rmdir|removedirs)\b|\.unlink\(|"
                                r"[\"']rm[\"']\s*,|\brm\s+-\w|\bfs\.(rm|unlink|rmdir)(Sync)?\b")),
]
_ENV_SECRET = re.compile(r"(?:environ(?:\.get)?\s*[\[(]|getenv\s*\()\s*[\"']([A-Z0-9_]*(?:TOKEN|KEY|SECRET|PASSWORD)[A-Z0-9_]*)[\"']")
# A URL that opens a string literal (so a URL quoted inside a User-Agent or a comment doesn't count).
_URL_LITERAL = re.compile(r"[\"']https?://([A-Za-z0-9.\-]+\.[A-Za-z]{2,})")


def scan_script(path, clf, label):
    """One hop into a script SKILL.md runs. Returns (capabilities, status).

    status is 'read', 'missing', 'unreadable', or 'too large'. Anything but
    'read' means this script's reach is unknown, not empty.
    """
    try:
        if os.path.getsize(path) > MAX_SCRIPT_BYTES:
            return [], "too large"
        with open(path, errors="replace") as fh:
            lines = fh.read().splitlines()
    except FileNotFoundError:
        return [], "missing"
    except OSError:
        return [], "unreadable"
    caps = []
    for i, line in enumerate(lines):
        code = line.strip()
        if not code or code.startswith("#") or code.startswith("//"):
            continue
        where = "%s line %d" % (label, i + 1)
        for key, detail, _ in clf.text_wide(code):
            caps.append(cap(key, INFERRED, where, detail, confidence="script"))
        for m in _URL_LITERAL.finditer(code):
            host = m.group(1).lower()
            ch = clf.channel(host)
            caps.append(cap("send:%s" % ch if ch else "net:%s" % host, INFERRED, where,
                            "URL in script, %s" % ("a known messaging host" if ch else "direction unknown"),
                            confidence="script"))
        for key, rx in _SCRIPT_CLI:
            if rx.search(code):
                caps.append(cap(key, INFERRED, where, "command built in script", confidence="script"))
                head = key.split(":")[1] if key.startswith("data:") else None
                if head == "salesforce":
                    caps.append(cap("cred:salesforce-cli", INFERRED, where, "sf uses its stored login",
                                    confidence="script"))
        for m in _ENV_SECRET.finditer(code):
            caps.append(cap("cred:env:%s" % m.group(1), INFERRED, where, "reads a secret-named environment variable",
                            confidence="script"))
    return caps, "read"


# --------------------------------------------------------------------------
# settings, registry, and assembling the register
# --------------------------------------------------------------------------

def read_json(path):
    """(data, None) or (None, reason). A missing file and a broken one are different reasons."""
    try:
        with open(path) as fh:
            return json.load(fh), None
    except FileNotFoundError:
        return None, "missing"
    except PermissionError:
        return None, "unreadable (permission denied)"
    except (OSError, ValueError) as e:
        return None, "unreadable (%s)" % type(e).__name__


def find_registry(pattern):
    """The registry file to read: the newest match of a path or glob, plus how many others matched."""
    if not pattern:
        return None, 0
    matches = sorted(globmod.glob(pattern), key=os.path.getmtime)
    if not matches:
        return pattern, 0
    return matches[-1], len(matches) - 1


def registry_rows(data):
    """(rows, problem). A registry this tool doesn't recognise is a problem, not an empty fleet."""
    if isinstance(data, dict):
        rows = data.get("scheduledTasks", data.get("tasks"))
        if not isinstance(rows, list):
            return [], "has neither a scheduledTasks nor a tasks list: its shape isn't one this tool knows"
    elif isinstance(data, list):
        rows = data
    else:
        return [], "isn't a list or an object"
    out, dropped = [], 0
    for r in rows:
        tid = (r.get("id") or r.get("taskId")) if isinstance(r, dict) else None
        if tid:
            out.append(dict(r, id=tid))
        else:
            dropped += 1
    return out, ("has %d row(s) with no id that couldn't be read as tasks" % dropped) if dropped else None


class Register:
    def __init__(self, cfg, env):
        self.cfg, self.env = cfg, env
        self.clf = Classifier(cfg, env)
        self.errors = []      # inputs that couldn't be read: the register is incomplete
        self.facts = {}
        self.secrets = []

    def fact(self, name, scope, text, **extra):
        self.facts.setdefault(name, []).append(dict({"scope": scope, "text": text}, **extra))

    # ---- shared config: one settings file is one scope -------------------

    def load_scope(self, path, kind, cwd):
        """Parse one settings file into a scope: its rules as capabilities, plus what's odd about it."""
        scope = {"id": self.env.tilde(path), "kind": kind, "path": path, "cwd": cwd, "status": "read",
                 "allow": 0, "deny": 0, "ask": 0, "by_tool": {}, "caps": [], "broad_exec": [],
                 "dead": [], "unclassified": 0, "hooks": [], "default_mode": None,
                 "read_patterns": [], "deny_patterns": [], "additional_dirs": [], "agents": []}
        data, why = read_json(path)
        if data is None:
            scope["status"] = why
            if why != "missing" or kind == "user":
                self.errors.append("%s is %s: its rules are unknown, not absent" % (scope["id"], why))
            return scope
        perms = data.get("permissions") or {}
        scope["default_mode"] = perms.get("defaultMode")
        scope["additional_dirs"] = [self.env.expand(d) for d in perms.get("additionalDirectories") or []]
        settings_dir = os.path.dirname(path) if kind == "user" else (cwd or os.path.dirname(os.path.dirname(path)))
        for name in ("allow", "deny", "ask"):
            rules = [r for r in perms.get(name) or [] if isinstance(r, str)]
            scope[name] = len(rules)
            for idx, rule in enumerate(rules):
                self.scan_rule_secret(rule, "%s %s rule %d" % (scope["id"], name, idx + 1))
                if name == "allow":
                    self.classify_rule(rule, scope, settings_dir, cwd, scope["id"] + " allow")
                elif name == "deny":
                    tool, content = parse_rule(rule)
                    if tool in ("Read", "Edit") and content:
                        pat, _ = anchor(content, settings_dir, cwd, self.env)
                        if pat:
                            scope["deny_patterns"].append((pat, safe(rule, 110)))
        for event, groups in (data.get("hooks") or {}).items():
            for g in groups or []:
                for h in g.get("hooks") or []:
                    scope["hooks"].append({"event": event, "matcher": g.get("matcher") or "",
                                           "command": safe(h.get("command", ""), 120)})
        return scope

    def scan_rule_secret(self, rule, where):
        for start, end, kind in secret_spans(rule):
            if end - start >= REPORT_MIN:
                self.secrets.append({"where": where, "length": end - start, "kind": kind})

    def classify_rule(self, rule, scope, settings_dir, cwd, source, into=None):
        """One allow rule -> capabilities appended to scope['caps'] (or `into`)."""
        caps = scope["caps"] if into is None else into
        tool, content = parse_rule(rule)
        shown = safe(rule, 110)
        if tool is None:
            scope["unclassified"] += 1
            return
        bucket = "mcp" if tool.startswith("mcp__") else tool
        scope["by_tool"][bucket] = scope["by_tool"].get(bucket, 0) + 1
        if tool == "Bash":
            if is_broad_exec(content):
                scope["broad_exec"].append(shown)
                caps.append(cap("exec:interpreter", DECLARED, source, shown))
                # the rest of the rule text (helpers, paths) can still name something specific
            found = self.clf.command(content or "", wild=True)
            if not found and not is_broad_exec(content):
                scope["unclassified"] += 1
            for key, detail in found:
                caps.append(cap(key, DECLARED, source, "%s (%s)" % (shown, detail)))
        elif tool in ("Read", "Edit", "Write", "NotebookEdit"):
            kind = "read" if tool == "Read" else "write"
            if content is None:
                caps.append(cap("%s:any" % kind, DECLARED, source, shown))
                if kind == "read":
                    scope["read_patterns"].append(("/**", shown))
                return
            pat, how = anchor(content, settings_dir, cwd, self.env)
            if pat is None:
                caps.append(cap("%s:%s" % (kind, content), DECLARED, source,
                                "%s (relative to each agent's working directory)" % shown))
                return
            caps.append(cap("%s:%s" % (kind, self.env.tilde(pat)), DECLARED, source, shown))
            scope["read_patterns"].append((pat, shown))  # an Edit rule implies the file can be opened
            if how == "settings-relative" and not os.path.exists(static_prefix(pat)):
                scope["dead"].append("%s anchors at %s, which doesn't exist. A single leading slash is "
                                     "relative to the settings file, not the filesystem root."
                                     % (shown, self.env.tilde(static_prefix(pat))))
            if tool == "Write":
                scope["dead"].append("%s is a Write() path rule. Claude Code has warned these match "
                                     "nothing; Edit() is the rule that covers file writes. Counted "
                                     "here anyway." % shown)
        elif tool == "WebFetch":
            m = re.match(r"domain:(.+)", content or "")
            caps.append(cap("web:fetch:%s" % (m.group(1) if m else "any"), DECLARED, source, shown))
        elif tool == "WebSearch":
            caps.append(cap("web:search", DECLARED, source, shown))
        elif tool.startswith("mcp__"):
            caps.append(cap(classify_mcp(tool, self.cfg["mcp_servers"]), DECLARED, source,
                            safe(re.sub(_UUID, lambda m: mcp_label(m.group(0), self.cfg["mcp_servers"]), rule), 110)))
        elif tool == "Skill":
            caps.append(cap("skill:%s" % (content or "any").split(":")[0], DECLARED, source, shown))
        elif tool in ("Agent", "Task"):
            caps.append(cap("exec:agent", DECLARED, source, shown))
        else:
            scope["unclassified"] += 1

    # ---- agents ----------------------------------------------------------

    def build(self):
        cfg, env = self.cfg, self.env
        reg_path, others = find_registry(cfg["registry"])
        data, why = read_json(reg_path) if reg_path else (None, "not configured")
        if data is None:
            self.errors.append("registry %s is %s: no agents can be listed"
                               % (_UUID.sub("…", env.tilde(reg_path or "?")), why))
            rows = []
        else:
            rows, problem = registry_rows(data)
            if problem:
                self.errors.append("registry %s %s" % (_UUID.sub("…", env.tilde(reg_path)), problem))

        scopes = {}

        def scope_for(path, kind, cwd):
            if path not in scopes:
                scopes[path] = self.load_scope(path, kind, cwd)
            return scopes[path]

        for p in cfg["user_settings"]:
            scope_for(p, "user", None)

        stores = []
        for s in cfg["credential_stores"]:
            stores.append({"id": s["id"], "label": s.get("label", s["id"]), "path": s["path"],
                           "exists": os.path.lexists(s["path"]), "allowed_by": [], "denied_by": []})

        agents = []
        for row in rows:
            agents.append(self.build_agent(row, scope_for, stores))

        for scope in scopes.values():
            for st in stores:
                for pat, rule in scope["read_patterns"]:
                    if pattern_covers(pat, st["path"]):
                        st["allowed_by"].append({"scope": scope["id"], "rule": rule})
                for pat, rule in scope["deny_patterns"]:
                    if pattern_covers(pat, st["path"]):
                        st["denied_by"].append({"scope": scope["id"], "rule": rule})

        registered = {a["id"] for a in agents}
        orphans = []
        for root in cfg["tasks_roots"]:
            try:
                names = sorted(os.listdir(root))
            except FileNotFoundError:
                continue
            except OSError:
                self.errors.append("%s can't be listed: task folders there are unknown" % env.tilde(root))
                continue
            for name in names:
                if os.path.isdir(os.path.join(root, name)) and name not in registered:
                    orphans.append({"id": name, "root": env.tilde(root)})

        self.collect_facts(scopes, agents, stores, orphans)
        return {"generated": datetime.now().replace(microsecond=0).isoformat(),
                "title": cfg["title"], "errors": self.errors,
                "registry": {"path": _UUID.sub("…", env.tilde(reg_path)) if reg_path else None, "others": others,
                             "rows": len(rows)},
                # a project folder with no settings file isn't a scope; a file that exists and can't be read is
                "scopes": sorted((s for s in scopes.values() if s["status"] != "missing" or s["kind"] == "user"),
                                 key=lambda s: (s["kind"] != "user", s["id"])),
                "stores": [dict(s, path=env.tilde(s["path"])) for s in stores],
                "agents": agents, "orphans": orphans, "facts": self.facts, "secrets": self.secrets}

    def build_agent(self, row, scope_for, stores):
        cfg, env = self.cfg, self.env
        tid = row["id"]
        cwd = os.path.normpath(env.expand(row["cwd"])) if row.get("cwd") else None   # "~/x/" and "~/x" are one place
        skill = env.expand(row.get("filePath")) if row.get("filePath") else None
        if not skill:
            for root in cfg["tasks_roots"]:
                cand = os.path.join(root, tid, "SKILL.md")
                if os.path.exists(cand):
                    skill = cand
                    break
        a = {"id": tid, "name": row.get("displayName") or tid, "enabled": bool(row.get("enabled", True)),
             "mode": row.get("permissionMode"), "cwd": env.tilde(cwd) if cwd else None,
             "schedule": row.get("cronExpression") or ("once: %s" % row["fireAt"] if row.get("fireAt") else None),
             "model": None, "skill": env.tilde(skill) if skill else None, "skill_status": "read",
             "declared": [], "inferred": [], "prohibited": [], "hops": [], "scopes": [],
             "unknowns": [], "approved": len(row.get("approvedPermissions") or [])}

        # shared scopes this agent runs under: user settings plus its working directory's project files
        scope_ids = [env.tilde(p) for p in cfg["user_settings"]]
        local = {"caps": [], "broad_exec": [], "dead": [], "unclassified": 0, "by_tool": {},
                 "read_patterns": [], "deny_patterns": []}
        workdirs = [cwd] if cwd else []
        for p in cfg["user_settings"]:
            workdirs += scope_for(p, "user", None)["additional_dirs"]
        if cwd:
            for name in ("settings.json", "settings.local.json"):
                p = os.path.join(cwd, ".claude", name)
                sc = scope_for(p, "user" if p in cfg["user_settings"] else "project", cwd)
                if sc["status"] == "read" and sc["id"] not in scope_ids:
                    scope_ids.append(sc["id"])
                    workdirs += sc["additional_dirs"]
        else:
            a["unknowns"].append("no working directory in the registry: project settings unknown")
        a["scopes"] = scope_ids
        workdirs = [os.path.normpath(d) for d in workdirs if d]

        # per-task approvals
        for idx, ap in enumerate(row.get("approvedPermissions") or []):
            tool = ap.get("toolName")
            if not tool:
                continue
            rule = tool if ap.get("ruleContent") is None else "%s(%s)" % (tool, ap["ruleContent"])
            self.scan_rule_secret(rule, "registry approval %d for %s" % (idx + 1, tid))
            self.classify_rule(rule, local, cwd or env.home, cwd, "approved for this task", into=a["declared"])
        a["approved_broad_exec"] = local["broad_exec"]

        # working directory: reads there need no approval in any mode; edits don't either in auto/acceptEdits
        mode = a["mode"]
        if cwd:
            a["declared"].append(cap("read:%s/**" % a["cwd"], DECLARED, "working directory",
                                     "reads inside the working directory need no approval in any mode",
                                     derived=True))
            if mode in ("auto", "acceptEdits", "bypassPermissions"):
                a["declared"].append(cap("write:%s/**" % a["cwd"], DECLARED, "working directory + %s mode" % mode,
                                         "file edits inside the working directory run without approval",
                                         derived=True))
        if mode == "bypassPermissions":
            a["declared"].append(cap("exec:interpreter", DECLARED, "bypassPermissions mode",
                                     "every tool call runs; allow rules are irrelevant"))

        # credential reach, declared: by location, or by a rule in a scope this agent runs under
        a["cred_reach"] = []
        inside = []
        for st in stores:
            if not st["exists"]:
                continue
            holder = next((d for d in workdirs if st["path"] == d or st["path"].startswith(d.rstrip("/") + "/")), None)
            if holder:
                where = "the working directory" if holder == cwd else "additional directory %s" % env.tilde(holder)
                a["cred_reach"].append({"id": st["id"], "how": "inside %s" % where})
                inside.append(st["label"])
                continue
            for pat, rule in local["read_patterns"]:
                if pattern_covers(pat, st["path"]):
                    a["cred_reach"].append({"id": st["id"], "how": "task approval %s" % rule})
                    a["declared"].append(cap("cred:%s" % st["id"], DECLARED, "approved for this task",
                                             "%s covers the store" % rule, derived=True))
                    # a per-task approval is an allow rule like any other: it has to raise the same fact
                    st["allowed_by"].append({"scope": "task approval for %s" % tid, "rule": rule, "agent": tid})
                    break
        if inside:
            # one line, not one per store: the stores table carries the detail
            a["declared"].append(cap("cred:%d of %d stores, by location" % (len(inside), sum(1 for s in stores if s["exists"])),
                                     DECLARED, "working directory",
                                     "they sit inside a working directory, where reads need no approval",
                                     derived=True))
        a["_inside"] = inside
        a["_cwd"] = cwd

        # instructions
        if not skill:
            a["skill_status"] = "missing"
        else:
            try:
                with open(skill, errors="replace") as fh:
                    text = fh.read()
            except FileNotFoundError:
                a["skill_status"], text = "missing", None
            except OSError:
                a["skill_status"], text = "unreadable", None
            if text is not None:
                meta = split_frontmatter(text)
                a["model"] = meta.get("model") or None
                caps, prohibited, scripts, skills, secrets = scan_instructions(text, self.clf, "SKILL.md")
                a["inferred"], a["prohibited"] = caps, prohibited
                for s in secrets:
                    self.secrets.append(dict(s, where="%s %s" % (a["skill"], s["where"].replace("SKILL.md ", ""))))
                self.follow_hops(a, scripts, skills, cwd, os.path.dirname(skill))
        if a["skill_status"] != "read":
            a["unknowns"].append("instructions %s: what this agent is told to do is unknown" % a["skill_status"])
            self.errors.append("%s: SKILL.md is %s" % (tid, a["skill_status"]))
        a["inferred"] = dedupe(a["inferred"])
        a["declared"] = dedupe(a["declared"])
        a["prohibited"] = dedupe(a["prohibited"])
        return a

    def follow_hops(self, a, scripts, skills, cwd, skill_dir):
        """One hop: scripts the instructions run, and skills they hand off to. No second hop."""
        env, seen = self.env, set()
        for raw, line_no in scripts:
            p = re.sub(r"^(?:\$HOME|\$\{HOME\}|/Users/[\w.\-]+|/home/[\w.\-]+)/", "~/", raw)
            p = env.expand(p)
            cands = [p] if os.path.isabs(p) else [os.path.join(d, p) for d in (cwd, skill_dir) if d]
            path = next((c for c in cands if os.path.exists(c)), cands[0] if cands else p)
            path = os.path.normpath(path)
            if path in seen:
                continue
            seen.add(path)
            shown = env.tilde(path)
            caps, status = scan_script(path, self.clf, shown)
            a["hops"].append({"path": shown, "status": status, "line": line_no})
            a["inferred"].extend(caps)
            if status != "read":
                a["unknowns"].append("script %s is %s: what it reaches is unknown" % (shown, status))
        for name, quoted, line_no in skills:
            path = os.path.join(self.cfg["skills_root"] or "", name.split(":")[-1], "SKILL.md")
            if path in seen:
                continue
            seen.add(path)
            shown = env.tilde(path)
            try:
                with open(path, errors="replace") as fh:
                    text = fh.read()
            except OSError:
                if not quoted:
                    continue   # "use the same skill": a phrase, not a hand-off, unless a folder backs it
                a["hops"].append({"path": "skill %s" % name, "status": "not found", "line": line_no})
                a["unknowns"].append("hands off to skill “%s”, whose instructions weren't found: "
                                     "what it reaches is unknown" % name)
                continue
            caps, prohibited, _, _, _ = scan_instructions(text, self.clf, shown)
            a["hops"].append({"path": shown, "status": "read", "line": line_no})
            a["inferred"].extend(caps)
            a["prohibited"].extend(prohibited)
            a["unknowns"].append("skill “%s” was read one level deep; scripts it runs were not followed" % name)

    # ---- facts: the things policy rules can point at ---------------------

    def collect_facts(self, scopes, agents, stores, orphans):
        env = self.env
        by_id = {s["id"]: s for s in scopes.values()}
        for a in agents:
            for sid in a["scopes"]:
                if sid in by_id:
                    by_id[sid]["agents"].append(a["id"])
            # project-scope rules can also reach a store for this agent
            for st in stores:
                if not st["exists"] or any(c["id"] == st["id"] for c in a["cred_reach"]):
                    continue
                for sid in a["scopes"]:
                    sc = by_id.get(sid)
                    hit = next((rule for pat, rule in (sc["read_patterns"] if sc else [])
                                if pattern_covers(pat, st["path"])), None)
                    if hit:
                        a["cred_reach"].append({"id": st["id"], "how": "%s: %s" % (sid, hit)})
                        a["declared"].append(cap("cred:%s" % st["id"], DECLARED, sid, "allow rule %s" % hit,
                                                 derived=True))
                        break
            if a["mode"] is None:
                self.fact("mode_unset", a["id"], "no permission mode in the registry")
            elif a["mode"] == "bypassPermissions":
                self.fact("mode_bypass", a["id"], "runs with permission checks off")
            if a["skill_status"] == "read" and not a["model"]:
                self.fact("model_unset", a["id"], "SKILL.md has no model line")
            inside = a.pop("_inside")
            if a["_cwd"] and a["_cwd"] == env.home:
                self.fact("home_as_cwd", a["id"], "working directory is the home folder")
            elif inside:
                # not home, but a credential store still sits where this agent reads without asking
                self.fact("store_in_workdir", a["id"], "a working directory holds %s" % ", ".join(inside))
            for rule in a.pop("approved_broad_exec"):
                self.fact("broad_exec_rule", a["id"], "task approval %s" % rule)
            a.pop("_cwd")
        for sc in scopes.values():
            if sc["status"] != "read":
                continue
            who = scope_who(sc, len(agents))
            for rule in sc["broad_exec"]:
                self.fact("broad_exec_rule", who, "%s allows %s" % (sc["id"], rule), shared=sc["id"])
            for d in sc["dead"]:
                self.fact("dead_rule", who, "%s: %s" % (sc["id"], d), shared=sc["id"])
        allowed, undenied = {}, {}
        for st in stores:
            if not st["exists"]:
                self.fact("store_not_found", "config", "%s (%s) isn't on disk" % (st["label"], env.tilde(st["path"])))
                continue
            for hit in st["allowed_by"]:
                allowed.setdefault((hit["scope"], hit["rule"]), []).append(st["label"])
            # a deny rule only protects the agents that run under the settings file it's in
            denying = {d["scope"] for d in st["denied_by"]}
            bare = tuple(a["id"] for a in agents if not denying & set(a["scopes"]))
            if bare:
                undenied.setdefault(bare, []).append(st["label"])
        for (sid, rule), labels in allowed.items():
            sc = by_id.get(sid)
            if sc:
                self.fact("credential_path_allowed", scope_who(sc, len(agents)),
                          "%s allows %s, which covers %s" % (sid, rule, ", ".join(labels)), shared=sid)
            else:   # a per-task approval: one agent, not shared config
                self.fact("credential_path_allowed", sid.replace("task approval for ", ""),
                          "task approval %s covers %s" % (rule, ", ".join(labels)))
        for bare, labels in undenied.items():
            who = "all agents" if len(bare) == len(agents) else "%d of %d agents" % (len(bare), len(agents))
            self.fact("credential_not_denied", who, "no deny rule covers %s" % ", ".join(labels),
                      shared="*", agents=list(bare))
        # "none anywhere" can only be said when every settings file that exists was read
        all_read = all(s["status"] in ("read", "missing") for s in scopes.values()) and \
            all(s["status"] == "read" for s in scopes.values() if s["kind"] == "user")
        if all_read and not any(h["event"] == "PreToolUse" and re.search(r"Bash|\*|^$", h["matcher"])
                                for s in scopes.values() for h in s["hooks"]):
            self.fact("gate_hook_missing", "all agents", "no PreToolUse hook is registered for Bash", shared="*")
        if all_read and not any(s["deny"] for s in scopes.values()):
            self.fact("no_deny_rules", "all agents", "no deny rule exists in any settings file read", shared="*")
        for s in self.secrets:
            self.fact("secret_literal", s["where"], "%s, %d characters (value not shown, not verified as live)"
                      % (s["kind"], s["length"]))
        for o in orphans:
            self.fact("unregistered_folder", o["id"], "task folder in %s with no registry row" % o["root"])


def scope_who(scope, total):
    n = len(scope["agents"])
    if scope["kind"] == "user" or n == total:
        return "all agents"
    return "%d agent%s with working directory %s" % (n, "" if n == 1 else "s", scope.get("cwd_shown") or "there")


def dedupe(caps):
    """One entry per (key, evidence): keep the first source, count the rest."""
    seen, out = {}, []
    for c in caps:
        k = (c["key"], c["evidence"])
        if k in seen:
            seen[k]["more"] += 1 + c.get("more", 0)
            if c.get("confidence") in ("command", "token", "script") and seen[k].get("confidence") == "prose":
                seen[k]["confidence"] = c["confidence"]
            continue
        seen[k] = dict(c, more=c.get("more", 0))   # a copy: calling this twice must not inflate the count
        out.append(seen[k])
    return out


# --------------------------------------------------------------------------
# policy diff
# --------------------------------------------------------------------------

FACT_COVERS = {
    "broad_exec_rule": ["exec:interpreter"],
    "credential_path_allowed": ["cred:*"],
    "credential_not_denied": ["cred:*"],
    "home_as_cwd": ["cwd:*"],
    "store_in_workdir": ["cwd:*"],
}


def load_policy(path):
    """(policy, None) or (None, reason). A policy with no rules would pass everything, so it's refused."""
    data, why = read_json(path)
    if data is None:
        return None, why
    rules = data.get("rules") if isinstance(data, dict) else None
    if not isinstance(rules, list) or not rules:
        return None, "missing a non-empty rules list"
    for r in rules:
        if not isinstance(r, dict) or not r.get("id") or not r.get("title"):
            return None, "holding a rule with no id or title"
    return data, None


def key_matches(key, patterns):
    return any(fnmatch.fnmatchcase(key, p) for p in patterns)


def family(key):
    """Group path-like keys so the silent list stays readable."""
    head, _, rest = key.partition(":")
    if head in ("read", "write", "ref") and rest.startswith(("~", "/")):
        parts = rest.split("/")
        return "%s:%s" % (head, "/".join(parts[:2]) if rest.startswith("~") else "/" + parts[1])
    if head == "write" and rest not in ("any",) and not rest.startswith(("~", "/")) and ("." in rest or "/" in rest):
        return "write:(path relative to the working directory)"
    if head == "web" and rest.startswith("fetch:"):
        return "web:fetch"
    if head == "net":
        return "net:(web hosts fetched from the shell)"
    return key


def diff(report, policy, exceptions):
    """Compare the register against the policy.

    Returns four lists. `config_forbidden` is declared access that a rule forbids.
    `instructed_forbidden` is access the instructions ask for that a rule forbids;
    whether config would let it through is not known. `silent` is access no rule
    speaks to. `unchecked` is rules this tool has no way to test.
    """
    config_forbidden, instructed_forbidden, unchecked, covered = [], [], [], []
    agents = report["agents"]
    total = len(agents)
    scopes = [s for s in report["scopes"] if s["status"] == "read"]

    def excepted(rule_id, agent_id, key, what):
        """The reason on file if an exception covers this finding, else None.

        An exception names an agent (or "*"), the keys it covers, and optionally
        `match`: text the finding must contain. Without `match`, excepting one
        wildcard-interpreter rule would excuse every one of them.
        """
        for ex in (exceptions.get(rule_id) or []):
            if ex.get("agent") in (agent_id, "*") and key_matches(key, ex.get("keys") or ["*"]) \
                    and (not ex.get("match") or ex["match"] in what):
                return ex.get("reason") or "excepted, no reason given"
        return None

    def add(target, rule, who, what, source, key=None, shared=None, agent=None, name=None):
        target.append({"rule": rule["id"], "title": rule["title"], "rmf": rule.get("rmf"),
                       "who": who, "what": what, "source": source, "key": key, "shared": shared,
                       "excused": excepted(rule["id"], agent if agent is not None else who, name or key, what)})

    for rule in policy.get("rules", []):
        check = rule.get("check") or {"type": "process"}
        kind = check.get("type")
        covered.extend(rule.get("covers") or [])
        if kind == "process":
            unchecked.append({"rule": rule["id"], "title": rule["title"], "rmf": rule.get("rmf"),
                              "why": check.get("why") or "a process rule; nothing in config can show whether it's followed"})
        elif kind == "fact":
            for name in check["facts"]:
                covered.extend(FACT_COVERS.get(name, []))
                for inst in report["facts"].get(name, []):
                    add(config_forbidden, rule, inst["scope"], inst["text"], "config", shared=inst.get("shared"),
                        name=name)
        elif kind in ("forbid", "allow_only"):
            if kind == "forbid":
                patterns = check["keys"]
                spared = check.get("except_keys") or []
                covered.extend(patterns)
                bad = lambda k: key_matches(k, patterns) and not key_matches(k, spared)  # noqa: E731
            else:
                prefixes = check["prefixes"]
                allowed = check["allowed"]
                covered.extend(p + "*" for p in prefixes)
                bad = lambda k: k.startswith(tuple(prefixes)) and not key_matches(k, allowed)  # noqa: E731
            for sc in scopes:
                sc_who = scope_who(sc, total)
                for c in dedupe(sc["caps"]):   # one finding per kind of access, however many rules grant it
                    if bad(c["key"]):
                        more = " (and %d more rule%s)" % (c["more"], "" if c["more"] == 1 else "s") if c.get("more") else ""
                        add(config_forbidden, rule, sc_who, "%s: %s%s" % (c["key"], c["detail"], more), sc["id"],
                            key=c["key"], shared=sc["id"], agent="*")
            for a in agents:
                for c in a["declared"]:
                    if bad(c["key"]) and not c.get("derived"):
                        add(config_forbidden, rule, a["id"], "%s: %s" % (c["key"], c["detail"]), c["source"],
                            key=c["key"])
                for c in a["inferred"]:
                    if bad(c["key"]):
                        add(instructed_forbidden, rule, a["id"], "%s: %s" % (c["key"], c["detail"]), c["source"],
                            key=c["key"])
        else:
            unchecked.append({"rule": rule["id"], "title": rule["title"], "rmf": rule.get("rmf"),
                              "why": "check type %r isn't one this tool knows" % kind})

    # silence: every capability key that no rule's subject matter reaches
    silent = {}

    def note(key, who, evidence):
        if key.startswith("ref:") or key_matches(key, covered):
            return
        fam = family(key)
        entry = silent.setdefault(fam, {"key": fam, "agents": set(), "evidence": set(), "shared": set()})
        entry["evidence"].add(evidence)
        (entry["shared"] if who.startswith("shared:") else entry["agents"]).add(who.replace("shared:", ""))

    for sc in scopes:
        for c in sc["caps"]:
            note(c["key"], "shared:" + sc["id"], DECLARED)
    for a in agents:
        for c in a["declared"]:
            if not c.get("derived"):
                note(c["key"], a["id"], DECLARED)
        for c in a["inferred"]:
            note(c["key"], a["id"], INFERRED)
    silent_list = sorted(({"key": v["key"], "agents": sorted(v["agents"]), "shared": sorted(v["shared"]),
                           "evidence": sorted(v["evidence"])} for v in silent.values()),
                         key=lambda e: (-(len(e["agents"]) + 100 * len(e["shared"])), e["key"]))
    return {"config_forbidden": config_forbidden, "instructed_forbidden": instructed_forbidden,
            "silent": silent_list, "unchecked": unchecked}


def cannot_see(report):
    """What the register has no way to know. Printed on the page, always."""
    modes = {}
    for a in report["agents"]:
        modes[a["mode"] or "unset"] = modes.get(a["mode"] or "unset", 0) + 1
    out = []
    if modes.get("auto"):
        out.append("What the auto-mode classifier lets through. %d agent(s) run in auto, where anything "
                   "the allowlist doesn't name goes to a classifier this tool can't read. For those agents "
                   "the allowlist is a floor, not a ceiling." % modes["auto"])
    if modes.get("unset"):
        out.append("Which mode %d agent(s) with no mode in the registry actually start in." % modes["unset"])
    jit = report.get("jit")
    out += [
        ("What agents did beyond the tool calls in their run transcripts. The just-in-time pass reads those "
         "calls; it can't see inside a script a call runs, or any run outside its window."
         if jit and not jit.get("errors") else
         "What any agent has actually done. This is configured access read from files, not observed behavior."),
        "Which MCP servers and connectors are attached when a scheduled run starts. Tool names in rules "
        "and instructions are read; whether the tool is there at run time is not.",
        "Managed settings, command-line flags, and plugin or mod permission hooks.",
        "Whether any control works. A hook that is registered and a rule that is written are both "
        "reported as present, and neither has been probed by this tool.",
        "Scripts past one hop. A script that SKILL.md runs is scanned; anything that script imports or calls is not.",
        "What a script does at run time. Paths and hosts built from variables don't show up in a text scan.",
        "Keychain contents, and whether any credential file holds a live secret.",
        "Operating-system permissions (macOS privacy grants, file modes beyond existence).",
        "Other machines. Agents scheduled anywhere else aren't in this registry.",
    ]
    if report["registry"]["others"]:
        out.append("%d other registry file(s) matched and weren't read; the newest one was used."
                   % report["registry"]["others"])
    if report["orphans"]:
        out.append("%d task folder(s) on disk have no row in the registry. They're listed, not analysed: "
                   "something else may still run them." % len(report["orphans"]))
    return out


# --------------------------------------------------------------------------
# rendering
# --------------------------------------------------------------------------

_CSS = """
:root{--bg:#f7f6f2;--card:#fff;--ink:#1d1d1b;--muted:#6b6a64;--line:#e4e2da;
--bad:#b3261e;--bad-bg:#fbe9e7;--warn:#8a5a00;--warn-bg:#fdf1d8;--ok:#2e6b30;--ok-bg:#e5f2e3;
--dec:#1f4f8a;--dec-bg:#e3edf9;--inf:#6a3d8a;--inf-bg:#f0e7f6;--nd:#6b6a64;--nd-bg:#efeee9}
@media (prefers-color-scheme:dark){:root{--bg:#161614;--card:#1f1f1c;--ink:#ecebe6;--muted:#a3a29b;
--line:#34332e;--bad:#ff8a80;--bad-bg:#3a1d1a;--warn:#f3c060;--warn-bg:#352a12;--ok:#8fd18f;--ok-bg:#1b2f1b;
--dec:#9cc4f5;--dec-bg:#1b2a3d;--inf:#d3b0ee;--inf-bg:#2d2138;--nd:#a3a29b;--nd-bg:#2a2a26}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif}
main{max-width:1180px;margin:0 auto;padding:28px 16px 60px}
h1{font-size:24px;margin:0 0 4px}h2{font-size:17px;margin:34px 0 10px}h3{font-size:14.5px;margin:0 0 4px}
p{margin:8px 0}.sub{color:var(--muted);margin:0 0 18px}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:10px;margin:14px 0}
.tile{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px 14px}
.tile b{display:block;font-size:26px;line-height:1.1}.tile span{color:var(--muted);font-size:12.5px}
.banner{border-radius:10px;padding:12px 14px;margin:14px 0;border:1px solid var(--line);background:var(--card)}
.banner.bad{border-color:var(--bad);background:var(--bad-bg)}
.banner.warn{border-color:var(--warn);background:var(--warn-bg)}
.banner.good{border-color:var(--ok);background:var(--ok-bg)}
.find{background:var(--card);border:1px solid var(--line);border-left:4px solid var(--bad);border-radius:8px;padding:12px 14px;margin:10px 0}
.find.inst{border-left-color:var(--warn)}.find.quiet{border-left-color:var(--nd)}
.find ul{margin:6px 0 0;padding-left:20px}.find li{margin:3px 0;font-size:14px}
.tag{display:inline-block;font:600 11.5px ui-monospace,Menlo,monospace;padding:1px 7px;border-radius:999px;white-space:nowrap;margin-right:5px}
.t-rule{color:var(--bad);background:var(--bad-bg)}.t-rmf{color:var(--nd);background:var(--nd-bg)}
.t-declared{color:var(--dec);background:var(--dec-bg)}.t-inferred{color:var(--inf);background:var(--inf-bg)}
.t-on{color:var(--ok);background:var(--ok-bg)}.t-off{color:var(--nd);background:var(--nd-bg)}
.t-warn{color:var(--warn);background:var(--warn-bg)}
.t-observed{color:var(--ok);background:var(--ok-bg)}
.tablewrap{overflow-x:auto;background:var(--card);border:1px solid var(--line);border-radius:10px}
table{border-collapse:collapse;width:100%;min-width:900px}
th,td{text-align:left;padding:9px 12px;border-bottom:1px solid var(--line);vertical-align:top;font-size:13.5px}
th{font-size:12px;text-transform:uppercase;letter-spacing:.04em;color:var(--muted)}
tr:last-child td{border-bottom:0}
td ul{margin:0;padding:0;list-style:none}td li{margin:0 0 4px}
code,.k{font:12.5px ui-monospace,Menlo,monospace;overflow-wrap:anywhere}
.muted{color:var(--muted)}.small{font-size:12.5px}
details{margin-top:4px}summary{cursor:pointer;color:var(--muted);font-size:12.5px}
ul.plain{margin:6px 0 0;padding-left:20px}ul.plain li{margin:4px 0}
footer{margin-top:36px;color:var(--muted);font-size:13px}
a{color:var(--dec)}
"""

_FAVICON = ("<link rel='icon' href=\"data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' "
            "viewBox='0 0 100 100'><text y='.9em' font-size='90'>🗝️</text></svg>\">")


def _e(text):
    return html.escape(str(text)) if text is not None else ""


def _tag(evidence):
    return "<span class='tag t-%s'>%s</span>" % (evidence, evidence)


def _cap_li(c):
    more = " <span class='muted small'>+%d more</span>" % c["more"] if c.get("more") else ""
    conf = " · prose match" if c.get("confidence") == "prose" else ""
    head, _, rest = c["key"].partition(":")
    # "write:" is redundant in the Write column; "delete:" and "modify:" there are not
    shown = rest if head in ("read", "write", "send", "cred") and rest else c["key"]
    return "<li>%s<span class='k'>%s</span>%s<br><span class='muted small'>%s%s</span></li>" % (
        _tag(c["evidence"]), _e(shown), more, _e(c["source"]), _e(conf))


def _cell(caps, col, limit=4):
    mine = [c for c in caps if column(c["key"]) == col and not c["key"].startswith("ref:")]
    mine.sort(key=lambda c: (c["evidence"] != DECLARED, c.get("confidence") == "prose", c["key"]))
    if not mine:
        return "<span class='muted small'>nothing detected</span>"
    head = "".join(_cap_li(c) for c in mine[:limit])
    if len(mine) > limit:
        head += "<li><details><summary>%d more</summary><ul>%s</ul></details></li>" % (
            len(mine) - limit, "".join(_cap_li(c) for c in mine[limit:]))
    return "<ul>%s</ul>" % head


def _group(findings):
    """Findings grouped by rule, shared-scope instances first."""
    groups, order = {}, []
    for f in findings:
        if f["rule"] not in groups:
            groups[f["rule"]] = []
            order.append(f["rule"])
        groups[f["rule"]].append(f)
    return [(r, groups[r]) for r in order]


def _finding_cards(findings, cls):
    out = []
    for rule_id, items in _group(findings):
        live = [f for f in items if not f["excused"]]
        excused = [f for f in items if f["excused"]]
        if not live and not excused:
            continue
        first = items[0]
        out.append("<div class='find %s'><h3><span class='tag t-rule'>%s</span><span class='tag t-rmf'>%s</span>%s</h3>"
                   % (cls if live else "quiet", _e(rule_id), _e(first.get("rmf") or ""), _e(first["title"])))
        shared = [f for f in live if f.get("shared")]
        single = [f for f in live if not f.get("shared")]
        out.append("<ul>")
        for f in shared[:12]:
            out.append("<li><b>%s.</b> %s</li>" % (_e(f["who"][:1].upper() + f["who"][1:]), _e(f["what"])))
        if len(shared) > 12:
            out.append("<li class='muted'>and %d more shared-config instances</li>" % (len(shared) - 12))
        by_agent = {}
        for f in single:
            by_agent.setdefault(f["who"], []).append(f)
        if len(by_agent) > 6 and len({f["what"] for f in single}) <= 2:
            out.append("<li><b>%d agents.</b> %s <details><summary>which</summary>%s</details></li>" % (
                len(by_agent), _e(single[0]["what"]), _e(", ".join(sorted(by_agent)))))
        else:
            for who, fs in sorted(by_agent.items()):
                what = "; ".join(sorted({f["what"] for f in fs})[:3])
                extra = " <span class='muted small'>+%d more</span>" % (len(fs) - 3) if len({f["what"] for f in fs}) > 3 else ""
                out.append("<li><b>%s.</b> %s%s <span class='muted small'>(%s)</span></li>" % (
                    _e(who), _e(what), extra, _e(fs[0]["source"])))
        for f in excused:
            out.append("<li class='muted'>Excepted: %s, %s. Reason on file: %s</li>" % (
                _e(f["who"]), _e(f["what"]), _e(f["excused"])))
        out.append("</ul></div>")
    return out


def render_html(report, policy, result, note=None):
    agents = report["agents"]
    live_cf = [f for f in result["config_forbidden"] if not f["excused"]]
    live_if = [f for f in result["instructed_forbidden"] if not f["excused"]]
    rules_hit = len({f["rule"] for f in live_cf})
    out = ["<!doctype html><html lang='en'><head><meta charset='utf-8'>",
           "<meta name='viewport' content='width=device-width,initial-scale=1'>", _FAVICON,
           "<title>%s</title><style>%s</style></head><body><main>" % (_e(report["title"]), _CSS),
           "<h1>%s</h1>" % _e(report["title"]),
           "<p class='sub'>Generated %s · %d agents in the registry · policy: %s (%s)</p>" % (
               _e(report["generated"].replace("T", " ")), len(agents),
               _e(policy.get("title", "untitled")), _e(policy.get("status", "no status")))]
    if note:
        out.append("<div class='banner'>%s</div>" % note)
    jit = report.get("jit")
    if jit and not jit.get("errors"):
        t = jit["totals"]
        out.append("<div class='banner'><b>Just-in-time pass.</b> %s runs read over %d days: %s of %s shared allow "
                   "rules covered any call, and %s covered a call in every run of some agent. "
                   "<a href='#jit'>Per agent below.</a></div>" % (
                       "{:,}".format(t["runs_read"]), jit["window_days"], "{:,}".format(t["shared_rules_used"]),
                       "{:,}".format(t["shared_rules"]), "{:,}".format(t["shared_rules_every"])))
    if report["errors"]:
        out.append("<div class='banner bad'><b>This register is incomplete.</b> Something it needed couldn't "
                   "be read, so a blank below may mean unread, not none.<ul class='plain'>%s</ul></div>"
                   % "".join("<li>%s</li>" % _e(x) for x in report["errors"]))
    if live_cf:
        out.append("<div class='banner bad'><b>Config allows what policy forbids under %d rule%s.</b> "
                   "%d instance%s, listed first below.</div>" % (
                       rules_hit, "" if rules_hit == 1 else "s", len(live_cf), "" if len(live_cf) == 1 else "s"))
    else:
        out.append("<div class='banner good'><b>Nothing in config that the policy forbids.</b> That covers the "
                   "rules this tool can check and the files it could read; both limits are listed at the bottom.</div>")

    out.append("<h2>Config allows, policy forbids</h2>")
    out.append("<p class='muted small'>Declared access: it's in a settings file, a task approval, or the "
               "registry. Nothing here is a guess.</p>")
    out += _finding_cards(result["config_forbidden"], "") or ["<p>None.</p>"]

    out.append("<h2>Instructions ask for what policy forbids</h2>")
    out.append("<p class='muted small'>Inferred from each task's SKILL.md and the scripts it runs. Whether "
               "config would let these through isn't known for agents in auto mode, so they're kept apart "
               "from the list above.</p>")
    out += _finding_cards(result["instructed_forbidden"], "inst") or ["<p>None found.</p>"]

    modes = {}
    for a in agents:
        modes[a["mode"] or "unset"] = modes.get(a["mode"] or "unset", 0) + 1
    senders = sum(1 for a in agents if any(column(c["key"]) == "send" for c in a["declared"] + a["inferred"]))
    out.append("<div class='tiles'>")
    for num, label in ((len(agents), "agents registered"),
                       (sum(1 for a in agents if a["enabled"]), "enabled"),
                       (senders, "can send or publish (declared or inferred)"),
                       (sum(1 for s in report["stores"] if s["exists"]), "credential stores on disk"),
                       (len(live_if), "instructed, policy forbids"),
                       (len(result["silent"]), "kinds of access policy is silent on")):
        out.append("<div class='tile'><b>%d</b><span>%s</span></div>" % (num, _e(label)))
    out.append("<div class='tile'><b class='small' style='font-size:15px'>%s</b><span>permission modes</span></div>"
               % _e(" · ".join("%s %d" % kv for kv in sorted(modes.items()))))
    out.append("</div>")

    # shared config
    out.append("<h2>Shared config: what every agent under it inherits</h2>")
    out.append("<p class='muted small'>Allow rules aren't per-agent. Each settings file below applies to "
               "every agent listed against it, so its rows aren't repeated in the per-agent table.</p>")
    out.append("<div class='tablewrap'><table><thead><tr><th>Settings file</th><th>Applies to</th>"
               "<th>Rules</th><th>What stands out</th></tr></thead><tbody>")
    for sc in report["scopes"]:
        if sc["status"] != "read":
            out.append("<tr><td><code>%s</code></td><td colspan='3' class='muted'>%s</td></tr>" % (
                _e(sc["id"]), _e(sc["status"])))
            continue
        stand = []
        if sc["default_mode"]:
            stand.append("default mode <code>%s</code>" % _e(sc["default_mode"]))
        if not sc["deny"]:
            stand.append("no deny rules")
        if sc["broad_exec"]:
            stand.append("%d wildcard interpreter rule(s): %s%s <span class='muted'>(Claude Code's docs say "
                         "these are set aside while a session is in auto mode and apply in every other mode; "
                         "not probed here)</span>" % (
                             len(sc["broad_exec"]), ", ".join("<code>%s</code>" % _e(r) for r in sc["broad_exec"][:4]),
                             " and %d more" % (len(sc["broad_exec"]) - 4) if len(sc["broad_exec"]) > 4 else ""))
        sends = sorted({c["key"] for c in sc["caps"] if column(c["key"]) == "send"})
        if sends:
            stand.append("send or publish: " + ", ".join("<code>%s</code>" % _e(k) for k in sends[:10]))
        creds = sorted({c["key"] for c in sc["caps"] if column(c["key"]) == "cred"})
        if creds:
            stand.append("credentials named: " + ", ".join("<code>%s</code>" % _e(k) for k in creds[:8]))
        for h in sc["hooks"]:
            stand.append("hook %s on <code>%s</code> <span class='muted'>(registered, not probed)</span>" % (
                _e(h["event"]), _e(h["matcher"] or "everything")))
        if sc["dead"]:
            stand.append("%d rule(s) that probably grant nothing" % len(sc["dead"]))
        if sc["unclassified"]:
            stand.append("<span class='muted'>%d rule(s) no detector recognised</span>" % sc["unclassified"])
        tools = ", ".join("%s %d" % kv for kv in sorted(sc["by_tool"].items(), key=lambda kv: -kv[1])[:6])
        out.append("<tr><td><code>%s</code></td><td>%s</td><td>%d allow · %d deny · %d ask"
                   "<br><span class='muted small'>%s</span></td><td><ul>%s</ul></td></tr>" % (
                       _e(sc["id"]), _e(scope_who(sc, len(agents))), sc["allow"], sc["deny"], sc["ask"], _e(tools),
                       "".join("<li>%s</li>" % s for s in stand) or "<li class='muted'>nothing</li>"))
    out.append("</tbody></table></div>")

    if report["stores"]:
        out.append("<h2>Credential stores</h2><p class='muted small'>Existence and the rules that reach each "
                   "one. No store is opened.</p><div class='tablewrap'><table><thead><tr><th>Store</th>"
                   "<th>Path</th><th>Agents that reach it (declared)</th><th>Agents that use it (inferred)</th>"
                   "%s<th>Deny rule</th></tr></thead><tbody>" % (
                       "<th>Runs that used it (observed)</th>" if jit and not jit.get("errors") else ""))
        for st in report["stores"]:
            reach = [a["id"] for a in agents if any(c["id"] == st["id"] for c in a["cred_reach"])]
            use = [a["id"] for a in agents if any(c["key"] == "cred:%s" % st["id"] for c in a["inferred"])]
            observed = None
            if jit and not jit.get("errors"):
                hits = []
                for ja in jit["agents"]:
                    n = next((x["runs"] for x in ja["reach"] if x["key"] == "cred:%s" % st["id"]), 0)
                    if n:
                        hits.append("%s %d/%d" % (ja["id"], n, ja["runs"]))
                observed = _e(", ".join(hits)) if hits else "<span class='muted'>none seen</span>"
            if not st["exists"]:
                out.append("<tr><td><b>%s</b></td><td><code>%s</code></td><td colspan='%d' class='muted'>not on "
                           "disk</td></tr>" % (_e(st["label"]), _e(st["path"]), 4 if observed is not None else 3))
                continue

            def names(ids):
                if not ids:
                    return "<span class='muted'>none found</span>"
                if len(ids) > 5:
                    return "%d of %d <details><summary>which</summary>%s</details>" % (
                        len(ids), len(agents), _e(", ".join(ids)))
                return _e(", ".join(ids))
            out.append("<tr><td><b>%s</b></td><td><code>%s</code></td><td>%s</td><td>%s</td>%s<td>%s</td></tr>" % (
                _e(st["label"]), _e(st["path"]), names(reach), names(use),
                "<td class='small'>%s</td>" % observed if observed is not None else "",
                _e("; ".join(d["rule"] for d in st["denied_by"])) or "<span class='tag t-warn'>none</span>"))
        out.append("</tbody></table></div>")

    # per agent
    out.append("<h2>Every agent</h2>")
    out.append("<p class='muted small'>%s is in permission config. %s was read out of the task's instructions "
               "or a script they run; it can be wrong in both directions. Shared rules above apply on top of "
               "each row.</p>" % (_tag(DECLARED), _tag(INFERRED)))
    out.append("<div class='tablewrap'><table><thead><tr><th>Agent</th><th>Read</th><th>Write</th>"
               "<th>Send</th><th>Credentials</th><th>Also</th></tr></thead><tbody>")
    for a in sorted(agents, key=lambda a: (not a["enabled"], a["id"])):
        caps = a["declared"] + a["inferred"]
        mode = a["mode"] or "mode unset"
        head = ["<b>%s</b>" % _e(a["id"]),
                "<span class='tag %s'>%s</span><span class='tag %s'>%s</span>" % (
                    "t-on" if a["enabled"] else "t-off", "enabled" if a["enabled"] else "disabled",
                    "t-warn" if a["mode"] in (None, "bypassPermissions") else "t-off", _e(mode)),
                "<span class='muted small'>model %s · runs in <code>%s</code>%s</span>" % (
                    _e(a["model"] or "not set"), _e(a["cwd"] or "unknown"),
                    " · %d task approvals" % a["approved"] if a["approved"] else "")]
        also = [c for c in caps if column(c["key"]) == "other" and not c["key"].startswith("ref:")]
        extra = []
        if also:
            extra.append("<ul>%s</ul>" % "".join(_cap_li(c) for c in also[:5]))
        if a["prohibited"]:
            extra.append("<details><summary>%d thing(s) the instructions say not to do</summary><ul>%s</ul>"
                         "<span class='muted small'>A prompt-level rule, not a config control.</span></details>" % (
                             len(a["prohibited"]), "".join(
                                 "<li><span class='k'>%s</span> <span class='muted small'>%s</span></li>" % (
                                     _e(c["key"]), _e(c["source"])) for c in a["prohibited"][:12])))
        if a["hops"]:
            extra.append("<details><summary>%d script/skill hop(s)</summary><ul>%s</ul></details>" % (
                len(a["hops"]), "".join("<li><code>%s</code> <span class='muted small'>%s</span></li>" % (
                    _e(h["path"]), _e(h["status"])) for h in a["hops"])))
        for u in a["unknowns"]:
            extra.append("<div class='small'><span class='tag t-warn'>unknown</span>%s</div>" % _e(u))
        if a["skill_status"] != "read":
            blank = "<span class='tag t-warn'>unknown</span><span class='muted small'>instructions %s</span>" % _e(a["skill_status"])
        else:
            blank = None
        cells = []
        for col in ("read", "write", "send", "cred"):
            cell = _cell(caps, col)
            if blank and not any(column(c["key"]) == col for c in a["declared"]):
                cell = blank
            elif blank:
                cell += blank
            cells.append(cell)
        out.append("<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>" % (
            "<br>".join(head), cells[0], cells[1], cells[2], cells[3],
            "".join(extra) or "<span class='muted small'>—</span>"))
    out.append("</tbody></table></div>")

    if jit:
        import jit_pass
        out += jit_pass.render_section(jit)

    out.append("<h2>Where policy is silent</h2>")
    out.append("<p class='muted small'>Access that shows up in config or instructions and that no policy rule "
               "speaks to, for or against. Silence isn't approval; each line is a decision nobody has written down.</p>")
    if result["silent"]:
        out.append("<div class='tablewrap'><table><thead><tr><th>Access</th><th>Evidence</th><th>Where</th>"
                   "</tr></thead><tbody>")
        for s in result["silent"][:60]:
            where = []
            if s["shared"]:
                where.append("shared config: " + ", ".join(s["shared"]))
            if s["agents"]:
                where.append("%d agent%s%s" % (len(s["agents"]), "" if len(s["agents"]) == 1 else "s",
                                               ": " + ", ".join(s["agents"][:6]) + ("…" if len(s["agents"]) > 6 else "")))
            out.append("<tr><td><span class='k'>%s</span></td><td>%s</td><td class='small'>%s</td></tr>" % (
                _e(s["key"]), "".join(_tag(ev) for ev in s["evidence"]), _e("; ".join(where))))
        out.append("</tbody></table></div>")
        if len(result["silent"]) > 60:
            out.append("<p class='muted small'>%d more in the JSON output.</p>" % (len(result["silent"]) - 60))
    else:
        out.append("<p>Every kind of access found is covered by a rule.</p>")

    out.append("<h2>What this page can't see</h2><ul class='plain'>%s</ul>" % "".join(
        "<li>%s</li>" % _e(x) for x in cannot_see(report)))
    if report["orphans"]:
        out.append("<details><summary>Task folders with no registry row (%d)</summary><p class='small'>%s</p></details>"
                   % (len(report["orphans"]), _e(", ".join(o["id"] for o in report["orphans"]))))

    out.append("<h2>The policy this was checked against</h2>")
    out.append("<p class='muted small'>%s</p>" % _e(policy.get("preamble", "")))
    unchecked = {u["rule"]: u["why"] for u in result["unchecked"]}
    hit = {f["rule"] for f in live_cf} | {f["rule"] for f in live_if}
    out.append("<div class='tablewrap'><table><thead><tr><th>Rule</th><th>NIST AI RMF</th><th>Says</th>"
               "<th>Checked?</th></tr></thead><tbody>")
    for r in policy.get("rules", []):
        if r["id"] in unchecked:
            status = "<span class='tag t-off'>can't check</span><br><span class='muted small'>%s</span>" % _e(unchecked[r["id"]])
        elif r["id"] in hit:
            status = "<span class='tag t-rule'>findings</span>"
        else:
            status = "<span class='tag t-on'>no findings</span>"
        out.append("<tr><td><b>%s</b><br>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>" % (
            _e(r["id"]), _e(r["title"]), _e(r.get("rmf", "")), _e(r["text"]), status))
    out.append("</tbody></table></div>")
    out.append("<footer>%s Declared rows come from permission config; inferred rows are a text scan and can be "
               "wrong. No credential file was opened and no secret value appears on this page.</footer>"
               "</main></body></html>" % (
                   "Configured access, plus what runs' transcripts show they used." if jit and not jit.get("errors")
                   else "Configured access, not observed behavior."))
    return "\n".join(out)


def render_policy_md(policy):
    lines = ["# %s" % policy.get("title", "Acceptable-use policy"), "",
             "**Status:** %s" % policy.get("status", ""), "", policy.get("preamble", ""), ""]
    by_fn = {}
    for r in policy.get("rules", []):
        by_fn.setdefault(r.get("rmf", "Other"), []).append(r)
    for fn in ("Govern", "Map", "Measure", "Manage", "Other"):
        if fn not in by_fn:
            continue
        lines += ["## %s" % fn, ""]
        for r in by_fn[fn]:
            check = r.get("check") or {"type": "process"}
            how = "Not machine-checked: %s" % check.get("why", "a process rule.") if check["type"] == "process" \
                else "Checked by the register."
            lines += ["**%s. %s**" % (r["id"], r["title"]), "", r["text"], "", "*%s*" % how, ""]
    lines += ["---", "",
              "Generated from `%s` by `access_register.py --render-policy`. Edit the JSON, not this file."
              % "acceptable-use.json", ""]
    return "\n".join(lines)


# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------

def run(cfg, env, runs=True):
    """Build the register and diff it. Returns (report, policy, result, exit_code).

    With runs=True and a run-record source in config, the just-in-time pass runs
    too and its result lands in report["jit"].
    """
    reg = Register(cfg, env)
    report = reg.build()
    for sc in report["scopes"]:
        sc["cwd_shown"] = sc["cwd"] = env.tilde(sc["cwd"]) if sc.get("cwd") else None
        sc["additional_dirs"] = [env.tilde(d) for d in sc["additional_dirs"]]
        for key in ("read_patterns", "deny_patterns"):
            sc[key] = [[mask(env.tilde(p)), r] for p, r in sc[key]]   # the pattern is rule text too
        sc.pop("path", None)
    policy, why = load_policy(cfg["policy"])
    if policy is None:
        report["errors"].append("policy %s is %s: nothing was diffed" % (env.tilde(cfg["policy"]), why))
        policy = {"title": "no policy loaded", "status": why, "rules": []}
    # scope_who needs cwd_shown, which is set above; facts built earlier used the fallback wording
    for name, items in report["facts"].items():
        for inst in items:
            sc = next((s for s in report["scopes"] if s["id"] == inst.get("shared")), None)
            if sc and inst["scope"] != "all agents":
                inst["scope"] = scope_who(sc, len(report["agents"]))
    result = diff(report, policy, cfg.get("exceptions") or {})
    if runs and (cfg.get("runs") or {}).get("sessions"):
        import jit_pass
        report["jit"] = jit_pass.run_pass(report, cfg, env)
        report["errors"] += ["just-in-time pass: %s" % e for e in report["jit"]["errors"]]
    report["cannot_see"] = cannot_see(report)
    if report["errors"]:
        code = 2
    elif any(not f["excused"] for f in result["config_forbidden"]):
        code = 1
    else:
        code = 0
    return report, policy, result, code


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--config")
    ap.add_argument("--out")
    ap.add_argument("--json")
    ap.add_argument("--render-policy", metavar="POLICY_JSON")
    ap.add_argument("--no-runs", action="store_true", help="skip the just-in-time pass over run transcripts")
    args = ap.parse_args(argv)

    if args.render_policy:
        policy, why = load_policy(args.render_policy)
        if policy is None:
            print("policy is %s" % why, file=sys.stderr)
            return 2
        target = os.path.splitext(args.render_policy)[0] + ".md"
        with open(target, "w") as fh:
            fh.write(render_policy_md(policy))
        print(target)
        return 0

    try:
        cfg, env = load_config(args.config)
    except (OSError, ValueError) as e:
        print("config can't be read: %s" % e, file=sys.stderr)
        return 2
    report, policy, result, code = run(cfg, env, runs=not args.no_runs)
    out = args.out or cfg.get("out")
    if out:
        out = os.path.expanduser(out)
        with open(out, "w") as fh:
            fh.write(render_html(report, policy, result))
    if args.json:
        with open(os.path.expanduser(args.json), "w") as fh:
            json.dump({"report": report, "policy": policy, "result": result}, fh, indent=2, default=str)
    live_cf = [f for f in result["config_forbidden"] if not f["excused"]]
    live_if = [f for f in result["instructed_forbidden"] if not f["excused"]]
    print("%d agents · config allows/policy forbids: %d · instructed/policy forbids: %d · policy silent: %d kinds"
          % (len(report["agents"]), len(live_cf), len(live_if), len(result["silent"])))
    jit = report.get("jit")
    if jit and not jit["errors"]:
        t = jit["totals"]
        print("just-in-time pass: %d runs · shared rules used %d of %d (every run of some agent: %d) · "
              "task approvals used %d of %d" % (t["runs_read"], t["shared_rules_used"], t["shared_rules"],
                                                 t["shared_rules_every"], t["approvals_used"], t["approvals"]))
    for e in report["errors"]:
        print("INCOMPLETE: %s" % e)
    if out:
        print(out)
    return code


if __name__ == "__main__":
    sys.modules.setdefault("access_register", sys.modules[__name__])   # so jit_pass imports this module, not a copy
    sys.exit(main())
