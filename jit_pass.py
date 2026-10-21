#!/usr/bin/env python3
"""Just-in-time pass: which standing permissions each scheduled agent's runs actually use.

The register says what each agent is allowed to touch. This pass says what its
runs touched. It reads the desktop app's record of every scheduled run in a
window, opens the transcript each run left, and takes every tool call the run
made. Each call is matched to the standing grant that let it through: a shared
allow rule, a per-task approval, or the working directory. Then, per agent:

    every run uses     standing grants every run in the window used
    some runs use      used by some runs and not others: these could be granted
                       to the run that needs one and dropped when it ends
    no run used        standing access nothing in the window exercised

Calls that ran on no standing grant are counted apart. The auto-mode
classifier's per-call approvals and grants made inside a single run are
already just-in-time; they're what the rest could become.

Everything here carries a third label, observed: it was read from what a run
did, not from config or instructions. The register's three rules still hold.
A transcript that's gone is an unknown run, not an empty one. A run that made
no tool calls is counted and left out of "every run", since it proves nothing
either way. No secret value is kept: tool inputs are cut to the fields that
name a command, path, or host, and masked before anything is stored.
"""

import glob as globmod
import json
import os
import re
import time
from datetime import datetime
from urllib.parse import urlsplit

import access_register as ar
from access_register import anchor, mask, parse_rule, pattern_covers, read_json, safe, split_commands

OBSERVED = "observed"

DEFAULT_RUNS = {"sessions": None, "transcripts_root": "~/.claude/projects", "window_days": 30, "min_runs": 3}

READ_TOOLS = ("Read", "Glob", "Grep", "LS", "NotebookRead")
EDIT_TOOLS = ("Edit", "Write", "MultiEdit", "NotebookEdit")
# The only input fields kept from a tool call. Everything else (file contents, prompts, queries) is dropped.
KEEP_INPUT = ("command", "file_path", "path", "notebook_path", "url", "skill", "subagent_type")
# Modes where Claude Code edits files inside the working directory without asking.
EDIT_MODES = ("auto", "acceptEdits", "bypassPermissions")

_MCP_NAME = re.compile(r"^mcp__(.+?)__(.+)$")
# Stripped before a command is matched, per Claude Code's permissions docs (Oct 2026).
_WRAPPERS = ("timeout", "time", "nice", "nohup", "stdbuf", "command", "builtin", "noglob", "xargs")
# Claude Code's built-in read-only commands: they run in every mode with no rule.
_READ_ONLY = ("ls", "cat", "echo", "pwd", "head", "tail", "grep", "find", "wc", "diff", "stat", "cd")
_GIT_READ_ONLY = ("status", "log", "diff", "show", "rev-parse", "ls-files", "blame", "describe", "shortlog")
# Edits here aren't auto-approved by acceptEdits or auto mode, even inside the working directory.
_PROTECTED = (".git", ".claude", ".vscode", ".idea")
# The desktop app's own tools (plan, wrap-up, session management). Claude Code records them as allowed
# by a rule, and no settings file read here holds one.
_APP_TOOL = re.compile(r"^mcp__ccd_", re.I)
# Claude Code's session scratchpad: it reads and writes there with no rule.
_SCRATCH = re.compile(r"^/(?:private/)?tmp/claude-\d+/")
_ENV_PREFIX = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=(?:'[^']*'|\"[^\"]*\"|\S*)\s+")
_HEREDOC = re.compile(r"<<-?\s*['\"]?([A-Za-z_][A-Za-z0-9_]*)['\"]?")

# Shown when a call was blocked. The decision Claude Code recorded wins; the
# denial kind and then the message text are fallbacks for older transcripts.
_DENIED_TEXT = [
    ("hook", re.compile(r"hook error|Blocked by project policy")),
    ("classifier", re.compile(r"auto mode classifier|Auto mode is unavailable")),
    ("no one to approve", re.compile(r"needs a person's approval|^This command requires approval")),
    ("deny rule", re.compile(r"^Permission to use \S+ .*has been denied")),
]


# --------------------------------------------------------------------------
# finding runs and reading what they did
# --------------------------------------------------------------------------

def find_runs(runs_cfg, env, now_ms, task_ids):
    """Session records for scheduled runs inside the window.

    Returns (runs, counts, problem). `problem` is set when the record source
    can't be read at all: then nothing below can be said, which is not the
    same as no run having used anything.
    """
    pattern = runs_cfg.get("sessions")
    files = sorted(globmod.glob(pattern)) if pattern else []
    counts = {"records": len(files), "unreadable": 0, "in_window": 0, "unregistered": {}, "older": 0}
    if not files:
        return [], counts, "no session records match %s" % ar._UUID.sub("…", env.tilde(pattern or "(not set)"))
    window = float(runs_cfg.get("window_days") or 30) * 86400000
    runs = []
    for f in files:
        data, why = read_json(f)
        if not isinstance(data, dict):
            counts["unreadable"] += 1
            continue
        tid = data.get("scheduledTaskId")
        if not tid:
            continue            # an interactive session, not a scheduled run
        created = data.get("createdAt")
        if not isinstance(created, (int, float)):
            counts["unreadable"] += 1
            continue
        if now_ms - created > window or created > now_ms + 86400000:
            counts["older"] += 1
            continue
        counts["in_window"] += 1
        if tid not in task_ids:
            counts["unregistered"][tid] = counts["unregistered"].get(tid, 0) + 1
            continue
        runs.append({"task": tid, "session": data.get("cliSessionId"), "cwd": data.get("cwd"),
                     "mode": data.get("permissionMode"), "created": created,
                     "grants": [u for u in data.get("sessionPermissionUpdates") or [] if isinstance(u, dict)],
                     "reasons": [r for r in data.get("alwaysAllowedReasons") or [] if isinstance(r, str)]})
    runs.sort(key=lambda r: r["created"])
    return runs, counts, None


def transcript_files(root, cwd, sid):
    """The run's transcript plus its subagents' transcripts. Empty when the transcript is gone."""
    if not sid or not root:
        return []
    main = os.path.join(root, re.sub(r"[^A-Za-z0-9]", "-", cwd or ""), sid + ".jsonl")
    if not os.path.exists(main):
        hits = globmod.glob(os.path.join(globmod.escape(root), "*", globmod.escape(sid) + ".jsonl"))
        if not hits:
            return []
        main = hits[0]
    subs = globmod.glob(os.path.join(globmod.escape(main[:-len(".jsonl")]), "subagents", "*.jsonl"))
    return [main] + sorted(subs)


def _result_text(block):
    body = block.get("content")
    if isinstance(body, list):
        body = " ".join(x.get("text", "") for x in body if isinstance(x, dict))
    return str(body or "")[:300]


def read_calls(paths):
    """Every tool call in a run's transcripts: (calls, unreadable lines).

    A call keeps its tool name, the input fields in KEEP_INPUT (masked), the
    permission decision Claude Code recorded for it if any, and whether it was
    blocked. Result text is read only to classify a block and is never kept.
    """
    calls, bad = [], 0
    for path in paths:
        uses, order, results = {}, [], {}
        try:
            fh = open(path, errors="replace")
        except OSError:
            bad += 1
            continue
        with fh:
            for line in fh:
                if '"tool_use"' not in line and '"tool_result"' not in line:
                    continue
                try:
                    e = json.loads(line)
                except ValueError:
                    bad += 1
                    continue
                if not isinstance(e, dict):
                    bad += 1            # the format is internal and can change; a line we can't read is unknown
                    continue
                msg = e.get("message")
                content = msg.get("content") if isinstance(msg, dict) else None
                if not isinstance(content, list):
                    continue
                if e.get("type") == "assistant":
                    for b in content:
                        if isinstance(b, dict) and b.get("type") == "tool_use" and b.get("id"):
                            inp = b.get("input") if isinstance(b.get("input"), dict) else {}
                            uses[b["id"]] = {"name": str(b.get("name") or ""),
                                             "input": {k: str(inp[k]) for k in KEEP_INPUT if inp.get(k) is not None}}
                            order.append(b["id"])
                elif e.get("type") == "user":
                    dec = e.get("permissionDecision")
                    for b in content:
                        if isinstance(b, dict) and b.get("type") == "tool_result" and b.get("tool_use_id"):
                            denied = None
                            verdict = dec.get("decision") if isinstance(dec, dict) else None
                            if verdict == "reject":
                                denied = {"hook": "hook", "user_reject": "no one to approve"}.get(
                                    dec.get("source"), "classifier" if dec.get("reasonType") == "classifier"
                                    else "deny rule")
                            elif verdict is None and (e.get("toolDenialKind") not in (None, "interrupted")
                                                      or b.get("is_error")):
                                # no decision recorded: an allowed call that then failed can't be told
                                # from a blocked one except by the message, so only known block messages count
                                text = _result_text(b)
                                denied = next((k for k, rx in _DENIED_TEXT if rx.search(text)), None)
                                if denied is None and e.get("toolDenialKind") == "automode-blocked":
                                    denied = "classifier"
                                elif denied is None and e.get("toolDenialKind") == "permission-rule":
                                    denied = "deny rule"
                            results[b["tool_use_id"]] = {"decision": dec if isinstance(dec, dict) else None,
                                                         "denied": denied}
        for cid in order:
            c = dict(uses[cid], **results.get(cid, {"decision": None, "denied": None}))
            c["answered"] = cid in results
            calls.append(c)
    return calls, bad


# --------------------------------------------------------------------------
# standing grants, and which one let a call through
# --------------------------------------------------------------------------

def _glob_rx(text):
    return ".*".join(re.escape(p) for p in text.split("*"))


def bash_rule_rx(content):
    """A Bash rule's content as a regex over one subcommand.

    `cmd:*` and `cmd *` both match `cmd` alone and `cmd` followed by arguments,
    but not `cmdx`. Any other `*` matches anything, spaces and slashes included.
    A rule with no wildcard matches only that exact command.
    """
    c = content.strip()
    if c.endswith(":*"):
        return re.compile("^" + _glob_rx(c[:-2]) + r"(?:\s.*)?$", re.S)
    if c.endswith(" *"):
        return re.compile("^" + _glob_rx(c[:-2]) + r"(?:\s.*)?$", re.S)
    return re.compile("^" + _glob_rx(c) + "$", re.S)


def strip_heredocs(command):
    """Drop heredoc bodies so their lines aren't read as commands."""
    lines, out, end = command.split("\n"), [], None
    for line in lines:
        if end is not None:
            if line.strip() == end:
                end = None
            continue
        out.append(line)
        m = _HEREDOC.search(line)
        if m:
            end = m.group(1)
    return "\n".join(out)


def strip_wrapper(s):
    """`timeout 60 cmd`, `nohup cmd`, `nice -n 5 cmd`, `xargs cmd` -> `cmd`. One wrapper per call."""
    try:
        toks = s.split()
    except ValueError:
        return None
    if not toks or toks[0] not in _WRAPPERS:
        return None
    i = 1
    if toks[0] == "xargs" and (len(toks) < 2 or toks[1].startswith("-")):
        return None             # only a bare xargs is stripped
    while i < len(toks) and (toks[i].startswith("-") or (toks[0] in ("timeout", "nice") and re.match(r"^[\d.]+[smhd]?$", toks[i]))):
        i += 1
    rest = toks[i:]
    if not rest:
        return None
    return s[s.index(rest[0], len(toks[0])):]


def bash_pieces(command):
    """The subcommands of a shell command, each checked on its own the way Claude Code checks them."""
    out = []
    for seg in split_commands(strip_heredocs(command)):
        s = seg.strip().lstrip("({").rstrip(")}").strip()
        if not s or s.startswith("#"):
            continue
        while True:
            m = _ENV_PREFIX.match(s)
            if m:
                s = s[m.end():]
                continue
            inner = strip_wrapper(s)
            if inner:
                s = inner
                continue
            break
        if s:
            out.append(s)
    return out


def read_only_builtin(cmd):
    """Is this subcommand one Claude Code runs with no rule at all?

    Not when it writes: `cat > f` and `echo x >> ~/.env` redirect into a file.
    """
    toks = cmd.split()
    if not toks:
        return False
    for m in ar._REDIRECT.finditer(cmd):
        if not (m.group(1).startswith("/dev/") or m.group(1) in ("&1", "&2")):
            return False
    head = toks[0]
    if head == "find":
        return not re.search(r"(?:^|\s)-(?:delete|exec|execdir|ok|okdir|fprint\w*)\b", cmd)
    if head == "git":
        rest = [t for t in toks[1:] if not t.startswith("-")]
        if "-C" in toks:      # git -C <dir> <sub>: the folder is an argument, not the subcommand
            j = toks.index("-C")
            rest = [t for t in toks[j + 2:] if not t.startswith("-")]
        return bool(rest) and rest[0] in _GIT_READ_ONLY
    return head in _READ_ONLY


def specificity(g):
    """How narrow a grant is. The narrowest grant that covers a call is the one credited with it."""
    if g["kind"] == "location":
        return 0
    c = g["content"]
    if c is None or c.strip() in ("", "*", ":*"):
        return 1
    literal = re.split(r"[*?]", c, maxsplit=1)[0]
    # `dir/*` and `dir/**` cover the same files under gitignore rules; the single star reads narrower
    return 10 + 2 * len(literal) + (100000 if ("*" not in c and "?" not in c) else 0) - (1 if "**" in c else 0)


def make_grant(gid, kind, scope, rule, settings_dir, cwd, env, servers=None):
    tool, content = parse_rule(rule)
    if tool is None:
        return None
    shown = ar._UUID.sub(lambda m: ar.mcp_label(m.group(0), servers or {}), rule) if tool.startswith("mcp__") else rule
    g = {"id": gid, "kind": kind, "scope": scope, "shown": safe(shown, 120), "tool": tool, "content": content}
    if tool == "Bash" and content is not None and content.strip() not in ("", "*", ":*"):
        g["rx"] = bash_rule_rx(content)
    elif tool in ("Read", "Edit", "Write", "NotebookEdit", "MultiEdit") and content:
        g["pat"], _ = anchor(content, settings_dir, cwd, env)
    g["spec"] = specificity(g)
    return g


def rule_matches(g, piece):
    """Does standing grant g allow this piece of a call?"""
    kind, arg = piece
    tool, content = g["tool"], g["content"]
    if g["kind"] == "location":
        if g["tool"] != kind or not (arg == g["dir"] or arg.startswith(g["dir"].rstrip("/") + "/")):
            return False
        if kind == "edit" and g["scope"] == "working directory":
            rel = os.path.relpath(arg, g["dir"]).split(os.sep)
            return not any(part in _PROTECTED for part in rel)
        return True
    if kind == "bash":
        return tool == "Bash" and (content is None or "rx" not in g or bool(g["rx"].match(arg)))
    if kind in ("read", "edit"):
        # Edit rules govern every file-editing tool and also permit reads. Write(), MultiEdit(), and
        # NotebookEdit() path rules are accepted by Claude Code and never checked, so they match nothing.
        tools = ("Read", "Edit") if kind == "read" else ("Edit",)
        if tool not in tools:
            return False
        if content is None:
            return True
        return bool(g.get("pat")) and pattern_covers(g["pat"], arg)
    if kind == "web":
        if tool != "WebFetch":
            return False
        if content is None:
            return True
        m = re.match(r"domain:(.+)", content)
        dom = m.group(1).strip().lower() if m else None
        if not dom:
            return False
        if dom.startswith("*."):
            return arg.endswith(dom[1:]) and arg != dom[2:]    # subdomains, not the apex
        return arg == dom                                     # the apex only, not its subdomains
    if kind == "mcp":
        m = _MCP_NAME.match(arg)
        server = m.group(1) if m else None
        return tool == arg or (server is not None and tool in ("mcp__" + server, "mcp__" + server + "__*"))
    # any other tool: a bare rule for it, or one whose content names the tool's argument
    name, sub = arg
    if tool != name:
        return False
    if content is None:
        return True
    if sub is None:
        return False
    if content.endswith("*"):
        return sub.startswith(content.rstrip("*:"))
    return sub == content or sub.startswith(content + ":")   # Skill(plugin) covers plugin:skill


def call_pieces(call, run_cwd):
    """A call as the pieces permission checks see: subcommands, a path, a host, or a tool name."""
    name, inp = call["name"], call["input"]
    if name == "Bash":
        return [("bash", p) for p in bash_pieces(inp.get("command", ""))]
    if name in READ_TOOLS or name in EDIT_TOOLS:
        raw = inp.get("file_path") or inp.get("notebook_path") or inp.get("path") or run_cwd or ""
        path = os.path.normpath(raw if os.path.isabs(raw) else os.path.join(run_cwd or "/", raw))
        return [("read" if name in READ_TOOLS else "edit", path)]
    if name == "WebFetch":
        try:
            host = urlsplit(inp.get("url", "")).hostname or ""    # drops any user:token@ in front of the host
        except ValueError:
            host = ""
        return [("web", host.lower())]
    if name.startswith("mcp__"):
        return [("mcp", name)]
    return [("tool", (name, inp.get("skill") or inp.get("subagent_type")))]


class AgentGrants:
    """Every standing grant one agent runs under: shared rules, task approvals, and its working directory."""

    def __init__(self, shared, approvals, cwd, extra_dirs, tilde=lambda p: p):
        self.shared, self.approvals = shared, approvals
        self.location = []
        for d in [cwd] + list(extra_dirs or []):
            if not d:
                continue
            for tool in ("read", "edit"):
                self.location.append({"id": "L:%s:%s" % (tool, tilde(d)), "kind": "location",
                                      "scope": "working directory", "tool": tool, "dir": d, "content": None, "spec": 0})
        self.all = self.shared + self.approvals + self.location
        # index by tool so a call isn't checked against every rule
        self.by_tool = {}
        for g in self.shared + self.approvals:
            key = g["tool"]
            if key.startswith("mcp__"):
                m = _MCP_NAME.match(key)
                key = "mcp__" + (m.group(1) if m else key[5:])
            self.by_tool.setdefault(key, []).append(g)

    def candidates(self, piece, mode):
        kind, arg = piece
        if kind == "bash":
            pool = self.by_tool.get("Bash", [])
        elif kind == "read":
            pool = self.by_tool.get("Read", []) + self.by_tool.get("Edit", []) + \
                [g for g in self.location if g["tool"] == "read"]
        elif kind == "edit":
            pool = list(self.by_tool.get("Edit", []))
            if mode in EDIT_MODES:
                pool += [g for g in self.location if g["tool"] == "edit"]
        elif kind == "web":
            pool = self.by_tool.get("WebFetch", [])
        elif kind == "mcp":
            m = _MCP_NAME.match(arg)
            pool = self.by_tool.get("mcp__" + (m.group(1) if m else ""), [])
        else:
            pool = self.by_tool.get(arg[0], [])
        return [g for g in pool if rule_matches(g, piece)]


def family(g):
    """approval, local (a settings.local.json rule), rule (a settings.json rule), or location."""
    if g["kind"] == "rule" and g["scope"].endswith("settings.local.json"):
        return "local"
    return g["kind"]


_SHAPE_SUB = ("git", "gh", "sf", "sfdx", "npm", "brew", "launchctl", "docker", "uv")


def shape(piece, env):
    """What a covered call looked like, cut to the part a narrower grant would name.

    `python3 ~/bin/send.py --channel x payload.json` -> `python3 ~/bin/send.py`;
    `git -C ~/repo commit -m ...` -> `git commit`; a path -> its folder. Masked.
    """
    kind, arg = piece
    if kind == "bash":
        toks = arg.split()
        if not toks:
            return None
        head = toks[0]
        rest = [t for t in toks[1:] if not t.startswith("-")]
        if ar._INTERPRETERS.match(os.path.basename(head)) and rest:
            out = "%s %s" % (head, rest[0])
        elif os.path.basename(head) in _SHAPE_SUB:
            skip = {"-C", "--git-dir", "--work-tree", "-c", "--repo", "-R", "--target-org", "-o"}
            words, i = [], 1
            while i < len(toks):
                if toks[i] in skip:
                    i += 2
                    continue
                if not toks[i].startswith("-"):
                    words.append(toks[i])
                i += 1
            out = " ".join([head] + words[:1 if head != "gh" else 2])
        else:
            out = head
        out = out.replace(env.home + "/", "~/")
        return safe(re.sub(r"/Users/[\w.\-]+/", "~/", out), 90)
    if kind in ("read", "edit"):
        return safe(area(arg, env), 90)
    if kind == "web":
        return safe(arg, 90) if arg else None
    return None


def attribute(call, grants, mode, temp_grants, run_cwd, seen=None):
    """What let one call through.

    Returns (status, credited grant ids, check). Statuses: standing (credited to
    a standing grant), this_run (granted inside this run only), classifier,
    builtin (Claude Code allows it with no rule), unmatched (no current grant
    covers it), denied, and unanswered (the run ended first).

    Claude Code's record, when there is one, names the kind of thing that
    allowed the call but not which rule. So the record picks the family
    (settings rule, task approval, working directory) and, inside it, the
    narrowest grant that covers the call gets the credit. Claude Code itself
    takes the first match; it doesn't rank. `check` compares the two for calls
    the record says a rule allowed: agree, family (only the other kind of
    grant covers it), or missing (no current grant does).
    """
    if call.get("denied"):
        return "denied", [], None
    if not call.get("answered"):
        return "unanswered", [], None
    dec = call.get("decision") or {}
    src, why = dec.get("source"), dec.get("reasonType")
    if src == "user_temporary":
        return "this_run", [], None
    if why == "classifier":
        return "classifier", [], None
    recorded_rule = why in ("rule", "subcommandResults")
    if _APP_TOOL.match(call["name"]) or (call["name"] in ("Agent", "Task", "TodoWrite", "ToolSearch")
                                          and not recorded_rule):
        return "builtin", [], None
    if src == "user_permanent":
        prefer = ("approval", "local")    # an "always allow" click: saved as a task approval or a settings.local.json rule
    elif src == "config" and recorded_rule:
        prefer = ("rule", "local")
    elif src == "config":
        prefer = ("location",)       # "mode" and "other": the working directory, or a built-in allowance
    else:
        prefer = None                # no record: the working directory first for paths, then the narrowest rule
    credited, unmatched, builtin, this_run, family_ok = set(), 0, 0, 0, True
    pieces = call_pieces(call, run_cwd)
    for p in pieces:
        if (p[0] == "bash" and read_only_builtin(p[1])) or (p[0] in ("read", "edit") and _SCRATCH.match(p[1])):
            builtin += 1              # allowed in every mode with no rule, so no rule gets credit for it
            continue
        cands = grants.candidates(p, mode)
        if not cands:
            if any(rule_matches(g, p) for g in temp_grants):
                this_run += 1
            else:
                unmatched += 1
            continue
        pick = [g for g in cands if prefer and family(g) in prefer]
        if prefer == ("location",) and not pick:
            builtin += 1              # the record says no rule was consulted, so none gets credit
            continue
        if prefer and not pick and recorded_rule:
            family_ok = False
        if not pick and prefer is None and p[0] in ("read", "edit"):
            pick = [g for g in cands if g["kind"] == "location"]
        pick = pick or cands
        top = max(g["spec"] for g in pick)
        won = [g for g in pick if g["spec"] == top]
        credited.update(g["id"] for g in won)
        if seen is not None:
            for g in won:
                if g["kind"] == "location" or (g["content"] and ("*" in g["content"] or "?" in g["content"])) \
                        or g["content"] is None:
                    seen.setdefault(g["id"], set()).add(p)
    check = None
    if recorded_rule:
        check = "missing" if unmatched else ("agree" if family_ok else "family")
    if credited:
        return "standing", sorted(credited), check
    if unmatched:
        # Claude Code accepted it on something other than a rule, and no grant here explains it; or a harness
        # tool (AskUserQuestion, SendUserFile, ...) that no settings file names
        harness = all(p[0] == "tool" for p in pieces)
        return ("builtin" if (src == "config" and not recorded_rule) or (harness and not recorded_rule)
                else "unmatched"), [], check
    if this_run:
        return "this_run", [], check
    return "builtin", [], check


# --------------------------------------------------------------------------
# where runs went
# --------------------------------------------------------------------------

def area(path, env):
    """Up to two folder levels of a path, in ~ form: ~/PhoneLog/bin, ~/.claude/agent-memory, /private/tmp."""
    t = env.tilde(path)
    if t == "~":
        return "~"
    if t.startswith("~/"):
        parts = t[2:].split("/")[:-1]
        return "~/" + "/".join(parts[:2]) if parts else "~"
    parts = [p for p in t.split("/") if p][:-1]
    return "/" + "/".join(parts[:2]) if parts else "/"


def reach_keys(call, clf, servers):
    """The register's capability keys for one observed call: the same vocabulary as the declared and inferred columns."""
    name, inp = call["name"], call["input"]
    if name == "Bash":
        return {k for k, _ in clf.command(inp.get("command", ""))}
    if name.startswith("mcp__"):
        return {ar.classify_mcp(name, servers)}
    if name == "WebFetch":
        return {"web:fetch"}
    if name == "WebSearch":
        return {"web:search"}
    if name in ("Agent", "Task"):
        return {"exec:agent"}
    return set()


def touched(call, run_cwd, env):
    """(area, 'read' or 'edit') for each path a call names: file tools by their path, shell commands by path tokens."""
    name, inp = call["name"], call["input"]
    out = set()
    if name in READ_TOOLS or name in EDIT_TOOLS:
        for _, p in call_pieces(call, run_cwd):
            if not _SCRATCH.match(p):      # the session scratchpad isn't standing access
                out.add((area(p, env), "read" if name in READ_TOOLS else "edit"))
    elif name == "Bash":
        for m in ar._PATH.finditer(inp.get("command", "")):
            p = env.expand(ar.norm_path(m.group(0)))
            out.add((area(p + "/x" if not os.path.splitext(p)[1] else p, env), "named"))
    return out


# --------------------------------------------------------------------------
# the pass
# --------------------------------------------------------------------------

def load_standing(report, cfg, env):
    """Raw allow rules per settings file and approvals per task, re-read so matching sees the real text.

    The register keeps only masked rule text; matching needs the rule as written.
    Display text is masked again here.
    """
    scopes = {}
    for sc in report["scopes"]:
        if sc["status"] != "read":
            continue
        path = env.expand(sc["id"])
        data, _ = read_json(path)
        perms = (data or {}).get("permissions") or {}
        kind = "user" if path in cfg["user_settings"] else "project"
        rules = [r for r in perms.get("allow") or [] if isinstance(r, str)]
        scopes[sc["id"]] = {"kind": kind, "path": path, "rules": rules,
                            "dirs": [env.expand(d) for d in perms.get("additionalDirectories") or []]}
    reg_path, _ = ar.find_registry(cfg["registry"])
    data, _ = read_json(reg_path) if reg_path else (None, None)
    rows, _ = ar.registry_rows(data) if data is not None else ([], None)
    approvals = {}
    for r in rows:
        out = []
        for ap in r.get("approvedPermissions") or []:
            tool = ap.get("toolName") if isinstance(ap, dict) else None
            if tool:
                out.append(tool if ap.get("ruleContent") is None else "%s(%s)" % (tool, ap["ruleContent"]))
        approvals[r["id"]] = out
    return scopes, approvals


def temp_grants_for(run, cwd, env):
    """Rules and folders granted inside one run (destination 'session'): already per-run grants."""
    out = []
    for u in run["grants"]:
        if u.get("destination") not in (None, "session"):
            continue
        if u.get("type") == "addRules" and u.get("behavior") == "allow":
            for r in u.get("rules") or []:
                if isinstance(r, dict) and r.get("toolName"):
                    text = r["toolName"] if r.get("ruleContent") is None else "%s(%s)" % (r["toolName"], r["ruleContent"])
                    g = make_grant("T:" + text, "this_run", "granted in this run", text, cwd or env.home, cwd, env)
                    if g:
                        out.append(g)
        elif u.get("type") == "addDirectories":
            for d in u.get("directories") or []:
                if isinstance(d, str):
                    for tool in ("read", "edit"):
                        out.append({"id": "T:dir:" + d, "kind": "location", "scope": "granted in this run",
                                    "tool": tool, "dir": d, "content": None, "spec": 0})
    return out


def named_secret(text):
    """A value assigned to a secret-sounding name, or a known key prefix, in one tool input.

    Stricter than the register's scan of settings files: a tool input is full of
    long filenames and URLs, and the bare long-string detector flags those. A
    raw token passed with no name in front of it is missed here.
    """
    if ar._KNOWN_PREFIX.search(text):
        return True
    for rx in (ar._ASSIGN, ar._COLON, ar._SCHEME):
        for m in rx.finditer(text):
            v = m.group(2)
            if len(v) >= ar.REPORT_MIN and ar._mixed(v) and not ar._UUID.fullmatch(v) and not ar._PATHLIKE.match(v):
                return True
    return False


def _date(ms):
    return datetime.fromtimestamp(ms / 1000.0).strftime("%Y-%m-%d")


def run_pass(report, cfg, env, now_ms=None):
    """The just-in-time pass over every registered agent. Returns a dict the page and the JSON both use."""
    rcfg = dict(DEFAULT_RUNS, **(cfg.get("runs") or {}))
    now_ms = now_ms if now_ms is not None else time.time() * 1000
    agents = {a["id"]: a for a in report["agents"]}
    out = {"window_days": rcfg["window_days"], "min_runs": rcfg["min_runs"], "errors": [], "unknowns": [],
           "agents": [], "shared_used": [], "secrets": [], "totals": {}}
    runs, counts, problem = find_runs(rcfg, env, now_ms, set(agents))
    out["counts"] = counts
    if problem:
        out["errors"].append("%s: which permissions runs use is unknown, not none" % problem)
        return out
    if counts["unreadable"] and counts["unreadable"] == counts["records"]:
        out["errors"].append("none of the %d session record(s) could be read" % counts["records"])
        return out
    if counts["unreadable"]:
        # a record can be mid-write while its session runs, so a few unreadable ones are listed, not fatal
        out["unknowns"].append("%d session record(s) couldn't be read; any runs among them are unknown"
                               % counts["unreadable"])
    if counts["unregistered"]:
        out["unknowns"].append("%d run(s) of %d task(s) no longer in the registry were skipped: %s" % (
            sum(counts["unregistered"].values()), len(counts["unregistered"]),
            ", ".join(sorted(counts["unregistered"]))))

    scopes, approvals = load_standing(report, cfg, env)
    clf = ar.Classifier(cfg, env)
    servers = cfg.get("mcp_servers") or {}
    shared_cache, shared_meta = {}, {}

    def shared_grants(scope_id, cwd):
        """One settings file's rules as grants. Ids are per file and rule, so the fleet view can add them up."""
        key = (scope_id, cwd)
        if key not in shared_cache:
            sc = scopes[scope_id]
            settings_dir = os.path.dirname(sc["path"]) if sc["kind"] == "user" else (cwd or os.path.dirname(os.path.dirname(sc["path"])))
            gs = []
            for i, rule in enumerate(sc["rules"]):
                g = make_grant("S:%s:%d" % (scope_id, i + 1), "rule", scope_id, rule, settings_dir, cwd, env, servers)
                if g:
                    gs.append(g)
                    shared_meta[g["id"]] = {"shown": g["shown"], "scope": scope_id}
            shared_cache[key] = gs
        return shared_cache[key]

    by_task = {}
    for r in runs:
        by_task.setdefault(r["task"], []).append(r)

    totals = {"calls": 0, "calls_recorded": 0, "runs_read": 0, "runs_missing": 0, "runs_empty": 0, "bad_lines": 0,
              "status": {}, "denied": {}, "check": {"agree": 0, "family": 0, "missing": 0}}
    shared_use = {}          # grant id -> {"agents": set, "runs": n}
    every_somewhere = set()  # shared grant ids every run of some sorted agent used
    fleet_shared = set()     # every shared grant id some agent runs under
    approvals_total = approvals_used = 0

    for tid in sorted(agents):
        a = agents[tid]
        cwd = env.expand(a["cwd"]) if a.get("cwd") else None
        cwd = os.path.normpath(cwd) if cwd else None
        shared, extra_dirs = [], []
        for sid in a["scopes"]:
            if sid in scopes:
                shared += shared_grants(sid, cwd)
                extra_dirs += scopes[sid]["dirs"]
        appr = []
        for i, rule in enumerate(approvals.get(tid, [])):
            g = make_grant("A:%s:%d" % (tid, i + 1), "approval", "task approval", rule, cwd or env.home, cwd, env,
                           servers)
            if g:
                appr.append(g)
        grants = AgentGrants(shared, appr, cwd, extra_dirs, env.tilde)
        fleet_shared.update(g["id"] for g in shared)
        approvals_total += len(appr)

        row = {"id": tid, "enabled": a["enabled"], "cwd": a.get("cwd"), "runs": 0, "runs_missing": 0,
               "runs_empty": 0, "first": None, "last": None, "standing": {"shared": len(shared), "approvals": len(appr)},
               "use": {}, "status": {}, "denied": {}, "areas": {}, "reach": {}, "this_run": {},
               "secret_calls": 0, "modes": {}, "shapes": {}}
        for run in by_task.get(tid, []):
            paths = transcript_files(env.expand(rcfg["transcripts_root"]), run["cwd"], run["session"])
            row["modes"][run["mode"] or "unset"] = row["modes"].get(run["mode"] or "unset", 0) + 1
            for k, text in [("approval reason", t) for t in run["reasons"]] + \
                    [("grant made in the run", json.dumps(u)) for u in run["grants"]]:
                for s, e, kind in ar.secret_spans(text):
                    if e - s >= ar.REPORT_MIN:
                        out["secrets"].append({"agent": tid, "where": "session record, %s, run of %s" % (k, _date(run["created"])),
                                               "length": e - s, "kind": kind})
            if not paths:
                row["runs_missing"] += 1
                continue
            calls, bad = read_calls(paths)
            totals["bad_lines"] += bad
            if not calls:
                row["runs_empty"] += 1
                continue
            row["runs"] += 1
            row["first"] = row["first"] or _date(run["created"])
            row["last"] = _date(run["created"])
            run_cwd = run["cwd"] or cwd
            temp = temp_grants_for(run, run_cwd, env)
            used_here, reach_here, areas_here, seen_pieces = set(), set(), set(), {}
            for c in calls:
                totals["calls"] += 1
                if c.get("decision"):
                    totals["calls_recorded"] += 1
                status, credited, check = attribute(c, grants, run["mode"], temp, run_cwd, seen_pieces)
                row["status"][status] = row["status"].get(status, 0) + 1
                totals["status"][status] = totals["status"].get(status, 0) + 1
                if check:
                    totals["check"][check] += 1
                if status == "denied":
                    row["denied"][c["denied"]] = row["denied"].get(c["denied"], 0) + 1
                    totals["denied"][c["denied"]] = totals["denied"].get(c["denied"], 0) + 1
                    continue
                if status == "this_run":
                    row["this_run"][c["name"] if not c["name"].startswith("mcp__") else "MCP tools"] = \
                        row["this_run"].get(c["name"] if not c["name"].startswith("mcp__") else "MCP tools", 0) + 1
                used_here.update(credited)
                reach_here |= reach_keys(c, clf, servers)
                areas_here |= touched(c, run_cwd, env)
                if any(named_secret(v) for v in c["input"].values()):
                    row["secret_calls"] += 1
            for gid, ps in seen_pieces.items():
                bucket = row["shapes"].setdefault(gid, {})
                for sh in {shape(p, env) for p in ps}:
                    if sh:
                        bucket[sh] = bucket.get(sh, 0) + 1
            for gid in used_here:
                row["use"][gid] = row["use"].get(gid, 0) + 1
                if gid.startswith("S:"):
                    u = shared_use.setdefault(gid, {"agents": set(), "runs": 0})
                    u["agents"].add(tid)
                    u["runs"] += 1
            for k in reach_here:
                row["reach"][k] = row["reach"].get(k, 0) + 1
            for k in areas_here:
                key = "%s|%s" % k
                row["areas"][key] = row["areas"].get(key, 0) + 1
        totals["runs_read"] += row["runs"]
        totals["runs_missing"] += row["runs_missing"]
        totals["runs_empty"] += row["runs_empty"]
        out["agents"].append(summarize(row, grants, rcfg["min_runs"], env))
        if row["runs"] >= rcfg["min_runs"]:
            # counted from the raw grant ids: the display merges the same rule text from two files into one line
            every_somewhere.update(gid for gid, used in row["use"].items() if used == row["runs"] and gid.startswith("S:"))
        approvals_used += sum(1 for g in appr if g["id"] in row["use"])

    out["totals"] = dict(totals, shared_rules=len({g for g in fleet_shared}), shared_rules_used=len(shared_use),
                         approvals=approvals_total, approvals_used=approvals_used,
                         since=_date(runs[0]["created"]) if runs else None,
                         until=_date(runs[-1]["created"]) if runs else None,
                         agents_with_runs=sum(1 for x in out["agents"] if x["runs"]))
    out["totals"]["shared_rules_every"] = len(every_somewhere)
    out["shared_used"] = sorted(({"id": gid, "shown": shared_meta[gid]["shown"], "scope": shared_meta[gid]["scope"],
                                  "agents": sorted(u["agents"]), "runs": u["runs"]}
                                 for gid, u in shared_use.items()),
                                key=lambda s: (-len(s["agents"]), -s["runs"], s["shown"]))
    if totals["runs_missing"] and not (totals["runs_read"] or totals["runs_empty"]):
        # not one transcript for any run: the transcript folder is wrong or gone, not every run idle
        out["errors"].append("none of the %d run(s) in the window left a transcript under %s"
                             % (totals["runs_missing"], env.tilde(env.expand(rcfg["transcripts_root"]))))
    elif totals["runs_missing"]:
        out["unknowns"].append("%d run(s) in the window left no transcript that could be found; they're "
                               "counted as unknown, not as runs that used nothing" % totals["runs_missing"])
    if totals["bad_lines"]:
        out["unknowns"].append("%d transcript line(s) couldn't be parsed; calls on them are unknown" % totals["bad_lines"])
    return out


def summarize(row, grants, min_runs, env):
    """Sort one agent's standing grants into every run, some runs, and no run."""
    n = row["runs"]
    by_id = {g["id"]: g for g in grants.all}

    def show(gid, used):
        g = by_id[gid]
        if g["kind"] == "location":
            what = "%s inside %s" % ("reads" if g["tool"] == "read" else "edits", mask(env.tilde(g["dir"])))
        else:
            what = g["shown"]
        seen = sorted(row["shapes"].get(gid, {}).items(), key=lambda kv: (-kv[1], kv[0]))
        return {"id": gid, "kind": g["kind"], "scope": g["scope"], "shown": what, "runs": used,
                "files": [g["scope"]], "covered": [{"what": k, "runs": v} for k, v in seen[:8]],
                "covered_more": max(0, len(seen) - 8)}

    every, some, merged = [], [], {}
    for gid, used in sorted(row["use"].items(), key=lambda kv: (-kv[1], kv[0])):
        item = show(gid, used)
        # the same rule text in two settings files is two grants; list it once and name both files
        key = (item["kind"], item["shown"], used)
        if item["kind"] == "rule" and key in merged:
            merged[key]["files"].append(item["scope"])
            continue
        merged[key] = item
        (every if used == n else some).append(item)
    unused_appr = [show(g["id"], 0) for g in grants.approvals if g["id"] not in row["use"]]
    used_shared = sum(1 for gid in row["use"] if gid.startswith("S:"))
    return {"id": row["id"], "enabled": row["enabled"], "cwd": row["cwd"], "runs": n,
            "runs_missing": row["runs_missing"], "runs_empty": row["runs_empty"], "first": row["first"],
            "last": row["last"], "too_few": n < min_runs, "standing": row["standing"],
            "every": every, "some": some, "unused_approvals": unused_appr,
            "unused_shared": row["standing"]["shared"] - used_shared, "status": row["status"],
            "denied": row["denied"], "this_run": row["this_run"], "modes": row["modes"],
            "areas": sorted(({"area": mask(k.split("|")[0]), "how": k.split("|")[1], "runs": v}
                             for k, v in row["areas"].items()), key=lambda x: (-x["runs"], x["area"], x["how"])),
            "reach": sorted(({"key": mask(k), "runs": v} for k, v in row["reach"].items()),
                            key=lambda x: (-x["runs"], x["key"])),
            "secret_calls": row["secret_calls"]}


# --------------------------------------------------------------------------
# rendering: a section of the register's page
# --------------------------------------------------------------------------

_e = ar._e

STATUS_LABELS = [
    ("classifier", "approved one call at a time by the auto-mode classifier"),
    ("this_run", "granted inside that run only"),
    ("builtin", "allowed by Claude Code with no rule"),
    ("unmatched", "matched no current standing grant"),
]


def _grant_li(g, n, show_runs=True):
    kind = {"rule": "shared rule", "approval": "task approval", "location": "working directory"}[g["kind"]]
    files = g.get("files") or [g["scope"]]
    where = "%s · %s" % (kind, " and ".join(files)) if g["kind"] == "rule" else kind
    runs = " · %d of %d runs" % (g["runs"], n) if show_runs else ""
    covered = ""
    if g.get("covered"):
        covered = "<br><span class='muted small'>covered: %s%s</span>" % (
            ", ".join("<code>%s</code>%s" % (_e(c["what"]), "" if c["runs"] == g["runs"] else " (%d)" % c["runs"])
                      for c in g["covered"][:4]),
            " and %d more" % (len(g["covered"]) - 4 + g.get("covered_more", 0))
            if len(g["covered"]) > 4 or g.get("covered_more") else "")
    return "<li><span class='k'>%s</span><br><span class='muted small'>%s%s</span>%s</li>" % (
        _e(g["shown"]), _e(where), _e(runs), covered)


def _list(items, n, limit=5, show_runs=True):
    if not items:
        return "<span class='muted small'>none</span>"
    head = "".join(_grant_li(g, n, show_runs) for g in items[:limit])
    if len(items) > limit:
        head += "<li><details><summary>%d more</summary><ul>%s</ul></details></li>" % (
            len(items) - limit, "".join(_grant_li(g, n, show_runs) for g in items[limit:]))
    return "<ul>%s</ul>" % head


def render_section(jit, fmt=lambda n: "{:,}".format(n)):
    """The page section. Returns a list of HTML strings for render_html to splice in."""
    out = ["<h2 id='jit'>Just-in-time pass: what each agent's runs use of what it's granted</h2>"]
    t = jit["totals"]
    if jit["errors"]:
        out.append("<div class='banner bad'><b>The just-in-time pass couldn't run.</b><ul class='plain'>%s</ul></div>"
                   % "".join("<li>%s</li>" % _e(x) for x in jit["errors"]))
        return out
    out.append("<p class='muted small'><span class='tag t-observed'>observed</span>Read from the transcripts of "
               "%s scheduled runs between %s and %s (a %s-day window). Every tool call is matched to the narrowest "
               "standing grant that covers it: a shared allow rule, a per-task approval, or the working directory. "
               "A grant every run used is one the agent needs each time. A grant only some runs used could be "
               "granted to the run that needs it and dropped when that run ends. Agents with fewer than %d runs "
               "are listed but not sorted.</p>" % (
                   fmt(t["runs_read"]), _e(t["since"] or "—"), _e(t["until"] or "—"), jit["window_days"], jit["min_runs"]))
    out.append("<div class='tiles'>")
    for num, label in ((t["shared_rules"], "shared allow rules agents run under"),
                       (t["shared_rules_used"], "of those, used by any run"),
                       (t["shared_rules_every"], "used by every run of some agent"),
                       (t["approvals"], "task approvals on file"),
                       (t["approvals_used"], "of those, used by any run"),
                       (t["status"].get("classifier", 0) + t["status"].get("this_run", 0),
                        "calls that ran on a per-call or per-run grant"),
                       (sum(t["denied"].values()), "calls blocked")):
        out.append("<div class='tile'><b>%s</b><span>%s</span></div>" % (fmt(num), _e(label)))
    out.append("</div>")
    for u in jit["unknowns"]:
        out.append("<div class='small'><span class='tag t-warn'>unknown</span>%s</div>" % _e(u))

    out.append("<div class='tablewrap'><table style='min-width:1080px'><thead><tr><th style='width:14%'>Agent</th>"
               "<th style='width:22%'>Every run uses</th><th style='width:22%'>Some runs use: grant per run, drop after</th>"
               "<th style='width:11%'>No run used</th><th style='width:14%'>Ran on no standing grant</th>"
               "<th style='width:17%'>Where runs went</th></tr></thead><tbody>")
    rows = sorted(jit["agents"], key=lambda r: (r["runs"] == 0, not r["enabled"], r["id"]))
    for r in rows:
        n = r["runs"]
        head = ["<b>%s</b>" % _e(r["id"]),
                "<span class='muted small'>%s run%s%s%s</span>" % (
                    n, "" if n == 1 else "s", " · %s to %s" % (r["first"], r["last"]) if n else "",
                    " · %d with no transcript" % r["runs_missing"] if r["runs_missing"] else ""),
                "<span class='muted small'>under %s shared rules and %d task approval%s</span>" % (
                    fmt(r["standing"]["shared"]), r["standing"]["approvals"], "" if r["standing"]["approvals"] == 1 else "s")]
        if r["runs_empty"]:
            head.append("<span class='muted small'>%d run%s made no tool calls</span>" % (
                r["runs_empty"], "" if r["runs_empty"] == 1 else "s"))
        if not n:
            out.append("<tr><td>%s</td><td colspan='5' class='muted small'>No run in the window left a transcript "
                       "with a tool call, so nothing can be said about what it uses.</td></tr>" % "<br>".join(head))
            continue
        if r["too_few"]:
            every = "<span class='tag t-warn'>too few runs</span><span class='muted small'>%d run%s can't show "\
                    "what every run needs.</span>" % (n, "" if n == 1 else "s")
            some = _list(r["every"] + r["some"], n)
        else:
            every = _list(r["every"], n)
            some = _list(r["some"], n)
        unused = ["%s of %s shared rules" % (fmt(r["unused_shared"]), fmt(r["standing"]["shared"]))]
        if r["standing"]["approvals"]:
            unused.append("%d of %d task approvals" % (len(r["unused_approvals"]), r["standing"]["approvals"]))
        unused_html = "<span class='small'>%s</span>" % _e("; ".join(unused))
        if r["unused_approvals"]:
            unused_html += "<details><summary>which approvals</summary><ul>%s</ul></details>" % "".join(
                _grant_li(g, n, False) for g in r["unused_approvals"])
        none = []
        for key, label in STATUS_LABELS:
            if r["status"].get(key):
                none.append("<li><b>%s</b> call%s %s</li>" % (fmt(r["status"][key]), "" if r["status"][key] == 1 else "s",
                                                             _e(label)))
        if r["denied"]:
            none.append("<li><b>%s</b> blocked <span class='muted small'>(%s)</span></li>" % (
                fmt(sum(r["denied"].values())), _e(", ".join("%s %d" % kv for kv in sorted(r["denied"].items())))))
        where = []
        for x in r["areas"][:6]:
            where.append("<li><code>%s</code> <span class='muted small'>%s · %d of %d runs</span></li>" % (
                _e(x["area"]), _e({"named": "named in a command"}.get(x["how"], x["how"])), x["runs"], n))
        if len(r["areas"]) > 6:
            where.append("<li><details><summary>%d more</summary><ul>%s</ul></details></li>" % (
                len(r["areas"]) - 6, "".join("<li><code>%s</code> <span class='muted small'>%s · %d</span></li>" % (
                    _e(x["area"]), _e(x["how"]), x["runs"]) for x in r["areas"][6:])))
        notable = [x for x in r["reach"] if ar.column(x["key"]) in ("send", "cred")]
        if notable:
            where.append("<li class='small'>%s</li>" % ", ".join(
                "<span class='k'>%s</span> %d" % (_e(x["key"]), x["runs"]) for x in notable[:6]))
        if r["secret_calls"]:
            where.append("<li class='small'><span class='tag t-warn'>secret in a call</span>%d call%s passed a value "
                         "assigned to a secret-sounding name, so it sits in the transcript "
                         "<span class='muted'>(not shown, not verified as live)</span></li>" % (
                             r["secret_calls"], "" if r["secret_calls"] == 1 else "s"))
        out.append("<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>" % (
            "<br>".join(head), every, some, unused_html,
            "<ul>%s</ul>" % "".join(none) if none else "<span class='muted small'>none</span>",
            "<ul>%s</ul>" % "".join(where) if where else "<span class='muted small'>no paths named</span>"))
    out.append("</tbody></table></div>")

    out.append("<h3 style='margin-top:18px'>Shared rules any run used</h3>")
    out.append("<p class='muted small'>%s of %s shared allow rules covered at least one call in the window. The "
               "rest covered none. These files also apply to interactive sessions, which this pass doesn't read, "
               "so unused here means unused by scheduled runs.</p>" % (fmt(t["shared_rules_used"]), fmt(t["shared_rules"])))
    if jit["shared_used"]:
        out.append("<div class='tablewrap'><table><thead><tr><th>Rule</th><th>Settings file</th><th>Agents</th>"
                   "<th>Runs</th></tr></thead><tbody>")
        for s in jit["shared_used"][:50]:
            who = ", ".join(s["agents"][:5]) + (" and %d more" % (len(s["agents"]) - 5) if len(s["agents"]) > 5 else "")
            out.append("<tr><td><span class='k'>%s</span></td><td><code>%s</code></td><td class='small'>%s</td>"
                       "<td>%s</td></tr>" % (_e(s["shown"]), _e(s["scope"]), _e(who), fmt(s["runs"])))
        out.append("</tbody></table></div>")
        if len(jit["shared_used"]) > 50:
            out.append("<p class='muted small'>%d more in the JSON output.</p>" % (len(jit["shared_used"]) - 50))
    chk = t["check"]
    recorded = sum(chk.values())
    if recorded:
        out.append("<p class='small'><b>Matcher check.</b> %s of %s calls carry Claude Code's own record of what "
                   "allowed them; for the rest, attribution is this matcher alone. " % (
                       fmt(t.get("calls_recorded", 0)), fmt(t["calls"])) +
                   "On %s calls, Claude Code's own record says a standing "
                   "rule let the call through. The matcher found a current rule of the same kind for %s of them "
                   "(%d%%). For %s it found a rule of the other kind (a task approval where Claude Code named a "
                   "settings rule, or the reverse), and for %s it found none: a rule removed since, or one this "
                   "matcher reads differently.</p>" % (
                       fmt(recorded), fmt(chk["agree"]), round(100.0 * chk["agree"] / recorded),
                       fmt(chk["family"]), fmt(chk["missing"])))
    out.append("<details><summary>What this pass can't see</summary><ul class='plain'>%s</ul></details>" % "".join(
        "<li>%s</li>" % _e(x) for x in cannot_see()))
    return out


def cannot_see():
    return [
        "Runs older than the window, and runs whose transcripts Claude Code has already cleaned up.",
        "Interactive sessions. The shared settings files apply to them too, so a rule no scheduled run used "
        "may still be in use by hand.",
        "What a script does once it runs. A call to python3 some_script.py is one call; the files and hosts "
        "inside the script don't show up as calls.",
        "Which rule Claude Code actually applied. Its record names the kind (settings rule, task approval, "
        "classifier, mode) but not the rule, so the narrowest current rule that covers the call is credited.",
        "Calls before Claude Code started recording decisions (late September 2026). For those, attribution is "
        "this matcher alone.",
        "Whether a grant could be dropped without breaking a run on a day the window didn't cover.",
    ]
