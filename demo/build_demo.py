#!/usr/bin/env python3
"""Build a synthetic fleet on disk, run the register against it, render docs/index.html.

Everything is a real file in a throwaway home folder: settings files, a scheduler
registry, task folders, helper scripts, empty stand-ins for credential stores, and
thirty days of run records with the transcripts the just-in-time pass reads.
The page a reviewer sees is the register's actual output against those files, not
a mockup. Every "secret" below is an obviously fake string, planted so the page
can show that it reports where one sits without printing it.

    python3 demo/build_demo.py
"""

import json
import os
import re
import shutil
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, REPO)

import access_register as ar  # noqa: E402

FAKE_BOT_TOKEN = "dEm0FAKEt0kenN0tReal0123456789abcdEFgh"
FAKE_WEATHER_KEY = "FAKE0000DEMO1111KEY2222NOTREAL3333"


def write(path, body=""):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as fh:
        fh.write(body)
    return path


def skill(home, tid, body, model="opus"):
    front = "---\nname: %s\ndescription: demo task\n%s---\n\n" % (tid, "model: %s\n" % model if model else "")
    return write(os.path.join(home, ".claude", "scheduled-tasks", tid, "SKILL.md"), front + body)


def row(home, tid, cron, mode="auto", cwd=None, enabled=True, approved=None):
    r = {"id": tid, "cronExpression": cron, "enabled": enabled,
         "filePath": os.path.join(home, ".claude", "scheduled-tasks", tid, "SKILL.md"),
         "cwd": cwd or home}
    if mode:
        r["permissionMode"] = mode
    if approved:
        r["approvedPermissions"] = approved
    return r


RULE = {"decision": "accept", "source": "config", "reasonType": "rule"}
PERM = {"decision": "accept", "source": "user_permanent", "reasonType": "rule"}
MODE = {"decision": "accept", "source": "config", "reasonType": "mode"}
CLASSIFIER = {"decision": "accept", "source": "config", "reasonType": "classifier"}
TEMP = {"decision": "accept", "source": "user_temporary"}
HOOK = {"decision": "reject", "source": "hook", "reasonType": "hook"}


def lay_runs(home, jobs, site):
    """Thirty days of scheduled runs: one session record per run, and the transcript it points at.

    Each call carries the permission decision Claude Code records, so the pass
    has the same evidence it gets on a real fleet.
    """
    now = time.time() * 1000
    n = [0]

    def run(tid, calls, days_ago, cwd=None, transcript=True, grants=None):
        n[0] += 1
        sid = "d3m0%04d-0000-4000-8000-000000000000" % n[0]
        cwd = cwd or home
        rec = {"sessionId": "local_demo%d" % n[0], "cliSessionId": sid, "cwd": cwd, "permissionMode": "auto",
               "createdAt": now - days_ago * 86400000 - 3600000, "scheduledTaskId": tid}
        if grants:
            rec["sessionPermissionUpdates"] = grants
        write(os.path.join(home, "sessions", "local_demo%d.json" % n[0]), json.dumps(rec))
        if not transcript:
            return
        lines = []
        for i, c in enumerate(calls):
            tu = "toolu_demo_%d_%d" % (n[0], i)
            lines.append({"type": "assistant", "message": {"content": [
                {"type": "tool_use", "id": tu, "name": c[0], "input": c[1]}]}})
            err = c[3] if len(c) > 3 else None
            u = {"type": "user", "message": {"content": [
                {"type": "tool_result", "tool_use_id": tu, "content": err or "ok", "is_error": bool(err)}]}}
            if c[2]:
                u["permissionDecision"] = c[2]
            lines.append(u)
        write(os.path.join(home, ".claude", "projects", re.sub(r"[^A-Za-z0-9]", "-", cwd), sid + ".jsonl"),
              "\n".join(json.dumps(x) for x in lines) + "\n")

    h = home
    for d in range(30):
        # the nagger runs one script, every time, on a wildcard interpreter rule
        run("habit-nagger", [("Bash", {"command": "python3 ~/bin/habit_nag.py"}, RULE)], d)
        # the sweep labels every run and never trashes, though it's approved to
        sweep = [("mcp__mail__search_threads", {"query": "label:inbox"}, RULE),
                 ("mcp__mail__label_thread", {"thread_id": "t%d" % d}, PERM),
                 ("Edit", {"file_path": h + "/Trackers/inbox/state.md"}, RULE)]
        run("inbox-junk-sweep", sweep, d)
        # rain: the key rides on the command line, and nothing in config covers that host
        run("daily-garden-check", [
            ("Bash", {"command": "curl -s \"https://api.weather.example.com/v1/rain?application_key=%s\"" % FAKE_WEATHER_KEY},
             CLASSIFIER),
            ("Bash", {"command": "python3 ~/bin/rain_rollup.py"}, RULE),
            ("Edit", {"file_path": h + "/Trackers/garden/log.csv"}, RULE)], d)
        if d % 7 < 5:
            brief = [("mcp__calendar__list_events", {}, PERM),
                     ("Edit", {"file_path": h + "/Downloads/morning-brief.html"}, PERM),
                     ("Bash", {"command": "python3 ~/bin/ntfy_send.py payload.json"}, RULE)]
            run("morning-brief", brief, d)
            pipe = [("Bash", {"command": ".venv/bin/python pipeline/run.py"}, RULE),
                    ("Edit", {"file_path": jobs + "/pipeline/logs/run.jsonl"}, MODE)]
            if d % 3 == 0:
                pipe.append(("mcp__mail__create_draft", {"to": "hiring@example.com"}, PERM))
            if d == 4:
                pipe.append(("Bash", {"command": "git push origin main"}, PERM))
            run("daily-job-pipeline", pipe, d, cwd=jobs)
        run("escalated-case-digest", [
            ("Bash", {"command": "sf data query --query \"SELECT Id, Subject FROM Case WHERE Status = 'Escalated'\" --json"}, RULE),
            ("mcp__slack__slack_send_message", {"channel": "D123"}, CLASSIFIER)], d)
    for d in (1, 8, 15, 22):
        review = [("Read", {"file_path": h + "/Trackers/fleet/report-%d.md" % d}, None),
                  ("Bash", {"command": "python3 ~/bin/discord_send.py payload.json"}, RULE)]
        if d == 15:
            review.append(("Bash", {"command": "curl -s -X POST https://discord.com/api/v10/channels/1/messages -d @p.json"},
                           HOOK, "PreToolUse:Bash hook error: Blocked by project policy"))
        run("weekly-fleet-review", review, d)
    for d in (0, 7, 14, 21):
        run("ship-weekly", [("Bash", {"command": "~/projects/site/bin/publish.sh"}, CLASSIFIER),
                            ("Read", {"file_path": site + "/build/index.html"}, None)], d, cwd=site)
    # one run whose transcript was cleaned up, and one that got a folder granted for that run only
    run("weekly-fleet-review", [], 29, transcript=False)
    run("pickup-reminder", [("Read", {"file_path": "/opt/shared/pickup.txt"}, TEMP)], 3,
        grants=[{"type": "addDirectories", "directories": ["/opt/shared"], "destination": "session"}])


def build(home):
    """Lay the fleet down under `home` and return the config dict."""
    # ---- credential stores: empty stand-ins, never read by the register
    for rel in (".config/chat/.env", ".config/weather/.env", ".config/gh/hosts.yml", ".ssh/id_ed25519"):
        write(os.path.join(home, rel))
    os.makedirs(os.path.join(home, ".sf"))

    # ---- shared settings
    write(os.path.join(home, ".claude", "settings.json"), json.dumps({
        "permissions": {
            "defaultMode": "auto",
            "allow": [
                "Bash(python3 *)",
                "Bash(sf *)",
                "Bash(curl -s https://ntfy.sh/*)",
                "Read(~/.claude/**)",
                "Read(~/.config/chat/.env)",
                "Edit(~/Trackers/**)",
                "Edit(/Reports/**)",
                "mcp__mail__search_threads",
            ]},
        "hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [
            {"type": "command", "command": "python3 ~/.claude/hooks/destructive_gate.py"}]}]},
    }, indent=2))
    write(os.path.join(home, ".claude", "settings.local.json"), json.dumps({
        "permissions": {"allow": [
            "Bash(curl -s -X POST -H \"Authorization: Bot %s\" https://discord.com/api/v10/channels/1/messages -d *)" % FAKE_BOT_TOKEN,
            "Bash(osascript -e ' *)",
            "Bash(grep -c TODO notes.md)",
            "WebFetch(domain:example.com)",
            "WebFetch(domain:news.example.org)",
            "WebSearch",
            "mcp__messages__send_imessage",
        ]}}, indent=2))
    jobs = os.path.join(home, "projects", "jobs")
    write(os.path.join(jobs, ".claude", "settings.json"), json.dumps({
        "permissions": {"allow": ["Bash(.venv/bin/python pipeline/run.py)", "Edit(/pipeline/logs/**)"],
                        "deny": ["Read(~/.config/weather/.env)"]}}, indent=2))
    os.makedirs(os.path.join(jobs, "pipeline", "logs"))

    # ---- helper scripts the tasks call
    write(os.path.join(home, "bin", "discord_send.py"),
          "import sys, urllib.request\nfrom pathlib import Path\n"
          "ENV_FILE = Path('~/.config/chat/.env').expanduser()\n"
          "req = urllib.request.Request(f\"https://discord.com/api/v10/channels/{sys.argv[1]}/messages\",\n"
          "    headers={'User-Agent': 'DemoBot (https://github.com/example/demo, 1.0)'})\n")
    write(os.path.join(home, "bin", "ntfy_send.py"),
          "import urllib.request\nreq = urllib.request.Request(f\"https://ntfy.sh/{topic}\")\n")
    write(os.path.join(home, "bin", "habit_nag.py"),
          "import subprocess\n# decides whether a nag is due, then hands the payload to the shared sender\n"
          "subprocess.run(['python3', '/home/demo/bin/discord_send.py', 'payload.json'])\n")
    write(os.path.join(jobs, "pipeline", "run.py"),
          "import os, urllib.request\nKEY = os.environ.get('JOBS_API_KEY')\n"
          "urllib.request.urlopen('https://boards-api.example.com/v1/jobs')\n")
    site = os.path.join(home, "projects", "site")
    write(os.path.join(site, "bin", "publish.sh"),
          "#!/bin/sh\ngit -C ~/projects/site push origin main\ngh pr create --fill\n")

    # ---- tasks
    rows = []
    skill(home, "morning-brief",
          "Check the calendar for today, then write the brief to `~/Downloads/morning-brief-YYYY-MM-DD.html`.\n\n"
          "When it's written, push one line:\n\n```\npython3 ~/bin/ntfy_send.py payload.json\n```\n")
    rows.append(row(home, "morning-brief", "0 7 * * 1-5",
                    approved=[{"toolName": "Edit", "ruleContent": "~/Downloads/*.html"},
                              {"toolName": "mcp__calendar__list_events"}]))

    skill(home, "daily-job-pipeline",
          "Run the pipeline:\n\n```\n.venv/bin/python pipeline/run.py\n```\n\n"
          "Create a Gmail draft for each cover letter. Do not send the email; a person sends it.\n"
          "Append the run summary to ~/projects/jobs/pipeline/logs/run.jsonl.\n")
    rows.append(row(home, "daily-job-pipeline", "0 3 * * 1-5", cwd=jobs,
                    approved=[{"toolName": "mcp__mail__create_draft"},
                              {"toolName": "Bash", "ruleContent": "git push origin main"}]))

    skill(home, "escalated-case-digest",
          "Pull the escalated cases:\n\n```\nsf data query --query \"SELECT Id, Subject FROM Case WHERE Status = 'Escalated'\" --json\n```\n\n"
          "Send the digest as a Slack DM using mcp__slack__slack_send_message.\n", model=None)
    rows.append(row(home, "escalated-case-digest", "0 9 * * *", mode=None))

    skill(home, "weekly-fleet-review",
          "Read the reports in ~/Trackers/fleet/ one file per call. Do not use shell loops or `curl -d` here.\n\n"
          "Post the summary with `python3 ~/bin/discord_send.py payload.json`, not a hand-built `curl -X POST`.\n",
          model="haiku")
    rows.append(row(home, "weekly-fleet-review", "0 16 * * 2"))

    skill(home, "inbox-junk-sweep",
          "Search the inbox for junk and label each thread. Never delete or trash a message.\n\n"
          "Write the count to ~/Trackers/inbox/state.md.\n")
    rows.append(row(home, "inbox-junk-sweep", "0 7 * * *",
                    approved=[{"toolName": "mcp__mail__label_thread"}, {"toolName": "mcp__mail__trash_thread"}]))

    skill(home, "daily-garden-check",
          "Get yesterday's rain:\n\n```\ncurl -s \"https://api.weather.example.com/v1/rain?application_key=%s\"\n```\n\n"
          "Then run `python3 ~/bin/rain_rollup.py` and update ~/Trackers/garden/log.csv.\n" % FAKE_WEATHER_KEY)
    rows.append(row(home, "daily-garden-check", "0 18 * * *"))

    skill(home, "ship-weekly",
          "Build this week's page, then publish it: `~/projects/site/bin/publish.sh`.\n")
    rows.append(row(home, "ship-weekly", "0 10 * * 0", cwd=site))

    skill(home, "habit-nagger",
          "YOUR FIRST TOOL CALL IS THIS BASH COMMAND:\n\n    python3 ~/bin/habit_nag.py\n\nReport its one line and stop.\n",
          model="haiku")
    rows.append(row(home, "habit-nagger", "0 8-20 * * *"))

    skill(home, "pickup-reminder",
          "Send an iMessage to the saved contact with the pickup time. One message, no follow-up.\n")
    rows.append(row(home, "pickup-reminder", "30 14 * * 5",
                    approved=[{"toolName": "mcp__messages__send_imessage"}]))

    skill(home, "old-rainfall-report", "Parse the station feed and write ~/Downloads/rain.html.\n")
    rows.append(row(home, "old-rainfall-report", "0 21 * * *", mode="bypassPermissions", enabled=False))

    # registered, but its instructions are gone
    rows.append(row(home, "manual-backfill", "0 2 1 * *"))

    # on disk, never registered
    skill(home, "shelf-audit", "Count the shelf and write ~/Trackers/shelf/count.md.\n")

    write(os.path.join(home, "registry.json"), json.dumps({"scheduledTasks": rows}, indent=2))
    lay_runs(home, jobs, site)

    cfg = {
        "home": home,
        "title": "Agent access register",
        "user_settings": ["~/.claude/settings.json"],
        "registry": "~/registry.json",
        "tasks_roots": ["~/.claude/scheduled-tasks"],
        "skills_root": "~/.claude/skills",
        "policy": os.path.join(REPO, "policy", "acceptable-use.json"),
        "credential_stores": [
            {"id": "discord-bot", "label": "Discord bot token", "path": "~/.config/chat/.env"},
            {"id": "weather-api", "label": "Weather API keys", "path": "~/.config/weather/.env"},
            {"id": "github-cli", "label": "GitHub CLI login", "path": "~/.config/gh/hosts.yml"},
            {"id": "salesforce-cli", "label": "Salesforce CLI login", "path": "~/.sf"},
            {"id": "ssh-keys", "label": "SSH private key", "path": "~/.ssh/id_ed25519"},
            {"id": "cloud", "label": "Cloud credentials", "path": "~/.aws/credentials"},
        ],
        "mcp_servers": {"mail": "email", "messages": "imessage"},
        "send_helpers": [
            {"match": "discord_send.py", "channel": "discord", "credential": "discord-bot"},
            {"match": "ntfy_send.py", "channel": "ntfy"},
        ],
        "runs": {"sessions": "~/sessions/*.json", "transcripts_root": "~/.claude/projects", "window_days": 30,
                 "min_runs": 3},
        "exceptions": {"AUP-11": [{"agent": "ship-weekly", "keys": ["publish:*"],
                                   "reason": "publishes the portfolio site on Sundays; owner approved 2026-09-14"}]},
    }
    path = write(os.path.join(home, "register.config.json"), json.dumps(cfg, indent=2))
    return path


def main():
    home = tempfile.mkdtemp(prefix="register-demo-")
    try:
        cfg, env = ar.load_config(build(home))
        report, policy, result, code = ar.run(cfg, env)
        note = ("<b>Demo fleet.</b> Synthetic agents, settings, scripts, and thirty days of run transcripts, built "
                "on disk by <code>demo/build_demo.py</code>. Every row is the register's real output against those "
                "files. The two planted secrets are fake; the page shows where they sit and never what they say.")
        page = ar.render_html(report, policy, result, note=note)
        for leak in (home, FAKE_BOT_TOKEN, FAKE_WEATHER_KEY):
            if leak in page:
                raise SystemExit("demo page leaks %r" % leak[:12])
        os.makedirs(os.path.join(REPO, "docs"), exist_ok=True)
        out = os.path.join(REPO, "docs", "index.html")
        with open(out, "w") as fh:
            fh.write(page)
        print(out)
        print("exit %d · config/policy %d · instructed/policy %d · silent %d" % (
            code, len([f for f in result["config_forbidden"] if not f["excused"]]),
            len([f for f in result["instructed_forbidden"] if not f["excused"]]), len(result["silent"])))
    finally:
        shutil.rmtree(home)


if __name__ == "__main__":
    main()
