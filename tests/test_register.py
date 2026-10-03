#!/usr/bin/env python3
"""Fixture tests for access_register.py.

Every fixture is a real file in a throwaway home folder, because most of what
is under test is how the register reads files it can't fully trust: a settings
file that's unreadable, a SKILL.md that's gone, a rule that looks like a grant
and isn't. The secrets are fake strings planted to prove they never come back out.

    python3 tests/test_register.py
"""

import json
import os
import shutil
import sys
import tempfile
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)
sys.path.insert(0, os.path.join(REPO, "demo"))

import access_register as ar  # noqa: E402
import build_demo  # noqa: E402
from access_register import (DECLARED, INFERRED, Classifier, Env, anchor, classify_mcp, is_broad_exec,
                             negated_at, parse_rule, pattern_covers, safe, scan_instructions,
                             scan_script, secret_spans)

FAKE = "zQ9FAKEsecret0000NOTREAL1111abcd"


def write(path, body=""):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as fh:
        fh.write(body)
    return path


def clf(home="/home/t", **over):
    cfg = json.loads(json.dumps(ar.DEFAULT_CONFIG))
    cfg.update({"send_helpers": [{"match": "discord_send.py", "channel": "discord", "credential": "discord-bot"},
                                 {"match": "ntfy_send.py", "channel": "ntfy"}],
                "credential_stores": [{"id": "discord-bot", "path": home + "/.config/chat/.env"}]})
    cfg.update(over)
    return Classifier(cfg, Env(home))


def keys(pairs):
    return sorted({p[0] for p in pairs})


def cap_keys(caps):
    return sorted({c["key"] for c in caps})


class SecretTests(unittest.TestCase):
    def test_mixed_token_is_found_and_masked(self):
        text = "curl -H 'Authorization: Bot %s' https://x.example.com" % FAKE
        self.assertTrue(secret_spans(text))
        self.assertNotIn(FAKE, safe(text))
        self.assertIn("[masked", safe(text))

    def test_param_value_is_masked_and_name_is_kept(self):
        out = safe("https://api.example.com/v1?application_key=ABCDEF0123456789ABCDEF0123456789")
        self.assertIn("application_key=", out)
        self.assertNotIn("ABCDEF0123456789", out)

    def test_names_are_not_secrets(self):
        for ok in ("ship-sunday-verify-2026-09-20", "Senior-Customer-Success-Manager_R12345",
                   "Projects_backup_20260918.json", "mcp__8d597ae8-3c99-43f5-8eb1-7dba02b3dec7__send_message",
                   "8d597ae8-3c99-43f5-8eb1-7dba02b3dec7", "training-move-verify-2026-10-03",
                   "T1-Onboarding-build-2026-Q3-final"):
            self.assertEqual(secret_spans(ok), [], ok)

    def test_known_prefix(self):
        self.assertTrue(secret_spans("export GH=ghp_abcdefghijklmnop1234"))

    def test_shapes_the_first_version_let_through(self):
        # each of these printed verbatim before the review pass
        for text, secret in (
                ("curl -H 'Authorization: Bearer abcDEF0123456789abcDEF/0123456789abcDEF0' https://x.example.com",
                 "abcDEF0123456789abcDEF/0123456789abcDEF0"),
                ("login --password=Hunter2Hunter2", "Hunter2Hunter2"),
                ("password=abcdefghijklmnopqrstuvwxyz", "abcdefghijklmnopqrstuvwxyz"),
                ("token=12345678901234567890123456", "12345678901234567890123456"),
                ("https://maps.example.com/v1?key=AbCd1234EfGh5678IjKl&q=x", "AbCd1234EfGh5678IjKl"),
                ("discord_bot_token: Zx9Kq2Lm8Pw4", "Zx9Kq2Lm8Pw4"),
                ("-H 'Authorization: Bot shortbutreal'", "shortbutreal"),
                ("blob abcDEF0123456789abcDEF/0123456789abcDEF0xyz end", "abcDEF0123456789abcDEF/0123456789abcDEF0xyz")):
            self.assertNotIn(secret, safe(text), text)
            self.assertTrue(secret_spans(text), text)

    def test_key_prefix_before_a_wildcard_is_masked(self):
        # found on the live fleet: an approval holding the first characters of a key, then a *
        out = safe("curl -s https://api.example.net/v3?application_key=0123456789ABCDEF0123456789ABCDEF&api_key=0a1b2*")
        self.assertNotIn("0a1b2", out)
        self.assertNotIn("0123456789ABCDEF", out)

    def test_a_path_after_a_secret_name_is_not_a_secret(self):
        for ok in ("- Bot token: /Users/someone/.claude/channels/discord/.env, read with the helper",
                   "token=~/.config/chat/.env"):
            self.assertEqual(secret_spans(ok), [], ok)

    def test_ordinary_text_is_left_alone(self):
        for ok in ("the token refresh procedure is documented", "password: required for the portal",
                   "the bot responds in the channel", "sort the keys, then key: value pairs",
                   "/Users/someone/Documents/resume_project/pipeline/fetch_jd.py",
                   "~/Library/Application Support/Claude/claude-code-sessions"):
            self.assertEqual(safe(ok, 300), ok, ok)

    def test_capability_keys_are_masked_too(self):
        c = ar.cap("read:~/tmp/ghp_abcdefghijklmnop1234.json", DECLARED, "x")
        self.assertNotIn("ghp_abcdefghijklmnop1234", c["key"])


class RuleTests(unittest.TestCase):
    def test_parse(self):
        self.assertEqual(parse_rule("Bash(python3 *)"), ("Bash", "python3 *"))
        self.assertEqual(parse_rule("WebSearch"), ("WebSearch", None))
        self.assertEqual(parse_rule("mcp__a-b__send_message"), ("mcp__a-b__send_message", None))
        self.assertEqual(parse_rule("Bash(echo (x))"), ("Bash", "echo (x)"))

    def test_broad_exec(self):
        for broad in (None, "*", "python3 *", "python3:*", "python*", "/usr/bin/python3:*", ".venv/bin/python -c ' *",
                      "osascript -e ' *", "bash *", "node -e ' *", "xargs:*", "/bin/bash:*"):
            self.assertTrue(is_broad_exec(broad), broad)
        for broad in ("python3 -m *", "node --eval *", "uv run *", "sh -x *", "npm run *", "cd ~/x && *",
                      "cd ~/x && python3 *", "sudo *"):
            self.assertTrue(is_broad_exec(broad), broad)
        # pipes and stars inside a quoted regex are not a command separator and a bare wildcard
        self.assertFalse(is_broad_exec('grep -v "^| *|*$"'))
        self.assertEqual(ar.split_commands('a "x | y; z" && b \'p & q\' | c'), ['a "x | y; z" ', " b 'p & q' ", " c"])
        for narrow in ("python3 ~/bin/send.py", "python3 ~/bin/send.py *", "npm test", "sf *", "git push",
                       "osascript -e 'quit app \"Shelf\"'", "curl -s https://ntfy.sh/*", "python3 -m pytest *",
                       "cd ~/x && git status", "python3 -c 'print(1)'"):
            self.assertFalse(is_broad_exec(narrow), narrow)

    def test_anchors(self):
        env = Env("/home/t")
        self.assertEqual(anchor("//etc/x", "/home/t/.claude", "/w", env), ("/etc/x", "absolute"))
        self.assertEqual(anchor("~/Trackers/**", "/home/t/.claude", "/w", env), ("/home/t/Trackers/**", "home"))
        # the gotcha: a single leading slash is relative to the settings file, not the filesystem root
        self.assertEqual(anchor("/Users/t/PhoneLog/**", "/home/t/.claude", "/w", env),
                         ("/home/t/.claude/Users/t/PhoneLog/**", "settings-relative"))
        self.assertEqual(anchor("src/**", "/s", "/w", env), ("/w/src/**", "cwd-relative"))
        self.assertEqual(anchor(".env", "/s", "/w", env), ("/w/**/.env", "cwd-relative"))
        self.assertEqual(anchor("src/**", "/s", None, env), (None, "cwd-relative"))

    def test_pattern_covers(self):
        self.assertTrue(pattern_covers("/h/.claude/**", "/h/.claude/channels/discord/.env"))
        self.assertTrue(pattern_covers("/h/.claude/channels/discord/.env", "/h/.claude/channels/discord/.env"))
        self.assertTrue(pattern_covers("/h/Documents/*", "/h/Documents/a/b/c.txt"))  # matched dir covers its contents
        self.assertTrue(pattern_covers("/w/**/.env", "/w/a/b/.env"))
        self.assertTrue(pattern_covers("/w/**/.env", "/w/.env"))
        self.assertTrue(pattern_covers("/**", "/h/.ssh/id_rsa"))
        self.assertFalse(pattern_covers("/h/Trackers/**", "/h/.config/chat/.env"))
        self.assertFalse(pattern_covers("/h/Downloads/*.html", "/h/Downloads/x.json"))
        self.assertFalse(pattern_covers("/h/.claude/skills/**", "/h/.claude/channels/discord/.env"))


class McpTests(unittest.TestCase):
    def test_verbs(self):
        s = {"8d597ae8-3c99-43f5-8eb1-7dba02b3dec7": "email"}
        g = "mcp__8d597ae8-3c99-43f5-8eb1-7dba02b3dec7__"
        self.assertEqual(classify_mcp(g + "send_message", s), "send:email")
        self.assertEqual(classify_mcp(g + "create_draft", s), "draft:email")
        self.assertEqual(classify_mcp(g + "get_draft", s), "read:email")
        self.assertEqual(classify_mcp(g + "delete_draft", s), "delete:email")
        self.assertEqual(classify_mcp(g + "trash_thread", s), "delete:email")
        self.assertEqual(classify_mcp(g + "label_thread", s), "modify:email")
        self.assertEqual(classify_mcp("mcp__slack__slack_send_message", {}), "send:slack")
        self.assertEqual(classify_mcp("mcp__plugin_discord_discord__reply", {"plugin_discord_discord": "discord"}),
                         "send:discord")
        self.assertEqual(classify_mcp("mcp__claude-in-chrome__navigate", {}), "browser:chrome")
        self.assertEqual(classify_mcp("mcp__sf-caseops__soql_query", {}), "read:sf-caseops")

    def test_unknown_verb_stays_unknown(self):
        # no verb the tool recognises: reported as-is, in the "direction unknown" bucket, not as a read
        self.assertEqual(classify_mcp("mcp__thing__frobnicate", {}), "mcp:thing:frobnicate")

    def test_unlabelled_server_is_shortened_not_dropped(self):
        self.assertEqual(classify_mcp("mcp__8d597ae8-3c99-43f5-8eb1-7dba02b3dec7__send_message", {}), "send:8d597ae8")


class CommandTests(unittest.TestCase):
    def setUp(self):
        self.c = clf()

    def test_curl_send_vs_read(self):
        self.assertEqual(keys(self.c.command("curl -s https://api.weather.gov/x")), ["net:api.weather.gov"])
        self.assertEqual(keys(self.c.command("curl -s -X POST -d @p.json https://hooks.example.com/a")),
                         ["send:http:hooks.example.com"])
        self.assertEqual(keys(self.c.command("curl -s -d hi https://ntfy.sh/topic")), ["send:ntfy"])

    def test_wildcard_rule_is_read_the_wide_way(self):
        # as an allow rule, the * can stand for "-d body": this is how a GET-looking rule sends
        self.assertEqual(keys(self.c.command("curl -s https://ntfy.sh/*", wild=True)), ["send:ntfy"])
        # the same text as an instruction is just a fetch
        self.assertEqual(keys(self.c.command("curl -s https://ntfy.sh/*")), ["net:ntfy.sh"])
        # a literal rule with no wildcard stays a read
        self.assertEqual(keys(self.c.command("curl -s https://api.example.com/jobs?x=1", wild=True)),
                         ["net:api.example.com"])

    def test_salesforce(self):
        self.assertEqual(keys(self.c.command("sf data query --query \"SELECT Id FROM Case\" --json")),
                         ["cred:salesforce-cli", "data:salesforce:read"])
        self.assertEqual(keys(self.c.command("sf data update record -s Case -i 500 -v \"Status=Closed\"")),
                         ["cred:salesforce-cli", "data:salesforce:write"])
        self.assertEqual(keys(self.c.command("sf *", wild=True)), ["cred:salesforce-cli", "data:salesforce:any"])
        self.assertEqual(keys(self.c.command("sf data:*", wild=True)), ["cred:salesforce-cli", "data:salesforce:any"])
        self.assertEqual(keys(self.c.command("sf --version", wild=True)), [])

    def test_github_and_git(self):
        self.assertEqual(keys(self.c.command("gh repo view me/x")), ["cred:github-cli", "read:github"])
        self.assertEqual(keys(self.c.command("gh api *", wild=True)), ["cred:github-cli", "publish:github"])
        self.assertEqual(keys(self.c.command("gh pr create --fill")), ["cred:github-cli", "publish:github"])
        self.assertEqual(keys(self.c.command("git -C ~/site push origin main")), ["publish:git-push"])
        self.assertEqual(keys(self.c.command("git status")), [])
        self.assertEqual(keys(self.c.command("git add *", wild=True)), [])

    def test_compound_command_is_split(self):
        got = keys(self.c.command("cd ~/x && python3 ~/bin/discord_send.py p.json; rm -rf ~/tmp/*"))
        self.assertEqual(got, ["cred:discord-bot", "delete:files", "send:discord"])

    def test_named_file_delete_is_its_own_key(self):
        self.assertEqual(keys(self.c.command("rm /tmp/page.html")), ["delete:named-file"])
        self.assertEqual(keys(self.c.command("rm -rf build")), ["delete:files"])

    def test_store_path_and_redirect(self):
        self.assertIn("cred:discord-bot", keys(self.c.command("cat ~/.config/chat/.env")))
        self.assertIn("cred:discord-bot", keys(self.c.command("source /home/t/.config/chat/.env")))
        self.assertEqual(keys(self.c.command("echo hi >> ~/Trackers/log.md 2>/dev/null")), ["write:~/Trackers/log.md"])
        self.assertEqual(keys(self.c.command("cat > *", wild=True)), ["write:any"])

    def test_sends_the_first_version_read_as_reads_or_nothing(self):
        c = self.c
        self.assertEqual(keys(c.command("curl -sSX POST https://hooks.example.com/a")), ["send:http:hooks.example.com"])
        self.assertEqual(keys(c.command("curl -sSd @p.json https://hooks.example.com/a")), ["send:http:hooks.example.com"])
        self.assertEqual(keys(c.command("wget --post-data=x https://hooks.example.com/a")), ["send:http:hooks.example.com"])
        self.assertEqual(keys(c.command("wget -T 10 https://files.example.com/a")), ["net:files.example.com"])
        self.assertEqual(keys(c.command("http POST https://hooks.example.com/a name=x")), ["send:http:hooks.example.com"])
        self.assertEqual(keys(c.command("sleep 1 & curl -d x https://e.example.com/a")), ["send:http:e.example.com"])
        self.assertEqual(keys(c.command("FOO=\"a b\" curl -d x https://e.example.com/a")), ["send:http:e.example.com"])
        self.assertEqual(keys(c.command("curl -fsSL https://e.example.com/a 2>&1")), ["net:e.example.com"])

    def test_git_and_gh_wide_readings(self):
        c = self.c
        self.assertEqual(keys(c.command("git -C ~/site *", wild=True)), ["publish:git-push"])
        self.assertEqual(keys(c.command("git:*", wild=True)), ["publish:git-push"])
        self.assertEqual(keys(c.command("git -C ~/site log *", wild=True)), [])
        self.assertEqual(keys(c.command("git stash push")), [])
        self.assertEqual(keys(c.command("gh pr review 12 --approve")), ["cred:github-cli", "publish:github"])
        self.assertEqual(keys(c.command("gh pr *", wild=True)), ["cred:github-cli", "publish:github"])
        self.assertEqual(keys(c.command("gh repo view me/*", wild=True)), ["cred:github-cli", "read:github"])
        self.assertEqual(keys(c.command("gh search *", wild=True)), ["cred:github-cli", "read:github"])
        self.assertEqual(keys(c.command("gh api repos/me/x")), ["cred:github-cli", "read:github"])
        self.assertEqual(keys(c.command("gh api repos/me/x -f title=hi")), ["cred:github-cli", "publish:github"])

    def test_deletes(self):
        c = self.c
        self.assertEqual(keys(c.command("rm --recursive build")), ["delete:files"])
        self.assertEqual(keys(c.command("rm -f a b c")), ["delete:files"])
        self.assertEqual(keys(c.command("rm -f /tmp/one.html")), ["delete:named-file"])
        self.assertEqual(keys(c.command("find ~/Downloads -mtime +30 -delete")), ["delete:files"])
        self.assertEqual(keys(c.command("find . -name '*.pyc' -exec rm {} +")), ["delete:files"])
        self.assertEqual(keys(c.command("find ~/Downloads -name '*.html'")), [])

    def test_file_writers_are_writes(self):
        c = self.c
        self.assertEqual(keys(c.command("cp a.json ~/Trackers/b.json")), ["write:~/Trackers/b.json"])
        self.assertEqual(keys(c.command("echo x | tee -a ~/Trackers/log.md")), ["write:~/Trackers/log.md"])
        self.assertEqual(keys(c.command("sed -i '' 's/a/b/' notes.md")), ["write:notes.md"])
        self.assertEqual(keys(c.command("sed 's/a/b/' notes.md")), [])
        self.assertEqual(keys(c.command("cp:*", wild=True)), ["write:any"])
        self.assertEqual(keys(c.command("python3 -c 'print(1 > 0)'")), ["exec:interpreter"])

    def test_misc_heads(self):
        self.assertEqual(keys(self.c.command("ssh -o BatchMode=yes worker ls")), ["cred:ssh-keys", "exec:remote"])
        self.assertEqual(keys(self.c.command("osascript -e 'tell application \"Messages\" to send'")), ["exec:osascript"])
        self.assertEqual(keys(self.c.command("security find-generic-password -s x -w")), ["cred:keychain"])
        self.assertEqual(keys(self.c.command("security find-identity -v")), [])
        self.assertEqual(keys(self.c.command("open:*", wild=True)), ["exec:open"])


class NegationTests(unittest.TestCase):
    def at(self, text, needle):
        return negated_at(text, text.index(needle))

    def test_negation_before_hit_in_same_statement(self):
        self.assertTrue(self.at("Do not post to Slack", "Slack"))
        self.assertTrue(self.at("never a hand-built curl", "curl"))

    def test_negation_after_hit_does_not_count(self):
        t = "Send via HELPER, not a hand-built CURL"
        self.assertFalse(self.at(t, "HELPER"))
        self.assertTrue(self.at(t, "CURL"))

    def test_negation_in_an_earlier_sentence_does_not_count(self):
        self.assertFalse(self.at("Do not skip this step. Run HELPER now", "HELPER"))
        self.assertFalse(self.at("Don't build the request in bash: write the payload, then run HELPER", "HELPER"))
        self.assertFalse(self.at("Don't skip this, run HELPER", "HELPER"))

    def test_negation_carries_through_a_list(self):
        self.assertTrue(self.at("Do not use shell loops,       , or CURL here", "CURL"))
        self.assertTrue(self.at("never archive, stop, or DELETE a session", "DELETE"))

    def test_requirements_written_with_a_negative_are_not_prohibitions(self):
        # the worse direction: each of these made a sending agent look like a non-sender
        self.assertFalse(self.at("Don't forget to post the summary to DISCORD", "DISCORD"))
        self.assertFalse(self.at("Never end the run without running HELPER", "HELPER"))
        self.assertFalse(self.at("Without a DISCORD post the run is incomplete", "DISCORD"))
        self.assertFalse(self.at("Do not stop until you have posted to DISCORD", "DISCORD"))
        self.assertFalse(self.at("Never skip the DISCORD post", "DISCORD"))
        # and the plain ones still prohibit
        self.assertTrue(self.at("Do not post the report to SLACK", "SLACK"))
        self.assertTrue(self.at("Do it without using CURL", "CURL"))

    def test_longer_lists_and_one_line_lead_ins(self):
        t = "Do not post to Slack, DISCORD, Teams, or EMAIL"
        self.assertTrue(self.at(t, "DISCORD"))
        self.assertTrue(self.at(t, "EMAIL"))
        self.assertTrue(self.at("Do NOT: post to SLACK", "SLACK"))
        self.assertFalse(self.at("Don't do it by hand, run HELPER", "HELPER"))

    def test_otherwise_resets(self):
        self.assertFalse(self.at("If nothing changed do not post; otherwise send to DISCORD", "DISCORD"))


class InstructionTests(unittest.TestCase):
    def scan(self, text):
        caps, prohibited, scripts, skills, secrets = scan_instructions(text, clf(), "SKILL.md")
        return cap_keys(caps), cap_keys(prohibited), scripts, skills, secrets

    def test_warning_is_not_the_offense(self):
        caps, pro, _, _, _ = self.scan("Read one file per call. Do not use shell loops or `curl -d x https://a.example.com`.\n")
        self.assertEqual(caps, [])
        self.assertEqual(pro, ["send:http:a.example.com"])

    def test_helper_instructed_curl_prohibited_on_one_line(self):
        caps, pro, scripts, _, _ = self.scan(
            "Post with `python3 ~/bin/discord_send.py p.json`, not a hand-built `curl -X POST https://discord.com/api/x`.\n")
        self.assertEqual(caps, ["cred:discord-bot", "send:discord"])
        self.assertEqual(pro, ["send:discord"])
        self.assertEqual(scripts[0][0], "~/bin/discord_send.py")

    def test_do_not_lead_in_over_bullets(self):
        caps, pro, _, _, _ = self.scan("Do NOT:\n- run `sf data update record -s Case`\n- post to Slack\n\nThen run `gh repo view me/x`.\n")
        self.assertIn("data:salesforce:write", pro)
        self.assertIn("send:slack", pro)
        self.assertNotIn("data:salesforce:write", caps)
        self.assertIn("read:github", caps)

    def test_negation_on_previous_line_without_colon_does_not_prohibit(self):
        # dropping a real capability because a nearby sentence said "not" would be guessing toward safe
        caps, pro, _, _, _ = self.scan("Do not skip this step.\nRun `python3 ~/bin/ntfy_send.py p.json`.\n")
        self.assertEqual(caps, ["send:ntfy"])
        self.assertEqual(pro, [])

    def test_lead_in_has_to_be_about_not_doing(self):
        for body in ("Don't skip this step:\nRun `python3 ~/bin/ntfy_send.py p.json`.\n",
                     "Do not forget the rule about tone:\n- post with `python3 ~/bin/ntfy_send.py p.json`\n",
                     "If the helper doesn't answer:\n- fall back to `python3 ~/bin/ntfy_send.py p.json`\n"):
            caps, pro, _, _, _ = self.scan(body)
            self.assertEqual((caps, pro), (["send:ntfy"], []), body)
        for body in ("Never:\n- run `python3 ~/bin/ntfy_send.py p.json`\n",
                     "**Things to avoid:**\n- `python3 ~/bin/ntfy_send.py p.json`\n"):
            caps, pro, _, _, _ = self.scan(body)
            self.assertEqual((caps, pro), ([], ["send:ntfy"]), body)

    def test_dont_forget_is_an_instruction(self):
        caps, pro, _, _, _ = self.scan("Don't forget to post the summary to Discord.\n")
        self.assertEqual((caps, pro), (["send:discord"], []))

    def test_fenced_block_is_instruction_even_after_a_stray_not(self):
        caps, pro, _, _, _ = self.scan("This is not optional.\n\n```\nsf data query --query \"SELECT Id FROM Case\"\n```\n")
        self.assertIn("data:salesforce:read", caps)
        self.assertEqual(pro, [])

    def test_draft_yes_send_no(self):
        caps, pro, _, _, _ = self.scan("Create a Gmail draft for each letter. Do not send the email; a person sends it.\n")
        self.assertIn("draft:email", caps)
        self.assertNotIn("send:email", caps)
        self.assertIn("send:email", pro)

    def test_tool_name_in_prose(self):
        caps, _, _, _, _ = self.scan("Send the brief as a DM using mcp__slack__slack_send_message.\n")
        self.assertIn("send:slack", caps)

    def test_mention_is_not_access(self):
        caps, _, _, _, _ = self.scan("Pick a prompt a Salesforce admin would find useful.\n")
        self.assertEqual([k for k in caps if "salesforce" in k], [])
        caps, _, _, _, _ = self.scan("Query Salesforce for this week's case volume.\n")
        self.assertIn("data:salesforce:any", caps)

    def test_path_direction_follows_nearest_verb(self):
        caps, _, _, _, _ = self.scan("Parse the feed and write ~/Downloads/rain.html.\nRead the notes in /Users/someone/Trackers/notes.md first.\nSee also ~/Documents/x.md.\n")
        self.assertIn("write:~/Downloads/rain.html", caps)
        self.assertNotIn("read:~/Downloads/rain.html", caps)
        self.assertIn("read:~/Trackers/notes.md", caps)       # /Users/<name>/ is read as home
        self.assertIn("read:~/Documents/x.md", caps)
        caps, _, _, _, _ = self.scan("State lives at ~/Trackers/state.json.\n")
        self.assertEqual(caps, ["ref:~/Trackers/state.json"])  # no verb: direction unknown, not guessed

    def test_secret_in_instructions_is_located_not_returned(self):
        _, _, _, _, secrets = self.scan("x\n```\ncurl -s \"https://api.example.com/v1?application_key=%s\"\n```\n" % FAKE)
        self.assertEqual(len(secrets), 1)
        self.assertEqual(secrets[0]["where"], "SKILL.md line 3")
        self.assertNotIn(FAKE, json.dumps(secrets))

    def test_skill_handoff(self):
        _, _, _, skills, _ = self.scan("Then run the `amex-pass` skill.\nUse the same skill as before.\n")
        self.assertEqual([(s[0], s[1]) for s in skills], [("amex-pass", True), ("same", False)])


class ScriptTests(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.root)

    def test_url_literal_counts_user_agent_does_not(self):
        p = write(os.path.join(self.root, "s.py"),
                  "import os\n# https://ignored.example.com in a comment\n"
                  "req = Request(f\"https://discord.com/api/v10/x\", headers={'User-Agent': 'Bot (https://github.com/x/y, 1)'})\n"
                  "urlopen('https://api.example.org/v1')\nT = os.environ.get('CHAT_TOKEN')\n"
                  "subprocess.run(['sf', 'data', 'query', '-q', q])\n")
        caps, status = scan_script(p, clf(), "s.py")
        self.assertEqual(status, "read")
        self.assertEqual(cap_keys(caps), ["cred:env:CHAT_TOKEN", "cred:salesforce-cli", "data:salesforce:read",
                                          "net:api.example.org", "send:discord"])

    def test_missing_and_oversized_are_not_empty(self):
        self.assertEqual(scan_script(os.path.join(self.root, "nope.py"), clf(), "x")[1], "missing")
        big = write(os.path.join(self.root, "big.py"), "x = 1\n" * (ar.MAX_SCRIPT_BYTES // 6 + 10))
        self.assertEqual(scan_script(big, clf(), "x")[1], "too large")

    @unittest.skipIf(os.geteuid() == 0, "root reads through chmod 000")
    def test_unreadable_is_its_own_status(self):
        p = write(os.path.join(self.root, "locked.py"), "x = 1\n")
        os.chmod(p, 0)
        self.addCleanup(os.chmod, p, 0o600)
        self.assertEqual(scan_script(p, clf(), "x")[1], "unreadable")


class FleetCase(unittest.TestCase):
    """A small fleet on disk. Subclasses lay down files, then call self.run_register()."""

    def setUp(self):
        self.home = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.home)
        self.rows = []
        self.cfg = {"home": self.home, "user_settings": ["~/.claude/settings.json"], "registry": "~/registry.json",
                    "tasks_roots": ["~/.claude/scheduled-tasks"], "skills_root": "~/.claude/skills",
                    "policy": "~/policy.json",
                    "credential_stores": [{"id": "discord-bot", "label": "Bot token", "path": "~/.config/chat/.env"},
                                          {"id": "ssh-keys", "label": "SSH key", "path": "~/.ssh/id_ed25519"}],
                    "send_helpers": [{"match": "discord_send.py", "channel": "discord", "credential": "discord-bot"}]}
        write(os.path.join(self.home, ".config/chat/.env"))
        write(os.path.join(self.home, ".ssh/id_ed25519"))
        self.settings({"permissions": {"allow": []}})
        # a valid policy that can't produce a finding, so a test's exit code reflects only what it sets up
        self.policy([{"id": "P0", "title": "placeholder", "text": "", "check": {"type": "process"}}])

    def settings(self, data, rel=".claude/settings.json"):
        return write(os.path.join(self.home, rel), json.dumps(data))

    def policy(self, rules):
        write(os.path.join(self.home, "policy.json"), json.dumps({"title": "t", "status": "test", "rules": rules}))

    def task(self, tid, body="Do the thing.\n", mode="auto", cwd=None, model="opus", approved=None, skill=True, **extra):
        path = os.path.join(self.home, ".claude/scheduled-tasks", tid, "SKILL.md")
        if skill:
            write(path, "---\nname: %s\n%s---\n%s" % (tid, "model: %s\n" % model if model else "", body))
        row = {"id": tid, "cronExpression": "0 7 * * *", "enabled": True, "filePath": path,
               "cwd": cwd or self.home}
        if mode:
            row["permissionMode"] = mode
        if approved:
            row["approvedPermissions"] = approved
        row.update(extra)
        self.rows.append(row)

    def run_register(self):
        write(os.path.join(self.home, "registry.json"), json.dumps({"scheduledTasks": self.rows}))
        path = write(os.path.join(self.home, "cfg.json"), json.dumps(self.cfg))
        cfg, env = ar.load_config(path)
        self.report, self.pol, self.result, self.code = ar.run(cfg, env)
        self.agents = {a["id"]: a for a in self.report["agents"]}
        return self.report

    def facts(self, name):
        return self.report["facts"].get(name, [])


class RegisterTests(FleetCase):
    def test_unreadable_is_not_empty(self):
        self.task("a")
        p = self.settings({"permissions": {"allow": ["Bash(sf *)"]}})
        with open(p, "w") as fh:
            fh.write("{ not json")
        self.run_register()
        self.assertEqual(self.code, 2)
        self.assertTrue(any("unknown, not absent" in e for e in self.report["errors"]))
        # and it must not claim "no deny rules" about a file it couldn't read
        self.assertEqual(self.facts("no_deny_rules"), [])
        self.assertEqual(self.facts("gate_hook_missing"), [])

    def test_missing_registry_is_exit_2(self):
        path = write(os.path.join(self.home, "cfg.json"), json.dumps(self.cfg))
        cfg, env = ar.load_config(path)
        report, _, _, code = ar.run(cfg, env)
        self.assertEqual(code, 2)
        self.assertEqual(report["agents"], [])

    def test_missing_skill_is_unknown_not_clean(self):
        self.task("gone", skill=False)
        self.run_register()
        a = self.agents["gone"]
        self.assertEqual(a["skill_status"], "missing")
        self.assertTrue(a["unknowns"])
        self.assertEqual(self.code, 2)
        page = ar.render_html(self.report, self.pol, self.result)
        self.assertIn("instructions missing", page)
        # a missing SKILL.md must not be reported as a missing model line
        self.assertEqual(self.facts("model_unset"), [])

    def test_home_as_cwd_reaches_every_store(self):
        self.task("homey")
        self.task("scoped", cwd=os.path.join(self.home, "proj"))
        os.makedirs(os.path.join(self.home, "proj"))
        self.run_register()
        self.assertEqual(sorted(c["id"] for c in self.agents["homey"]["cred_reach"]), ["discord-bot", "ssh-keys"])
        self.assertEqual(self.agents["scoped"]["cred_reach"], [])
        self.assertEqual([f["scope"] for f in self.facts("home_as_cwd")], ["homey"])

    def test_user_rule_reaches_store_for_scoped_agent(self):
        self.settings({"permissions": {"allow": ["Read(~/.config/**)", "Edit(~/Trackers/**)"]}})
        os.makedirs(os.path.join(self.home, "proj"))
        self.task("scoped", cwd=os.path.join(self.home, "proj"))
        self.run_register()
        self.assertEqual([c["id"] for c in self.agents["scoped"]["cred_reach"]], ["discord-bot"])
        f = self.facts("credential_path_allowed")
        self.assertEqual(len(f), 1)
        self.assertIn("Read(~/.config/**)", f[0]["text"])
        self.assertEqual(f[0]["scope"], "all agents")

    def test_project_settings_apply_only_under_that_cwd(self):
        proj = os.path.join(self.home, "proj")
        self.settings({"permissions": {"allow": ["mcp__mail__send_message"], "deny": ["Read(~/.ssh/**)"]}},
                      rel="proj/.claude/settings.local.json")
        self.task("inside", cwd=proj)
        self.task("outside")
        self.policy([{"id": "R1", "title": "channels", "text": "", "check": {
            "type": "allow_only", "prefixes": ["send:"], "allowed": ["send:discord"]}},
            {"id": "R2", "title": "deny", "text": "", "check": {"type": "fact", "facts": ["credential_not_denied"]}}])
        self.run_register()
        self.assertEqual(len(self.agents["inside"]["scopes"]), 2)
        self.assertEqual(len(self.agents["outside"]["scopes"]), 1)
        hits = [f for f in self.result["config_forbidden"] if f["rule"] == "R1"]
        self.assertEqual([f["who"] for f in hits], ["1 agent with working directory ~/proj"])
        # the deny rule protects the ssh key for one agent only; both stores are bare for the other
        texts = {f["who"]: f["what"] for f in self.result["config_forbidden"] if f["rule"] == "R2"}
        self.assertEqual(texts, {"all agents": "no deny rule covers Bot token",
                                 "1 of 2 agents": "no deny rule covers SSH key"})

    def test_dead_rules(self):
        self.settings({"permissions": {"allow": ["Edit(/Users/t/PhoneLog/**)", "Write(~/Trackers/**)", "Edit(~/Trackers/**)"]}})
        self.task("a")
        self.run_register()
        dead = [f["text"] for f in self.facts("dead_rule")]
        self.assertEqual(len(dead), 2)
        self.assertTrue(any("single leading slash" in d for d in dead))
        self.assertTrue(any("Write() path rule" in d for d in dead))

    def test_mode_model_and_bypass_facts(self):
        self.task("nomode", mode=None)
        self.task("nomodel", model=None)
        self.task("bypass", mode="bypassPermissions")
        self.run_register()
        self.assertEqual([f["scope"] for f in self.facts("mode_unset")], ["nomode"])
        self.assertEqual([f["scope"] for f in self.facts("model_unset")], ["nomodel"])
        self.assertEqual([f["scope"] for f in self.facts("mode_bypass")], ["bypass"])
        # in default-ish modes an edit inside cwd still prompts, so no write grant is claimed for the unset one
        self.assertFalse(any(c["key"].startswith("write:") for c in self.agents["nomode"]["declared"]))
        self.assertTrue(any(c["key"].startswith("write:") for c in self.agents["nomodel"]["declared"]))

    def test_task_approvals_are_declared_and_classified(self):
        self.task("a", approved=[{"toolName": "mcp__mail__send_message"},
                                 {"toolName": "Bash", "ruleContent": "git push origin main"},
                                 {"toolName": "Bash", "ruleContent": "python3 -c ' *"},
                                 {"toolName": "Edit", "ruleContent": "~/Downloads/*.html"},
                                 {"toolName": "Bash", "ruleContent": "curl -H 'Authorization: Bearer %s' https://x.example.com" % FAKE}])
        self.run_register()
        got = {c["key"] for c in self.agents["a"]["declared"] if not c.get("derived")}
        self.assertEqual(got, {"send:mail", "publish:git-push", "exec:interpreter", "write:~/Downloads/*.html",
                               "net:x.example.com"})
        self.assertEqual([f["scope"] for f in self.facts("broad_exec_rule")], ["a"])
        self.assertEqual(len(self.facts("secret_literal")), 1)
        blob = json.dumps(self.report) + ar.render_html(self.report, self.pol, self.result)
        self.assertNotIn(FAKE, blob)

    def test_one_hop_script_and_relative_path(self):
        proj = os.path.join(self.home, "proj")
        write(os.path.join(proj, "pipeline/run.py"), "subprocess.run(['python3', 'x/discord_send.py', 'p.json'])\n")
        self.task("a", body="Run it:\n\n```\n.venv/bin/python pipeline/run.py\n```\nThen `python3 ~/bin/absent.py`.\n", cwd=proj)
        self.run_register()
        a = self.agents["a"]
        self.assertIn("send:discord", cap_keys(a["inferred"]))
        self.assertEqual({h["status"] for h in a["hops"]}, {"read", "missing"})
        self.assertTrue(any("absent.py is missing" in u for u in a["unknowns"]))

    def test_skill_handoff_is_followed_one_level(self):
        write(os.path.join(self.home, ".claude/skills/amex-pass/SKILL.md"),
              "Post the picks with `python3 ~/bin/discord_send.py p.json`.\n")
        self.task("a", body="Run the `amex-pass` skill. Then use the `ghost` skill. Use the same skill twice.\n")
        self.run_register()
        a = self.agents["a"]
        self.assertIn("send:discord", cap_keys(a["inferred"]))
        self.assertTrue(any("ghost" in u for u in a["unknowns"]))
        self.assertFalse(any("same" in u for u in a["unknowns"]))

    def test_orphans_and_registry_shapes(self):
        write(os.path.join(self.home, ".claude/scheduled-tasks/leftover/SKILL.md"), "x\n")
        self.task("a")
        self.run_register()
        self.assertEqual([o["id"] for o in self.report["orphans"]], ["leftover"])
        # the MCP list shape: a bare list with taskId
        rows, problem = ar.registry_rows([{"taskId": "z", "enabled": False}])
        self.assertEqual(([r["id"] for r in rows], problem), (["z"], None))

    def test_unrecognised_registry_is_incomplete_not_an_empty_fleet(self):
        rows, problem = ar.registry_rows({"version": 2, "items": [{"id": "a"}]})
        self.assertEqual(rows, [])
        self.assertIn("shape", problem)
        rows, problem = ar.registry_rows([{"taskId": "z"}, {"nope": 1}, "junk"])
        self.assertEqual(len(rows), 1)
        self.assertIn("2 row(s)", problem)
        write(os.path.join(self.home, "registry.json"), json.dumps({"version": 2, "items": [{"id": "a"}]}))
        path = write(os.path.join(self.home, "cfg.json"), json.dumps(self.cfg))
        cfg, env = ar.load_config(path)
        report, _, _, code = ar.run(cfg, env)
        self.assertEqual(code, 2)

    def test_task_approval_covering_a_store_raises_the_same_fact_as_a_settings_rule(self):
        os.makedirs(os.path.join(self.home, "proj"))
        self.settings({"permissions": {"allow": [], "deny": ["Read(~/.ssh/**)", "Read(~/.config/**)"]}})
        self.task("a", cwd=os.path.join(self.home, "proj"), approved=[{"toolName": "Read", "ruleContent": "~/.ssh/**"}])
        self.policy([{"id": "R", "title": "creds", "text": "", "check": {"type": "fact", "facts": ["credential_path_allowed"]}}])
        self.run_register()
        f = self.facts("credential_path_allowed")
        self.assertEqual([(x["scope"], "SSH key" in x["text"]) for x in f], [("a", True)])
        self.assertEqual(self.code, 1)

    def test_store_inside_a_non_home_working_directory(self):
        self.task("cfg-agent", cwd=os.path.join(self.home, ".config") + "/")   # trailing slash on purpose
        self.task("homey", cwd=self.home + "/")
        self.run_register()
        self.assertEqual([f["scope"] for f in self.facts("store_in_workdir")], ["cfg-agent"])
        self.assertIn("Bot token", self.facts("store_in_workdir")[0]["text"])
        # and the trailing slash doesn't hide a home working directory
        self.assertEqual([f["scope"] for f in self.facts("home_as_cwd")], ["homey"])

    def test_additional_directories_count_as_reach(self):
        proj = os.path.join(self.home, "proj")
        self.settings({"permissions": {"allow": [], "additionalDirectories": ["~/.ssh"]}}, rel="proj/.claude/settings.json")
        self.task("a", cwd=proj)
        self.run_register()
        self.assertEqual([c["id"] for c in self.agents["a"]["cred_reach"]], ["ssh-keys"])
        self.assertEqual([f["scope"] for f in self.facts("store_in_workdir")], ["a"])

    def test_unreadable_project_settings_block_the_none_anywhere_facts(self):
        proj = os.path.join(self.home, "proj")
        write(os.path.join(proj, ".claude/settings.json"), "{ broken")
        self.task("a", cwd=proj)
        self.run_register()
        self.assertEqual(self.code, 2)
        self.assertEqual(self.facts("no_deny_rules"), [])
        self.assertEqual(self.facts("gate_hook_missing"), [])

    def test_deny_rule_text_is_masked_in_json_too(self):
        self.settings({"permissions": {"allow": ["Read(~/tmp/%s.json)" % FAKE], "deny": ["Read(~/keys/ghp_abcdefghijklmnop1234/**)"]}})
        self.task("a")
        self.run_register()
        blob = json.dumps(self.report, default=str) + ar.render_html(self.report, self.pol, self.result)
        self.assertNotIn("ghp_abcdefghijklmnop1234", blob)
        self.assertNotIn(FAKE, blob)

    def test_script_named_bare_or_behind_a_flag_is_still_hopped(self):
        proj = os.path.join(self.home, "proj")
        write(os.path.join(proj, "nag.py"), "import shutil\nshutil.rmtree(target)\n")
        write(os.path.join(self.home, "bin/x.py"), "subprocess.run(['python3', 'discord_send.py', 'p.json'])\n")
        self.task("a", cwd=proj, body="Run `python3 nag.py`, then `python3 -u ${HOME}/bin/x.py`, then `python3 gone.py`.\n")
        self.run_register()
        a = self.agents["a"]
        self.assertEqual(sorted(h["status"] for h in a["hops"]), ["missing", "read", "read"])
        self.assertIn("delete:files", cap_keys(a["inferred"]))
        self.assertIn("send:discord", cap_keys(a["inferred"]))
        self.assertTrue(any("gone.py is missing" in u for u in a["unknowns"]))

    def test_gate_hook_fact(self):
        self.task("a")
        self.run_register()
        self.assertEqual(len(self.facts("gate_hook_missing")), 1)
        self.settings({"permissions": {"allow": []}, "hooks": {"PreToolUse": [
            {"matcher": "Bash", "hooks": [{"type": "command", "command": "python3 gate.py"}]}]}})
        self.rows = []
        self.task("a")
        self.run_register()
        self.assertEqual(self.facts("gate_hook_missing"), [])


class DiffTests(FleetCase):
    RULES = [
        {"id": "R-SEND", "rmf": "Manage", "title": "channels", "text": "", "check": {
            "type": "allow_only", "prefixes": ["send:", "draft:"], "allowed": ["send:discord", "draft:*"]}},
        {"id": "R-WORK", "rmf": "Map", "title": "work", "text": "", "check": {
            "type": "forbid", "keys": ["data:salesforce:*", "cred:ssh-keys"]}},
        {"id": "R-DEL", "rmf": "Manage", "title": "delete", "text": "", "check": {
            "type": "forbid", "keys": ["delete:*"], "except_keys": ["delete:named-file"]}},
        {"id": "R-PROC", "rmf": "Govern", "title": "process", "text": "", "check": {"type": "process"}},
        {"id": "R-ODD", "rmf": "Govern", "title": "odd", "text": "", "check": {"type": "telepathy"}},
    ]

    def test_declared_and_inferred_land_in_different_lists(self):
        self.settings({"permissions": {"allow": ["Bash(sf *)", "Bash(rm /tmp/x.html)"]}})
        self.task("told", body="Send it using mcp__slack__slack_send_message.\n")
        self.task("granted", approved=[{"toolName": "mcp__mail__send_message"}, {"toolName": "mcp__mail__trash_thread"}])
        self.task("fine", body="Post with `python3 ~/bin/discord_send.py p.json`. Create a Gmail draft.\n")
        self.policy(self.RULES)
        self.run_register()
        cf = {(f["rule"], f["who"], f["key"]) for f in self.result["config_forbidden"]}
        self.assertEqual(cf, {("R-WORK", "all agents", "data:salesforce:any"),
                              ("R-SEND", "granted", "send:mail"),
                              ("R-DEL", "granted", "delete:mail")})
        inst = {(f["rule"], f["who"], f["key"]) for f in self.result["instructed_forbidden"]}
        self.assertEqual(inst, {("R-SEND", "told", "send:slack")})
        self.assertEqual(self.code, 1)
        self.assertEqual({u["rule"] for u in self.result["unchecked"]}, {"R-PROC", "R-ODD"})

    def test_location_reach_is_reported_once_as_a_fact_not_per_store(self):
        # The ssh key sits inside cwd. A forbid rule on cred:ssh-keys doesn't fire per agent per store;
        # the working-directory facts carry it, so a policy has to name them to see it.
        self.task("a")
        self.policy(self.RULES)
        self.run_register()
        self.assertEqual(self.result["config_forbidden"], [])
        self.assertEqual([f["scope"] for f in self.facts("home_as_cwd")], ["a"])
        self.policy(self.RULES + [{"id": "R-CWD", "title": "cwd", "text": "", "check": {
            "type": "fact", "facts": ["home_as_cwd", "store_in_workdir"]}}])
        self.rows = []
        self.task("a")
        self.run_register()
        self.assertEqual([(f["rule"], f["who"]) for f in self.result["config_forbidden"]], [("R-CWD", "a")])
        self.assertEqual(self.code, 1)

    def test_policy_without_rules_is_refused(self):
        self.task("a", mode="bypassPermissions")
        write(os.path.join(self.home, "policy.json"), json.dumps({"title": "t", "status": "s"}))
        self.run_register()
        self.assertEqual(self.code, 2)
        self.assertTrue(any("rules list" in e for e in self.report["errors"]))

    def test_more_count_does_not_grow_with_the_number_of_rules(self):
        self.settings({"permissions": {"allow": ["Bash(sf data:*)", "Bash(sf org:*)", "Bash(sf *)"]}})
        self.task("a")
        extra = [{"id": "X%d" % i, "title": "x", "text": "", "check": {"type": "forbid", "keys": ["data:salesforce:*"]}}
                 for i in range(5)]
        self.policy(extra)
        self.run_register()
        whats = {f["what"] for f in self.result["config_forbidden"]}
        self.assertEqual(len(whats), 1)
        self.assertIn("and 2 more rules", whats.pop())

    def test_exception_needs_to_match_agent_and_key(self):
        self.task("a", approved=[{"toolName": "mcp__mail__send_message"}])
        self.task("b", approved=[{"toolName": "mcp__mail__send_message"}])
        self.policy(self.RULES)
        self.cfg["exceptions"] = {"R-SEND": [{"agent": "a", "keys": ["send:mail"], "reason": "weekly recipe email"}]}
        self.run_register()
        by = {f["who"]: f["excused"] for f in self.result["config_forbidden"]}
        self.assertEqual(by, {"a": "weekly recipe email", "b": None})
        self.assertEqual(self.code, 1)   # b still stands
        page = ar.render_html(self.report, self.pol, self.result)
        self.assertIn("weekly recipe email", page)

    def test_exception_can_target_one_rule_by_its_text(self):
        # excepting the deliberate interpreter rule must not excuse the stale ones beside it
        self.settings({"permissions": {"allow": ["Bash(python3 *)", "Bash(node -e ' *)"]}})
        self.task("a")
        self.policy([{"id": "R", "title": "interp", "text": "", "check": {"type": "fact", "facts": ["broad_exec_rule"]}}])
        self.cfg["exceptions"] = {"R": [{"agent": "*", "keys": ["broad_exec_rule"], "match": "Bash(python3 *)",
                                         "reason": "helper scripts run through python3"}]}
        self.run_register()
        by = {f["what"].split("allows ")[1]: f["excused"] for f in self.result["config_forbidden"]}
        self.assertEqual(by, {"Bash(python3 *)": "helper scripts run through python3", "Bash(node -e ' *)": None})
        self.assertEqual(self.code, 1)

    def test_inferred_only_findings_do_not_fail_the_run(self):
        self.task("told", body="Send it using mcp__slack__slack_send_message.\n")
        self.policy(self.RULES)
        self.run_register()
        self.assertEqual(len(self.result["instructed_forbidden"]), 1)
        self.assertEqual(self.code, 0)

    def test_silence_lists_what_no_rule_speaks_to(self):
        self.settings({"permissions": {"allow": ["WebSearch", "Bash(ssh worker *)", "Bash(sf *)"]}})
        self.task("a", body="Open the page with mcp__claude-in-chrome__navigate. Write ~/Trackers/x/y/z.md.\n"
                            "Post with `python3 ~/bin/discord_send.py p.json`.\n")
        self.policy(self.RULES)
        self.run_register()
        silent = {s["key"] for s in self.result["silent"]}
        self.assertEqual(silent, {"web:search", "exec:remote", "browser:chrome", "write:~/Trackers",
                                  "cred:salesforce-cli", "cred:discord-bot"})
        # covered by a rule's subject matter, even though allowed: not silent
        self.assertNotIn("send:discord", silent)
        self.assertNotIn("data:salesforce:any", silent)

    def test_prohibited_things_are_not_findings(self):
        self.task("a", body="Never post to Slack.\n")
        self.policy(self.RULES)
        self.run_register()
        self.assertEqual(self.result["instructed_forbidden"], [])
        self.assertEqual(cap_keys(self.agents["a"]["prohibited"]), ["send:slack"])

    def test_missing_policy_is_incomplete_not_clean(self):
        self.task("a")
        os.remove(os.path.join(self.home, "policy.json"))
        self.run_register()
        self.assertEqual(self.code, 2)
        self.assertTrue(any("nothing was diffed" in e for e in self.report["errors"]))


class RepoTests(unittest.TestCase):
    def test_policy_markdown_matches_its_json(self):
        policy, why = ar.load_policy(os.path.join(REPO, "policy", "acceptable-use.json"))
        self.assertIsNone(why)
        with open(os.path.join(REPO, "policy", "acceptable-use.md")) as fh:
            self.assertEqual(fh.read(), ar.render_policy_md(policy),
                             "run: python3 access_register.py --render-policy policy/acceptable-use.json")

    def test_policy_rules_are_well_formed(self):
        policy, _ = ar.load_policy(os.path.join(REPO, "policy", "acceptable-use.json"))
        ids = [r["id"] for r in policy["rules"]]
        self.assertEqual(len(ids), len(set(ids)))
        known = {"mode_unset", "model_unset", "mode_bypass", "home_as_cwd", "secret_literal", "broad_exec_rule",
                 "credential_path_allowed", "credential_not_denied", "gate_hook_missing", "no_deny_rules", "dead_rule",
                 "store_in_workdir"}
        for r in policy["rules"]:
            self.assertIn(r["rmf"], ("Govern", "Map", "Measure", "Manage"))
            self.assertIn(r["check"]["type"], ("fact", "forbid", "allow_only", "process"))
            for f in r["check"].get("facts", []):
                self.assertIn(f, known)

    def test_demo_end_to_end(self):
        home = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, home)
        cfg, env = ar.load_config(build_demo.build(home))
        report, policy, result, code = ar.run(cfg, env)
        page = ar.render_html(report, policy, result)
        blob = page + json.dumps({"report": report, "result": result}, default=str)
        for leak in (home, build_demo.FAKE_BOT_TOKEN, build_demo.FAKE_WEATHER_KEY):
            self.assertNotIn(leak, blob)
        self.assertEqual(code, 2)   # one task's instructions are missing on purpose
        agents = {a["id"]: a for a in report["agents"]}
        self.assertEqual(len(agents), 11)
        # the prompt says never delete; the config says it may
        self.assertIn("delete:email", cap_keys(agents["inbox-junk-sweep"]["declared"]))
        self.assertIn("delete:mail", cap_keys(agents["inbox-junk-sweep"]["prohibited"]))
        # helper instructed, curl prohibited
        self.assertIn("send:discord", cap_keys(agents["weekly-fleet-review"]["inferred"]))
        self.assertTrue(any(k.startswith("send:") for k in cap_keys(agents["weekly-fleet-review"]["prohibited"])))
        # the exception holds for the one agent that has it
        pub = [f for f in result["instructed_forbidden"] if f["rule"] == "AUP-11"]
        self.assertTrue(pub and all(f["excused"] for f in pub))
        self.assertTrue(any(f["rule"] == "AUP-11" and f["who"] == "daily-job-pipeline" and not f["excused"]
                            for f in result["config_forbidden"]))
        self.assertEqual(len(report["facts"]["secret_literal"]), 2)
        self.assertIn("<link rel='icon'", page)


if __name__ == "__main__":
    unittest.main()
