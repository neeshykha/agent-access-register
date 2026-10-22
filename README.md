# agent-access-register

A script I run on demand that answers one question about my scheduled Claude Code agents: **what is each one allowed to touch?** It reads the permission config they run under, reads each agent's instructions, and diffs both against a written acceptable-use policy.

Then a just-in-time pass asks the follow-up: for each agent, which standing permissions every run uses, and which could be granted per run and dropped. It answers from the transcripts the runs left behind, not from config.

**[See the demo page →](https://neeshykha.github.io/agent-access-register/)** (a synthetic fleet, built on disk by `demo/build_demo.py`)

This is the third of a set. [skill-regression-harness](https://github.com/neeshykha/skill-regression-harness) asks whether the right agent fires. [scheduled-agent-detector](https://github.com/neeshykha/scheduled-agent-detector) asks whether it did its job. This one asks what it's allowed to do.

## Why this exists

I run a few dozen agents on a schedule with nobody watching: a job pipeline, health and garden check-ins, digests, a weekly fleet review. In September I found a bot token baked into an allowlist. Approving a one-off command had saved its literal text, secret included, as a permanent rule. I cleaned that up by hand and then couldn't answer the obvious follow-up: which of these agents can read that token file at all?

I assumed the answer lived in config, one row per agent. It doesn't. That turned out to be the finding.

## What the first run against my real fleet found

1. **Permissions aren't per-agent.** Every agent inherits one shared allowlist. There are zero deny rules and zero ask rules in any settings file. The "declared" column reads nearly the same on every row, so most of what tells two agents apart has to be inferred from their instructions.
2. **The working directory is the real boundary, and mine was the whole home folder.** 51 of 55 agents run from `~`. Reads inside the working directory need no approval in any permission mode, so every credential file under home is in reach of every one of them, and no rule anywhere says so.
3. **In auto mode the allowlist is a floor, not a ceiling.** 50 agents run in auto, where anything the allowlist doesn't name goes to a classifier. The register can't read that classifier, and the page says so instead of pretending the allowlist is the limit.
4. **The cleanup missed a place.** There's a per-agent layer I didn't know about when I pitched this: every "always allow" click is also saved against the routine it was made in. Seven of those saved approvals carried secret-shaped strings in the same positions as the ones I'd removed from the settings file three weeks earlier. The register reports shape and position, never the value, so it can't say whether they were the same strings. I'd cleaned one file and never looked in the other.
5. **Five agents had no permission mode set**, and five had no model line. All ten were created after the last time I set modes in bulk.

None of that needed a clever scan. It needed somebody to read four files side by side.

## The just-in-time pass

The register says what each agent may touch. The pass says what its runs touched. It reads the desktop app's record of every scheduled run in the last 30 days, opens the transcript each run left, and matches every tool call to the narrowest standing grant that covers it: a shared allow rule, a per-task approval, or the working directory.

A grant every run used is one the agent needs each time. A grant only some runs used could be issued to the run that needs it and revoked when that run ends. Everything else is standing access nothing used.

Since late September, Claude Code has written down what kind of thing allowed each call: a settings rule, a saved approval, the auto-mode classifier, or the permission mode. It doesn't say which rule. The pass uses that record to pick the kind of grant, credits the narrowest one of that kind, and checks itself against the record. On my fleet the matcher found a current rule of the recorded kind for 6,689 of the 6,696 calls Claude Code says a rule allowed. The other seven match no rule that exists today. The catch: only 9,201 of the month's 27,859 calls carry that record at all, since many runs were on older CLI versions. For the other two-thirds, the matcher works alone.

### What it found on my fleet (October 21, 2026)

1,030 runs of 44 agents between September 21 and October 21, and 27,859 tool calls. The 41 agents with at least three runs get sorted into every-run and some-run grants; three with only one or two runs are listed but not sorted.

1. **Each agent holds about 1,200 standing permissions and uses about ten.** The median agent runs under 1,186 shared allow rules. Its runs used 2 grants every time and 8 more some of the time. All 1,186 are live around the clock, for jobs that run a few minutes a day.
2. **215 of the 1,625 shared rules covered any call in 30 days, and 44 covered a call in every run of some agent.** The other 1,410 covered nothing a scheduled run did. The same files govern my interactive sessions, so unused here means unused by the fleet, not safe to delete.
3. **Saved approvals are mostly leftovers.** The scheduler registry holds 472, and runs used 72. daily-job-pipeline has 136 and used 7. friday-portfolio-ideas used 1 of 93. habit-nagger holds 36 and used none: all 383 of its runs went through one shared rule.
4. **One wildcard rule carries most of the fleet.** The rule that lets `python3` run anything in `~/PhoneLog/bin` covered calls for 25 agents across 877 runs. That folder holds 45 scripts; the fleet ran 19 of them, and the median agent ran 2. A per-run grant naming those two scripts does the same job as a standing grant over all 45.
5. **The home folder is the biggest grant, and runs use a sliver of it.** 42 of the 45 agents run from `~`, where reads need no approval. 35 of them read through that grant in the window, and the median one touched two folders. The widest, daily-followups, touched 11.
6. **Some of the fleet already runs just-in-time.** 1,443 calls ran on the auto-mode classifier approving that one call, and 42 on a grant made inside the run that ended with it. 165 calls were blocked, 117 of them by the shell hook. What never expires is the allowlist.
7. **One agent's old runs still hold an API key.** Until September 25, daily-garden-check-v2 put a value shaped like its weather station's API key into a request URL; four calls in the window did it. A fix that day moved the key into a script, and none of the 27 runs since carry it. The four that did left it in their transcripts on disk: the same kind of leftover copy the September cleanup missed. The page reports it by shape and length. It doesn't print the value or test it.

The pass doesn't revoke anything. Like the rest of the register it's read-only, and the page is the worklist: drop what no run used, narrow what every run used to the commands it covered, and move what some runs used to a grant that lives as long as the run.

## What it reads, and the three labels

| Source | What it gives | Label |
| --- | --- | --- |
| `settings.json`, plus each working directory's `.claude/settings*.json` | allow, deny, and ask rules; hooks | **declared** |
| The scheduler registry | each agent's permission mode, working directory, and saved approvals | **declared** |
| Each agent's `SKILL.md` | what it's told to read, write, send, and run | **inferred** |
| Scripts and skills that `SKILL.md` names | one hop, no further | **inferred** |
| The desktop app's session records and each scheduled run's transcript | every tool call a run made, and what Claude Code says allowed it | **observed** |

**Declared** means it's in permission config. **Inferred** means it was read out of free text and can be wrong in both directions. **Observed** means a run's transcript shows the call. That proves a grant was used; it can't prove one is safe to remove. Every row on the page carries one of the three, and they never share a findings list: "config allows what policy forbids" is declared-only, "instructions ask for what policy forbids" sits below it, and the just-in-time pass has its own section.

Credential stores are checked for existence, for which rules reach them, and for which runs named them. None is ever opened. From a transcript the pass keeps only a call's tool name and the input fields that name a command, path, or host, masked before anything is stored.

## Three rules the code holds to

- **Unknown stays unknown.** An unreadable settings file is not an empty one. A missing `SKILL.md` is not a clean agent. A registry in a shape the tool doesn't recognize is not a fleet of zero. Each of those exits 2 and puts a banner on the page. The pass follows suit: no run records at all, or no transcript for any run, exits 2, and a run whose transcript is gone counts as unknown, never as a run that used nothing.
- **A warning is not the offense.** "Do not post to Slack" is recorded as a prohibition the instructions make, shown on the row, and not counted as a Slack capability. The reverse mistake is worse, so "don't forget to post to Discord" and "never end the run without posting" both count as instructions.
- **No secret value is printed.** Secret-shaped strings are reported by file, line, and length. Rule text is masked before it's shown anywhere, including in capability keys and the JSON output.

## The policy

[`policy/acceptable-use.md`](policy/acceptable-use.md) is twelve plain rules, grouped loosely under the NIST AI RMF functions (Govern, Map, Measure, Manage). I adopted it for my own fleet after dropping one rule from the first draft, and the mapping is for orientation, not a compliance claim.

Ten rules are checked by the register. Two can't be ("spending money is never delegated" and "re-run this when the fleet changes"), and the page lists them as unchecked instead of passing them.

The diff has three outputs:

- **Config allows, policy forbids.** Declared access a rule prohibits. This is the list at the top of the page and the only thing that sets exit code 1.
- **Instructions ask for what policy forbids.** Inferred. Whether config would let it through isn't knowable for an agent in auto mode.
- **Where policy is silent.** Access that exists and that no rule speaks to. Browser automation, remote shells, and most write locations landed here on my fleet. Silence isn't approval; it's a decision nobody wrote down.

Exceptions live in the local config, not the policy, and each one needs a reason. An excepted finding still shows on the page, greyed, with the reason beside it.

## How I use it

In a Claude conversation: "run the access register." That runs one script and hands back the page.

```
./run_register.sh
```

On my fleet that takes about 20 seconds, most of it reading a month of transcripts. `--no-runs` skips the pass.

It's read-only and nothing schedules it. I open it when I add or change a routine, and after anything like the September incident.

Exit codes: `0` nothing config allows that policy forbids, `1` at least one such finding, `2` an input couldn't be read and the register is incomplete.

## Setup

Python 3.9+, standard library only.

```
cp register.config.example.json local/live.config.json
python3 access_register.py --config local/live.config.json --out page.html
```

The config names your settings files, the registry (a path or a glob; the newest match wins), the task folders, and three lists the tool can't guess:

- `credential_stores`: `{id, label, path}` for each file or folder that holds a secret.
- `send_helpers`: `{match, channel, credential}` for scripts your agents send through.
- `mcp_servers`: a readable name for each MCP server id.
- `runs` (optional, turns on the pass): `sessions`, a glob for the desktop app's session records; `transcripts_root`, where Claude Code keeps transcripts; `window_days` (default 30); `min_runs` (default 3), below which an agent is listed but not sorted.

`python3 access_register.py --render-policy policy/acceptable-use.json` rewrites the markdown from the JSON. Edit the JSON.

## Tests

```
python3 tests/test_register.py
```

115 tests, all against real files in a throwaway home folder, run records and transcripts included. Most of what's under test is how the register reads files it can't fully trust, and mocking the filesystem would only test the mock.

## What a second model's review caught

None of this can be checked by looking, so I had a stronger model review the parsing and diff logic before I trusted any of it. It found sixteen defects. Five mattered:

- **Masking let real shapes through.** A token with a `/` in it, a `password=` value with no digits, and anything under sixteen characters all printed verbatim.
- **Negation erred in the dangerous direction.** "Don't forget to post to Discord" read as a prohibition, which turned a sending agent into a non-sender.
- **A saved approval covering a credential file raised nothing**, while the identical rule in a settings file raised two findings.
- **A working directory below home that held a credential store raised nothing.**
- **A registry in an unfamiliar shape produced "0 agents, clean, exit 0."**

Each has a test now. Then the live run found one the review hadn't: a saved approval holding the first few characters of an API key followed by a wildcard, short enough to slip under the masking floor. A value assigned to a secret-sounding name is now masked whatever its length.

The masking and negation logic passed their first tests and were wrong. A check that has only been run against the cases its author thought of isn't verified.

The just-in-time pass got the same review before release, and it found six defects. Two would have shipped in this README. The headline count of rules every run used was 41 instead of 44, because the page merges the same rule text from two settings files into one line and the total was counted after the merge. And a token in a URL's `user:password@` prefix would have reached the page through the list of what a rule covered; no run in the window had one, so nothing leaked. The others: a rule got credit when Claude Code's record said the permission mode allowed the call, `cat > file` counted as a read-only command, one malformed transcript line could crash the run, and a wrong transcript folder reported "nothing used" instead of exiting 2. Each has a test now.

## Honest limits

- **Most of it reports configured access.** Only the just-in-time pass looks at behavior, and only at the tool calls a transcript records.
- **The decision record is undocumented.** Claude Code calls its transcript format internal and liable to change. The pass reads the `permissionDecision` field as it appears in CLI versions 2.1.293 to 2.1.299, and falls back to its own matcher for older runs and calls without one, which on my fleet was two-thirds of them.
- **The credit is a choice.** Claude Code takes the first allow rule that matches and doesn't record which. The pass credits the narrowest rule that covers the call, and credits both when two equivalent rules tie (`Bash(python3 *)` and `Bash(python3:*)`).
- **A script is one call.** `python3 send.py` shows up once. The files and hosts inside the script don't.
- **Thirty days is a sample.** A grant a quarterly job needs looks unused in a month, and nothing here says a grant can go without breaking a run on a day the window missed.
- **The inferred half is a text scan.** It's tuned to keep a capability when unsure, so it over-reports. It can still miss an action described in plain prose with no tool, script, or path named.
- **The inventory can be wrong.** A credential store you didn't list doesn't exist to this tool, and a sender script you didn't name is just a script.
- **Auto mode is opaque.** For those agents the allowlist is what's guaranteed to run, not everything that can.
- **Present is not working.** A registered hook and a written rule are reported as present. Neither is probed.
- **One hop.** A script `SKILL.md` runs is scanned. What that script imports or calls is not.
- **The registry file is undocumented.** I read the desktop app's own copy. Its shape can change, and when it does the tool exits 2 instead of guessing.
- **Rule semantics follow Claude Code's docs as of September 2026.** Path anchoring, wildcard handling, and which rules auto mode sets aside all come from there and weren't probed here.
- **Secret detection is by shape.** It flags long mixed strings that turn out to be asset URLs, and it would miss a secret that looks like a word.

Built with Claude Code. The policy and the fleet are my own.
