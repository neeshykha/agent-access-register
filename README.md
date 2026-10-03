# agent-access-register

A script I run on demand that answers one question about my scheduled Claude Code agents: **what is each one allowed to touch?** It reads the permission config they run under, reads each agent's instructions, and diffs both against a written acceptable-use policy.

**[See the demo page →](https://neeshykha.github.io/agent-access-register/)** (a synthetic fleet, built on disk by `demo/build_demo.py`)

This is the third of a set. [skill-regression-harness](https://github.com/neeshykha/skill-regression-harness) asks whether the right agent fires. [scheduled-agent-detector](https://github.com/neeshykha/scheduled-agent-detector) asks whether it did its job. This one asks what it's allowed to do.

## Why this exists

I run a few dozen agents on a schedule with nobody watching: a job pipeline, health and garden check-ins, digests, a weekly fleet review. In September I found a live bot token baked into an allowlist. Approving a one-off command had saved its literal text, secret included, as a permanent rule. I cleaned that up by hand and then couldn't answer the obvious follow-up: which of these agents can read that token file at all?

I assumed the answer lived in config, one row per agent. It doesn't. That turned out to be the finding.

## What the first run against my real fleet found

1. **Permissions aren't per-agent.** Every agent inherits one shared allowlist. There are zero deny rules and zero ask rules in any settings file. The "declared" column reads nearly the same on every row, so most of what tells two agents apart has to be inferred from their instructions.
2. **The working directory is the real boundary, and mine was the whole home folder.** 51 of 55 agents run from `~`. Reads inside the working directory need no approval in any permission mode, so every credential file under home is in reach of every one of them, and no rule anywhere says so.
3. **In auto mode the allowlist is a floor, not a ceiling.** 50 agents run in auto, where anything the allowlist doesn't name goes to a classifier. The register can't read that classifier, and the page says so instead of pretending the allowlist is the limit.
4. **The cleanup missed a place.** There's a per-agent layer I didn't know about when I pitched this: every "always allow" click is saved against the routine in the scheduler's registry. Seven of those saved approvals still carried what look like the same token and keys I thought I'd removed three weeks earlier. The register reports shape and position, never the value, so "look like" is as far as it goes. I'd cleaned the settings file and never looked there.
5. **Five agents had no permission mode set**, and five had no model line. All ten were created after the last time I set modes in bulk.

None of that needed a clever scan. It needed somebody to read four files side by side.

## What it reads, and the two labels

| Source | What it gives | Label |
| --- | --- | --- |
| `settings.json`, plus each working directory's `.claude/settings*.json` | allow, deny, and ask rules; hooks | **declared** |
| The scheduler registry | each agent's permission mode, working directory, and saved approvals | **declared** |
| Each agent's `SKILL.md` | what it's told to read, write, send, and run | **inferred** |
| Scripts and skills that `SKILL.md` names | one hop, no further | **inferred** |

**Declared** means it's in permission config. **Inferred** means it was read out of free text and can be wrong in both directions. Every row on the page carries one label or the other, and the two never share a findings list: "config allows what policy forbids" is declared-only, and "instructions ask for what policy forbids" sits below it.

Credential stores are checked for existence and for which rules reach them. None is ever opened.

## Three rules the code holds to

- **Unknown stays unknown.** An unreadable settings file is not an empty one. A missing `SKILL.md` is not a clean agent. A registry in a shape the tool doesn't recognize is not a fleet of zero. Each of those exits 2 and puts a banner on the page.
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

`python3 access_register.py --render-policy policy/acceptable-use.json` rewrites the markdown from the JSON. Edit the JSON.

## Tests

```
python3 tests/test_register.py
```

84 tests, all against real files in a throwaway home folder. Most of what's under test is how the register reads files it can't fully trust, and mocking the filesystem would only test the mock.

## What a second model's review caught

None of this can be checked by looking, so I had a stronger model review the parsing and diff logic before I trusted any of it. It found sixteen defects. Five mattered:

- **Masking let real shapes through.** A token with a `/` in it, a `password=` value with no digits, and anything under sixteen characters all printed verbatim.
- **Negation erred in the dangerous direction.** "Don't forget to post to Discord" read as a prohibition, which turned a sending agent into a non-sender.
- **A saved approval covering a credential file raised nothing**, while the identical rule in a settings file raised two findings.
- **A working directory below home that held a credential store raised nothing.**
- **A registry in an unfamiliar shape produced "0 agents, clean, exit 0."**

Each has a test now. Then the live run found one the review hadn't: a saved approval holding the first few characters of an API key followed by a wildcard, short enough to slip under the masking floor. A value assigned to a secret-sounding name is now masked whatever its length.

The masking and negation logic passed their first tests and were wrong. A check that has only been run against the cases its author thought of isn't verified.

## Honest limits

- **It reports configured access, not observed behavior.** Nothing here says what any agent has done.
- **The inferred half is a text scan.** It's tuned to keep a capability when unsure, so it over-reports. It can still miss an action described in plain prose with no tool, script, or path named.
- **The inventory can be wrong.** A credential store you didn't list doesn't exist to this tool, and a sender script you didn't name is just a script.
- **Auto mode is opaque.** For those agents the allowlist is what's guaranteed to run, not everything that can.
- **Present is not working.** A registered hook and a written rule are reported as present. Neither is probed.
- **One hop.** A script `SKILL.md` runs is scanned. What that script imports or calls is not.
- **The registry file is undocumented.** I read the desktop app's own copy. Its shape can change, and when it does the tool exits 2 instead of guessing.
- **Rule semantics follow Claude Code's docs as of September 2026.** Path anchoring, wildcard handling, and which rules auto mode sets aside all come from there and weren't probed here.
- **Secret detection is by shape.** It flags long mixed strings that turn out to be asset URLs, and it would miss a secret that looks like a word.

Built with Claude Code. The policy and the fleet are my own.
