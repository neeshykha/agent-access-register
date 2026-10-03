# Acceptable-use policy for scheduled agents

**Status:** Adopted 2026-10-03 by the fleet owner, with edits to the 2026-10-02 draft. Rule AUP-05 (work systems) was considered and dropped, so the numbering skips it.

Plain rules for agents that run on a schedule with nobody watching. Each one is grouped under the NIST AI RMF function it serves most (Govern, Map, Measure, Manage); the mapping is loose and meant for orientation, not a compliance claim. A rule the register can test says so. A rule it can't test says that instead of pretending.

## Govern

**AUP-01. Every agent is registered, with a named model and an explicit permission mode**

An agent that runs on a schedule has a row in the scheduler, a model line in its instructions, and a permission mode somebody chose. Nothing runs on a default nobody picked.

*Checked by the register.*

**AUP-02. No agent runs with permission checks off**

No scheduled agent uses bypassPermissions. Unattended is exactly when the checks matter.

*Checked by the register.*

**AUP-03. Spending money is never delegated**

No agent buys, pays, books, or transfers. It can prepare a cart or a draft; a person places the order.

*Not machine-checked: nothing in permission config marks an action as a purchase.*

## Map

**AUP-04. An agent runs from its own project folder, and no credential store sits inside it**

The working directory is the boundary reads and edits are approved inside. Set to the home folder, that boundary is everything the account owns, credential files included. The same goes for any folder, or added directory, that holds a credential store.

*Checked by the register.*

## Measure

**AUP-06. No secrets in instructions or allow rules**

A token, key, or password never appears in a SKILL.md or a permission rule. Approving a one-off command bakes its literal text into the allowlist, so this gets checked, not assumed.

*Checked by the register.*

**AUP-07. The register is re-run when the fleet changes**

Run it when an agent is added or its instructions change, and after any credential incident. Each finding is fixed or excepted in writing, with a reason and a name.

*Not machine-checked: a habit, not a setting.*

## Manage

**AUP-08. Credential files are off the allowlist and on the deny list**

No allow rule names or covers a credential store, and every store has a deny rule. A deny rule stops the file tools and the shell readers the harness recognises; it does not stop a script that opens the file itself, which is why AUP-04 and AUP-09 exist.

*Checked by the register.*

**AUP-09. No wildcard interpreter in an allowlist**

A rule that allows an interpreter with a wildcard (python, bash, node, osascript) allows everything that interpreter can do. Allow the named script instead.

*Checked by the register.*

**AUP-10. Agents message only through the approved channels**

Outbound goes through the Discord helper, the ntfy helper, or a mail draft a person sends. Sending mail directly, texting, posting to any other service, or a raw HTTP request with a body needs a named exception.

*Checked by the register.*

**AUP-11. Publishing is a person's decision**

No agent pushes to a remote, opens or merges a pull request, or publishes a page unless it holds a named exception for that one destination.

*Checked by the register.*

**AUP-12. Deleting is a person's decision**

No agent deletes mail, records, or files in bulk. It can list what it would remove and wait for a yes. Removing one named scratch file it made itself is fine.

*Checked by the register.*

**AUP-13. Destructive shell commands pass a gate**

A PreToolUse hook on the shell tool is registered. The register confirms it's registered; it doesn't confirm it works, and a gate that has never been probed is an assumption.

*Checked by the register.*

---

Generated from `acceptable-use.json` by `access_register.py --render-policy`. Edit the JSON, not this file.
