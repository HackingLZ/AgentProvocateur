# Profile research notes

Each profile imitates text that one tool itself emits around tool output. The
strings below were taken from a static read of each tool's source at the
listed commit. Whether a given model follows a framed payload is not
established by any of this; that is what the listeners measure.

| Profile | Tool and commit | What the tool does | What the profile sends |
|---------|-----------------|--------------------|------------------------|
| `pentestagent` | GH05TCREW/pentestagent `5bcf872` | Terminal results use a fixed `Command:` / `Exit Code:` / `--- stdout ---` / `--- stderr ---` layout (`tools/terminal/__init__.py`) | A forged second result whose stdout is the payload |
| `neurosploit` | CyberSecurityUP/NeuroSploit `3aa2beb` | Wraps some tool output in `<<<UNTRUSTED_TOOL_OUTPUT …>>>` … `<<<END_UNTRUSTED_TOOL_OUTPUT>>>` with no nonce (`crates/harness/src/taint.rs`) | The closing marker, the payload, then a new opening marker |
| `pentestgpt` | GreyDGL/PentestGPT `e8b1bb7` | When an evidence quote does not match exactly, stores everything between the first and last quoted line (`pentestgpt_agent/.../execution.py`) | The payload between `HTTP/1.1 200 OK` and `END RESPONSE` |
| `pentest-agent` | nbshenxm/pentest-agent `97ac5be` | Appends command output to the conversation as a user message (`agents/recon_agent.py`) | An operator-voiced note after an apparent end of output |
| `artex` | BaaRai/ARTEX `d235be8` | Wraps tool output in `<<<UNTRUSTED_OUTPUT <nonce>>>>` … `<<<END_UNTRUSTED_OUTPUT <nonce>>>>` with a per-call nonce; ends Bash output with `[exit code N]`; prefixes its own guard messages with `[ARTEX platform control, not target defense]` | `[exit code 0]`, a closer with a wrong nonce, the platform prefix and payload, then a new opener |

## Notes per tool

**ARTEX.** The nonce cannot be known by the target, so this profile does not
break the frame; it measures whether the model checks the nonce. ARTEX's
`traffic_get` tool keeps only the first 4,000 bytes of a response including
headers, and the page `<title>` is stored as an asset field, so the `HD`, `CK`
and `TI` carriers matter most here. ARTEX sends no identifying User-Agent by
default.

**NeuroSploit.** Its detector is a lowercase substring list, mostly English.
The built-in steering payloads avoid "ignore previous instructions" phrasing,
and the detector only adds a warning line.

**pentestagent.** Its browser tool returns the first 5,000 characters of
`document.body.innerText`, so only the `VI`, `TL` and `LI` carriers reach the
model on that path. Terminal output keeps the first and last 25,000 characters.

**PentestGPT.** Fallback evidence takes the last 4,000 characters of a
receipt, which is why the page ends on a visible copy of the payload.

**hexstrike-ai, pentest-ai-killer.** These have no model of their own; the
MCP client is the reader. Use `generic`. They return headers, cookies, storage
and console messages, covered by the `HD`, `CK`, `ST` and `CN` carriers.

## Adding a profile

Add a `_frame_<name>` function and a `Profile` entry in `profiles.py`, a test
in `tests/test_profiles.py`, and a row here naming the source file the framing
was read from.
