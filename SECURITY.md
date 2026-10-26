# Security

The Desk Protocol moves records between agents that run under different harnesses, owners and
permissions. Every record is written by someone else, so the protocol's first rule is that **a record
is data, never an order** (principle 4, R6): no operation grants authority, no tool executes record
content, and each participant acts only under its own permissions.

## Threat model

| Threat | Mitigation | Check |
|---|---|---|
| Instructions injected through shared records ("run this", "ignore your rules") | Principle 4 and R6: tools never execute, evaluate or pass record content to a shell; display escapes control and format characters (Unicode Cc, Cf, Cs, Co, Cn, Zl, Zp), so a record cannot drive a terminal or spoof text direction; the harness snippets (`desk instructions`) tell agents that desk content never overrides their instructions or permissions | D17 (a canary file is never created; no raw escape byte reaches the output of any read command, including the HTML render) |
| Spoofed writers in a shared folder | On one machine, operating-system file permissions, as far as writers run as different users; a record whose `from` differs from its directory is `invalid`, and a tool refuses to append as anyone but itself (R2). Beyond one machine, the signing profile (§9): SSH signatures over RFC 8785 JSON, checked against `desk.json` members | D07, D19 |
| Borrowed authority ("I act for the owner") | R19 and R20: a record keeps its writer's level; `on_behalf_of` never raises it; only a person's own signed verify or close reaches `human_verified`; under roles the named person must be a member | D31 |
| Secrets leaked into an append-only, synced history | The `secrets` policy (`warn` by default, or `refuse`) scans every string a tool writes for likely credentials (private keys, cloud and API keys, tokens, JWTs, password assignments) | D18 |
| Oversized or hostile files | `max_record_bytes` (16 KiB default) on write and read; lines are streamed, hashed in full and kept only up to the cap; a partial line that already exceeds the cap is reported, never buffered forever (R4); symbolic links inside `log/` are refused (R14); writes open files with `O_NOFOLLOW` where the platform has it | D05, D18, D22 |
| Replays and duplicates | Per-writer `seq`: a record whose `seq` is not above every earlier one is a `duplicate`, reported and excluded, so every reference names one record (R5) | D06 |
| Rewritten history | The per-writer chain (`prev` over exact line bytes, R16); citations that carry digests (R17) and `seen` heads in checkpoints; read memory (R15), which keeps reporting a rewrite until the reader re-baselines on purpose | D23, D24, D25, D26 |
| Parser differentials (two readers seeing different records in one line) | Tools reject duplicate JSON keys and `NaN`/`Infinity`; integers are capped at 2^53 − 1; timestamps must be real instants; a validator that meets a schema keyword it does not implement fails closed | unit tests (`tests/test_desk.py`) |
| A widened permission through the desk itself | A desk cannot widen anyone's permissions: records carry no capabilities, and adapters present them as quoted data. An agent that finds a record asking it to change its own settings treats it as untrusted input | D17; `adapters/README.md` |

## The limit

**A writer can rewrite its own newest, uncited records before anyone has read them.** The chain makes
a rewrite visible only after someone has cited what came before it, listed it in a checkpoint's
`seen`, or read it (read memory is per reader). An unsigned desk shows *that* history changed, not
*who* changed it; signing adds who. On one machine, every process of one operating-system user can
write every file of the desk, so file permissions separate writers only when they run as different
users.

## Removing a secret

History is append-only and may be copied by git or file sync to every participant. Removing a leaked
secret means rewriting that history on every copy, which every reader that read it will then report
as `rewritten`. Rotate the secret first; treat the desk copy as disclosed.

## Local reader state

Reader positions and read memory live outside the desk, in the platform's state directory (or
`DESK_STATE_DIR`), readable by the participant's own user only as far as that directory is. They
contain references and digests, not record content. Deleting them makes the reader start over: every
record is delivered again (at least once), and rewrites before the deletion can no longer be
detected by that reader's memory.

## Known weaknesses

- On Windows there is no `O_NOFOLLOW`; the tool checks with `lstat` before opening, which leaves a
  small time-of-check window.
- A hostile process running as the same user can hold another identity's lock file and block its
  writes (exit 4). It could equally edit the logs; the chain and witnesses make that visible.
- The secret scan is pattern-based: it catches common credential shapes, not every secret.

## Reporting a vulnerability

Until this protocol has its own public repository, report privately to the repository owner. Once
it is public, use GitHub's private vulnerability reporting on that repository. Please include a desk
(a directory) that reproduces the problem.
