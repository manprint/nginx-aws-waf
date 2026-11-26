# Plan 001 — execution protocol (read once; live state is STATE.md)

1. **Start.** Read STATE.md §1.
   - If ownership is active and you are not its writer, an explicit user invocation counts as a resume request. Take over only if STATE.md and a fresh snapshot (step 3) are unchanged between the first read and the takeover write. Record the previous and new writer, the time and the reason. Otherwise ask.
   - The header's repo path is a locator. When the checkout moved, confirm the branch and baseline exist here, update the path, and go on.
   - Only Execute sets or replaces the saved scope. Execute verify, Task, Bug and Verify run their own units beside it and never change the §3 defaults; Task, Bug and Verify also keep the roster.
   - Resume recovers OPEN or pending work first, then continues the saved scope. It never runs a TODO unit named by ID or work outside the scope.
2. **Recover.**
   - Compare HEAD and a fresh snapshot with the unit base, and preserve unrelated changes.
   - An unresolved `Last closure` reference (step 7) is a pending closure; finish it first.
   - Resume OPEN work at its first unverified step. Inspect the diff even if §6 is stale.
   - A Verify of unfinished work saves §1 and §6 to §12 first; there is no nested suspension.
3. **Open before editing.** Set in §1 the unit, attempt, OPEN, step S1, and assigned → actual agent. Mark the sub-phase and phase IN_PROGRESS. Base = HEAD + snapshot tree:
   ```bash
   idx="$(git rev-parse --git-dir)/pev-snapshot.$$.index"
   { GIT_INDEX_FILE="$idx" git read-tree HEAD 2>/dev/null ||
     GIT_INDEX_FILE="$idx" git read-tree --empty; } &&
   GIT_INDEX_FILE="$idx" git add -A && GIT_INDEX_FILE="$idx" git write-tree
   rm -f "$idx"
   ```
   Compare later with `git diff --stat <base-tree> <tree>`. Checkpoint §6 only before delegation, risky or long work, a blocker, or a likely pause.
4. **Implement** the phase file's steps; locate symbols, not line numbers.
   - Missing or contradictory design, or two failed fixes of one issue, go to agent-1. agent-1 may revise technical steps within the approved scope. Never weaken tests.
   - Run the unit's focused checks and confirm the tests actually executed.
   - The assigned reviewer does the required review; label it `self-review` when the reviewer is the implementer.
5. **Autonomy loop.** Continue to the next eligible unit in the same turn. Stop only at:
   - scope complete;
   - with autonomy false, after a phase closure P<N> (Task/Bug: at the approval gate);
   - a real blocker needing unavailable capability or authority (BLOCKED, with question and owner);
   - a safety stop (a possibly live writer, or unowned changes a commit would capture);
   - a user stop, handoff or deadline;
   - the host ending the session.

   Never stop for a closed sub-phase, a commit, context size, a substitutable agent, or to report progress. Never ask the user to type resume inside the scope.

   With autonomy true, never ask the user anything. agent-1 weighs the options against the goal, picks the one it recommends, and records it (`D<n>` `autonomous`, or history.md notes) with alternatives, rationale, risk and reversal. An autonomous decision is never a way to push, deploy, use unauthorized network or credentials, upgrade dependencies, destroy data or weaken tests. Permission modes never change the scope or the stop latch.
6. **Roster.** Run units assigned to your position or a higher-numbered one, and record substitutions. Reviews and plan revisions belong to agent-1. A model outside the roster coordinates but implements nothing.
7. **Close.** Append the unit's evidence to history.md (`cat >> history.md`). Update §1, §11 and the next eligible unit, and compact STATE.md (below). With commits enabled (autonomy true, or WIP on):
   - Record `Last closure: unit:<ID>:<attempt>`.
   - Stage only owned changes (`git add -A -- <paths>`), plus STATE.md and history.md. For shared paths apply only the unit's hunks: `git diff --binary <base-tree> <closure-tree> -- <path>` → `git reset -q <base-HEAD> -- <path>` → `git apply --cached`, with a `--3way` fallback; else restore and report a blocker.
   - Commit with the mandatory subject. `001` is the plan id, written identically in every subject, trailer and this file's header:
     - `sub-phase(001/<N.M>): sub-phase <N.M> of phase <N> complete — <title>`
     - `phase(001/P<N>): PHASE <N> COMPLETE — <title>; gates and review passed`
     - `plan(001): PLAN 001 COMPLETE — nginx AWS WAF; 7 phases, final gates passed`
     - `task(001/T-A<NNN>)`, `bug(001/B-A<NNN>)`, `correction(001/V<NNN>-C<n>)`, `verify(001/V<NNN>)`, `wip(001/<unit>)`, `handoff(request-by-user)`
   - End the message with a trailer block `PEV-Plan: 001`, `PEV-Unit`, `PEV-Attempt`, `PEV-Result: complete|wip`, beside any Co-Authored-By.
   - Hooks run; never `--no-verify`; never push or switch branches.
   - Resolve the reference by exact trailer values in `git log --format='%H%x09%(trailers:key=PEV-Unit,valueonly)' HEAD` (and PEV-Plan, PEV-Attempt, PEV-Result). Zero matches = pending closure.
   - With commits disabled, add a §4 row `uncommitted <base-tree>..<closure-tree>`.
8. **Phase closure P<N>.** Requires: all sub-phases DONE or SKIPPED with a reason, the README obligation met, the full phase gates passing, and agent-1's approval.
   - P<N> never edits code or tests.
   - A blocked gate keeps it OPEN/BLOCKED.
   - A failure closes the attempt `failed` (commit none) and reopens the responsible unit (attempt + 1) or revises the plan; then P<N> reruns.
   - After the last P<N>, the plan closure PLAN runs G-FINAL and the reference scenario, then agent-1's final review, marks the plan COMPLETE and commits, with no stop between them.
9. **Compaction.** STATE.md holds only the present:
   - §4 only unsettled rows;
   - §5/§6 only the OPEN unit;
   - §7 the latest result per gate of the open phase;
   - §8–§10 only what pending work needs;
   - §11 expands a phase from its phase file when its first unit opens and collapses it to one row at P<N> DONE.

   A correction that reopens a DONE phase re-expands it: every sub-phase DONE with its attempt and reference from the Git trailers, plus the correction rows. Detail goes to history.md first. This file belongs to `Format: pev-state 2`; never write a STATE.md of a newer format.
10. **Handoff** (`handoff`, or a `--deadline`): always honored, whatever the autonomy.
    - A deadline is binding: the report is written by that time. Keep a reserve of at least 10 minutes, start nothing that would cross the cutoff (deadline minus reserve), and bound long commands with `timeout`.
    - Before the cutoff a deadline is no stop, also when it arrives while awaiting a worker: record the §1 deadline, keep the worker running, send it the cutoff, arm a host wake-up at the cutoff, and continue. A completion notice before the cutoff continues the loop.
    - Only a session with no run in progress (its invocation already ended with its final report, nothing it started still pending) hands off at once.
    - At the cutoff or on `handoff`: set §1 `Stop latch: HANDOFF <trigger> <time>` and start nothing new. Close the OPEN unit only if that takes about 10 minutes and still leaves time for the handoff before the deadline; else stop at a step boundary. Save §6 with the commands not run; result HANDOFF; release ownership.
    - Code work gets one local handoff commit even with commits disabled. It holds the owned changes of the OPEN or pending unit and of every §4 `uncommitted` unit (one patch per unit), plus STATE.md and history.md. Subject: `handoff(request-by-user): 001/<unit> stopped <point>`. Trailers as above with `PEV-Result: wip`, `PEV-Handoff: user|deadline`, `PEV-Includes: <id>:<attempt>, …`. Those rows become `handoff:<id>:<attempt>` with their trees. Never amended.
    - Report the resume command, then stop: no tool call after the report, whatever the autonomy or permission mode. Only a new explicit user invocation clears the latch.
11. **Task/Bug.** agent-1 writes or validates the mini-plan (a Bug's with its root cause) before any code. With autonomy false, stop once with the entry PROPOSED until a user reply or `resume 001 <entry-id>` approves it.
12. **Run end only.** Cancel any deadline wake-up, release ownership, then end the report with `Next`:
    - Mode: the run's mode and every effective setting with its source (autonomy, WIP, executor power, deadline, roster, style).
    - Continue: one exact `/plan-execute-verify` command and the settings it runs with.
    - Stop: `/plan-execute-verify handoff` when uncommitted code work or a pending closure remains; else nothing to save.

    Suggest both; never run them.

## Plan-specific conventions
- **Go test names:** they start with the test ID without the dash. `T-R1` → `func TestR1_…`; `T-CAT1` → `TestCAT1_…`. A unit gate runs `go test -run '<regex of its IDs>' -v` and asserts that the count of `--- PASS` lines for those prefixes equals the number of IDs. `no tests to run` fails the gate.
- **Shell e2e scripts:** they print `PASS <id>` / `FAIL <id>` per check and exit non-zero on any FAIL.
- **Lab runtime artefacts** (`.run/`, `.run2/`, `build/`) are git-ignored and never staged.
- **Secrets** (`secrets.env`, `*.key`, `*.pem`, `pki/private/`, `pki/tokens.json`, `apprise-urls.txt` outside `lab/config/`) are never staged (G-SEC).
