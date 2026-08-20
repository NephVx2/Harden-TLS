# Harden-TLS_Win11


A small, focused PowerShell script that disables TLS 1.0 and TLS 1.1 at the Windows SCHANNEL level — nothing else. Read-before-write: a control that's already compliant is never rewritten, every run shows the exact current state before touching anything, and a JSON report tracks the score across runs.

> Scope, not scale. Four registry values, one job. TLS 1.2 and 1.3 are deliberately left alone — writing forcing keys for protocols Windows 11 already manages correctly would move further from Microsoft's own defaults, not closer to security.

---

## Table of contents

- [Overview](#overview)
- [In plain terms: what is TLS, and why disable old versions?](#in-plain-terms-what-is-tls-and-why-disable-old-versions)
- [Why only TLS 1.0 and 1.1](#why-only-tls-10-and-11)
- [Compatibility impact](#compatibility-impact)
- [How it works](#how-it-works)
- [Two modes: interactive menu and classic](#two-modes-interactive-menu-and-classic)
- [Elevation model](#elevation-model)
- [Prerequisites](#prerequisites)
- [First run](#first-run-step-by-step)
- [Menu reference](#menu-reference)
- [Command-line parameters](#command-line-parameters)
- [Files written by the script](#files-written-by-the-script)
- [Multi-machine deployment](#multi-machine-deployment)
- [Troubleshooting](#troubleshooting)

---

## Overview

`Harden-TLS_Win11_v1_2_1.ps1` writes four registry values under `HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols`, one pair (`Enabled=0`, `DisabledByDefault=1`) each for:

- TLS 1.0 — Client
- TLS 1.0 — Server
- TLS 1.1 — Client
- TLS 1.1 — Server

That's the entire scope of what this script does. It does not touch TLS 1.2, TLS 1.3, cipher suites, or anything else under SCHANNEL.

A **restart is required** for SCHANNEL to reload its configuration after a real change.

---

## In plain terms: what is TLS, and why disable old versions?

**TLS (Transport Layer Security)** is the encryption protocol that protects almost every connection your computer makes to the internet — it's the padlock icon in your browser, the reason your banking password isn't sent in plain text, the reason a stranger on the same Wi-Fi can't casually read your emails as they travel across the network. Every time you visit an HTTPS website, sign in somewhere, or sync an app to the cloud, TLS is quietly doing the encryption work in the background.

Like any protocol, TLS has had several versions over the years, each one fixing weaknesses found in the one before:

- **TLS 1.0** (1999) and **TLS 1.1** (2006) — old enough that known cryptographic weaknesses have been found in them over time (weak cipher support, vulnerability to specific downgrade and interception attacks). Neither is considered safe to rely on anymore.
- **TLS 1.2** (2008) and **TLS 1.3** (2018) — the current standards. Fast, well-vetted, and what virtually every modern website, app, and service uses today. This is what stays fully enabled and untouched by this script.

**So why does it matter if the old versions are just sitting there unused?** In normal daily use, it usually doesn't — your browser and most apps already prefer TLS 1.2/1.3 automatically, so TLS 1.0/1.1 rarely gets used even if it's technically still available. The risk is the word *available*: as long as Windows is willing to accept a TLS 1.0 or 1.1 connection, there's a narrow door left open — a **downgrade attack** (tricking a connection into falling back to an old, weaker protocol) or an old, poorly maintained server that only speaks TLS 1.0 could still succeed in negotiating a weak, crackable connection instead of being refused outright.

**What this script actually does:** it tells Windows, at the operating-system level, to flatly refuse TLS 1.0 and TLS 1.1 connections altogether — not "prefer something else," but "don't accept these at all." Closing that door means there's no fallback left to exploit, full stop. It's the digital equivalent of removing a rusty, easily-picked lock from a door you never use anyway, rather than just hoping nobody tries it.

---

## Why only TLS 1.0 and 1.1

TLS 1.0/1.1 deprecation has been a stable, uncontroversial recommendation since [RFC 8996](https://www.rfc-editor.org/rfc/rfc8996) (2021) formally deprecated both protocols across the industry. Forcing registry keys for TLS 1.2/1.3 as well was deliberately ruled out — Windows 11 already manages those correctly by default, and writing explicit override keys for them would only create a config that drifts further from Microsoft's own maintained defaults, for no real security gain.

---

## Compatibility impact

- **Affected:** any Windows application that uses the system TLS stack (WinHTTP, SChannel) directly.
- **Not affected:** modern browsers (Brave, Chrome, Firefox) — they implement TLS independently of the OS and ignore this setting entirely.
- **Worth checking first:** older network gear (NAS, printers, legacy VPN endpoints) that might still only support TLS 1.0/1.1. Unlikely in 2026, but worth a moment's thought before applying this on a machine that talks to older hardware.

---

## How it works

1. **Read first, always.** `Get-TlsControlState` performs a pure read of all four registry values — no decision, no write — and the result is shown in the console immediately, in both interactive and classic mode, before anything is touched.

2. **True idempotence.** A control already at `Enabled=0` / `DisabledByDefault=1` is **never rewritten** on a normal run. Earlier versions silently rewrote all four keys on every run via `New-ItemProperty -Force`, which masked the fact that most runs needed to do nothing at all — v1.2 made this explicit instead, and `-Force` is now the only way to force a rewrite of already-compliant controls (e.g. after restoring an older backup).

3. **The JSON report is always regenerated**, even on a run where literally nothing changed — this is deliberate, so the report and score history always reflect a current timestamp and state, not a stale file from whenever something last actually changed.

4. **Score.** `NbOk / NbTotal × 100`, cast explicitly to `[int]` (a documented fix — `[Math]::Round()` returns a `[double]`, which would otherwise serialize as `83.0` instead of `83` in the JSON output).

---

## Two modes: interactive menu and classic

- **No parameters at all** (e.g. double-clicking the script) → opens an **interactive menu**, in the same style as `Manage-ScriptSignatures.ps1` elsewhere in this suite: a persistent loop where you can check state, apply only what's missing, force a full re-application, or regenerate the JSON report without changing anything — without re-running the script from scratch each time.

- **Any explicit parameter** (`-DryRun`, `-Silent`, `-Force`, `-SelfTest`...) → runs once in **classic, non-interactive mode** and exits. This is what a scheduled task, or any script calling this one programmatically, should use.

- `-Menu` forces the interactive menu even if other parameters are also supplied (e.g. `-Menu -DryRun` opens a menu that simulates every action instead of applying it).

---

## Elevation model

Unlike some scripts in this suite, this one does **not** require administrator rights just to start (no `#Requires -RunAsAdministrator`). Elevation is checked dynamically, only right before an actual registry write:

- Reading current state, `-DryRun`, and generating the JSON report all work **without** administrator rights.
- A real write still requires elevation — if it's missing, the script prints a clear message and still produces a JSON report reflecting the actual (unmodified) state, rather than failing outright or silently doing nothing.

---

## Prerequisites

- Windows 10 or 11 (SCHANNEL protocol keys are a Windows-wide mechanism, not Windows 11-specific, though this script's compatibility notes are written with Windows 11 in mind).
- PowerShell 5.1 (built into Windows) or PowerShell 7+.
- Administrator rights **only** for an actual write — see [Elevation model](#elevation-model) above.
- If the script is digitally signed (recommended in environments using `-ExecutionPolicy AllSigned`/`RemoteSigned`): the signing certificate must be trusted on the target machine.

---

## First run (step by step)

1. Copy `Harden-TLS_Win11_v1_2_1.ps1` to the target machine.

2. Run the self-test first — pure logic, no registry access at all, no admin rights needed:

   ```powershell
   .\Harden-TLS_Win11_v1_2_1.ps1 -SelfTest
   ```

   Runs 13 assertions covering the score-history logic (including a specific regression test for a `$null`-pollution bug fixed in v1.2.1), the hardening decision logic against fake in-memory states (already-compliant, non-compliant, missing key, non-elevated), and the explicit `[int]` score cast. Exit code `0` = all passed, `1` = at least one failure.

3. Check the current state without changing anything and without needing elevation:

   ```powershell
   .\Harden-TLS_Win11_v1_2_1.ps1 -DryRun
   ```

   Shows exactly what's currently set for all four controls, and what would be written if you ran it for real.

4. Apply the hardening for real, from an elevated PowerShell session:

   ```powershell
   .\Harden-TLS_Win11_v1_2_1.ps1
   ```

   With no parameters, this opens the interactive menu instead (see [Two modes](#two-modes-interactive-menu-and-classic)) — use option `[2]` from there, or pass any explicit parameter (e.g. add `-Silent`) to skip straight to classic mode.

5. **Restart the machine** — SCHANNEL only reloads this configuration at boot.

6. Verify the effect: if you also use `Check-Security_Win11` from this same suite, re-run it after the restart — the 4 TLS 1.0/1.1 controls should flip from `WARN` to `OK`. The 2 TLS 1.2 controls will still show `WARN` in that script (a missing registry key there means "Windows default," which is fine on a recent Windows 11 build, not a real gap).

---

## Menu reference

Opens automatically when the script is run with no parameters:

| Option | Action |
|---|---|
| `[1]` | Show detailed current state (read-only) |
| `[2]` | Apply hardening — only what's currently non-compliant |
| `[3]` | Force a full re-application, even for controls already compliant |
| `[4]` | Generate/refresh the JSON report without changing anything |
| `[D]` | Toggle DryRun mode for the menu's own actions |
| `[Q]` | Quit |

---

## Command-line parameters

| Parameter | Description |
|---|---|
| `-DryRun` | Shows the registry keys that would be written, without applying them. |
| `-Force` | Re-applies all four controls even if already compliant (e.g. useful after restoring an older system backup). |
| `-Menu` | Forces the interactive menu even if other parameters are also supplied. |
| `-Silent` | Suppresses the final "press ENTER" pause (classic mode only) — for scheduled-task use. |
| `-RetainReportsDays <n>` | Purges `Rapport_TLS_*.json` files older than N days (default: `30`). `Baseline_TLS.json` is never purged. |
| `-SelfTest` | Runs the 13-assertion internal test suite (pure logic, no registry access) and exits. |

Any explicit parameter switches the script to classic non-interactive mode — see [Two modes](#two-modes-interactive-menu-and-classic).

**Examples:**

```powershell
.\Harden-TLS_Win11_v1_2_1.ps1 -SelfTest
.\Harden-TLS_Win11_v1_2_1.ps1 -DryRun
.\Harden-TLS_Win11_v1_2_1.ps1 -Force -Silent
.\Harden-TLS_Win11_v1_2_1.ps1 -RetainReportsDays 60
```

---

## Files written by the script

| File | Content |
|---|---|
| `%USERPROFILE%\Desktop\Rapports_Maintenance\TLS\Baseline_TLS.json` | Last run's score, timestamp, and a rolling history of up to 30 scores — never purged |
| `%USERPROFILE%\Desktop\Rapports_Maintenance\TLS\Rapport_TLS_<timestamp>.json` | Per-run detail: one entry per control (category, element, value, status) — purged automatically after `-RetainReportsDays` (default 30) |

Same reports root (`Desktop\Rapports_Maintenance\TLS`) and naming convention (`Baseline_TLS.json` for the running history, `Rapport_TLS_*.json` per run) used across the rest of this author's maintenance scripts, kept consistent purely so the files are predictable if you use more than one of them — no other script or tool is required to read them.

---

## Multi-machine deployment

1. **Distribute** the `.ps1` file to each target machine.

2. **Trust the signing certificate** if a strict execution policy is enforced (`-ExecutionPolicy AllSigned`/`RemoteSigned`).

3. **Run `-SelfTest` first** — pure logic, no registry access, no admin rights needed, safe on any machine before deciding to proceed.

4. **Schedule via Windows Task Scheduler** with an explicit parameter (any one works — even just `-Silent`) so it runs in classic mode rather than opening the interactive menu unattended:

   | Field | Value |
   |---|---|
   | Program/script | `pwsh.exe` (or `powershell.exe`) |
   | Arguments | `-NoProfile -ExecutionPolicy Bypass -File "C:\Scripts\Security\Harden-TLS_Win11_v1_2_1.ps1" -Silent` |
   | Run with highest privileges | Yes (required for the actual registry write; without it, the task still runs and produces a JSON report, just without applying anything) |

5. Because most machines only need this applied **once** (idempotence means subsequent runs do nothing), a one-time provisioning step is arguably more natural here than a recurring schedule — a recurring `-SelfTest`-style verification run is more useful than a recurring hardening run, since there's nothing left to reharden once it's compliant.

6. Reports are written to the profile of the user running the script — local to each machine. Aggregating results across a fleet is left to whatever tooling you choose to build on top, this script only produces the per-machine JSON.

7. **Don't forget the restart.** A scheduled task that applies this and exits doesn't itself trigger a reboot — build that into your deployment sequence separately if you need the change to take effect immediately rather than at the machine's next natural restart.

---

## Troubleshooting

<details>
<summary><strong>The script says a control was applied, but Check-Security_Win11 still shows WARN</strong></summary>

Restart the machine — SCHANNEL only reloads its protocol configuration at boot, not live. Re-run the security audit after rebooting.
</details>

<details>
<summary><strong>Running without admin rights doesn't apply anything</strong></summary>

Expected — see [Elevation model](#elevation-model). Reading state, `-DryRun`, and the JSON report all work without elevation, but an actual registry write needs it. Re-run from an elevated PowerShell session (or an elevated scheduled task).
</details>

<details>
<summary><strong>-Force didn't seem to change anything</strong></summary>

If all four controls were already at `Enabled=0` / `DisabledByDefault=1`, `-Force` rewrites them to the exact same values — there's nothing visibly different to see, but the JSON report will show `Applied` counts instead of `Skipped` counts for that run, confirming the rewrite happened.
</details>

<details>
<summary><strong>A legacy device (NAS, printer, old VPN) stopped connecting after this ran</strong></summary>

See [Compatibility impact](#compatibility-impact) — this is the one realistic side effect of disabling TLS 1.0/1.1 system-wide. If reverting is needed, delete the `Enabled`/`DisabledByDefault` values under the relevant `SCHANNEL\Protocols\TLS 1.0` or `TLS 1.1` key(s), or set `Enabled=1`/`DisabledByDefault=0`, then restart.
</details>

<details>
<summary><strong>-SelfTest reports a FAIL</strong></summary>

All 13 assertions are pure logic checks (score-history array handling, the hardening decision function against fake states, the `[int]` score cast) — none of them touch the real registry, so a FAIL points at the script's internal logic, not at the machine's actual TLS configuration. Read the assertion name for the specific issue.
</details>

---

<sub>Harden-TLS_Win11 — 4 registry values, read-before-write idempotence, JSON score history, 13-assertion self-test.</sub>
