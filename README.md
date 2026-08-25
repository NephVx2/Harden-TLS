# Harden-TLS

**Idempotent TLS/SCHANNEL hardening for Windows 11 — with plain-English explanations, visual reports, and one-command rollback.**

[🇫🇷 Lire en français](README.fr.md)

> Disables outdated, insecure encryption technology built into Windows so that nothing on your PC — browsers excluded, they manage this themselves — can accidentally use it. Safe to run more than once. Safe to undo.

---

## Table of contents

- [Why this script exists](#why-this-script-exists)
- [What this script actually does](#what-this-script-actually-does)
- [Background: what is TLS, and why does any of this matter?](#background-what-is-tls-and-why-does-any-of-this-matter)
  - [TLS in one paragraph](#tls-in-one-paragraph)
  - [Protocols (TLS 1.0 / 1.1 / 1.2 / 1.3)](#protocols-tls-10--11--12--13)
  - [Cipher suites (encryption)](#cipher-suites-encryption)
  - [Hashing algorithms](#hashing-algorithms)
  - [Diffie-Hellman key exchange](#diffie-hellman-key-exchange)
  - [.NET Framework "Strong Crypto"](#net-framework-strong-crypto)
- [What this script will NOT touch](#what-this-script-will-not-touch)
- [Requirements](#requirements)
- [Getting started — your first run](#getting-started--your-first-run)
- [Every option, explained](#every-option-explained)
- [The interactive menu](#the-interactive-menu)
- [Undoing everything (-Undo)](#undoing-everything--undo)
- [Reports (JSON & HTML)](#reports-json--html)
- [Group Policy / domain-joined machines](#group-policy--domain-joined-machines)
- [Frequently asked questions](#frequently-asked-questions)
- [Disclaimer](#disclaimer)

---

## Why this script exists

Windows ships with support for old, weak versions of the technology that encrypts your internet traffic — because turning it off by default would break some very old hardware and software still in use. That backward compatibility is a reasonable default for Microsoft, but it also means every Windows 11 PC, right out of the box, is still *capable* of using encryption that is considered broken by today's standards.

In practice, nothing forces an attacker to use the strong, modern encryption your PC supports — if the weak, old options are still switched on, an attacker on the same network (a coffee shop Wi-Fi, a compromised router, etc.) can sometimes trick a connection into "downgrading" to the weakest option both sides technically support, and then break it. This is a real, named category of attack (it's why protocols like SSL 3.0 and RC4 encryption were formally banned in internet standards years ago).

**Harden-TLS turns off only the parts that are genuinely obsolete**, and leaves everything modern exactly as Windows configured it. It's the same hardening that security benchmarks (like the CIS Benchmark for Windows) recommend, packaged as a script you can run, verify, export a report from, and undo — safely, and repeatedly, across as many machines as you like.

## What this script actually does

Harden-TLS makes five categories of change, all under `HKLM` (machine-wide registry, not tied to any one user account) so the result is identical no matter who logs in:

| Category | What's disabled | What's left alone |
|---|---|---|
| **Protocols** | TLS 1.0, TLS 1.1 (Client + Server) | TLS 1.2, TLS 1.3 |
| **Cipher suites** | RC4 (all key lengths), DES 56/56, RC2 (all key lengths), Triple DES 168, NULL | AES 128/256, and modern GCM / ChaCha20 suites |
| **Hashing** | MD5, SHA-1 | SHA-256, SHA-384, SHA-512 |
| **Diffie-Hellman** | Any key exchange shorter than 2048 bits is raised to 2048 bits | Already-compliant machines are left untouched |
| **.NET Framework** | Enables "Strong Crypto" (`SchUseStrongCrypto`, `SystemDefaultTlsVersions`) on every .NET Framework install found on the machine | Never invents a .NET install that isn't there |

On top of that, the script:

- **Checks before it writes.** Every single control is read first; if it's already compliant, it is left completely alone — nothing gets needlessly rewritten on every run.
- **Detects Group Policy conflicts** (read-only) — useful on domain-joined machines, where a policy could silently redefine these same settings on the next `gpupdate`.
- **Can undo itself** (`-Undo`) — removes exactly what it created, and nothing else, returning the machine to Windows defaults.
- **Supports `-WhatIf`/`-DryRun`** — see exactly what would change before anything is written.
- **Exports a JSON report** every run, and optionally a self-contained, dark-themed **HTML report** you can open in any browser.
- **Never touches your web browser.** Chrome, Firefox, Brave, Edge, etc. manage their own encryption independently of Windows and are unaffected.

## Background: what is TLS, and why does any of this matter?

This section assumes no prior security background. If you already know this material, skip to [Getting started](#getting-started--your-first-run).

### TLS in one paragraph

**TLS (Transport Layer Security)** is the technology that puts the padlock icon in your browser's address bar. Every time your computer talks to a website, an email server, a company VPN, or almost anything else over the internet, TLS is what scrambles that conversation so that anyone intercepting the traffic in between — your ISP, someone on the same public Wi-Fi, an attacker who's compromised a router — sees only meaningless noise instead of your passwords, messages, or banking details. TLS is not one single thing; it's a *negotiation* between your computer and the other side, where they agree on **which version of the protocol**, **which encryption method**, and **which hashing method** to use for that specific conversation. This script narrows down the menu of options Windows is willing to offer during that negotiation, so only the modern, safe choices remain on the table.

### Protocols (TLS 1.0 / 1.1 / 1.2 / 1.3)

Think of the "protocol version" as the edition of the TLS rulebook both sides agree to follow.

- **TLS 1.0** (1999) and **TLS 1.1** (2006) are old enough that they predate most of the attacks we now know how to carry out against them. Both were **officially deprecated** by the standards body that governs the internet (the IETF, in RFC 8996, published in 2021) and by every major browser vendor. They are the digital equivalent of a lock that a hardware store stopped recommending twenty years ago — it still *works*, but it's a known weak point.
- **TLS 1.2** (2008) is still considered secure today when configured correctly, and remains extremely widely supported.
- **TLS 1.3** (2018) is the current standard: faster, and it removes entire categories of weak options (bad cipher suites, weak hashes) from the negotiation table by design.

**This script disables TLS 1.0 and 1.1 only.** TLS 1.2 and 1.3 are left exactly as Windows configures them by default.

### Cipher suites (encryption)

Once both sides agree on a protocol version, they need to agree on **how the actual data gets encrypted**. That choice is called a "cipher" (or "cipher suite" when it bundles several related choices together).

- **RC4**: a stream cipher that was extremely popular for over a decade, until researchers demonstrated practical attacks that let an eavesdropper recover parts of the traffic. It's formally banned from use in TLS by internet standards (RFC 7465, 2015).
- **DES / Triple DES ("3DES")**: DES (1977) uses a key so short by modern standards that dedicated hardware can brute-force it in hours; 3DES was a patch that runs DES three times to compensate, but it's slow and has its own well-documented weaknesses (the "Sweet32" attack). Both are considered obsolete by NIST (the US National Institute of Standards and Technology) and Microsoft alike.
- **RC2**: another dated cipher from the same era as DES, with the same category of weaknesses.
- **NULL cipher**: this is the "cipher" that means *no encryption at all* — the connection is still wrapped in TLS's format, but the contents aren't scrambled. It exists for testing purposes and should never be reachable in production.

**This script disables all of the above.** It never touches **AES** (128 or 256-bit) or modern suites using **GCM** or **ChaCha20** — those are the encryption methods every current security guidance recommends, and Windows will continue offering them exactly as before.

### Hashing algorithms

A **hash function** takes any amount of data and produces a short, fixed-size fingerprint of it. In TLS, hashes are used to make sure the data arriving is exactly the data that was sent — that nothing was altered in transit (a role called "integrity").

- **MD5** (1992) and **SHA-1** (1995) are both hash functions that researchers have since demonstrated can be deliberately "broken" — an attacker can construct two different pieces of data that produce the *same* fingerprint, defeating the whole point of the check. Both have been formally retired from TLS use (MD5 in RFC 6151, SHA-1 use in TLS certificates phased out by every major browser since 2017).

**This script disables MD5 and SHA-1.** SHA-256, SHA-384 and SHA-512 — the modern, currently-unbroken members of the same family — are left completely untouched.

### Diffie-Hellman key exchange

Before your computer and a server can start encrypting data with a shared secret, they first need to agree on *what that secret is* — without ever transmitting the secret itself in a way an eavesdropper could capture. **Diffie-Hellman (DH)** is the classic mathematical trick (published in 1976, and still the conceptual basis of most modern key exchange) that makes this possible: both sides can arrive at the same secret number through public back-and-forth math, even though anyone watching the exchange can't reconstruct that number themselves.

The security of that trick depends entirely on the size of the numbers involved — this is described as the **key length**, measured in bits. A DH exchange using a **key shorter than 2048 bits** can, with today's computing power (and certainly with a well-resourced attacker, as demonstrated by the 2015 "Logjam" research), be broken. **2048 bits has been Microsoft's recommended minimum since 2016.**

**This script raises any DH key exchange configuration below 2048 bits up to 2048 bits.** It never lowers a setting that's already stronger.

### .NET Framework "Strong Crypto"

This last part is a bit different — it's not about the network negotiation itself, but about making sure Windows applications actually *use* the secure settings above.

Many Windows applications are built on **.NET Framework**, Microsoft's application platform. For historical compatibility reasons, older .NET Framework versions can be configured to manage their *own* list of allowed TLS versions and ciphers — completely independently of the SCHANNEL settings this script just hardened. In practice, that means an old .NET application (or even a Windows component like WinRM) could keep negotiating with TLS 1.0 or weak ciphers even after this script disables them at the operating-system level, simply because that particular app never asked the operating system what to use.

**"Strong Crypto" is a .NET Framework setting** (`SchUseStrongCrypto` + `SystemDefaultTlsVersions`, both registry DWORDs) that tells every .NET application on the machine: *stop managing your own list — just use whatever Windows itself is configured to allow.* This script enables it on every .NET Framework installation it finds on your machine (both the 32-bit "Wow6432Node" and native 64-bit locations, if present) — it never creates a .NET installation that doesn't already exist.

Without this step, hardening SCHANNEL alone leaves a real, documented blind spot for .NET-based software.

## What this script will NOT touch

- **TLS 1.2 and TLS 1.3** — left exactly as Windows configures them.
- **AES encryption**, and modern **GCM / ChaCha20** cipher suites.
- **SHA-256, SHA-384, SHA-512** hashing.
- **Web browsers** (Chrome, Firefox, Brave, Edge...) — they all manage TLS independently of Windows and are completely unaffected by this script.
- **Anything already compliant** — every control is read before it's written; already-hardened settings are left alone rather than rewritten.
- **Group Policy** — the script only *reads* GPO-related registry keys to warn you about conflicts; it never modifies a policy.

## Requirements

- **Windows 11** (the script targets SCHANNEL registry paths present on Windows 11; it has not been validated on other Windows versions).
- **PowerShell 5.1 or later** (included by default in Windows 11).
- **Administrator privileges** to actually apply changes. Without them, the script still runs and shows you the current state and what it *would* change (read-only) — it simply can't write to the registry.
- **A restart** is required afterward for SCHANNEL (protocols/ciphers/hashes/Diffie-Hellman) to reload its configuration. The .NET Strong Crypto change technically only needs the affected applications restarted, but a full restart is the simplest way to guarantee a clean state, especially across multiple machines.

## Getting started — your first run

1. **Download** `Harden-TLS.ps1` from this repository.
2. **Right-click the file → "Run with PowerShell"**, or open a PowerShell window **as Administrator** and run it from there. Running without Administrator rights still works, but only in read-only mode.
3. With no options at all, the script opens straight into its **interactive menu** — you don't need to memorize any command-line flags to get started. From there you can:
   - View the current state of every control (nothing is changed).
   - Preview exactly what would change with a dry run.
   - Apply the hardening for real.
   - Export a report.
4. **Restart the computer** once you're done, so SCHANNEL picks up the new settings.
5. *(Optional but recommended)* A few days later, or after any Windows Update, re-run the script — it will show everything as already compliant and make no changes, confirming nothing reset your hardening.

If you'd rather skip the menu and drive everything from the command line, see the options below.

## Every option, explained

| Option | What it does |
|---|---|
| `-DryRun` | Shows exactly what *would* be written to the registry, without writing anything. Always safe to run. |
| `-Force` | Re-applies every control even if it's already compliant (useful after restoring an old system backup, for example). |
| `-Undo` | Removes everything this script created and restores Windows defaults. See [below](#undoing-everything--undo). |
| `-Html` | Also generates a self-contained, dark-themed HTML report you can open in any browser, in addition to the JSON report. |
| `-Menu` | Forces the interactive menu to open even if other options are also supplied (e.g. `-Menu -DryRun` opens a menu that simulates every action). |
| `-Silent` | Skips the final "press Enter to continue" prompt — useful for scheduled tasks or silent multi-machine deployment. |
| `-RetainReportsDays <N>` | Deletes report files older than N days (default: 30). The baseline file used for change tracking is never deleted. |
| `-SelfTest` | Runs the script's internal test suite (scoring logic, history handling) and exits. Does not touch the registry at all. |
| `-WhatIf` | Standard PowerShell switch; behaves identically to `-DryRun` here. |

Examples:

```powershell
# See what would change, without changing anything
.\Harden-TLS.ps1 -DryRun

# Apply hardening and generate an HTML report
.\Harden-TLS.ps1 -Html

# Silent run for a scheduled task / fleet deployment
.\Harden-TLS.ps1 -Silent

# Undo everything this script has done on this machine
.\Harden-TLS.ps1 -Undo
```

## The interactive menu

Running the script with no arguments (or with `-Menu`) opens a menu that always shows your current compliance status up top, then lets you:

1. View the detailed state of every control (read-only)
2. Apply hardening (only what's missing)
3. Force a full re-application (even if already compliant)
4. Generate/refresh the JSON report without changing anything
5. Check for Group Policy conflicts (read-only)
6. Undo the hardening (`-Undo`)
7. Export an HTML report

Plus a toggle for dry-run mode and a quit option. It's the easiest way to explore the script safely before trusting it with real changes.

## Undoing everything (`-Undo`)

If a particular device or piece of legacy software turns out to be incompatible with this hardening, run:

```powershell
.\Harden-TLS.ps1 -Undo
```

This removes exactly what the script itself created — the dedicated protocol/cipher/hash registry keys, and the individual Diffie-Hellman/.NET values it added — and nothing else. It never deletes a registry key that existed before the script ran, or that belongs to another setting. This gives you a genuine, safe way back to Windows' out-of-the-box defaults, machine by machine.

## Reports (JSON & HTML)

Every run writes a JSON report to `Desktop\Rapports_Maintenance\TLS\`, following the same convention used across the rest of this author's script suite — useful if you're also running the companion dashboard/monitoring scripts. Add `-Html` for a visual, shareable report you can open directly in a browser, with no dependencies.

## Group Policy / domain-joined machines

If your PC is joined to a company/organization domain, an administrator's Group Policy could redefine these exact same SCHANNEL settings the next time policy refreshes (`gpupdate`) — silently overriding what this script configured. Harden-TLS checks for this (read-only) and will warn you if a relevant policy is present. It never modifies Group Policy itself. If you see a warning and want to confirm what's actually in effect, run `gpresult /h` for a full report.

## Frequently asked questions

**Will this break anything?**
For virtually all modern software (current Windows apps, current browsers, current company VPNs/services), no — TLS 1.2/1.3 with AES/GCM has been the practical standard for years. Genuinely old hardware (old printers, some NAS devices, ancient VPN appliances) that *only* speaks TLS 1.0/1.1 or the disabled ciphers could lose connectivity to this specific PC. If that happens, run `-Undo` on that machine.

**Is it safe to run more than once?**
Yes — that's the whole design. The script checks the current state before making any change and skips anything already compliant. Running it ten times in a row after the first successful run should show zero changes made each time.

**Do I need to restart every time I run it?**
Only after a run that actually changes something. If everything was already compliant, no restart is needed.

**Does this affect my browser?**
No. Chrome, Firefox, Brave, Edge and other modern browsers manage their own TLS configuration independently of Windows.

**Can I check the result independently?**
Yes — after restarting, you can verify with any external TLS scanner, or with tools like `nmap --script ssl-enum-ciphers`, or simply by checking Windows Event Viewer / SCHANNEL logs.

## Disclaimer

This script modifies system-level (`HKLM`) registry settings. While it's built to be conservative, idempotent, and fully reversible via `-Undo`, you use it at your own risk. Always test with `-DryRun` first, and keep in mind that very old or specialized hardware/software on your network might rely on the protocols and ciphers this script disables. When in doubt, test on one machine before deploying to a fleet.

---

*Harden-TLS is part of a small suite of Windows 11 maintenance/security PowerShell scripts by [Nephren](https://github.com/NephVx2).*
