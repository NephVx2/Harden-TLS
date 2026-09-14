<#
    Harden-TLS — Idempotent TLS/SCHANNEL hardening for Windows 11
    ================================================================
    Protocols, cipher suites, hashes, Diffie-Hellman & .NET Strong Crypto —
    with visual HTML/JSON reporting, GPO conflict detection, and one-command
    rollback. Safe for repeated runs and multi-machine/multi-user fleets.

    https://github.com/NephVx2/Harden-TLS
    by Nephren
    ================================================================

.SYNOPSIS
    Harden-TLS — TLS/SCHANNEL hardening for Windows 11: protocols,
    cipher suites, hashes, Diffie-Hellman and .NET Framework.
    Designed for multi-machine / multi-user deployment (idempotent,
    reversible, GPO-aware).
.DESCRIPTION
    [v1.x] Disables TLS 1.0 and TLS 1.1 (Client + Server) via SCHANNEL.
    TLS 1.2 and TLS 1.3 are NOT touched (Windows defaults preserved).

    [NEW v2.0] The scope is extended to the whole relevant SCHANNEL surface,
    with the same "check before acting, never rewrite what's already
    compliant" philosophy as the rest of the script:
      - Obsolete cipher suites disabled (RC4 all variants, DES 56/56,
        RC2 all variants, Triple DES 168, NULL). AES 128/256 and the modern
        GCM/ChaCha suites are never touched.
      - Weak hash algorithms disabled (MD5, SHA-1). SHA-256/384/512 are
        never touched.
      - Minimum Diffie-Hellman key length raised to 2048 bits
        (Client + Server), a Microsoft recommendation in effect since 2016 —
        no compatibility impact expected on a 2026 fleet.
      - .NET Framework hardening (SchUseStrongCrypto=1,
        SystemDefaultTlsVersions=1) on the native/Wow6432Node HKLM locations
        present on the machine — never inventing a .NET install that isn't
        there. This closes a real blind spot: without it, a .NET app
        (or WinRM) can keep negotiating via its own stack instead of via
        the SCHANNEL settings above.

    All these values are DWORDs under HKLM (never HKCU): the result is
    identical regardless of which user runs the script or who logs in
    afterwards on the machine — a necessary condition for a consistent
    multi-user deployment.

    [NEW v2.0] Test-TlsGpoOverride: READ-ONLY check for the presence of a
    group policy ("SSL Cipher Suite Order"). A domain-joined machine may see
    its SCHANNEL settings redefined on the next policy refresh (same registry
    path) — this script never modifies a policy, it only reports on it.

    [NEW v2.0] -Undo: cleanly removes everything this script may have created
    (entire Protocols/Ciphers/Hashes keys, individual Diffie-Hellman/.NET
    values) to return to Windows defaults — an essential safety net for a
    multi-machine deployment if a piece of hardware or a legacy app turns out
    to be incompatible on a particular machine.

    [NEW v2.0] Native -WhatIf support (CmdletBinding SupportsShouldProcess):
    -WhatIf is now equivalent to -DryRun (automatic switch), and -Undo is
    additionally guarded by $PSCmdlet.ShouldProcess() given its wider impact.

    A restart is required for SCHANNEL to reload its configuration
    (protocols/ciphers/hashes/Diffie-Hellman). For the .NET keys, restarting
    the affected applications is technically enough, but a full restart is
    still recommended for a fleet deployment, to start from a clean, uniform
    state.

    Compatibility: this change only affects Windows applications that use the
    system TLS stack (WinHTTP, SChannel, .NET Framework). Modern browsers
    (Brave, Chrome, Firefox) manage TLS independently and are not affected.
    Older network equipment (NAS, printers, legacy VPN) may be affected if it
    only supports TLS 1.0/1.1 or the cipher suites now disabled — use -Undo
    on the affected machine if needed.

    To verify the effect: re-run Check-Security.ps1 after the restart.

    JSON export aligned with the rest of the suite's conventions
    (Baseline_<Module>.json + Rapport_<Module>_*.json in
    Desktop\Maintenance_Reports\Harden-TLS), so Dashboard-Global_Win11 can read
    this script (Get-TLSModule). The score now reflects all categories
    (Protocols + Ciphers + Hashes + Diffie-Hellman + .NET), not just the
    4 original TLS 1.0/1.1 checks.
.PARAMETER DryRun
    Shows the registry keys that would be written, without applying them.
.PARAMETER Force
    Forces re-application of all checks even if already compliant (useful
    after a system restore, for example).
.PARAMETER Undo
    [NEW v2.0] Removes the keys/values created by this script (all
    categories) and reverts to Windows defaults. Guarded by
    $PSCmdlet.ShouldProcess(): honors -WhatIf and -Confirm.
.PARAMETER Html
    [NEW v2.1.0] Also generates a visual HTML report (Rapport_Harden-TLS_*.html
    in Desktop\Maintenance_Reports\Harden-TLS), same visual identity as the
    Toolbox Commandes Système. Always in addition to the JSON, never
    instead of it — the JSON remains the source read by
    Dashboard-Global_Win11.
.PARAMETER Menu
    Forces interactive mode to open, even if other parameters are
    supplied (e.g. -Menu -DryRun for a menu that simulates).
.PARAMETER Silent
    Suppresses the final "Press ENTER" pause (classic mode only) —
    useful for scheduled tasks / silent multi-machine deployment.
.PARAMETER RetainReportsDays
    Purges Rapport_Harden-TLS_*.json files older than N days (default 30).
    Baseline_Harden-TLS.json is never purged.
.PARAMETER SelfTest
    Runs an internal test suite on the scoring and history persistence
    logic (no registry reads/writes), then exits.
.NOTES
    Project : Harden-TLS
    Author  : Nephren (github.com/NephVx2)
    Version : 2.2.2
    Date    : 2026-08-25

    CHANGELOG v1.0:
      Initial creation. Targeted disabling of TLS 1.0 and TLS 1.1 only
      (Client and Server side), without touching TLS 1.2/1.3.
      New-ItemProperty -PropertyType DWord syntax (more portable than
      Set-ItemProperty -Type, which is PS 5.1+ only).

    CHANGELOG v1.1:
      [NEW] JSON export: Baseline_Harden-TLS.json + Rapport_Harden-TLS_<timestamp>.json
        in Desktop\Maintenance_Reports\Harden-TLS, for Dashboard-Global_Win11.
      [NEW] Scoring based on the final state actually re-read from the
        registry after writing (not on the absence of an exception).
      [NEW] Update-TlsScoreHistory (same double-@() precaution as the rest
        of the suite), explicit [int] cast on the score.
      [NEW] -Silent, -RetainReportsDays, -SelfTest.

    CHANGELOG v1.2:
      [NEW] Get-TlsControlState: PURE read of the 4 checks' state, BEFORE
        any decision, displayed in the console right at launch (whether in
        classic mode or menu mode) via Show-TlsControlState.
      [NEW] EXPLICIT idempotence: a check that's already compliant
        (Enabled=0/DisabledByDefault=1) is never rewritten again — before,
        the 4 keys were rewritten on every run (New-ItemProperty -Force),
        which hid the fact that no real change was needed. The JSON report
        is still always generated/refreshed regardless.
      [NEW] -Force: re-applies the 4 checks even if already compliant.
      [NEW] -Menu: interactive mode in the style of
        Manage-ScriptSignatures.ps1 (Clear-Host, persistent state summary,
        numbered options, Read-Host loop). Enabled by default if the script
        is launched with no parameter at all.
      [NEW] Test-IsElevated: administrator elevation is no longer imposed
        globally via #Requires -RunAsAdministrator (which even prevented
        viewing the state without elevation), but checked dynamically, right
        before an actual write. State reading, DryRun, and JSON report
        generation remain possible without elevation; a clear message is
        shown if an actual write is needed without elevation, and the JSON
        report is still generated with the real (unmodified) state.
      [Refactor] Reading, applying, and exporting logic extracted into
        dedicated functions (Get-TlsControlState / Show-TlsControlState /
        Invoke-TlsHardening / Export-TlsReport / Show-TlsMenu), reused
        identically by classic mode and menu mode.

    CHANGELOG v1.2.1:
      [FIX] Update-TlsScoreHistory now filters out any $null present in
        $ExistingHistory before combining it with the new point. An
        existing Baseline_Harden-TLS.json can contain a $null within ScoreHistory
        (leftover from an earlier version); a 1-element array containing
        $null stays "truthy" in PowerShell (Count -gt 0), so the guard
        "if ($PrevBaseline -and $PrevBaseline.ScoreHistory)" in
        Export-TlsReport wasn't enough to filter it out — the $null then
        propagated indefinitely, run after run. The script now self-heals
        on the next launch regardless of the existing file's state.

    CHANGELOG v2.0.0:
      [NEW] Hardening of obsolete cipher suites (SCHANNEL\Ciphers) and weak
        hash algorithms (SCHANNEL\Hashes), via the generic functions
        Get-BinaryHardeningState / Show-BinaryState / Invoke-BinaryHardening
        (same idempotent pattern as the protocols). Only strictly
        obsolete/dangerous items (RC4, RC2, DES 56/56, Triple DES 168, NULL,
        MD5, SHA-1) — AES and SHA-256+ are never touched, to stay
        compatibility-risk-free across a heterogeneous fleet.
      [NEW] Minimum Diffie-Hellman key length raised to 2048 bits
        (Get-DhState / Invoke-DhHardening), a stable Microsoft
        recommendation since 2016 — negligible compatibility impact in 2026.
      [NEW] .NET Framework hardening (SchUseStrongCrypto,
        SystemDefaultTlsVersions) via Get-DotNetPaths / Get-DotNetState /
        Invoke-DotNetHardening. Only touches .NET locations actually
        present on the machine (native v4.0.30319 + Wow6432Node if it
        exists; v2.0.50727 only if already installed) — never an invented
        .NET key.
      [NEW] Test-TlsGpoOverride: read-only detection of a domain policy on
        cipher suite order, shown in the state and tracked in the JSON
        report (category "Group Policy"), to avoid a false sense of
        compliance on an AD-joined machine.
      [NEW] -Undo: removes the created Protocols/Ciphers/Hashes keys and
        the added Diffie-Hellman/.NET values, machine by machine — a
        safety net for a multi-machine deployment (Remove-Item for keys
        dedicated to the script, Remove-ItemProperty for values isolated
        within keys shared with other settings, so as to never remove
        anything other than what this script may have written).
      [NEW] Native -WhatIf/-Confirm support:
        [CmdletBinding(SupportsShouldProcess)]. $WhatIfPreference
        automatically switches to DryRun; -Undo is additionally guarded by
        an explicit $PSCmdlet.ShouldProcess() given its impact.
      [Refactor] Get-AllHardeningStates / Show-AllHardeningStates /
        Invoke-AllHardening now orchestrate the 5 categories (Protocols,
        Ciphers, Hashes, Diffie-Hellman, .NET) with the same
        Applied/Skipped/Errors counters as before, reused identically by
        classic mode and menu mode.
      [Security note] The v1.2.1 Authenticode signature is removed at the
        end of the file: since the content changed, the old signature
        would no longer match the file's hash. Re-sign via
        Manage-ScriptSignatures.ps1 before any fleet deployment.

    CHANGELOG v2.1.0:
      [NEW] -Html: export of a visual HTML report (Rapport_Harden-TLS_*.html),
        same visual identity as the Toolbox Commandes Système (dark
        background, cyan accent, gradient Windows logo, stat cards,
        grouped/filterable table). Self-contained file (inline CSS/JS),
        always generated in addition to the JSON, never instead of it.
      [NEW] Menu [7]: on-demand HTML export of the current state
        (read-only), with an offer to open it immediately in the browser.
      [Refactor] Get-AllResultsSnapshot centralizes building the read-only
        Results table (Category/Item/Value/Status), previously
        duplicated hardcoded in menu [4] — now reused by menu [4]/[7] AND
        by Export-TlsHtmlReport.
      [Refactor] ConvertTo-HtmlSafe (System.Net.WebUtility) escapes every
        value before insertion into the HTML — no registry value or error
        message is ever injected as-is.

    CHANGELOG v2.1.1:
      [FIX] "Group Policy" line literally displaying "System.Object[]"
        instead of the warning text, in Invoke-AllHardening AND
        Get-AllResultsSnapshot. Cause: both callers were wrapping
        "Test-TlsGpoOverride" in one @() too many — the function already
        guarantees an array via "return ,$Findings" (an earlier v2.0.0 fix
        for the ".Count" crash on a 1-element result), so the extra @()
        created an array INSIDE an array. The Status (WARNING/OK) stayed
        correct by accident (.Count was 1 or 0 either way), only the
        "-join" text was corrupted. Fix: removed the extra @() at both call
        sites — Test-TlsGpoOverride alone is enough and remains the single
        source of truth for the array.

    CHANGELOG v2.1.2:
      [FIX] "Group Policy" false positive: Test-TlsGpoOverride only checked
        the EXISTENCE of the SSL\00010002 key (SSL Cipher Suite Order), not
        the presence of the "Functions" value that actually defines a
        suite order. Observed under real conditions on NEPH-DESKTOP: the
        key exists (likely leftover from a past install) but is empty — no
        active policy — which triggered a warning on every run even though
        nothing threatened to redefine this script's settings. Fixed via
        Test-RegValueExists -Name "Functions" instead of a plain Test-Path
        on the key.

    CHANGELOG v2.1.3:
      [CRITICAL FIX] Diffie-Hellman (Client) and (Server) were erasing each
        other between runs, seemingly at random — a symptom observed and
        investigated in depth on NEPH-DESKTOP (registry auditing,
        software-by-software isolation testing) before being reproduced and
        confirmed in 3 isolated command lines, with no external factor at
        all: "New-Item -Path -Force" on a key that ALREADY EXISTS recreates
        the key and erases any other value it held. Diffie-Hellman is the
        ONLY key in the script where two independent values
        (ClientMinKeyBitLength/ServerMinKeyBitLength) coexist and are
        written during SEPARATE passes of the loop (one per role) — as soon
        as one was already compliant and skipped by the idempotent logic,
        processing the other called New-Item -Force on the shared key again
        and silently erased the one that didn't actually need touching.
        Fixed in Invoke-DhHardening (and, as a precaution, in the 3 other
        apply functions): the key is now created ONLY if it doesn't exist
        yet (Test-Path before New-Item), never recreated on a key that's
        already present. No other category was structurally exposed (a
        single value per key, or all of a key's values written together in
        the same pass) but the guard was added everywhere for consistency.

    CHANGELOG v2.1.4:
      [FIX] HTML report: banner renamed to "Harden-TLS vX.X.X" (main title)
        with "by Nephren" as subtitle, instead of "TLS/SCHANNEL Hardening" /
        "by Harden-TLS_Win11 vX.X.X" — consistent project identity for the
        GitHub release.
      [FIX] HTML report's "Windows" field sometimes displaying "Windows 10"
        on a machine actually running Windows 11 — a known bug in the
        ProductName registry key, never updated by Microsoft after a 10→11
        migration. Now read via Win32_OperatingSystem (WMI/CIM), reliable
        in every case observed; falls back to the registry only if WMI is
        unavailable.

    CHANGELOG v2.2.2:
      [CRITICAL FIX] The script refused to launch under Windows PowerShell
        5.1 ("Unexpected token", "Missing closing brace", etc.), while it
        worked normally under PowerShell 7 (pwsh). Cause: the file was
        saved as UTF-8 WITHOUT a BOM marker. PowerShell 7 always reads
        .ps1 files as UTF-8 by default, BOM or not — but Windows
        PowerShell 5.1 relies on the presence of the BOM to detect the
        encoding and, without it, falls back to the system's
        ANSI/Windows-1252. All the multi-byte characters added in v2.2.0
        (icons ✓ ! ✗ · », banner frames ╔═╗║╚╝, separators │─) were then
        misdecoded into several garbage characters each, breaking
        PowerShell syntax (extra quotes and braces being counted). Fixed by
        re-saving the file as UTF-8 WITH BOM — transparent for PowerShell 7,
        which ignores it, and makes the file readable again by PowerShell
        5.1. Note for the future: any re-editing of this file outside of
        this environment (Notepad, misconfigured VS Code, etc.) must keep
        saving it as "UTF-8 with BOM" or this bug will come back.

    CHANGELOG v2.3.0:
      [NEW] Full French-to-English translation: SYNOPSIS/DESCRIPTION,
        every CHANGELOG entry, all inline comments, console output, menu
        text, and the HTML report (title, labels, table headers, CSS row
        classes) are now in English. The Results object fields were
        renamed Categorie/Element/Valeur/Statut -> Category/Item/Value/
        Status, and status literals AVERTISSEMENT/ERREUR ->
        WARNING/ERROR, both in the console output and in the exported
        JSON/HTML reports — Dashboard-Global_Win11's Get-TLSModule reader
        must be updated to match the new field/status names.
      [Note] This script has no locale-dependent parsing of external
        command output (unlike SpicyCheck/Check-Security's DISM/SFC/
        auditpol/wbadmin handling) — every check reads and writes the
        registry directly, which behaves identically regardless of the
        machine's Windows display language. No bilingual regex was
        needed: registry values are what they are on an English or a
        French Windows install alike.
      [FIX] HTML report date display switched from "dd/MM/yyyy" to
        "dd MMM yyyy HH:mm:ss" (InvariantCulture) to avoid day/month
        ambiguity for English-speaking readers, same fix pattern as
        Check-Security's Format-AuditDate.
      [Security note] Old Authenticode signature removed
        at the end of the file (content changed). Re-sign via
        Manage-ScriptSignatures.ps1 before any fleet deployment.
#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = "Medium")]
param(
    [switch]$DryRun,
    [switch]$Force,
    [switch]$Undo,
    [switch]$Html,
    [switch]$Menu,
    [switch]$Silent,
    [int]$RetainReportsDays = 30,
    [switch]$SelfTest
)

# [NEW v2.0] Native -WhatIf: simply aliased to the already-proven -DryRun
# pipeline, rather than duplicating the "what would be done" display logic.
if ($WhatIfPreference) { $DryRun = $true }

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ──────────────────────────────────────────────
#  CONFIGURATION
# ──────────────────────────────────────────────
$ScriptVersion = "2.3.0"
$SchannelRoot  = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL"
$SchannelBase  = "$SchannelRoot\Protocols"          # kept for compat (protocols)
$ProtocolBase  = $SchannelBase
$CipherBase    = "$SchannelRoot\Ciphers"
$HashBase      = "$SchannelRoot\Hashes"
$DhPath        = "$SchannelRoot\KeyExchangeAlgorithms\Diffie-Hellman"

# Protocols to explicitly disable.
# TLS 1.2 and TLS 1.3 are deliberately absent from this list.
$ProtosToDisable = @("TLS 1.0", "TLS 1.1")
$Roles           = @("Client", "Server")

# [NEW v2.0] Obsolete/dangerous cipher suites (RFC 7465 for RC4,
# NIST/Microsoft recommendations for DES/RC2/3DES/NULL). AES 128/256 and
# the modern GCM/ChaCha suites are deliberately absent from this list.
$WeakCiphers = @(
    "RC4 40/128", "RC4 56/128", "RC4 64/128", "RC4 128/128",
    "DES 56/56", "RC2 40/128", "RC2 56/128", "RC2 128/128",
    "Triple DES 168", "NULL"
)

# [NEW v2.0] Weak hash algorithms. SHA-256/384/512 deliberately absent —
# these are the modern defaults, never disabled by this script.
$WeakHashes = @("MD5", "SHA")

# [NEW v2.0] Minimum Diffie-Hellman key length (Microsoft recommendation
# since 2016, see Logjam). Negligible compatibility impact in 2026.
$DhMinKeyBitLength = 2048

# Same root as the rest of the suite (Dashboard-Global, Check-Boot, etc.).
$ReportsRoot   = "$env:USERPROFILE\Desktop\Maintenance_Reports\Harden-TLS"
$BaselinePath  = "$ReportsRoot\Baseline_Harden-TLS.json"

# [NEW v2.1.0] Logical reading order for the HTML report (not alphabetical) —
# any unexpected category (e.g. "Rollback" after an -Undo) is appended
# automatically by Export-TlsHtmlReport, never losing a row.
$CategoryDisplayOrder = @("Protocol", "Cipher", "Hash", "Diffie-Hellman", ".NET Framework", "Group Policy", "Rollback")

# [NEW v1.2] Interactive mode by default if NO parameter was supplied (double-click);
# any explicit parameter switches to non-interactive classic mode (scheduled task /
# scripted call from Dashboard-Global compatibility unchanged).
$InteractiveMode = $Menu -or ($PSBoundParameters.Count -eq 0)

# [NEW v2.2.0] Console visual identity aligned with Check-Security_Win11 /
# Toolbox-SystemCommands: short icons + fixed column (stable rendering
# regardless of glyph), "category" column width to align all results into
# a readable table instead of a wall of text.
$script:LogIcons        = @{ "OK"="✓"; "WARN"="!"; "FAIL"="✗"; "INFO"="·"; "DRY"="»" }
$script:LogIconWidth    = 2
$script:LogCategoryWidth = 16
$script:LogItemWidth    = 20
$script:BannerWidth     = 55

# ──────────────────────────────────────────────
#  UTILITY FUNCTIONS
# ──────────────────────────────────────────────

# [FIX v2.0] Under Set-StrictMode -Version Latest, "(Get-ItemProperty -Name X
# -ErrorAction SilentlyContinue).X" is dangerous both ways:
#   - if the key exists but value X doesn't exist yet (the normal case on
#     the very first run, e.g. .NET keys never hardened), the object
#     returned by Get-ItemProperty exists but has no X property: accessing
#     it throws "The property 'X' cannot be found on this object" instead
#     of returning $null;
#   - a plain "$null -ne (Get-ItemProperty ...)" test is also wrong: the
#     returned object is NOT $null even when X is absent, which would have
#     thrown off the existence detection used by the rollback.
# Get-RegValue centralizes a safe read: $null if the key or value doesn't
# exist, the value otherwise — never an exception, regardless of strict mode.
function Get-RegValue {
    param([string]$Path, [string]$Name)
    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    $Item = Get-ItemProperty -LiteralPath $Path -ErrorAction SilentlyContinue
    if ($null -eq $Item) { return $null }
    if ($Item.PSObject.Properties.Name -contains $Name) { return $Item.$Name }
    return $null
}

function Test-RegValueExists {
    param([string]$Path, [string]$Name)
    if (-not (Test-Path -LiteralPath $Path)) { return $false }
    $Item = Get-ItemProperty -LiteralPath $Path -ErrorAction SilentlyContinue
    if ($null -eq $Item) { return $false }
    return ($Item.PSObject.Properties.Name -contains $Name)
}

# [NEW v2.1.0] HTML escaping for the visual report — System.Net.WebUtility
# is part of the System assembly (loaded by default), no Add-Type needed.
function ConvertTo-HtmlSafe {
    param([string]$Text)
    if ($null -eq $Text) { return "" }
    return [System.Net.WebUtility]::HtmlEncode($Text)
}

function Write-Step {
    # [REDESIGN v2.2.0] Same spirit as before (timestamp + colored level),
    # but rendered aligned in columns like Check-Security_Win11 (Write-Log):
    #   time · icon · [category · [item ·]] message
    # [FIX v2.2.1] -Category alone wasn't enough to align the "│" bar
    # when the category combined a fixed group AND a variable-length item
    # name (e.g. "Cipher: Triple DES 168" vs "Cipher: NULL"): PadRight only
    # compensates up to its width, so any entry longer than that threshold
    # shifted the bar for that one line. The group (-Category, always a
    # fixed word: "Protocol", "Cipher", ".NET Framework"...) and the
    # variable item (-Item) are now two DISTINCT columns, each with its own
    # fixed width — the bar stays in the same column regardless of the
    # displayed name's length. -Item is optional: without it, the render
    # keeps 2 columns (category + message), for cases with no sub-item to
    # align (Rollback, GPO Policy, summaries).
    param(
        [string]$Message,
        [string]$Level = "INFO",
        [string]$Category = "",
        [string]$Item = ""
    )
    $timestamp = Get-Date -Format "HH:mm:ss"
    $colors = @{ "INFO"="Cyan"; "OK"="Green"; "WARN"="Yellow"; "FAIL"="Red"; "DRY"="Magenta" }
    $color  = if ($colors.ContainsKey($Level)) { $colors[$Level] } else { "White" }
    $icon   = if ($script:LogIcons.ContainsKey($Level)) { $script:LogIcons[$Level] } else { "•" }
    $iconCol = $icon.PadRight($script:LogIconWidth)

    Write-Host "  $timestamp  " -NoNewline -ForegroundColor DarkGray
    Write-Host "$iconCol " -NoNewline -ForegroundColor $color
    if ($Category) {
        Write-Host "$($Category.PadRight($script:LogCategoryWidth))" -NoNewline -ForegroundColor DarkCyan
        if ($Item) {
            Write-Host "$($Item.PadRight($script:LogItemWidth))" -NoNewline -ForegroundColor Gray
        }
        Write-Host "│ " -NoNewline -ForegroundColor DarkGray
    }
    Write-Host "$Message" -ForegroundColor $color
}

# [NEW v2.2.0] Framed ╔═╗ banner for section titles — same style as
# Check-Security_Win11 (Write-Log -Level SECTION), for a consistent visual
# identity across the whole script suite. $Color applies to both the frame
# AND the title (Check-Security's green "AUDIT COMPLETE", the red
# "-Undo-" here, etc.).
function Write-Banner {
    param([string]$Title, [string]$Color = "Cyan", [int]$Width = $script:BannerWidth)
    Write-Host ""
    Write-Host ("  ╔" + ("═" * $Width) + "╗") -ForegroundColor $Color
    Write-Host "  ║" -NoNewline -ForegroundColor $Color
    Write-Host (" $Title").PadRight($Width) -NoNewline -ForegroundColor $Color
    Write-Host "║" -ForegroundColor $Color
    Write-Host ("  ╚" + ("═" * $Width) + "╝") -ForegroundColor $Color
}

# [NEW v2.2.0] Mini visual gauge (Check-Security_Win11 style) — used in the
# final summary to visualize at a glance the proportion of compliant
# checks, without having to do the mental math from raw numbers.
function Write-ComplianceGauge {
    param([int]$Compliant, [int]$Total, [int]$Blocks = 20)
    $ratio  = if ($Total -gt 0) { $Compliant / $Total } else { 0 }
    $filled = [math]::Round($ratio * $Blocks)
    $gauge  = ("█" * $filled) + ("░" * ($Blocks - $filled))
    $color  = if ($ratio -eq 1) { "Green" } elseif ($ratio -ge 0.5) { "Yellow" } else { "Red" }
    Write-Host "  Overall compliance  " -NoNewline -ForegroundColor Gray
    Write-Host "$gauge" -NoNewline -ForegroundColor $color
    Write-Host "  $Compliant/$Total" -ForegroundColor $color
}

function Test-IsElevated {
    # [NEW v1.2] Dynamic elevation check, instead of a global
    # #Requires -RunAsAdministrator which even prevented viewing the state without
    # elevation. Only an actual registry write needs it.
    $Identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
    $Principal = New-Object Security.Principal.WindowsPrincipal($Identity)
    return $Principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Update-TlsScoreHistory {
    # Local equivalent of Update-ScoreHistory (Dashboard-Global). Adds a point, truncates
    # to $MaxPoints. The call site must always write
    # "$x = @(Update-TlsScoreHistory ...)" (the [array] on $ExistingHistory isn't enough to
    # guard against a 1-element array unrolling on the output stream).
    #
    # [FIX v1.2.1] An earlier Baseline_Harden-TLS.json can contain a $null within
    # ScoreHistory (e.g. leftover from an earlier version). A 1-element array
    # containing $null stays "truthy" in PowerShell (Count -gt 0), so the guard
    # "if ($PrevBaseline -and $PrevBaseline.ScoreHistory)" in Export-TlsReport isn't
    # enough to filter it out - $ExistingHistory then receives that $null as-is, which
    # propagates indefinitely across every following run. Filtered here, on entry, so it
    # self-heals on the next run regardless of the existing file's state.
    param(
        [array]$ExistingHistory = @(),
        [PSCustomObject]$NewPoint,
        [int]$MaxPoints = 30
    )
    $ExistingHistory = @($ExistingHistory | Where-Object { $null -ne $_ })
    $Combined = @($ExistingHistory) + @($NewPoint)
    if ($Combined.Count -gt $MaxPoints) {
        $Combined = @($Combined | Select-Object -Last $MaxPoints)
    }
    return $Combined
}

function Remove-OldTlsReports {
    # Purges Rapport_Harden-TLS_*.json files older than $Days days. Never touches
    # Baseline_Harden-TLS.json (score history, not a one-off report).
    param([string]$Folder, [int]$Days)
    if (-not (Test-Path $Folder)) { return }
    try {
        $Cutoff = (Get-Date).AddDays(-$Days)
        Get-ChildItem -Path $Folder -Filter "Rapport_Harden-TLS_*.json" -File -ErrorAction SilentlyContinue |
            Where-Object { $_.LastWriteTime -lt $Cutoff } |
            Remove-Item -Force -ErrorAction SilentlyContinue
    } catch {
        Write-Step "Could not purge old reports: $($_.Exception.Message)" -Level WARN
    }
}

function Get-TlsControlState {
    # [NEW v1.2] PURE read of the 4 checks' state (no writes). Serves as the single
    # source for display, the "does this need changing?" decision, and the JSON export —
    # before, this read was duplicated (once for the "before" display, once implicitly
    # inside the apply loop).
    $States = @()
    foreach ($proto in $ProtosToDisable) {
        foreach ($role in $Roles) {
            $keyPath  = "$SchannelBase\$proto\$role"
            $enabled  = $null
            $dbd      = $null
            $KeyExists = $false
            try {
                if (Test-Path -LiteralPath $keyPath) {
                    $KeyExists = $true
                    $enabled = Get-RegValue -Path $keyPath -Name "Enabled"
                    $dbd     = Get-RegValue -Path $keyPath -Name "DisabledByDefault"
                }
            } catch { }
            $Applied = ($null -ne $enabled -and [int]$enabled -eq 0 -and $null -ne $dbd -and [int]$dbd -eq 1)
            $States += [PSCustomObject]@{
                Proto     = $proto
                Role      = $role
                KeyExists = $KeyExists
                Enabled   = $enabled
                Dbd       = $dbd
                Applied   = $Applied
            }
        }
    }
    return $States
}

function Show-TlsControlState {
    # [NEW v1.2] Console display of the current state — used both as the preamble of
    # classic mode and as option [1] of the interactive menu: it shows whether items are
    # applied or not without having to run an apply pass to find out.
    param([array]$States)
    foreach ($S in $States) {
        $Item = "$($S.Proto) ($($S.Role))"
        if ($S.Applied) {
            Write-Step "already compliant (Enabled=0, DisabledByDefault=1)" -Level OK -Category "Protocol" -Item $Item
        } elseif (-not $S.KeyExists) {
            Write-Step "key absent (Windows default — will be created and forced)" -Level INFO -Category "Protocol" -Item $Item
        } elseif ($null -eq $S.Enabled -and $null -eq $S.Dbd) {
            Write-Step "key present but values absent (implicit Windows default)" -Level WARN -Category "Protocol" -Item $Item
        } else {
            Write-Step "ENABLED (Enabled=$($S.Enabled)) — will be disabled" -Level WARN -Category "Protocol" -Item $Item
        }
    }
}

function Invoke-TlsHardening {
    # [NEW v1.2] Core of the "check before acting" logic: a check that's already
    # compliant is NEVER rewritten again, unless -ForceAll. Returns a single object
    # grouping the detailed results (for the JSON export) and the counters (for the
    # console summary).
    param(
        [array]$States,
        [switch]$ForceAll,
        [switch]$IsDryRun,
        [bool]$Elevated
    )

    $Results = @()
    $Applied = 0
    $Errors  = 0
    $Skipped = 0

    foreach ($S in $States) {
        $path        = "$SchannelBase\$($S.Proto)\$($S.Role)"
        $NeedsChange = (-not $S.Applied) -or $ForceAll
        $BeforeTxt   = if ($S.KeyExists) { "Enabled=$($S.Enabled), DisabledByDefault=$($S.Dbd)" } else { "key absent" }

        if (-not $NeedsChange) {
            Write-Step "already compliant, no change" -Level OK -Category "Protocol" -Item "$($S.Proto) ($($S.Role))"
            $Skipped++
            $Results += [PSCustomObject]@{
                Category = "Protocol"; Item = "$($S.Proto) ($($S.Role))"
                Value    = "Enabled=0, DisabledByDefault=1 (already compliant, not changed)"
                Status    = "OK"
            }
            continue
        }

        if ($IsDryRun) {
            $Action = if ($S.Applied) { "would be re-applied (Force)" } else { "would be applied" }
            Write-Step "[DRY-RUN] $Action (current state: $BeforeTxt)" -Level DRY -Category "Protocol" -Item "$($S.Proto) ($($S.Role))"
            $Results += [PSCustomObject]@{
                Category = "Protocol"; Item = "$($S.Proto) ($($S.Role))"
                Value    = "Current state: $BeforeTxt [DRY-RUN, not changed]"
                Status    = if ($S.Applied) { "OK" } else { "WARNING" }
            }
            continue
        }

        if (-not $Elevated) {
            Write-Step "elevation required to apply (relaunch as Administrator)" -Level FAIL -Category "Protocol" -Item "$($S.Proto) ($($S.Role))"
            $Errors++
            $Results += [PSCustomObject]@{
                Category = "Protocol"; Item = "$($S.Proto) ($($S.Role))"
                Value    = "Not applied: administrator elevation required (current state: $BeforeTxt)"
                Status    = "ERROR"
            }
            continue
        }

        try {
            # [FIX v2.1.1] Create the key ONLY if absent — never call
            # New-Item -Force on an existing key again (see the detailed note in
            # Invoke-DhHardening: this behavior can erase the existing content
            # of the key on some systems). Each protocol subkey only has a
            # single set of values written at once here, so it's not exposed in
            # practice, but the guard is kept for consistency and caution.
            if (-not (Test-Path -LiteralPath $path)) {
                New-Item -Path $path -Force | Out-Null
            }

            # NOTE: New-ItemProperty -PropertyType DWord is the portable syntax
            # (works on PS 5.1 and PS 7+). -Force silently overwrites if the
            # value already exists.
            New-ItemProperty -Path $path -Name "Enabled"           -Value 0 -PropertyType DWord -Force | Out-Null
            New-ItemProperty -Path $path -Name "DisabledByDefault" -Value 1 -PropertyType DWord -Force | Out-Null

            # Re-read AFTER writing: don't assume that the absence of an exception
            # means the value was actually applied.
            $VerifEnabled = Get-RegValue -Path $path -Name "Enabled"
            $VerifDbd     = Get-RegValue -Path $path -Name "DisabledByDefault"

            if ([int]$VerifEnabled -eq 0 -and [int]$VerifDbd -eq 1) {
                Write-Step "Enabled=0, DisabledByDefault=1" -Level OK -Category "Protocol" -Item "$($S.Proto) ($($S.Role))"
                $Applied++
                $Results += [PSCustomObject]@{
                    Category = "Protocol"; Item = "$($S.Proto) ($($S.Role))"
                    Value    = "Enabled=0, DisabledByDefault=1 (before: $BeforeTxt)"
                    Status    = "OK"
                }
            } else {
                Write-Step "write succeeded without exception but unexpected value re-read (Enabled=$VerifEnabled, DisabledByDefault=$VerifDbd)" -Level FAIL -Category "Protocol" -Item "$($S.Proto) ($($S.Role))"
                $Errors++
                $Results += [PSCustomObject]@{
                    Category = "Protocol"; Item = "$($S.Proto) ($($S.Role))"
                    Value    = "Unexpected value re-read: Enabled=$VerifEnabled, DisabledByDefault=$VerifDbd"
                    Status    = "ERROR"
                }
            }
        } catch {
            Write-Step "ERROR: $($_.Exception.Message)" -Level FAIL -Category "Protocol" -Item "$($S.Proto) ($($S.Role))"
            $Errors++
            $Results += [PSCustomObject]@{
                Category = "Protocol"; Item = "$($S.Proto) ($($S.Role))"
                Value    = "Write failed: $($_.Exception.Message)"
                Status    = "ERROR"
            }
        }
    }

    return [PSCustomObject]@{ Results = $Results; Applied = $Applied; Errors = $Errors; Skipped = $Skipped }
}

# ──────────────────────────────────────────────
#  [NEW v2.0] CIPHERS / HASHES — generic functions
#  (same pattern as the protocols: pure read, then idempotent apply.
#  Ciphers and Hashes only have an "Enabled" value, no
#  "DisabledByDefault" — unlike protocols.)
# ──────────────────────────────────────────────
function Get-BinaryHardeningState {
    param([string]$BasePath, [string[]]$Items, [string]$Label)
    $States = @()
    foreach ($item in $Items) {
        $path      = "$BasePath\$item"
        $enabled   = $null
        $KeyExists = $false
        try {
            if (Test-Path -LiteralPath $path) {
                $KeyExists = $true
                $enabled = Get-RegValue -Path $path -Name "Enabled"
            }
        } catch { }
        $Applied = ($KeyExists -and $null -ne $enabled -and [int]$enabled -eq 0)
        $States += [PSCustomObject]@{
            Label = $Label; Item = $item; Path = $path
            KeyExists = $KeyExists; Enabled = $enabled; Applied = $Applied
        }
    }
    return $States
}

function Show-BinaryState {
    param([array]$States)
    foreach ($S in $States) {
        if ($S.Applied) {
            Write-Step "already disabled" -Level OK -Category $S.Label -Item $S.Item
        } elseif (-not $S.KeyExists) {
            Write-Step "key absent (will be created and disabled)" -Level INFO -Category $S.Label -Item $S.Item
        } else {
            Write-Step "ENABLED (Enabled=$($S.Enabled)) — will be disabled" -Level WARN -Category $S.Label -Item $S.Item
        }
    }
}

function Invoke-BinaryHardening {
    # Only writes "Enabled"=0. Same idempotent logic (check before acting)
    # and same return contract {Results;Applied;Errors;Skipped} as
    # Invoke-TlsHardening, to stay interchangeable in the orchestrators.
    param([array]$States, [switch]$ForceAll, [switch]$IsDryRun, [bool]$Elevated)

    $Results = @(); $Applied = 0; $Errors = 0; $Skipped = 0

    foreach ($S in $States) {
        $NeedsChange = (-not $S.Applied) -or $ForceAll
        $BeforeTxt   = if ($S.KeyExists) { "Enabled=$($S.Enabled)" } else { "key absent" }

        if (-not $NeedsChange) {
            Write-Step "already disabled, no change" -Level OK -Category $S.Label -Item $S.Item
            $Skipped++
            $Results += [PSCustomObject]@{
                Category = $S.Label; Item = $S.Item
                Value    = "Enabled=0 (already compliant, not changed)"; Status = "OK"
            }
            continue
        }

        if ($IsDryRun) {
            Write-Step "[DRY-RUN] would be disabled (current state: $BeforeTxt)" -Level DRY -Category $S.Label -Item $S.Item
            $Results += [PSCustomObject]@{
                Category = $S.Label; Item = $S.Item
                Value    = "Current state: $BeforeTxt [DRY-RUN, not changed]"
                Status    = if ($S.Applied) { "OK" } else { "WARNING" }
            }
            continue
        }

        if (-not $Elevated) {
            Write-Step "elevation required to apply" -Level FAIL -Category $S.Label -Item $S.Item
            $Errors++
            $Results += [PSCustomObject]@{
                Category = $S.Label; Item = $S.Item
                Value    = "Not applied: administrator elevation required (current state: $BeforeTxt)"
                Status    = "ERROR"
            }
            continue
        }

        try {
            # [FIX v2.1.1] See the detailed note in Invoke-DhHardening.
            if (-not (Test-Path -LiteralPath $S.Path)) {
                New-Item -Path $S.Path -Force | Out-Null
            }
            New-ItemProperty -Path $S.Path -Name "Enabled" -Value 0 -PropertyType DWord -Force | Out-Null
            $Verif = Get-RegValue -Path $S.Path -Name "Enabled"

            if ([int]$Verif -eq 0) {
                Write-Step "Enabled=0 ✔" -Level OK -Category $S.Label -Item $S.Item
                $Applied++
                $Results += [PSCustomObject]@{
                    Category = $S.Label; Item = $S.Item
                    Value    = "Enabled=0 (before: $BeforeTxt)"; Status = "OK"
                }
            } else {
                Write-Step "unexpected value re-read (Enabled=$Verif)" -Level FAIL -Category $S.Label -Item $S.Item
                $Errors++
                $Results += [PSCustomObject]@{
                    Category = $S.Label; Item = $S.Item
                    Value    = "Unexpected value re-read: Enabled=$Verif"; Status = "ERROR"
                }
            }
        } catch {
            Write-Step "ERROR: $($_.Exception.Message)" -Level FAIL -Category $S.Label -Item $S.Item
            $Errors++
            $Results += [PSCustomObject]@{
                Category = $S.Label; Item = $S.Item
                Value    = "Write failed: $($_.Exception.Message)"; Status = "ERROR"
            }
        }
    }

    return [PSCustomObject]@{ Results = $Results; Applied = $Applied; Errors = $Errors; Skipped = $Skipped }
}

# ──────────────────────────────────────────────
#  [NEW v2.0] DIFFIE-HELLMAN — minimum key length
# ──────────────────────────────────────────────
function Get-DhState {
    $States = @()
    foreach ($role in @("Client", "Server")) {
        $valueName = "${role}MinKeyBitLength"
        $KeyExists = Test-Path -LiteralPath $DhPath
        $val = $null
        if ($KeyExists) {
            $val = Get-RegValue -Path $DhPath -Name $valueName
        }
        $Applied = ($null -ne $val -and [int]$val -ge $DhMinKeyBitLength)
        $States += [PSCustomObject]@{
            Role = $role; ValueName = $valueName; KeyExists = $KeyExists
            Value = $val; Applied = $Applied
        }
    }
    return $States
}

function Show-DhState {
    param([array]$States)
    foreach ($S in $States) {
        if ($S.Applied) {
            Write-Step "already >= $DhMinKeyBitLength bits (current: $($S.Value))" -Level OK -Category "Diffie-Hellman" -Item $S.Role
        } elseif (-not $S.KeyExists -or $null -eq $S.Value) {
            Write-Step "not set (will be set to $DhMinKeyBitLength bits)" -Level INFO -Category "Diffie-Hellman" -Item $S.Role
        } else {
            Write-Step "insufficient (current: $($S.Value)) — will be raised to $DhMinKeyBitLength" -Level WARN -Category "Diffie-Hellman" -Item $S.Role
        }
    }
}

function Invoke-DhHardening {
    param([array]$States, [switch]$ForceAll, [switch]$IsDryRun, [bool]$Elevated)

    $Results = @(); $Applied = 0; $Errors = 0; $Skipped = 0

    foreach ($S in $States) {
        $NeedsChange = (-not $S.Applied) -or $ForceAll
        $BeforeTxt   = if ($null -ne $S.Value) { "$($S.Value) bits" } else { "not set" }
        $Item     = "Minimum key length ($($S.Role))"

        if (-not $NeedsChange) {
            Write-Step "already >= $DhMinKeyBitLength bits, no change" -Level OK -Category "Diffie-Hellman" -Item $S.Role
            $Skipped++
            $Results += [PSCustomObject]@{
                Category = "Diffie-Hellman"; Item = $Item
                Value    = "$DhMinKeyBitLength bits (already compliant, not changed)"; Status = "OK"
            }
            continue
        }

        if ($IsDryRun) {
            Write-Step "[DRY-RUN] would be set to $DhMinKeyBitLength bits (current: $BeforeTxt)" -Level DRY -Category "Diffie-Hellman" -Item $S.Role
            $Results += [PSCustomObject]@{
                Category = "Diffie-Hellman"; Item = $Item
                Value    = "Current: $BeforeTxt [DRY-RUN, not changed]"
                Status    = if ($S.Applied) { "OK" } else { "WARNING" }
            }
            continue
        }

        if (-not $Elevated) {
            Write-Step "elevation required to apply" -Level FAIL -Category "Diffie-Hellman" -Item $S.Role
            $Errors++
            $Results += [PSCustomObject]@{
                Category = "Diffie-Hellman"; Item = $Item
                Value    = "Not applied: administrator elevation required (current: $BeforeTxt)"; Status = "ERROR"
            }
            continue
        }

        try {
            # [FIX v2.1.1] CRITICAL BUG identified through field testing on NEPH-DESKTOP:
            # "New-Item -Path -Force" on a key that ALREADY EXISTS recreates the key
            # and erases any other value it held — confirmed by an isolated test
            # (two New-ItemProperty calls followed by a plain New-Item -Force with no
            # other write: both values disappear). Diffie-Hellman is the ONLY key in
            # the script where two independent values (Client/Server) coexist and are
            # written during SEPARATE passes — as soon as one was already compliant
            # and skipped, processing the other re-ran New-Item -Force and silently
            # erased the first one without touching it explicitly. Only create the key
            # if it doesn't exist yet: NEVER call New-Item -Force on it again once it
            # exists.
            if (-not (Test-Path -LiteralPath $DhPath)) {
                New-Item -Path $DhPath -Force | Out-Null
            }
            New-ItemProperty -Path $DhPath -Name $S.ValueName -Value $DhMinKeyBitLength -PropertyType DWord -Force | Out-Null
            $Verif = Get-RegValue -Path $DhPath -Name $S.ValueName

            if ([int]$Verif -ge $DhMinKeyBitLength) {
                Write-Step "$Verif bits ✔" -Level OK -Category "Diffie-Hellman" -Item $S.Role
                $Applied++
                $Results += [PSCustomObject]@{
                    Category = "Diffie-Hellman"; Item = $Item
                    Value    = "$Verif bits (before: $BeforeTxt)"; Status = "OK"
                }
            } else {
                Write-Step "unexpected value re-read ($Verif)" -Level FAIL -Category "Diffie-Hellman" -Item $S.Role
                $Errors++
                $Results += [PSCustomObject]@{
                    Category = "Diffie-Hellman"; Item = $Item
                    Value    = "Unexpected value re-read: $Verif"; Status = "ERROR"
                }
            }
        } catch {
            Write-Step "ERROR: $($_.Exception.Message)" -Level FAIL -Category "Diffie-Hellman" -Item $S.Role
            $Errors++
            $Results += [PSCustomObject]@{
                Category = "Diffie-Hellman"; Item = $Item
                Value    = "Write failed: $($_.Exception.Message)"; Status = "ERROR"
            }
        }
    }

    return [PSCustomObject]@{ Results = $Results; Applied = $Applied; Errors = $Errors; Skipped = $Skipped }
}

# ──────────────────────────────────────────────
#  [NEW v2.0] .NET FRAMEWORK — SchUseStrongCrypto / SystemDefaultTlsVersions
#  Machine-wide (HKLM only) — never HKCU, so the result is identical no
#  matter which user logs in on the machine afterwards.
# ──────────────────────────────────────────────
function Get-DotNetPaths {
    # Only touches .NET locations actually present on the machine.
    # v4.0.30319 is part of the OS (always present on Win11); the
    # Wow6432Node counterpart only exists on a 64-bit OS; .NET 2.0/3.5 is
    # only added if already installed — never an invented key.
    $Paths = @("HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319")
    if (Test-Path -LiteralPath "HKLM:\SOFTWARE\Wow6432Node") {
        $Paths += "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319"
    }
    foreach ($Legacy in @(
        "HKLM:\SOFTWARE\Microsoft\.NETFramework\v2.0.50727",
        "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v2.0.50727"
    )) {
        if (Test-Path -LiteralPath $Legacy) { $Paths += $Legacy }
    }
    # [FIX v2.0] Same precaution as Test-TlsGpoOverride: on a 32-bit OS with
    # no Wow6432Node and no legacy .NET, $Paths would only contain 1 element
    # and would be flattened into a plain string on return — a "foreach" on
    # a string iterates character by character, which would silently break
    # Get-DotNetState. The unary "," operator guarantees a real array.
    return ,$Paths
}

function Get-DotNetState {
    $States = @()
    foreach ($path in (Get-DotNetPaths)) {
        $ssc = $null; $sdtv = $null
        $KeyExists = Test-Path -LiteralPath $path
        if ($KeyExists) {
            $ssc  = Get-RegValue -Path $path -Name "SchUseStrongCrypto"
            $sdtv = Get-RegValue -Path $path -Name "SystemDefaultTlsVersions"
        }
        $Applied = ($null -ne $ssc -and [int]$ssc -eq 1 -and $null -ne $sdtv -and [int]$sdtv -eq 1)
        $States += [PSCustomObject]@{ Path = $path; KeyExists = $KeyExists; Ssc = $ssc; Sdtv = $sdtv; Applied = $Applied }
    }
    return $States
}

function Get-DotNetShortLabel {
    param([string]$Path)
    return ($Path -replace [regex]::Escape("HKLM:\SOFTWARE\"), "")
}

# [NEW v2.2.1] Compact console tag — the full registry path
# ("Wow6432Node\Microsoft\.NETFramework\v4.0.30319", 48 characters) is
# kept as-is in the JSON/HTML (export traceability), but made the console
# table's "Item" column unmanageable (it would have needed a fixed width
# of ~50 characters, wasted across all OTHER categories). This version only
# keeps what actually distinguishes the locations from each other: the
# .NET version and native/Wow64.
function Get-DotNetConsoleTag {
    param([string]$Path)
    $VerMatch = [regex]::Match($Path, 'v[\d\.]+$')
    $Ver      = if ($VerMatch.Success) { $VerMatch.Value } else { $Path }
    $Bits     = if ($Path -match "Wow6432Node") { "Wow64" } else { "native" }
    return "$Ver ($Bits)"
}

function Show-DotNetState {
    param([array]$States)
    foreach ($S in $States) {
        $Tag = Get-DotNetConsoleTag -Path $S.Path
        if ($S.Applied) {
            Write-Step "Strong Crypto already active" -Level OK -Category ".NET Framework" -Item $Tag
        } else {
            Write-Step "absent or incomplete (will be enabled)" -Level WARN -Category ".NET Framework" -Item $Tag
        }
    }
}

function Invoke-DotNetHardening {
    param([array]$States, [switch]$ForceAll, [switch]$IsDryRun, [bool]$Elevated)

    $Results = @(); $Applied = 0; $Errors = 0; $Skipped = 0

    foreach ($S in $States) {
        $Label       = Get-DotNetShortLabel -Path $S.Path
        $Tag         = Get-DotNetConsoleTag -Path $S.Path
        $NeedsChange = (-not $S.Applied) -or $ForceAll
        $BeforeTxt   = "SchUseStrongCrypto=$($S.Ssc), SystemDefaultTlsVersions=$($S.Sdtv)"

        if (-not $NeedsChange) {
            Write-Step "Strong Crypto already active, no change" -Level OK -Category ".NET Framework" -Item $Tag
            $Skipped++
            $Results += [PSCustomObject]@{
                Category = ".NET Framework"; Item = $Label
                Value    = "SchUseStrongCrypto=1, SystemDefaultTlsVersions=1 (already compliant)"; Status = "OK"
            }
            continue
        }

        if ($IsDryRun) {
            Write-Step "[DRY-RUN] Strong Crypto would be enabled (current state: $BeforeTxt)" -Level DRY -Category ".NET Framework" -Item $Tag
            $Results += [PSCustomObject]@{
                Category = ".NET Framework"; Item = $Label
                Value    = "Current state: $BeforeTxt [DRY-RUN, not changed]"
                Status    = if ($S.Applied) { "OK" } else { "WARNING" }
            }
            continue
        }

        if (-not $Elevated) {
            Write-Step "elevation required to apply" -Level FAIL -Category ".NET Framework" -Item $Tag
            $Errors++
            $Results += [PSCustomObject]@{
                Category = ".NET Framework"; Item = $Label
                Value    = "Not applied: administrator elevation required (current state: $BeforeTxt)"; Status = "ERROR"
            }
            continue
        }

        try {
            # [FIX v2.1.1] See the detailed note in Invoke-DhHardening.
            if (-not (Test-Path -LiteralPath $S.Path)) {
                New-Item -Path $S.Path -Force | Out-Null
            }
            New-ItemProperty -Path $S.Path -Name "SchUseStrongCrypto"       -Value 1 -PropertyType DWord -Force | Out-Null
            New-ItemProperty -Path $S.Path -Name "SystemDefaultTlsVersions" -Value 1 -PropertyType DWord -Force | Out-Null
            $VerifSsc  = Get-RegValue -Path $S.Path -Name "SchUseStrongCrypto"
            $VerifSdtv = Get-RegValue -Path $S.Path -Name "SystemDefaultTlsVersions"

            if ([int]$VerifSsc -eq 1 -and [int]$VerifSdtv -eq 1) {
                Write-Step "Strong Crypto enabled" -Level OK -Category ".NET Framework" -Item $Tag
                $Applied++
                $Results += [PSCustomObject]@{
                    Category = ".NET Framework"; Item = $Label
                    Value    = "SchUseStrongCrypto=1, SystemDefaultTlsVersions=1 (before: $BeforeTxt)"; Status = "OK"
                }
            } else {
                Write-Step "unexpected values re-read (Ssc=$VerifSsc, Sdtv=$VerifSdtv)" -Level FAIL -Category ".NET Framework" -Item $Tag
                $Errors++
                $Results += [PSCustomObject]@{
                    Category = ".NET Framework"; Item = $Label
                    Value    = "Unexpected values re-read: SchUseStrongCrypto=$VerifSsc, SystemDefaultTlsVersions=$VerifSdtv"; Status = "ERROR"
                }
            }
        } catch {
            Write-Step "ERROR: $($_.Exception.Message)" -Level FAIL -Category ".NET Framework" -Item $Tag
            $Errors++
            $Results += [PSCustomObject]@{
                Category = ".NET Framework"; Item = $Label
                Value    = "Write failed: $($_.Exception.Message)"; Status = "ERROR"
            }
        }
    }

    return [PSCustomObject]@{ Results = $Results; Applied = $Applied; Errors = $Errors; Skipped = $Skipped }
}

# ──────────────────────────────────────────────
#  [NEW v2.0] GPO DETECTION — read-only, never blocking
# ──────────────────────────────────────────────
function Test-TlsGpoOverride {
    # [FIX v2.1.1] Checks for the presence of the "Functions" VALUE within the
    # "SSL Cipher Suite Order" policy key, not just the existence of the key
    # itself. An empty key (no Functions value) defines no suite order at
    # all — a plain Test-Path on the key gave a false positive (observed
    # under real conditions: the key exists, empty, with no active policy).
    # Never modifies anything: only serves to avoid a false sense of
    # compliance on a machine where a policy could redefine the cipher
    # suite order on the next refresh.
    $Findings = @()
    $GpoCipherOrderPath = "HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002"
    if (Test-RegValueExists -Path $GpoCipherOrderPath -Name "Functions") {
        $Findings += "A (local or group) policy defines the SSL/TLS cipher suite order ('SSL Cipher Suite Order', active Functions value). It may override this script's settings."
    }
    # [FIX v2.0] "return $Findings" flattens a 1-element array into a plain
    # string (standard PowerShell behavior on function output) — the unary
    # "," operator forces the output to stay a real array, regardless of
    # element count (0, 1, or several), so any caller can use .Count safely
    # under Set-StrictMode.
    return ,$Findings
}

function Show-GpoFindings {
    param([array]$Findings)
    if ($Findings.Count -gt 0) {
        foreach ($F in $Findings) { Write-Step $F -Level WARN -Category "GPO Policy" }
    } else {
        Write-Step "no known GPO on cipher suite order" -Level OK -Category "GPO Policy"
    }
    # Static note: the protocols/ciphers/hashes disabled by this script
    # share the SAME registry path as certain "Turn off TLS 1.0/1.1"
    # policies — on a domain-joined machine, any doubt about a possible
    # redefinition can be resolved with `gpresult /h`.
    Write-Step "if in doubt on a domain-joined machine: 'gpresult /h'" -Level INFO -Category "GPO Policy"
}

# ──────────────────────────────────────────────
#  [NEW v2.0] ORCHESTRATION — groups the 5 categories
# ──────────────────────────────────────────────
function Get-AllHardeningStates {
    return [PSCustomObject]@{
        Protocols = Get-TlsControlState
        Ciphers   = Get-BinaryHardeningState -BasePath $CipherBase -Items $WeakCiphers -Label "Cipher"
        Hashes    = Get-BinaryHardeningState -BasePath $HashBase   -Items $WeakHashes  -Label "Hash"
        Dh        = Get-DhState
        DotNet    = Get-DotNetState
    }
}

function Show-AllHardeningStates {
    param([PSCustomObject]$All)
    Write-Host "  ── Protocols (TLS 1.0/1.1) ───────────────────" -ForegroundColor DarkGray
    Show-TlsControlState -States $All.Protocols
    Write-Host ""
    Write-Host "  ── Obsolete cipher suites ────────────────────" -ForegroundColor DarkGray
    Show-BinaryState -States $All.Ciphers
    Write-Host ""
    Write-Host "  ── Obsolete hash algorithms ──────────────────" -ForegroundColor DarkGray
    Show-BinaryState -States $All.Hashes
    Write-Host ""
    Write-Host "  ── Diffie-Hellman (minimum key length) ───────" -ForegroundColor DarkGray
    Show-DhState -States $All.Dh
    Write-Host ""
    Write-Host "  ── .NET Framework (Strong Crypto) ────────────" -ForegroundColor DarkGray
    Show-DotNetState -States $All.DotNet
    Write-Host ""
    Write-Host "  ── Group Policy ───────────────────────────────" -ForegroundColor DarkGray
    Show-GpoFindings -Findings (Test-TlsGpoOverride)
}

function Invoke-AllHardening {
    param([PSCustomObject]$All, [switch]$ForceAll, [switch]$IsDryRun, [bool]$Elevated)

    $ProtoOutcome  = Invoke-TlsHardening    -States $All.Protocols -ForceAll:$ForceAll -IsDryRun:$IsDryRun -Elevated $Elevated
    $CipherOutcome = Invoke-BinaryHardening -States $All.Ciphers   -ForceAll:$ForceAll -IsDryRun:$IsDryRun -Elevated $Elevated
    $HashOutcome   = Invoke-BinaryHardening -States $All.Hashes    -ForceAll:$ForceAll -IsDryRun:$IsDryRun -Elevated $Elevated
    $DhOutcome     = Invoke-DhHardening     -States $All.Dh        -ForceAll:$ForceAll -IsDryRun:$IsDryRun -Elevated $Elevated
    $DotNetOutcome = Invoke-DotNetHardening -States $All.DotNet    -ForceAll:$ForceAll -IsDryRun:$IsDryRun -Elevated $Elevated

    $AllResults = @() + $ProtoOutcome.Results + $CipherOutcome.Results + $HashOutcome.Results + $DhOutcome.Results + $DotNetOutcome.Results
    # [FIX v2.1.0] NO @() here: Test-TlsGpoOverride already guarantees a real
    # array via "return ,$Findings" (unary comma operator). Wrapping it a
    # second time with @() created an array INSIDE an array — $Findings then
    # had .Count=1 by accident (so detection still worked), but "-join" on
    # that nested array fell back to .ToString() of its single element (the
    # inner array), literally producing "System.Object[]" in the report
    # instead of the warning text.
    $Findings   = Test-TlsGpoOverride
    $AllResults += [PSCustomObject]@{
        Category = "Group Policy"; Item = "SSL Cipher Suite Order (GPO)"
        Value    = if ($Findings.Count -gt 0) { $Findings -join " " } else { "No known GPO detected" }
        Status    = if ($Findings.Count -gt 0) { "WARNING" } else { "OK" }
    }

    $Applied = $ProtoOutcome.Applied + $CipherOutcome.Applied + $HashOutcome.Applied + $DhOutcome.Applied + $DotNetOutcome.Applied
    $Skipped = $ProtoOutcome.Skipped + $CipherOutcome.Skipped + $HashOutcome.Skipped + $DhOutcome.Skipped + $DotNetOutcome.Skipped
    $Errors  = $ProtoOutcome.Errors  + $CipherOutcome.Errors  + $HashOutcome.Errors  + $DhOutcome.Errors  + $DotNetOutcome.Errors

    return [PSCustomObject]@{ Results = $AllResults; Applied = $Applied; Errors = $Errors; Skipped = $Skipped }
}

# ──────────────────────────────────────────────
#  [NEW v2.0] ROLLBACK (-Undo) — revert to Windows defaults
#  Remove-Item on the keys dedicated to this script (Protocols/Ciphers/Hashes —
#  single-purpose subkeys, no risk of removing anything else).
#  Remove-ItemProperty on values isolated within keys SHARED with other
#  settings (Diffie-Hellman, .NET) — the key itself is never removed in
#  that case.
# ──────────────────────────────────────────────
function Get-TlsRollbackActions {
    $Actions = @()
    foreach ($proto in $ProtosToDisable) {
        foreach ($role in $Roles) {
            $Actions += [PSCustomObject]@{ Type = "Key"; Path = "$ProtocolBase\$proto\$role"; Description = "Protocol $proto ($role)" }
        }
    }
    foreach ($c in $WeakCiphers) {
        $Actions += [PSCustomObject]@{ Type = "Key"; Path = "$CipherBase\$c"; Description = "Cipher $c" }
    }
    foreach ($h in $WeakHashes) {
        $Actions += [PSCustomObject]@{ Type = "Key"; Path = "$HashBase\$h"; Description = "Hash $h" }
    }
    foreach ($valueName in @("ClientMinKeyBitLength", "ServerMinKeyBitLength")) {
        $Actions += [PSCustomObject]@{ Type = "Value"; Path = $DhPath; ValueName = $valueName; Description = "Diffie-Hellman $valueName" }
    }
    foreach ($path in (Get-DotNetPaths)) {
        foreach ($valueName in @("SchUseStrongCrypto", "SystemDefaultTlsVersions")) {
            $Actions += [PSCustomObject]@{
                Type = "Value"; Path = $path; ValueName = $valueName
                Description = ".NET $(Get-DotNetShortLabel -Path $path) / $valueName"
            }
        }
    }
    return $Actions
}

function Invoke-TlsRollback {
    param([switch]$IsDryRun, [bool]$Elevated)

    $Results = @(); $Removed = 0; $Errors = 0; $Skipped = 0

    foreach ($A in (Get-TlsRollbackActions)) {
        $Exists = if ($A.Type -eq "Key") {
            Test-Path -LiteralPath $A.Path
        } else {
            (Test-RegValueExists -Path $A.Path -Name $A.ValueName)
        }

        if (-not $Exists) {
            $Skipped++
            $Results += [PSCustomObject]@{ Category = "Rollback"; Item = $A.Description; Value = "Already absent (nothing to undo)"; Status = "OK" }
            continue
        }

        if ($IsDryRun) {
            Write-Step "[DRY-RUN] $($A.Description) — would be removed" -Level DRY -Category "Rollback"
            $Results += [PSCustomObject]@{ Category = "Rollback"; Item = $A.Description; Value = "Present [DRY-RUN, not removed]"; Status = "WARNING" }
            continue
        }

        if (-not $Elevated) {
            Write-Step "$($A.Description) — elevation required to undo" -Level FAIL -Category "Rollback"
            $Errors++
            $Results += [PSCustomObject]@{ Category = "Rollback"; Item = $A.Description; Value = "Not reverted: administrator elevation required"; Status = "ERROR" }
            continue
        }

        try {
            if ($A.Type -eq "Key") {
                Remove-Item -LiteralPath $A.Path -Recurse -Force -ErrorAction Stop
            } else {
                Remove-ItemProperty -LiteralPath $A.Path -Name $A.ValueName -Force -ErrorAction Stop
            }
            Write-Step "$($A.Description) — removed, reverted to Windows default" -Level OK -Category "Rollback"
            $Removed++
            $Results += [PSCustomObject]@{ Category = "Rollback"; Item = $A.Description; Value = "Removed (reverted to Windows default)"; Status = "OK" }
        } catch {
            Write-Step "$($A.Description) — ERROR: $($_.Exception.Message)" -Level FAIL -Category "Rollback"
            $Errors++
            $Results += [PSCustomObject]@{ Category = "Rollback"; Item = $A.Description; Value = "Removal failed: $($_.Exception.Message)"; Status = "ERROR" }
        }
    }

    return [PSCustomObject]@{ Results = $Results; Removed = $Removed; Errors = $Errors; Skipped = $Skipped }
}

function Get-AllResultsSnapshot {
    # [NEW v2.1.0] Read-only: builds the same results schema
    # (Category/Item/Value/Status) as Invoke-AllHardening, but without
    # applying anything — for "current state" reports (menu [4]/[7]) without
    # having to run an actual apply pass or a full DryRun. Replaces the
    # construction that was previously duplicated hardcoded in the menu
    # (JSON option).
    param([PSCustomObject]$All)

    $Results = @()
    foreach ($S in $All.Protocols) {
        $Results += [PSCustomObject]@{
            Category = "Protocol"; Item = "$($S.Proto) ($($S.Role))"
            Value    = if ($S.Applied) { "Enabled=0, DisabledByDefault=1" } elseif ($S.KeyExists) { "Enabled=$($S.Enabled), DisabledByDefault=$($S.Dbd)" } else { "Key absent (Windows default)" }
            Status    = if ($S.Applied) { "OK" } else { "WARNING" }
        }
    }
    foreach ($S in (@($All.Ciphers) + @($All.Hashes))) {
        $Results += [PSCustomObject]@{
            Category = $S.Label; Item = $S.Item
            Value    = if ($S.Applied) { "Enabled=0" } elseif ($S.KeyExists) { "Enabled=$($S.Enabled)" } else { "Key absent (Windows default)" }
            Status    = if ($S.Applied) { "OK" } else { "WARNING" }
        }
    }
    foreach ($S in $All.Dh) {
        $Results += [PSCustomObject]@{
            Category = "Diffie-Hellman"; Item = "Minimum key length ($($S.Role))"
            Value    = if ($null -ne $S.Value) { "$($S.Value) bits" } else { "Not set (Windows default)" }
            Status    = if ($S.Applied) { "OK" } else { "WARNING" }
        }
    }
    foreach ($S in $All.DotNet) {
        $Results += [PSCustomObject]@{
            Category = ".NET Framework"; Item = (Get-DotNetShortLabel -Path $S.Path)
            Value    = "SchUseStrongCrypto=$($S.Ssc), SystemDefaultTlsVersions=$($S.Sdtv)"
            Status    = if ($S.Applied) { "OK" } else { "WARNING" }
        }
    }
    $Findings = Test-TlsGpoOverride
    $Results += [PSCustomObject]@{
        Category = "Group Policy"; Item = "SSL Cipher Suite Order (GPO)"
        Value    = if ($Findings.Count -gt 0) { $Findings -join " " } else { "No known GPO detected" }
        Status    = if ($Findings.Count -gt 0) { "WARNING" } else { "OK" }
    }
    return $Results
}

# [NEW v2.1.0] Static HTML template — visual identity taken as-is from
# the Toolbox Commandes Système (dark background, cyan accent, gradient
# Windows logo, stat cards, grouped/filterable table). SINGLE-quoted
# here-string (@'...'@): no PowerShell interpolation in the static CSS/JS,
# the {{...}} tokens are explicitly replaced by Export-TlsHtmlReport.
# Self-contained file (inline CSS/JS): opens in any browser, offline,
# on any machine in the fleet.
$script:TlsHtmlTemplate = @'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{TITLE}}</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:       #080b12;
  --bg2:      #0d1117;
  --bg3:      #111827;
  --bg4:      #1a2235;
  --bg5:      #0a0f1a;
  --border:   #1e2d45;
  --border2:  #243350;
  --accent:   #00d4ff;
  --accent2:  #0099cc;
  --accent3:  #005f80;
  --purple:   #7c6af7;
  --yellow:   #ffb347;
  --green:    #a8ce81;
  --red:      #ef7066;
  --text:     #e2e8f0;
  --text2:    #94a3b8;
  --text3:    #475569;
}
body{background:var(--bg);color:var(--text);font-family:'Segoe UI',system-ui,sans-serif;font-size:13px;line-height:1.6;min-height:100vh}
::-webkit-scrollbar{width:12px;height:12px}
::-webkit-scrollbar-track{background:var(--bg2)}
::-webkit-scrollbar-thumb{background:var(--border2);border-radius:6px;border:3px solid var(--bg2)}
::-webkit-scrollbar-thumb:hover{background:var(--accent3)}
header{background:linear-gradient(160deg,#060c1a 0%,#0a1628 50%,#060a14 100%);border-bottom:2px solid var(--accent3);padding:32px 48px 24px;position:relative;overflow:hidden}
header::before{content:'';position:absolute;top:0;left:0;right:0;bottom:0;background:radial-gradient(ellipse at 20% 50%,rgba(0,212,255,.06) 0%,transparent 60%),radial-gradient(ellipse at 80% 20%,rgba(124,106,247,.05) 0%,transparent 50%);pointer-events:none}
.titlerow{display:flex;align-items:flex-end;gap:0;position:relative;z-index:1}
.title-text h1{font-family:'Cascadia Code','Consolas','Courier New',monospace;font-size:26px;font-weight:700;color:var(--accent);text-shadow:0 0 20px rgba(0,212,255,.4);letter-spacing:1px;margin:0 0 10px 0}
.logo-sub{font-family:'Cascadia Code','Consolas',monospace;font-size:12px;color:var(--text2);letter-spacing:2px;margin-bottom:14px}
.logo-sub b{color:var(--accent)}
.meta-bar{display:flex;flex-wrap:wrap;gap:8px 24px;font-size:11.5px;color:var(--text3);border-top:1px solid var(--border);padding-top:12px;margin-top:4px;position:relative;z-index:1}
.meta-bar span{display:flex;align-items:center;gap:6px}
.meta-bar b{color:var(--text2)}
.meta-dot{width:5px;height:5px;border-radius:50%;background:var(--accent);display:inline-block;box-shadow:0 0 6px var(--accent)}
main{padding:24px 48px 64px}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px;margin-bottom:22px}
.stat-card{background:var(--bg3);border:1px solid var(--border);border-radius:8px;padding:14px 16px}
.stat-card .num{font-size:22px;font-weight:700;color:var(--accent);line-height:1.2}
.stat-card .lbl{font-size:11px;color:var(--text3);text-transform:uppercase;letter-spacing:.05em;margin-top:2px}
.stat-card.warn .num{color:var(--yellow)}
.stat-card.err .num{color:var(--red)}
.stat-card.ok .num{color:var(--green)}
.searchbar{margin-bottom:18px;position:sticky;top:12px;z-index:5}
.searchbar input{width:100%;max-width:380px;padding:10px 14px;background:var(--bg3);border:1px solid var(--border2);color:var(--text);border-radius:6px;font-size:13px;transition:border-color .15s,box-shadow .15s}
.searchbar input::placeholder{color:var(--text3)}
.searchbar input:focus{outline:none;border-color:var(--accent);box-shadow:0 0 0 3px rgba(0,212,255,.12)}
table{border-collapse:collapse;width:100%}
th,td{padding:9px 12px;border-bottom:1px solid var(--border);text-align:left;font-size:13px;vertical-align:top}
th{color:var(--accent);text-transform:uppercase;font-size:11px;letter-spacing:.05em;background:var(--bg5);position:sticky;top:52px}
tr.row{transition:background-color .1s}
tr.row:hover{background:var(--bg3)}
tr.row.warn{background:rgba(255,179,71,.06)}
tr.row.warn:hover{background:rgba(255,179,71,.12)}
tr.row.err{background:rgba(239,112,102,.08)}
tr.row.err:hover{background:rgba(239,112,102,.14)}
tr.daysep{cursor:pointer;user-select:none}
tr.daysep td{background:var(--bg4);color:var(--accent);font-weight:700;font-size:12.5px;text-transform:uppercase;letter-spacing:.05em;padding:12px;border-bottom:1px solid var(--border2)}
tr.daysep:hover td{background:#212c45}
tr.daysep .count{color:var(--text3);font-weight:400;text-transform:none;letter-spacing:normal;margin-left:8px}
.chevron{display:inline-block;margin-right:8px;transition:transform .18s;color:var(--purple)}
tr.daysep.collapsed .chevron{transform:rotate(-90deg)}
.label-ok{color:var(--green);font-weight:600}
.label-ok::before{content:"✓ "}
.label-warn{color:var(--yellow);font-weight:600}
.label-warn::before{content:"⚠ "}
.label-err{color:var(--red);font-weight:600}
.label-err::before{content:"✖ "}
code{color:var(--accent2);background:var(--bg4);padding:2px 6px;border-radius:4px;font-family:Consolas,'Cascadia Code',monospace;font-size:12px;word-break:break-all}
</style>
</head>
<body>

<header>
  <div class="titlerow">
    <div class="title-text">
      <h1>{{TITLE}}</h1>
      <div class="logo-sub">{{SUBTITLE}}</div>
    </div>
    <svg xmlns="http://www.w3.org/2000/svg" viewBox="9.39 8.477 484.197 428.149" style="width:76px;height:76px;margin-left:24px;align-self:flex-end;filter:drop-shadow(0 0 12px rgba(0,212,255,.4));flex-shrink:0"><path d="m347.015 235.334 42.877-112.525 67.515 25.727-42.877 112.524z" fill="#a8ce81"/><path d="m303.267 350.143 42.92-112.634 67.514 25.726-42.919 112.634z" fill="#fddb1d"/><path d="m263.921 207.033 42.879-112.525 67.406 25.685-42.877 112.525z" fill="#ef7066"/><path d="m220.505 320.972 42.588-111.764 67.406 25.685-42.588 111.764z" fill="#6eaed7"/><path d="m415.69 247.559c-12.962-10.418-30.606-21.623-53.002-30.158-1.455-.43-2.827-1.077-4.131-1.574l33.307-87.41c1.755.295 3.277.875 4.893 1.864 22.194 8.083 39.661 19.097 52.64 29.147zm-44.284 116.221a216.14 216.14 0 0 0 -53.045-30.048c-1.496-.321-2.91-.86-4.131-1.574l34.136-89.586c1.673.513 3.236.984 4.893 1.865 22.153 8.192 39.62 19.206 52.392 29.8zm122.181-212.166s-25.485-37.351-81.827-59.07c-56.66-21.216-98.7-15.447-98.482-15.364l-15.038 39.466c-.135-.3 27.632-5.533 68.583 3.971l-33.597 88.172c-41.045-9.913-68.776-3.795-68.693-4.013l-10.29 27.33s27.736-7.111 69.123 2.558l-34.717 91.108c-33.74-8.499-58.772-7.828-67.506-6.798l-14.5 38.052c10.873-1.087 47.89-2.17 95.075 15.809 56.467 21.392 82.284 57.873 82.408 57.547zm-241.467-32.87 14.747-38.705 41.45-2.259-14.748 38.705zm-91.514 240.162 14.748-38.704 41.45-2.259-14.5 38.052zm16.364-42.944 13.38-35.117 41.492-2.367-13.423 35.225zm60.11-157.752 13.382-35.118 41.45-2.259-13.381 35.117zm-30.034 78.821 13.381-35.116 41.45-2.26-13.381 35.117zm-15.038 39.466 13.38-35.117 41.45-2.26-13.38 35.117zm30.035-78.823 13.422-35.225 41.45-2.259-13.423 35.225zm-10.213-90.174 11.476-30.115 40.145-2.756-11.766 30.876zm-110.927-84.974 4.93-12.937 16.36-1.112-4.93 12.937zm76.852 67.881 8.99-23.592 35.117-2.306-9.03 23.7zm-28.691-20.768 6.835-17.94 28.455-1.483-6.836 17.94zm-24.068-24.734 5.469-14.351 23.495-.884-5.179 13.59zm40.932 183.057 11.476-30.115 39.855-1.995-11.475 30.115zm-110.927-84.974 4.93-12.938 16.36-1.111-5.178 13.59zm76.852 67.881 9.031-23.7 35.077-2.198-9.032 23.7zm-28.691-20.769 6.835-17.938 28.455-1.484-6.835 17.939zm-24.067-24.734 5.22-13.698 23.743-1.536-5.179 13.59zm41.222 182.297 11.475-30.115 40.145-2.757-11.475 30.116zm-110.927-84.974 5.178-13.59 16.112-.46-4.93 12.938zm77.1 67.229 8.74-22.94 35.119-2.307-8.783 23.05zm-28.691-20.769 6.587-17.287 28.454-1.483-6.587 17.286zm-24.026-24.843 5.178-13.59 23.495-.883-5.178 13.59z" fill="#000101"/><path d="m114.017 84.174 4.889-12.83 17.411-1.582-4.888 12.829zm88.133 61.472 9.529-25.006 32.364-1.612-9.28 24.353zm-34.836-17.383 7.913-20.766 29.355-1.887-7.913 20.766zm-29.271-19.247 6.049-15.873 22.733-1.173-6.007 15.764zm-50.589-48.909 4.102-10.763 12.995-.776-4.101 10.764zm11.525 63.532 4.93-12.938 17.411-1.583-4.93 12.938zm88.133 61.472 9.57-25.114 32.612-2.265-9.528 25.006zm-34.588-18.035 7.664-20.113 29.397-1.996-7.954 20.874zm-29.478-18.703 6.007-15.764 22.734-1.174-5.758 15.112zm-50.63-48.8 4.392-11.525 12.995-.775-4.392 11.524z" fill="#ef7066"/><path d="m68.115 204.635 4.93-12.937 17.122-.822-4.93 12.938zm87.844 62.234 9.57-25.114 32.653-2.374-9.57 25.114zm-34.547-18.144 7.913-20.766 29.107-1.235-7.664 20.113zm-29.229-19.355 5.717-15.004 22.733-1.173-5.717 15.003zm-50.92-48.04 4.391-11.524 12.995-.776-4.35 11.416zm11.814 62.77 4.93-12.937 17.122-.822-4.93 12.938zm88.133 61.473 9.28-24.353 32.654-2.374-9.57 25.115zm-34.836-17.383 7.913-20.765 29.397-1.996-7.955 20.874zm-29.229-19.355 5.717-15.004 23.023-1.934-6.007 15.764zm-50.631-48.801 4.102-10.763 12.995-.775-4.101 10.763z" fill="#6eaed7"/></svg>
  </div>
  <div class="meta-bar">
    <span><span class="meta-dot"></span>Generated on <b>{{DATE}}</b></span>
    <span>Machine: <b>{{MACHINE}}</b></span>
    <span>User: <b>{{USER}}</b></span>
    <span>Windows: <b>{{WINDOWS}}</b></span>
    <span>Mode: <b>{{MODE}}</b></span>
  </div>
</header>

<main>
  <div class="stats">
    <div class="stat-card ok"><div class="num">{{NB_OK}} / {{NB_TOTAL}}</div><div class="lbl">Compliant checks</div></div>
    <div class="stat-card warn"><div class="num">{{NB_WARN}}</div><div class="lbl">Warnings</div></div>
    <div class="stat-card err"><div class="num">{{NB_ERR}}</div><div class="lbl">Errors</div></div>
    <div class="stat-card"><div class="num">{{SCORE}} / 100</div><div class="lbl">Compliance score</div></div>
  </div>

  <div class="searchbar"><input type="text" id="searchBox" placeholder="Filter (category, item, status...)" onkeyup="filterReport()"></div>

  <table>
    <tr><th>Category</th><th>Item</th><th>Detail</th><th>Status</th></tr>
{{ROWS}}
  </table>
</main>

<script>
function toggleGroup(id) {
  var header = document.querySelector('tr.daysep[data-group="' + id + '"]');
  var collapsed = header.classList.toggle('collapsed');
  document.querySelectorAll('tr.row[data-group="' + id + '"]').forEach(function(r) {
    r.style.display = collapsed ? 'none' : '';
  });
}
function filterReport() {
  var filterVal = document.getElementById('searchBox').value.toLowerCase();
  var groups = document.querySelectorAll('tr.daysep');
  if (filterVal === '') {
    groups.forEach(function(g) {
      var id = g.getAttribute('data-group');
      g.classList.remove('collapsed');
      document.querySelectorAll('tr.row[data-group="' + id + '"]').forEach(function(r) {
        r.style.display = '';
      });
    });
    return;
  }
  groups.forEach(function(g) { g.classList.remove('collapsed'); });
  document.querySelectorAll('tr.row').forEach(function(row) {
    var rowText = row.textContent.toLowerCase();
    row.style.display = rowText.indexOf(filterVal) !== -1 ? '' : 'none';
  });
}
</script>
</body>
</html>
'@

function Export-TlsHtmlReport {
    # [NEW v2.1.0] Visual HTML report — same visual identity as the Toolbox
    # Commandes Système. Self-contained file (inline CSS/JS), written next to
    # the JSON in the same folder ($ReportsRoot), never instead of it: the
    # JSON remains the source consumed by Dashboard-Global_Win11.
    param([array]$Results, [int]$Score, [string]$ModeLabel = "Application")

    try {
        if (-not (Test-Path $ReportsRoot)) {
            New-Item -ItemType Directory -Path $ReportsRoot -Force | Out-Null
        }

        $NbOk    = @($Results | Where-Object { $_.Status -eq "OK" }).Count
        $NbWarn  = @($Results | Where-Object { $_.Status -eq "WARNING" }).Count
        $NbErr   = @($Results | Where-Object { $_.Status -eq "ERROR" }).Count
        $NbTotal = @($Results).Count

        # [FIX v2.1.4] The "ProductName" registry key still shows "Windows 10"
        # on many machines migrated to Windows 11 — a known bug, never fixed
        # by Microsoft, the key is simply not updated during the migration.
        # Win32_OperatingSystem (WMI/CIM) stays correct in every case
        # observed; the registry is only used as a fallback if WMI is
        # unavailable (rare, but avoids a crash on an atypical machine).
        $DisplayVersion = Get-RegValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name "DisplayVersion"
        $WindowsLabel = $null
        try {
            $OsCaption = (Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop).Caption
            if ($OsCaption) {
                $WindowsLabel = "$($OsCaption -replace '^Microsoft\s+', '') $DisplayVersion".Trim()
            }
        } catch { }
        if (-not $WindowsLabel) {
            $ProductName  = Get-RegValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name "ProductName"
            $WindowsLabel = if ($ProductName) { "$ProductName $DisplayVersion".Trim() } else { "Windows" }
        }

        # Grouping in the order defined by $CategoryDisplayOrder, then any
        # unexpected category appended afterwards (never a lost row).
        $Categories = @()
        foreach ($cat in $CategoryDisplayOrder) {
            if (@($Results | Where-Object { $_.Category -eq $cat }).Count -gt 0) { $Categories += $cat }
        }
        foreach ($cat in @($Results | Select-Object -ExpandProperty Category -Unique)) {
            if ($Categories -notcontains $cat) { $Categories += $cat }
        }

        $RowsHtml = New-Object System.Text.StringBuilder
        $GroupIdx = 0
        foreach ($cat in $Categories) {
            $GroupItems = @($Results | Where-Object { $_.Category -eq $cat })
            $CatSafe    = ConvertTo-HtmlSafe $cat
            [void]$RowsHtml.AppendLine("<tr class=`"daysep`" data-group=`"$GroupIdx`" onclick=`"toggleGroup($GroupIdx)`"><td colspan=`"4`"><span class=`"chevron`">&#9662;</span>$CatSafe<span class=`"count`">($($GroupItems.Count) check(s))</span></td></tr>")
            foreach ($item in $GroupItems) {
                $ElemSafe    = ConvertTo-HtmlSafe $item.Item
                $ValSafe     = ConvertTo-HtmlSafe $item.Value
                $StatutClass = switch ($item.Status) {
                    "OK"            { "ok" }
                    "WARNING" { "warn" }
                    "ERROR"        { "err" }
                    default         { "warn" }
                }
                $RowClass = switch ($item.Status) {
                    "ERROR"        { "row err" }
                    "WARNING" { "row warn" }
                    default         { "row" }
                }
                [void]$RowsHtml.AppendLine("<tr class=`"$RowClass`" data-group=`"$GroupIdx`"><td>$CatSafe</td><td>$ElemSafe</td><td><code>$ValSafe</code></td><td><span class=`"label-$StatutClass`">$(ConvertTo-HtmlSafe $item.Status)</span></td></tr>")
            }
            $GroupIdx++
        }

        $Timestamp   = Get-Date -Format "yyyyMMdd_HHmmss"
        $DisplayDate = Get-Date -Format "dd MMM yyyy HH:mm:ss"
        $HtmlPath     = "$ReportsRoot\Rapport_Harden-TLS_$Timestamp.html"

        $Html = $script:TlsHtmlTemplate
        $Html = $Html.Replace("{{TITLE}}",    "Harden-TLS v$ScriptVersion")
        $Html = $Html.Replace("{{SUBTITLE}}", "by <b>Nephren</b>")
        $Html = $Html.Replace("{{DATE}}",     $DisplayDate)
        $Html = $Html.Replace("{{MACHINE}}",  (ConvertTo-HtmlSafe $env:COMPUTERNAME))
        $Html = $Html.Replace("{{USER}}",     (ConvertTo-HtmlSafe $env:USERNAME))
        $Html = $Html.Replace("{{WINDOWS}}",  (ConvertTo-HtmlSafe $WindowsLabel))
        $Html = $Html.Replace("{{MODE}}",     (ConvertTo-HtmlSafe $ModeLabel))
        $Html = $Html.Replace("{{NB_OK}}",    "$NbOk")
        $Html = $Html.Replace("{{NB_TOTAL}}", "$NbTotal")
        $Html = $Html.Replace("{{NB_WARN}}",  "$NbWarn")
        $Html = $Html.Replace("{{NB_ERR}}",   "$NbErr")
        $Html = $Html.Replace("{{SCORE}}",    "$Score")
        $Html = $Html.Replace("{{ROWS}}",     $RowsHtml.ToString())

        $Html | Out-File $HtmlPath -Encoding UTF8
        Write-Step "HTML export written: $HtmlPath" -Level INFO
        return $HtmlPath
    } catch {
        Write-Step "HTML export failed: $($_.Exception.Message)" -Level WARN
        return $null
    }
}

function Export-TlsReport {
    # Writes Baseline_Harden-TLS.json (score history) and Rapport_Harden-TLS_<timestamp>.json
    # (per-check detail) — ALWAYS called, even when nothing was changed, so that
    # Dashboard-Global_Win11 (Get-TLSModule) has an up-to-date state.
    param([array]$Results)
    try {
        if (-not (Test-Path $ReportsRoot)) {
            New-Item -ItemType Directory -Path $ReportsRoot -Force | Out-Null
        }

        $NbOk    = @($Results | Where-Object { $_.Status -eq "OK" }).Count
        $NbTotal = @($Results).Count
        # [Math]::Round() returns a [double] — explicit cast to [int], otherwise the score
        # serializes as "83.0" instead of 83 in the JSON.
        $Score = if ($NbTotal -gt 0) { [int][Math]::Round(100 * $NbOk / $NbTotal) } else { 0 }

        $Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $ReportPath = "$ReportsRoot\Rapport_Harden-TLS_$Timestamp.json"
        $Results | ConvertTo-Json -Depth 4 | Out-File $ReportPath -Encoding UTF8

        $PrevBaseline    = if (Test-Path $BaselinePath) { Get-Content $BaselinePath -Raw | ConvertFrom-Json } else { $null }
        $ExistingHistory = if ($PrevBaseline -and $PrevBaseline.ScoreHistory) { $PrevBaseline.ScoreHistory } else { @() }
        $NewPoint        = [PSCustomObject]@{ Date = (Get-Date -Format "yyyy-MM-dd HH:mm"); Score = $Score }
        # @() around the call, not just on the function's return — a history
        # with a single point would otherwise unroll into a scalar object on the output stream.
        $NewHistory = @(Update-TlsScoreHistory -ExistingHistory $ExistingHistory -NewPoint $NewPoint -MaxPoints 30)

        [PSCustomObject]@{
            LastRun      = (Get-Date -Format "yyyy-MM-dd HH:mm")
            LastScore    = $Score
            ScoreHistory = $NewHistory
        } | ConvertTo-Json -Depth 4 | Out-File $BaselinePath -Encoding UTF8

        Remove-OldTlsReports -Folder $ReportsRoot -Days $RetainReportsDays

        Write-Step "JSON export written: $ReportPath (score $Score/100)" -Level INFO
        return $Score
    } catch {
        Write-Step "JSON export failed: $($_.Exception.Message)" -Level WARN
        return $null
    }
}

# ──────────────────────────────────────────────
#  SELFTEST (pure tests — no registry access)
# ──────────────────────────────────────────────
if ($SelfTest) {
    $script:TestsTotal  = 0
    $script:TestsPassed = 0
    function Assert-True {
        param([string]$Name, [bool]$Condition)
        $script:TestsTotal++
        if ($Condition) {
            $script:TestsPassed++
            Write-Host "  [OK]   $Name" -ForegroundColor Green
        } else {
            Write-Host "  [FAIL] $Name" -ForegroundColor Red
        }
    }

    Write-Host ""
    Write-Host "=========================================================" -ForegroundColor Cyan
    Write-Host " SELFTEST - Harden-TLS v$ScriptVersion"
    Write-Host "=========================================================" -ForegroundColor Cyan

    # --- Update-TlsScoreHistory ---
    $H0 = @(Update-TlsScoreHistory -ExistingHistory @() -NewPoint ([PSCustomObject]@{Date="j1";Score=90}))
    Assert-True "Update-TlsScoreHistory: empty history -> 1 point (stays an array)" ($H0 -is [array] -and $H0.Count -eq 1)

    $H1 = @(Update-TlsScoreHistory -ExistingHistory $H0 -NewPoint ([PSCustomObject]@{Date="j2";Score=95}))
    Assert-True "Update-TlsScoreHistory: 1 existing point -> 2 points (no unrolling)" ($H1 -is [array] -and $H1.Count -eq 2)

    $Long = @()
    for ($i = 1; $i -le 35; $i++) { $Long = @(Update-TlsScoreHistory -ExistingHistory $Long -NewPoint ([PSCustomObject]@{Date="j$i";Score=$i}) -MaxPoints 30) }
    Assert-True "Update-TlsScoreHistory: truncation at MaxPoints=30" ($Long.Count -eq 30)
    Assert-True "Update-TlsScoreHistory: truncation keeps the most RECENT points" ($Long[-1].Score -eq 35)

    # [FIX v1.2.1] History polluted by a $null (real case encountered on 08/07/2026 in
    # Baseline_Harden-TLS.json - probably leftover from an earlier version): the $null must
    # never end up in the result, regardless of its position in the existing
    # history.
    $HPollueDebut = @(Update-TlsScoreHistory -ExistingHistory @($null, [PSCustomObject]@{Date="j1";Score=100}) -NewPoint ([PSCustomObject]@{Date="j2";Score=95}))
    Assert-True "Update-TlsScoreHistory: leading null in history filtered out (2 points, not 3)" ($HPollueDebut.Count -eq 2)
    Assert-True "Update-TlsScoreHistory: no null remains in the result" (@($HPollueDebut | Where-Object { $null -eq $_ }).Count -eq 0)

    # --- Get-TlsControlState / Invoke-TlsHardening (pure logic, no real registry access) ---
    $FakeStateOk       = [PSCustomObject]@{ Proto="TLS 1.0"; Role="Client"; KeyExists=$true;  Enabled=0;    Dbd=1;    Applied=$true }
    $FakeStateKo       = [PSCustomObject]@{ Proto="TLS 1.0"; Role="Server"; KeyExists=$true;  Enabled=1;    Dbd=1;    Applied=$false }
    $FakeStateAbsent   = [PSCustomObject]@{ Proto="TLS 1.1"; Role="Client"; KeyExists=$false; Enabled=$null; Dbd=$null; Applied=$false }

    $DryRes = Invoke-TlsHardening -States @($FakeStateOk, $FakeStateKo) -IsDryRun -Elevated $false
    Assert-True "Invoke-TlsHardening (DryRun): already-compliant check -> Skipped, not Applied" ($DryRes.Skipped -eq 1 -and $DryRes.Applied -eq 0)
    Assert-True "Invoke-TlsHardening (DryRun): non-compliant check -> no write (Errors=0)" ($DryRes.Errors -eq 0)

    $NonElevRes = Invoke-TlsHardening -States @($FakeStateKo) -Elevated $false
    Assert-True "Invoke-TlsHardening (not elevated, non-compliant check): ERROR, no write attempted" ($NonElevRes.Errors -eq 1 -and $NonElevRes.Applied -eq 0)

    $AlreadyOkRes = Invoke-TlsHardening -States @($FakeStateOk) -Elevated $true
    Assert-True "Invoke-TlsHardening (elevated, already compliant, no Force): Skipped, no write attempted" ($AlreadyOkRes.Skipped -eq 1 -and $AlreadyOkRes.Applied -eq 0)

    Assert-True "Invoke-TlsHardening: Results has exactly 1 entry per check passed" (@($DryRes.Results).Count -eq 2)

    # --- Score calculation (explicit [int] cast, see [Math]::Round() -> double bug) ---
    $ScoreTest = [int][Math]::Round((3 / 4) * 100)
    Assert-True "Score: explicit cast to [int] (not a [double])" ($ScoreTest.GetType().Name -eq "Int32")
    Assert-True "Score: 3/4 checks OK -> 75" ($ScoreTest -eq 75)

    # --- [NEW v2.0] Invoke-BinaryHardening (Ciphers/Hashes, pure logic) ---
    $FakeCipherOk  = [PSCustomObject]@{ Label="Cipher"; Item="RC4 128/128"; Path="HKLM:\FAKE\RC4"; KeyExists=$true;  Enabled=0;    Applied=$true }
    $FakeCipherKo  = [PSCustomObject]@{ Label="Cipher"; Item="NULL";        Path="HKLM:\FAKE\NUL"; KeyExists=$false; Enabled=$null; Applied=$false }
    $CipherDryRes  = Invoke-BinaryHardening -States @($FakeCipherOk, $FakeCipherKo) -IsDryRun -Elevated $false
    Assert-True "Invoke-BinaryHardening (DryRun): already compliant -> Skipped, not Applied" ($CipherDryRes.Skipped -eq 1 -and $CipherDryRes.Applied -eq 0)
    Assert-True "Invoke-BinaryHardening (DryRun): no write (Errors=0)" ($CipherDryRes.Errors -eq 0)

    # --- [NEW v2.0] Invoke-DhHardening (pure logic) ---
    $FakeDhOk = [PSCustomObject]@{ Role="Client"; ValueName="ClientMinKeyBitLength"; KeyExists=$true;  Value=2048; Applied=$true }
    $FakeDhKo = [PSCustomObject]@{ Role="Server"; ValueName="ServerMinKeyBitLength"; KeyExists=$true;  Value=1024; Applied=$false }
    $DhDryRes = Invoke-DhHardening -States @($FakeDhOk, $FakeDhKo) -IsDryRun -Elevated $false
    Assert-True "Invoke-DhHardening (DryRun): 1024 bits -> non-compliant, no write" ($DhDryRes.Skipped -eq 1 -and $DhDryRes.Applied -eq 0 -and $DhDryRes.Errors -eq 0)

    # --- [NEW v2.0] Invoke-TlsRollback: an already-absent action doesn't count as Removed ---
    # (indirect check via Get-TlsRollbackActions: the list must cover the 5 categories)
    $RollbackActions = Get-TlsRollbackActions
    Assert-True "Get-TlsRollbackActions: covers Protocols + Ciphers + Hashes + DH + .NET" (
        (@($RollbackActions | Where-Object { $_.Description -like "Protocol*" }).Count -eq 4) -and
        (@($RollbackActions | Where-Object { $_.Description -like "Cipher*" }).Count -eq $WeakCiphers.Count) -and
        (@($RollbackActions | Where-Object { $_.Description -like "Hash*" }).Count -eq $WeakHashes.Count) -and
        (@($RollbackActions | Where-Object { $_.Description -like "Diffie-Hellman*" }).Count -eq 2)
    )

    Write-Host ""
    Write-Host "=========================================================" -ForegroundColor Cyan
    Write-Host " RESULT: $script:TestsPassed / $script:TestsTotal tests passed" -ForegroundColor $(if ($script:TestsPassed -eq $script:TestsTotal) { "Green" } else { "Red" })
    Write-Host "=========================================================" -ForegroundColor Cyan
    Write-Host ""
    exit $(if ($script:TestsPassed -eq $script:TestsTotal) { 0 } else { 1 })
}

# ──────────────────────────────────────────────
#  INTERACTIVE MODE (-Menu, or no parameter supplied)
# ──────────────────────────────────────────────
function Show-TlsMenu {
    param([bool]$MenuDryRun)

    Clear-Host
    $All        = Get-AllHardeningStates
    $AllStates  = @($All.Protocols) + @($All.Ciphers) + @($All.Hashes) + @($All.Dh) + @($All.DotNet)
    $NbCompliant = @($AllStates | Where-Object { $_.Applied }).Count
    $Elevated   = Test-IsElevated

    Write-Banner -Title "HARDEN-TLS  v$ScriptVersion  — INTERACTIVE MODE" -Color Cyan
    Write-Host ""
    Write-ComplianceGauge -Compliant $NbCompliant -Total $AllStates.Count
    Write-Host "                      (protocols + ciphers + hashes + DH + .NET)" -ForegroundColor DarkGray
    Write-Host "  DryRun mode         " -NoNewline -ForegroundColor Gray
    Write-Host "$(if ($MenuDryRun) { 'ENABLED (no real write)' } else { 'disabled' })" -ForegroundColor $(if ($MenuDryRun) { "Magenta" } else { "DarkGray" })
    Write-Host "  Elevation           " -NoNewline -ForegroundColor Gray
    Write-Host "$(if ($Elevated) { 'Administrator' } else { 'Standard user (real apply not possible)' })" -ForegroundColor $(if ($Elevated) { "Green" } else { "Yellow" })
    Write-Host ""

    Show-AllHardeningStates -All $All

    Write-Host ""
    Write-Host ("  " + ("─" * $script:BannerWidth)) -ForegroundColor DarkCyan
    Write-Host "   [1] " -NoNewline -ForegroundColor White
    Write-Host "Show detailed state (read-only)" -ForegroundColor Gray
    Write-Host "   [2] " -NoNewline -ForegroundColor Yellow
    Write-Host "Apply hardening (only what's missing)" -ForegroundColor Gray
    Write-Host "   [3] " -NoNewline -ForegroundColor Yellow
    Write-Host "Force a full re-application (even if already compliant)" -ForegroundColor Gray
    Write-Host "   [4] " -NoNewline -ForegroundColor Cyan
    Write-Host "Generate / refresh the JSON report (without changing anything)" -ForegroundColor Gray
    Write-Host "   [5] " -NoNewline -ForegroundColor Cyan
    Write-Host "Check for group policy conflicts (read-only)" -ForegroundColor Gray
    Write-Host "   [6] " -NoNewline -ForegroundColor Red
    Write-Host "Undo hardening -Undo- (revert to Windows defaults)" -ForegroundColor Gray
    Write-Host "   [7] " -NoNewline -ForegroundColor Cyan
    Write-Host "Export to HTML (visual report, Toolbox style)" -ForegroundColor Gray
    Write-Host ("  " + ("─" * $script:BannerWidth)) -ForegroundColor DarkCyan
    Write-Host "   [D] " -NoNewline -ForegroundColor DarkGray
    Write-Host "Toggle DryRun mode (currently: $(if ($MenuDryRun) { 'enabled' } else { 'disabled' }))" -ForegroundColor DarkGray
    Write-Host "   [Q] " -NoNewline -ForegroundColor DarkGray
    Write-Host "Quit" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  Choice: " -NoNewline
    return (Read-Host)
}

if ($InteractiveMode) {
    $MenuDryRun = [bool]$DryRun
    do {
        $Choice = Show-TlsMenu -MenuDryRun $MenuDryRun

        switch ($Choice.ToUpper()) {
            "1" {
                Clear-Host
                Write-Banner -Title "DETAILED CHECK STATE" -Color Cyan
                Write-Host ""
                Show-AllHardeningStates -All (Get-AllHardeningStates)
                Write-Host ""
                Read-Host "  Press Enter to return to the menu"
            }
            "2" {
                Clear-Host
                Write-Host ""
                Write-Host "  Applying hardening (only what's missing)..." -ForegroundColor Cyan
                Write-Host ""
                $All = Get-AllHardeningStates
                $Outcome = Invoke-AllHardening -All $All -IsDryRun:$MenuDryRun -Elevated (Test-IsElevated)
                Write-Host ""
                Write-Host "  Done: " -NoNewline -ForegroundColor Gray
                Write-Host "$($Outcome.Applied) applied" -NoNewline -ForegroundColor Green
                Write-Host ", $($Outcome.Skipped) already compliant, " -NoNewline -ForegroundColor White
                Write-Host "$($Outcome.Errors) error(s)" -ForegroundColor $(if ($Outcome.Errors -gt 0) { "Red" } else { "White" })
                Export-TlsReport -Results $Outcome.Results | Out-Null
                Write-Host ""
                Read-Host "  Press Enter to return to the menu"
            }
            "3" {
                Clear-Host
                Write-Host ""
                Write-Host "  FORCED re-application of all checks (including already-compliant ones)..." -ForegroundColor Yellow
                Write-Host ""
                $All = Get-AllHardeningStates
                $Outcome = Invoke-AllHardening -All $All -ForceAll -IsDryRun:$MenuDryRun -Elevated (Test-IsElevated)
                Write-Host ""
                Write-Host "  Done: " -NoNewline -ForegroundColor Gray
                Write-Host "$($Outcome.Applied) applied" -NoNewline -ForegroundColor Green
                Write-Host ", $($Outcome.Skipped) already compliant, " -NoNewline -ForegroundColor White
                Write-Host "$($Outcome.Errors) error(s)" -ForegroundColor $(if ($Outcome.Errors -gt 0) { "Red" } else { "White" })
                Export-TlsReport -Results $Outcome.Results | Out-Null
                Write-Host ""
                Read-Host "  Press Enter to return to the menu"
            }
            "4" {
                Clear-Host
                Write-Host ""
                Write-Host "  Generating the JSON report from the current state (nothing is changed)..." -ForegroundColor Cyan
                Write-Host ""
                $All     = Get-AllHardeningStates
                $Results = Get-AllResultsSnapshot -All $All
                Export-TlsReport -Results $Results | Out-Null
                Write-Host ""
                Read-Host "  Press Enter to return to the menu"
            }
            "5" {
                Clear-Host
                Write-Banner -Title "GROUP POLICY CHECK (read-only)" -Color Cyan
                Write-Host ""
                Show-GpoFindings -Findings (Test-TlsGpoOverride)
                Write-Host ""
                Read-Host "  Press Enter to return to the menu"
            }
            "6" {
                Clear-Host
                Write-Banner -Title "UNDOING HARDENING (-Undo)" -Color Red
                Write-Host ""
                Write-Host "  This will remove the keys/values created by this script on THIS machine" -ForegroundColor Yellow
                Write-Host "  and revert to Windows defaults for all checks." -ForegroundColor Yellow
                Write-Host ""
                $Confirm = Read-Host "  Confirm the undo? (Y/N)"
                if ($Confirm.ToUpper() -eq "Y") {
                    $Outcome = Invoke-TlsRollback -IsDryRun:$MenuDryRun -Elevated (Test-IsElevated)
                    Write-Host ""
                    Write-Host "  Done: " -NoNewline -ForegroundColor Gray
                    Write-Host "$($Outcome.Removed) removed" -NoNewline -ForegroundColor Green
                    Write-Host ", $($Outcome.Skipped) already absent, " -NoNewline -ForegroundColor White
                    Write-Host "$($Outcome.Errors) error(s)" -ForegroundColor $(if ($Outcome.Errors -gt 0) { "Red" } else { "White" })
                    Export-TlsReport -Results $Outcome.Results | Out-Null
                } else {
                    Write-Host "  Undo canceled." -ForegroundColor Gray
                }
                Write-Host ""
                Read-Host "  Press Enter to return to the menu"
            }
            "7" {
                Clear-Host
                Write-Banner -Title "HTML EXPORT — current state (nothing is changed)" -Color Cyan
                Write-Host ""
                $All      = Get-AllHardeningStates
                $Results  = Get-AllResultsSnapshot -All $All
                $ScoreVal = Export-TlsReport -Results $Results
                if ($null -eq $ScoreVal) { $ScoreVal = 0 }
                $HtmlPath = Export-TlsHtmlReport -Results $Results -Score $ScoreVal -ModeLabel "Current state (read-only)"
                if ($HtmlPath) {
                    Write-Host ""
                    Write-Host "  Open in the default browser? (Y/N)" -ForegroundColor Cyan
                    $OpenIt = Read-Host "  Choice"
                    if ($OpenIt.ToUpper() -eq "Y") { Start-Process $HtmlPath }
                }
                Write-Host ""
                Read-Host "  Press Enter to return to the menu"
            }
            "D" {
                $MenuDryRun = -not $MenuDryRun
            }
            "Q" {
                Clear-Host
                Write-Host ""
                Write-Host "  Goodbye." -ForegroundColor Gray
                Write-Host ""
            }
            default {
                Write-Host "  Invalid choice." -ForegroundColor Red
                Start-Sleep -Seconds 1
            }
        }
    } while ($Choice.ToUpper() -ne "Q")

    exit 0
}

# ──────────────────────────────────────────────
#  CLASSIC MODE (explicit parameter(s) supplied)
# ──────────────────────────────────────────────

$HeaderColor = if ($Undo) { "Red" } elseif ($DryRun) { "Magenta" } else { "Cyan" }
Write-Banner -Title "HARDEN-TLS  v$ScriptVersion" -Color $HeaderColor
if ($DryRun) {
    Write-Host "  DRY-RUN MODE — no changes will be applied" -ForegroundColor Magenta
}
if ($Force) {
    Write-Host "  FORCE MODE — re-applying even if already compliant" -ForegroundColor Yellow
}
if ($Undo) {
    Write-Host "  UNDO MODE — reverting to Windows defaults" -ForegroundColor Red
}
Write-Host ""

# [NEW v2.0] -Undo is handled first and exits the script: it's a path
# distinct from the normal apply, never combined with it. Guarded by
# ShouldProcess (wider impact than a classic apply), in addition to
# -DryRun/-WhatIf already handled upstream.
if ($Undo) {
    Write-Step "Reading keys/values eligible for removal..." -Level INFO
    Write-Host ""

    $Elevated = Test-IsElevated
    if (-not $DryRun -and -not $Elevated) {
        Write-Step "Administrator elevation required to undo the hardening — relaunch as Administrator." -Level WARN
    }

    $RollbackOutcome = $null
    if ($DryRun -or $PSCmdlet.ShouldProcess("$env:COMPUTERNAME", "Undo TLS/SCHANNEL hardening (remove created keys, revert to Windows defaults)")) {
        $RollbackOutcome = Invoke-TlsRollback -IsDryRun:$DryRun -Elevated $Elevated
    } else {
        Write-Step "Undo canceled (ShouldProcess declined)." -Level WARN
        $RollbackOutcome = Invoke-TlsRollback -IsDryRun -Elevated $Elevated
    }

    $RollbackBannerColor = if ($RollbackOutcome.Errors -eq 0) { "Green" } else { "Yellow" }
    $RollbackTitle       = if ($RollbackOutcome.Errors -eq 0) { "✓ UNDO COMPLETE" } else { "! PARTIAL UNDO" }
    Write-Banner -Title $RollbackTitle -Color $RollbackBannerColor
    Write-Host "  Removed       " -NoNewline -ForegroundColor Gray
    Write-Host "$($RollbackOutcome.Removed)" -NoNewline -ForegroundColor Green
    Write-Host "   ·   " -NoNewline -ForegroundColor DarkGray
    Write-Host "Already absent " -NoNewline -ForegroundColor Gray
    Write-Host "$($RollbackOutcome.Skipped)" -NoNewline -ForegroundColor White
    Write-Host "   ·   " -NoNewline -ForegroundColor DarkGray
    Write-Host "Errors " -NoNewline -ForegroundColor Gray
    Write-Host "$($RollbackOutcome.Errors)" -ForegroundColor $(if ($RollbackOutcome.Errors -eq 0) { "Green" } else { "Red" })
    Write-Host ""

    Export-TlsReport -Results $RollbackOutcome.Results | Out-Null
    if ($Html) {
        $RollbackScore = if ($RollbackOutcome.Results.Count -gt 0) { [int][Math]::Round(100 * (@($RollbackOutcome.Results | Where-Object { $_.Status -eq "OK" }).Count) / $RollbackOutcome.Results.Count) } else { 0 }
        Export-TlsHtmlReport -Results $RollbackOutcome.Results -Score $RollbackScore -ModeLabel "Annulation (-Undo)" | Out-Null
    }

    if (-not $Silent) {
        Write-Host "  ╔═══════════════════════════════════════════════════╗" -ForegroundColor DarkCyan
        Write-Host "  ║  Press ENTER to close this window...              ║" -ForegroundColor DarkCyan
        Write-Host "  ╚═══════════════════════════════════════════════════╝" -ForegroundColor DarkCyan
        $null = Read-Host
    }
    exit $(if ($RollbackOutcome.Errors -eq 0) { 0 } else { 1 })
}

# [NEW v1.2] State checked and displayed BEFORE any decision — whether everything is already compliant or not.
Write-Step "Reading current state (protocols, ciphers, hashes, Diffie-Hellman, .NET)..." -Level INFO
Write-Host ""
$All       = Get-AllHardeningStates
$AllStates = @($All.Protocols) + @($All.Ciphers) + @($All.Hashes) + @($All.Dh) + @($All.DotNet)
Show-AllHardeningStates -All $All
Write-Host ""

$NbCompliant = @($AllStates | Where-Object { $_.Applied }).Count
if ($NbCompliant -eq $AllStates.Count -and -not $Force) {
    Write-Step "All $($AllStates.Count) checks are already compliant — no change needed (use -Force to re-apply anyway)." -Level OK
} elseif (-not $DryRun -and -not (Test-IsElevated)) {
    Write-Step "Administrator elevation required to apply the changes — relaunch this script as Administrator. The JSON report will still be generated with the current state." -Level WARN
}

Write-Banner -Title "APPLICATION" -Color Cyan
Write-Host ""

$Outcome  = Invoke-AllHardening -All $All -ForceAll:$Force -IsDryRun:$DryRun -Elevated (Test-IsElevated)

# [FIX v2.0] $Outcome.Applied is ALWAYS 0 in -DryRun (nothing is actually
# written) — testing "Applied -eq 0" alone then confused "nothing to do"
# with "plenty to do but -DryRun prevents writing". $NbPending
# distinguishes the two: checks neither applied, nor already compliant,
# nor errored.
$NbPending = $AllStates.Count - $Outcome.Applied - $Outcome.Skipped - $Outcome.Errors

if ($Outcome.Errors -eq 0) {
    if ($DryRun -and $NbPending -gt 0) {
        Write-Banner -Title "» DRY-RUN — $NbPending CHANGE(S) IDENTIFIED" -Color Magenta
    } elseif ($Outcome.Applied -eq 0 -and $NbPending -eq 0) {
        Write-Banner -Title "✓ NOTHING TO DO — EVERYTHING WAS ALREADY COMPLIANT" -Color Green
    } else {
        Write-Banner -Title "✓ TLS HARDENING APPLIED" -Color Green
    }
} else {
    Write-Banner -Title "! PARTIAL HARDENING ($($Outcome.Errors) error(s))" -Color Yellow
}
Write-Host ""

$NbCompliantAfter = $Outcome.Applied + $Outcome.Skipped
Write-ComplianceGauge -Compliant $NbCompliantAfter -Total $AllStates.Count
Write-Host ""

Write-Host "  Applied               " -NoNewline -ForegroundColor Gray
Write-Host "$($Outcome.Applied) / $($AllStates.Count)" -ForegroundColor Green
Write-Host "  Already compliant     " -NoNewline -ForegroundColor Gray
Write-Host "$($Outcome.Skipped) / $($AllStates.Count)" -ForegroundColor White
if ($NbPending -gt 0) {
    Write-Host "  Pending (DryRun)      " -NoNewline -ForegroundColor Gray
    Write-Host "$NbPending / $($AllStates.Count)" -NoNewline -ForegroundColor Magenta
    Write-Host "  — relaunch WITHOUT -DryRun (as Administrator) to apply" -ForegroundColor DarkGray
}
if ($Outcome.Errors -gt 0) {
    Write-Host "  Errors                " -NoNewline -ForegroundColor Gray
    Write-Host "$($Outcome.Errors) / $($AllStates.Count)" -ForegroundColor Red
}
Write-Host ""
Write-Host "  ── Scope detail ──────────────────────────────" -ForegroundColor DarkGray
Write-Host "  Protocols             " -NoNewline -ForegroundColor Gray
Write-Host "$($ProtosToDisable -join ', ') (Client + Server)" -ForegroundColor White
Write-Host "  Ciphers               " -NoNewline -ForegroundColor Gray
Write-Host "$($WeakCiphers.Count) obsolete suites disabled" -ForegroundColor White
Write-Host "  Hashes                " -NoNewline -ForegroundColor Gray
Write-Host "$($WeakHashes -join ', ')" -ForegroundColor White
Write-Host "  Diffie-Hellman        " -NoNewline -ForegroundColor Gray
Write-Host "minimum length $DhMinKeyBitLength bits (Client + Server)" -ForegroundColor White
Write-Host "  .NET Framework        " -NoNewline -ForegroundColor Gray
Write-Host "Strong Crypto on $($All.DotNet.Count) location(s) detected" -ForegroundColor White
Write-Host "  Not touched           " -NoNewline -ForegroundColor Gray
Write-Host "TLS 1.2 / TLS 1.3, AES, SHA-256+ (Windows defaults preserved)" -ForegroundColor DarkGray
if (-not $DryRun -and $Outcome.Applied -gt 0) {
    Write-Host ""
    Write-Host "  ! Restart required    " -NoNewline -ForegroundColor Yellow
    Write-Host "for SCHANNEL to reload its configuration" -ForegroundColor Yellow
    Write-Host "                        (protocols/ciphers/hashes/DH). In case of incompatibility" -ForegroundColor Yellow
    Write-Host "                        on a specific machine: relaunch with -Undo." -ForegroundColor Yellow
}
Write-Host ""
Write-Host ("  " + ("─" * $script:BannerWidth)) -ForegroundColor DarkCyan
Write-Host ""

# Systematic JSON export — including when everything was already compliant and no
# write took place, so Dashboard-Global_Win11 has an up-to-date state.
$ScoreValue = Export-TlsReport -Results $Outcome.Results
if ($Html) {
    if ($null -eq $ScoreValue) { $ScoreValue = 0 }
    $ModeLabelClassic = if ($DryRun) { "DRY-RUN (no changes)" } elseif ($Force) { "Forced apply" } else { "Apply" }
    $HtmlPath = Export-TlsHtmlReport -Results $Outcome.Results -Score $ScoreValue -ModeLabel $ModeLabelClassic
    if ($HtmlPath -and -not $Silent) {
        Write-Step "Open the HTML report: $HtmlPath" -Level INFO
    }
}

Write-Host ""

if (-not $Silent) {
    Write-Host "  ╔═══════════════════════════════════════════════════╗" -ForegroundColor DarkCyan
    Write-Host "  ║  Press ENTER to close this window...              ║" -ForegroundColor DarkCyan
    Write-Host "  ╚═══════════════════════════════════════════════════╝" -ForegroundColor DarkCyan
    $null = Read-Host
}


# SIG # Begin signature block
# MIIFwgYJKoZIhvcNAQcCoIIFszCCBa8CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDR/URQFXpT1bJS
# kHaKZGOEJNRmrJP38zuPU5Bj3Lixk6CCAygwggMkMIICDKADAgECAhB6X4r8AlBU
# p0MV3JpMuQ6sMA0GCSqGSIb3DQEBCwUAMCoxKDAmBgNVBAMMH05lcGhyZW4gUG93
# ZXJTaGVsbCBDb2RlIFNpZ25pbmcwHhcNMjYwNzA0MDIzMzIwWhcNMzEwNzA0MDI0
# MzIwWjAqMSgwJgYDVQQDDB9OZXBocmVuIFBvd2VyU2hlbGwgQ29kZSBTaWduaW5n
# MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1JnV5AocUnAMNIG3nYF9
# 5mOQz5NzMYJqc9D6mq3pjRlmuYIgvYEuJL5dvt8eoAiUKd+XHTaY5wl+zt7LUon+
# TmEldVwfrYvROpI+5TDyBRc5BzY4uACsA4JUM4ienjX04BBKT3uH6JwHzBluWqcG
# Xrg16NqzDiae7WNzVrev+BME00mgSvBo3hKp3sHIvFQaAmjGXLyJd+llfnBpmoD9
# JnOxMKO7VFIlhAz5cEUnFu/xDLHgARdBUfXA5odScWKiDvygNZsH1vHo07Oo7pDK
# awR3bT6lcXWRXSUmawgE1mZra+b9qpeNol+5J+86zN83RccBKZBUtQQoyy+cv20x
# VQIDAQABo0YwRDAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0lBAwwCgYIKwYBBQUHAwMw
# HQYDVR0OBBYEFNxVaDYoNv8UXQWnbtEy/DTaQHjYMA0GCSqGSIb3DQEBCwUAA4IB
# AQCE4NqZbeximmbNEORyLxvIYiMQwP59B9R95blQQ/zugPSt4wab61yBbgO1E3mH
# mUdN0fCHhN/u0uB7h7ZBYw1w4hnzoiBac4UYzsXH4/D41gBjutbtDllRy6/zs3dl
# /hbbHAmwKXdjNVLG9cPkpWlkvKR1DJLMugU2uj+S6k+U7DfHo76sbAKqiu3biXtd
# mao6PP99EU7JBYZjsJ+BsnYcZ2KcnZ8TKiRuhSXoxAyPman7Z0BVo1H2O+fxd96b
# 4W8VclmpFh7T2CyRAHolwEy5coFYyueisO0PZg+nKwXr66+m1T1CBLQYwh79/SKO
# wGUJyU5RtTryD+hfLwkTQKVCMYIB8DCCAewCAQEwPjAqMSgwJgYDVQQDDB9OZXBo
# cmVuIFBvd2VyU2hlbGwgQ29kZSBTaWduaW5nAhB6X4r8AlBUp0MV3JpMuQ6sMA0G
# CWCGSAFlAwQCAQUAoIGEMBgGCisGAQQBgjcCAQwxCjAIoAKAAKECgAAwGQYJKoZI
# hvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcC
# ARUwLwYJKoZIhvcNAQkEMSIEIIP8fRr0sNBzyz1tjoQEx26vyGv5LhtIkKUX5bAx
# qpLXMA0GCSqGSIb3DQEBAQUABIIBAB4Ca4Y/Rjj9ebBRdwYz+hDpFbSR32SGjBxl
# V8maOWWRsPEMS0cu4sztNKORwTly9mON9J1Z2XgyYNTUvJiZeyM9NjV8nJFWoSYD
# 6G/WNUAnW3Vvh8/G31hE9r18wpdUwGHcqcluC85OLzW06LxKblfbPAivJs9wnFVZ
# 7929xO/P+173M3fm0K1jJD70uFCYTjZiQTV13iaA9nXbCARcTrLsklROKaC1Xs/4
# tGr+sWc57KZuqxtT7HSbF622xDhQqwqtG8NmgSLAOE/Yrduol1wdW6IGz/ThfIse
# +ZtO8hIM+Rgqd9287CnU9i3m07VD2eWaL0swsVBvSJD+vRcG1Q4=
# SIG # End signature block
