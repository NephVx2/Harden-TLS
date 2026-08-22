<#
.SYNOPSIS
    Durcissement TLS/SCHANNEL — désactivation explicite de TLS 1.0 et TLS 1.1
.DESCRIPTION
    Positionne les clés registre SCHANNEL pour forcer la désactivation de
    TLS 1.0 et TLS 1.1 (côté Client ET Serveur) sur la machine locale.

    TLS 1.2 et TLS 1.3 ne sont PAS touchés — Windows 11 les gère correctement
    par défaut, et écrire des clés de forçage pour eux nous éloignerait de la
    configuration gérée par Microsoft (contrairement à TLS 1.0/1.1 dont la
    désactivation est une recommandation stable depuis la RFC 8996 de 2021).

    Effets concrets :
      - TLS 1.0 (Client) : Enabled=0, DisabledByDefault=1
      - TLS 1.0 (Server) : Enabled=0, DisabledByDefault=1
      - TLS 1.1 (Client) : Enabled=0, DisabledByDefault=1
      - TLS 1.1 (Server) : Enabled=0, DisabledByDefault=1

    Un redémarrage est requis pour que SCHANNEL recharge sa configuration.

    Compatibilité : ce changement n'affecte que les applications Windows qui
    utilisent la pile TLS système (WinHTTP, SChannel). Les navigateurs modernes
    (Brave, Chrome, Firefox) gèrent TLS indépendamment et ne sont pas concernés.
    Les équipements réseau anciens (NAS, imprimantes, VPN legacy) peuvent être
    affectés si ils ne supportent que TLS 1.0/1.1 — ce qui est peu probable en
    2026 mais à garder en tête.

    Pour vérifier l'effet : relancer Check-Security_Win11.ps1 après redémarrage.
    Les 4 contrôles TLS 1.0/1.1 (Client/Server) passeront de WARN à OK.
    Les 2 contrôles TLS 1.2 (Client/Server) resteront WARN (clé absente =
    défaut Windows, acceptable sur Win11 récent).

    Export JSON aligné sur les conventions du reste de la suite
    (Baseline_<Module>.json + Rapport_<Module>_*.json dans
    Desktop\Rapports_Maintenance\TLS), pour que Dashboard-Global_Win11 puisse
    lire ce script (Get-TLSModule).

    [NEW v1.2] L'état de chaque contrôle est vérifié AVANT toute décision et
    affiché en console dès le lancement. Un contrôle déjà conforme n'est
    JAMAIS réécrit (le script ne se contente plus de laisser -Force sur
    New-ItemProperty faire le travail silencieusement) — le rapport JSON est
    en revanche toujours généré/rafraîchi, même quand rien n'a été modifié.
    [NEW v1.2] Mode interactif (-Menu), dans le même esprit que
    Manage-ScriptSignatures.ps1 : un menu persistant permet de consulter
    l'état, appliquer uniquement ce qui manque, forcer une ré-application, ou
    régénérer le rapport JSON sans rien modifier — sans avoir à relancer le
    script à chaque fois. Activé automatiquement si le script est lancé sans
    AUCUN paramètre (double-clic) ; tout paramètre explicite (-DryRun,
    -Silent, -Force, -SelfTest...) bascule en mode classique non-interactif
    pour rester compatible avec un appel scripté ou une tâche planifiée.
.PARAMETER DryRun
    Affiche les clés registre qui seraient écrites sans les appliquer.
.PARAMETER Force
    [NEW v1.2] Force la ré-application des 4 contrôles même s'ils sont déjà
    conformes (utile après une restauration système, par exemple).
.PARAMETER Menu
    [NEW v1.2] Force l'ouverture du mode interactif, même si d'autres
    paramètres sont fournis (ex : -Menu -DryRun pour un menu qui simule).
.PARAMETER Silent
    Supprime la pause "Appuyez sur ENTRÉE" finale (mode classique uniquement)
    — utile en tâche planifiée.
.PARAMETER RetainReportsDays
    Purge les Rapport_TLS_*.json plus vieux que N jours (défaut 30).
    Baseline_TLS.json n'est jamais purgé.
.PARAMETER SelfTest
    Exécute une suite de tests internes sur la logique de notation et de
    persistance de l'historique (aucune lecture/écriture registre), puis
    quitte.
.NOTES
    Auteur  : Harden-TLS Win11
    Version : 1.2
    Date    : 2026-07-07

    CHANGELOG v1.0 :
      Création initiale. Désactivation ciblée de TLS 1.0 et TLS 1.1 uniquement
      (côté Client et Server), sans toucher TLS 1.2/1.3.
      Syntaxe New-ItemProperty -PropertyType DWord (plus portable que
      Set-ItemProperty -Type, qui est PS 5.1+ seulement).

    CHANGELOG v1.1 :
      [NEW] Export JSON : Baseline_TLS.json + Rapport_TLS_<horodatage>.json
        dans Desktop\Rapports_Maintenance\TLS, pour Dashboard-Global_Win11.
      [NEW] Notation basée sur l'état final réellement relu en registre après
        écriture (pas sur l'absence d'exception).
      [NEW] Update-TlsScoreHistory (même précaution de double @() que le
        reste de la suite), cast [int] explicite sur le score.
      [NEW] -Silent, -RetainReportsDays, -SelfTest.

    CHANGELOG v1.2 :
      [NEW] Get-TlsControlState : lecture pure de l'état des 4 contrôles,
        AVANT toute décision, affichée en console dès le lancement (que ce
        soit en mode classique ou en mode menu) via Show-TlsControlState.
      [NEW] Idempotence EXPLICITE : un contrôle déjà conforme
        (Enabled=0/DisabledByDefault=1) n'est plus jamais réécrit — avant,
        les 4 clés étaient réécrites à chaque run (New-ItemProperty -Force),
        ce qui masquait le fait qu'aucun changement réel n'était nécessaire.
        Le rapport JSON est toujours généré/rafraîchi dans tous les cas.
      [NEW] -Force : ré-applique les 4 contrôles même s'ils sont déjà
        conformes.
      [NEW] -Menu : mode interactif façon Manage-ScriptSignatures.ps1
        (Clear-Host, résumé d'état persistant, options numérotées, boucle
        Read-Host). Activé par défaut si le script est lancé sans aucun
        paramètre.
      [NEW] Test-IsElevated : l'élévation administrateur n'est plus imposée
        globalement via #Requires -RunAsAdministrator (qui empêchait même de
        consulter l'état sans élévation) mais vérifiée dynamiquement, juste
        avant une écriture réelle. Lecture d'état, DryRun et génération du
        rapport JSON restent possibles sans élévation ; un message clair
        s'affiche si une écriture réelle est nécessaire sans élévation, et le
        rapport JSON est quand même généré avec l'état réel (non modifié).
      [Refactor] Logique de lecture, application et export extraite dans des
        fonctions dédiées (Get-TlsControlState / Show-TlsControlState /
        Invoke-TlsHardening / Export-TlsReport / Show-TlsMenu), réutilisées à
        l'identique par le mode classique et le mode menu.

    CHANGELOG v1.2.1 :
      [FIX] Update-TlsScoreHistory filtre désormais tout $null présent dans
        $ExistingHistory avant de le combiner au nouveau point. Un
        Baseline_TLS.json existant peut contenir un $null au sein de
        ScoreHistory (séquelle d'une version antérieure) ; un tableau à 1
        élément valant $null reste "truthy" en PowerShell (Count -gt 0), donc
        le garde-fou "if ($PrevBaseline -and $PrevBaseline.ScoreHistory)" dans
        Export-TlsReport ne suffisait pas à l'écarter — le $null se propageait
        alors indéfiniment, run après run. Le script s'auto-corrige maintenant
        au prochain lancement quel que soit l'état du fichier existant.
#>

[CmdletBinding()]
param(
    [switch]$DryRun,
    [switch]$Force,
    [switch]$Menu,
    [switch]$Silent,
    [int]$RetainReportsDays = 30,
    [switch]$SelfTest
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ──────────────────────────────────────────────
#  CONFIGURATION
# ──────────────────────────────────────────────
$ScriptVersion = "1.2.1"
$SchannelBase  = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols"

# Protocoles à désactiver explicitement.
# TLS 1.2 et TLS 1.3 sont volontairement absents de cette liste.
$ProtosToDisable = @("TLS 1.0", "TLS 1.1")
$Roles           = @("Client", "Server")

# Même racine que le reste de la suite (Dashboard-Global, Check-Boot, etc.).
$ReportsRoot   = "$env:USERPROFILE\Desktop\Rapports_Maintenance\TLS"
$BaselinePath  = "$ReportsRoot\Baseline_TLS.json"

# [NEW v1.2] Mode interactif par défaut si AUCUN paramètre n'a été fourni (double-clic) ;
# tout paramètre explicite bascule en mode classique non-interactif (compatibilité tâche
# planifiée / appel scripté depuis Dashboard-Global inchangée).
$InteractiveMode = $Menu -or ($PSBoundParameters.Count -eq 0)

# ──────────────────────────────────────────────
#  FONCTIONS UTILITAIRES
# ──────────────────────────────────────────────
function Write-Step {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "HH:mm:ss"
    $colors = @{ "INFO"="Cyan"; "OK"="Green"; "WARN"="Yellow"; "FAIL"="Red"; "DRY"="Magenta" }
    $color = if ($colors.ContainsKey($Level)) { $colors[$Level] } else { "White" }
    Write-Host "[$timestamp] [$Level] $Message" -ForegroundColor $color
}

function Test-IsElevated {
    # [NEW v1.2] Vérification dynamique de l'élévation, à la place d'un
    # #Requires -RunAsAdministrator global qui empêchait même de consulter l'état sans
    # élévation. Seule une écriture registre réelle en a besoin.
    $Identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
    $Principal = New-Object Security.Principal.WindowsPrincipal($Identity)
    return $Principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Update-TlsScoreHistory {
    # Equivalent local de Update-ScoreHistory (Dashboard-Global). Ajoute un point, tronque
    # a $MaxPoints. Le point d'appel doit systematiquement ecrire
    # "$x = @(Update-TlsScoreHistory ...)" (le [array] sur $ExistingHistory ne suffit pas a
    # proteger contre le deroulement d'un tableau a 1 seul element sur le flux de sortie).
    #
    # [FIX v1.2.1] Un Baseline_TLS.json anterieur peut contenir un $null au sein de
    # ScoreHistory (ex: pollution d'une version anterieure). Un tableau a 1 element
    # contenant $null reste "truthy" en PowerShell (Count -gt 0), donc le garde-fou
    # "if ($PrevBaseline -and $PrevBaseline.ScoreHistory)" cote Export-TlsReport ne suffit
    # pas a l'ecarter - $ExistingHistory recoit alors ce $null tel quel, qui se propage
    # indefiniment dans tous les runs suivants. Filtre ici, a l'entree, pour s'auto-corriger
    # au prochain run quel que soit l'etat du fichier existant.
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
    # Purge des Rapport_TLS_*.json plus vieux que $Days jours. Ne touche jamais
    # Baseline_TLS.json (historique de scores, pas un rapport ponctuel).
    param([string]$Folder, [int]$Days)
    if (-not (Test-Path $Folder)) { return }
    try {
        $Cutoff = (Get-Date).AddDays(-$Days)
        Get-ChildItem -Path $Folder -Filter "Rapport_TLS_*.json" -File -ErrorAction SilentlyContinue |
            Where-Object { $_.LastWriteTime -lt $Cutoff } |
            Remove-Item -Force -ErrorAction SilentlyContinue
    } catch {
        Write-Step "Purge des anciens rapports impossible : $($_.Exception.Message)" -Level WARN
    }
}

function Get-TlsControlState {
    # [NEW v1.2] Lecture PURE de l'état des 4 contrôles (aucune écriture). Sert de socle
    # unique à l'affichage, à la décision "faut-il modifier ?" et à l'export JSON — avant,
    # cette lecture était dupliquée (une fois pour l'affichage "avant", une fois implicite
    # dans la boucle d'application).
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
                    $enabled = (Get-ItemProperty -LiteralPath $keyPath -Name "Enabled" -ErrorAction SilentlyContinue).Enabled
                    $dbd     = (Get-ItemProperty -LiteralPath $keyPath -Name "DisabledByDefault" -ErrorAction SilentlyContinue).DisabledByDefault
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
    # [NEW v1.2] Affichage console de l'état actuel — utilisé aussi bien en préambule du
    # mode classique qu'en option [1] du menu interactif : "cela permet de savoir si les
    # éléments sont appliqués ou non" sans avoir à lancer une application pour le voir.
    param([array]$States)
    foreach ($S in $States) {
        if ($S.Applied) {
            Write-Step "$($S.Proto) ($($S.Role)) — déjà conforme (Enabled=0, DisabledByDefault=1)" -Level OK
        } elseif (-not $S.KeyExists) {
            Write-Step "$($S.Proto) ($($S.Role)) — clé absente (défaut Windows — sera créée et forcée)" -Level INFO
        } elseif ($null -eq $S.Enabled -and $null -eq $S.Dbd) {
            Write-Step "$($S.Proto) ($($S.Role)) — clé présente mais valeurs absentes (défaut Windows implicite)" -Level WARN
        } else {
            Write-Step "$($S.Proto) ($($S.Role)) — ACTIVÉ (Enabled=$($S.Enabled)) — sera désactivé" -Level WARN
        }
    }
}

function Invoke-TlsHardening {
    # [NEW v1.2] Coeur de la logique "vérifier avant d'agir" : un contrôle déjà conforme
    # n'est PLUS JAMAIS réécrit, sauf -ForceAll. Retourne un objet unique regroupant les
    # résultats détaillés (pour l'export JSON) et les compteurs (pour le résumé console).
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
        $AvantTxt    = if ($S.KeyExists) { "Enabled=$($S.Enabled), DisabledByDefault=$($S.Dbd)" } else { "clé absente" }

        if (-not $NeedsChange) {
            Write-Step "$($S.Proto) ($($S.Role)) — déjà conforme, aucune modification" -Level OK
            $Skipped++
            $Results += [PSCustomObject]@{
                Categorie = "Protocole"; Element = "$($S.Proto) ($($S.Role))"
                Valeur    = "Enabled=0, DisabledByDefault=1 (déjà conforme, non modifié)"
                Statut    = "OK"
            }
            continue
        }

        if ($IsDryRun) {
            $Action = if ($S.Applied) { "serait ré-appliqué (Force)" } else { "serait appliqué" }
            Write-Step "$($S.Proto) ($($S.Role)) — [DRY-RUN] $Action (état actuel : $AvantTxt)" -Level DRY
            $Results += [PSCustomObject]@{
                Categorie = "Protocole"; Element = "$($S.Proto) ($($S.Role))"
                Valeur    = "État actuel : $AvantTxt [DRY-RUN, non modifié]"
                Statut    = if ($S.Applied) { "OK" } else { "AVERTISSEMENT" }
            }
            continue
        }

        if (-not $Elevated) {
            Write-Step "$($S.Proto) ($($S.Role)) — élévation requise pour appliquer (relancer en Administrateur)" -Level FAIL
            $Errors++
            $Results += [PSCustomObject]@{
                Categorie = "Protocole"; Element = "$($S.Proto) ($($S.Role))"
                Valeur    = "Non appliqué : élévation administrateur requise (état actuel : $AvantTxt)"
                Statut    = "ERREUR"
            }
            continue
        }

        try {
            # Créer la clé si absente (New-Item -Force ne plante pas si elle existe déjà)
            New-Item -Path $path -Force | Out-Null

            # NOTE : New-ItemProperty -PropertyType DWord est la syntaxe portable
            # (fonctionne sur PS 5.1 et PS 7+). -Force écrase silencieusement si la
            # valeur existe déjà.
            New-ItemProperty -Path $path -Name "Enabled"           -Value 0 -PropertyType DWord -Force | Out-Null
            New-ItemProperty -Path $path -Name "DisabledByDefault" -Value 1 -PropertyType DWord -Force | Out-Null

            # Re-lecture APRES écriture : ne pas supposer que l'absence d'exception veut
            # dire que la valeur a bien été appliquée.
            $VerifEnabled = (Get-ItemProperty -LiteralPath $path -Name "Enabled" -ErrorAction SilentlyContinue).Enabled
            $VerifDbd     = (Get-ItemProperty -LiteralPath $path -Name "DisabledByDefault" -ErrorAction SilentlyContinue).DisabledByDefault

            if ([int]$VerifEnabled -eq 0 -and [int]$VerifDbd -eq 1) {
                Write-Step "$($S.Proto) ($($S.Role)) — Enabled=0, DisabledByDefault=1 ✔" -Level OK
                $Applied++
                $Results += [PSCustomObject]@{
                    Categorie = "Protocole"; Element = "$($S.Proto) ($($S.Role))"
                    Valeur    = "Enabled=0, DisabledByDefault=1 (avant : $AvantTxt)"
                    Statut    = "OK"
                }
            } else {
                Write-Step "$($S.Proto) ($($S.Role)) — écriture sans exception mais valeur relue inattendue (Enabled=$VerifEnabled, DisabledByDefault=$VerifDbd)" -Level FAIL
                $Errors++
                $Results += [PSCustomObject]@{
                    Categorie = "Protocole"; Element = "$($S.Proto) ($($S.Role))"
                    Valeur    = "Valeur relue inattendue : Enabled=$VerifEnabled, DisabledByDefault=$VerifDbd"
                    Statut    = "ERREUR"
                }
            }
        } catch {
            Write-Step "$($S.Proto) ($($S.Role)) — ERREUR : $($_.Exception.Message)" -Level FAIL
            $Errors++
            $Results += [PSCustomObject]@{
                Categorie = "Protocole"; Element = "$($S.Proto) ($($S.Role))"
                Valeur    = "Échec d'écriture : $($_.Exception.Message)"
                Statut    = "ERREUR"
            }
        }
    }

    return [PSCustomObject]@{ Results = $Results; Applied = $Applied; Errors = $Errors; Skipped = $Skipped }
}

function Export-TlsReport {
    # Écrit Baseline_TLS.json (historique de score) et Rapport_TLS_<horodatage>.json
    # (détail par contrôle) — TOUJOURS appelée, même quand rien n'a été modifié, pour que
    # Dashboard-Global_Win11 (Get-TLSModule) dispose d'un état à jour.
    param([array]$Results)
    try {
        if (-not (Test-Path $ReportsRoot)) {
            New-Item -ItemType Directory -Path $ReportsRoot -Force | Out-Null
        }

        $NbOk    = @($Results | Where-Object { $_.Statut -eq "OK" }).Count
        $NbTotal = @($Results).Count
        # [Math]::Round() renvoie un [double] — cast explicite en [int], sinon le score se
        # sérialise "83.0" au lieu de 83 dans le JSON.
        $Score = if ($NbTotal -gt 0) { [int][Math]::Round(100 * $NbOk / $NbTotal) } else { 0 }

        $Horodatage = Get-Date -Format "yyyyMMdd_HHmmss"
        $ReportPath = "$ReportsRoot\Rapport_TLS_$Horodatage.json"
        $Results | ConvertTo-Json -Depth 4 | Out-File $ReportPath -Encoding UTF8

        $PrevBaseline    = if (Test-Path $BaselinePath) { Get-Content $BaselinePath -Raw | ConvertFrom-Json } else { $null }
        $ExistingHistory = if ($PrevBaseline -and $PrevBaseline.ScoreHistory) { $PrevBaseline.ScoreHistory } else { @() }
        $NewPoint        = [PSCustomObject]@{ Date = (Get-Date -Format "yyyy-MM-dd HH:mm"); Score = $Score }
        # @() autour de l'appel, pas seulement sur le retour de la fonction — un historique
        # a 1 seul point se deroule sinon en objet scalaire sur le flux de sortie.
        $NewHistory = @(Update-TlsScoreHistory -ExistingHistory $ExistingHistory -NewPoint $NewPoint -MaxPoints 30)

        [PSCustomObject]@{
            LastRun      = (Get-Date -Format "yyyy-MM-dd HH:mm")
            LastScore    = $Score
            ScoreHistory = $NewHistory
        } | ConvertTo-Json -Depth 4 | Out-File $BaselinePath -Encoding UTF8

        Remove-OldTlsReports -Folder $ReportsRoot -Days $RetainReportsDays

        Write-Step "Export JSON écrit : $ReportPath (score $Score/100)" -Level INFO
        return $Score
    } catch {
        Write-Step "Export JSON impossible : $($_.Exception.Message)" -Level WARN
        return $null
    }
}

# ──────────────────────────────────────────────
#  SELFTEST (tests purs — aucun acces registre)
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
    Write-Host " SELFTEST - Harden-TLS_Win11 v$ScriptVersion"
    Write-Host "=========================================================" -ForegroundColor Cyan

    # --- Update-TlsScoreHistory ---
    $H0 = @(Update-TlsScoreHistory -ExistingHistory @() -NewPoint ([PSCustomObject]@{Date="j1";Score=90}))
    Assert-True "Update-TlsScoreHistory : historique vide -> 1 point (reste un tableau)" ($H0 -is [array] -and $H0.Count -eq 1)

    $H1 = @(Update-TlsScoreHistory -ExistingHistory $H0 -NewPoint ([PSCustomObject]@{Date="j2";Score=95}))
    Assert-True "Update-TlsScoreHistory : 1 point existant -> 2 points (pas de deroulement)" ($H1 -is [array] -and $H1.Count -eq 2)

    $Long = @()
    for ($i = 1; $i -le 35; $i++) { $Long = @(Update-TlsScoreHistory -ExistingHistory $Long -NewPoint ([PSCustomObject]@{Date="j$i";Score=$i}) -MaxPoints 30) }
    Assert-True "Update-TlsScoreHistory : troncature a MaxPoints=30" ($Long.Count -eq 30)
    Assert-True "Update-TlsScoreHistory : troncature garde les points les plus RECENTS" ($Long[-1].Score -eq 35)

    # [FIX v1.2.1] Historique pollue par un $null (cas reel rencontre le 08/07/2026 dans
    # Baseline_TLS.json - probable sequelle d'une version anterieure) : le $null ne doit
    # jamais se retrouver dans le resultat, quel que soit sa position dans l'historique
    # existant.
    $HPollueDebut = @(Update-TlsScoreHistory -ExistingHistory @($null, [PSCustomObject]@{Date="j1";Score=100}) -NewPoint ([PSCustomObject]@{Date="j2";Score=95}))
    Assert-True "Update-TlsScoreHistory : null en tete d'historique filtre (2 points, pas 3)" ($HPollueDebut.Count -eq 2)
    Assert-True "Update-TlsScoreHistory : aucun null ne subsiste dans le resultat" (@($HPollueDebut | Where-Object { $null -eq $_ }).Count -eq 0)

    # --- Get-TlsControlState / Invoke-TlsHardening (logique pure, sans toucher au vrai registre) ---
    $FakeStateOk       = [PSCustomObject]@{ Proto="TLS 1.0"; Role="Client"; KeyExists=$true;  Enabled=0;    Dbd=1;    Applied=$true }
    $FakeStateKo       = [PSCustomObject]@{ Proto="TLS 1.0"; Role="Server"; KeyExists=$true;  Enabled=1;    Dbd=1;    Applied=$false }
    $FakeStateAbsent   = [PSCustomObject]@{ Proto="TLS 1.1"; Role="Client"; KeyExists=$false; Enabled=$null; Dbd=$null; Applied=$false }

    $DryRes = Invoke-TlsHardening -States @($FakeStateOk, $FakeStateKo) -IsDryRun -Elevated $false
    Assert-True "Invoke-TlsHardening (DryRun) : contrôle déjà conforme -> Skipped, pas Applied" ($DryRes.Skipped -eq 1 -and $DryRes.Applied -eq 0)
    Assert-True "Invoke-TlsHardening (DryRun) : contrôle non conforme -> aucune écriture (Errors=0)" ($DryRes.Errors -eq 0)

    $NonElevRes = Invoke-TlsHardening -States @($FakeStateKo) -Elevated $false
    Assert-True "Invoke-TlsHardening (non élevé, contrôle non conforme) : ERREUR, pas de tentative d'écriture" ($NonElevRes.Errors -eq 1 -and $NonElevRes.Applied -eq 0)

    $AlreadyOkRes = Invoke-TlsHardening -States @($FakeStateOk) -Elevated $true
    Assert-True "Invoke-TlsHardening (élevé, déjà conforme, pas de Force) : Skipped, aucune écriture tentée" ($AlreadyOkRes.Skipped -eq 1 -and $AlreadyOkRes.Applied -eq 0)

    Assert-True "Invoke-TlsHardening : Results contient bien 1 entrée par contrôle passé" (@($DryRes.Results).Count -eq 2)

    # --- Calcul de score (cast [int] explicite, cf. bug [Math]::Round() -> double) ---
    $ScoreTest = [int][Math]::Round((3 / 4) * 100)
    Assert-True "Score : cast explicite en [int] (pas un [double])" ($ScoreTest.GetType().Name -eq "Int32")
    Assert-True "Score : 3/4 controles OK -> 75" ($ScoreTest -eq 75)

    Write-Host ""
    Write-Host "=========================================================" -ForegroundColor Cyan
    Write-Host " RESULTAT : $script:TestsPassed / $script:TestsTotal tests reussis" -ForegroundColor $(if ($script:TestsPassed -eq $script:TestsTotal) { "Green" } else { "Red" })
    Write-Host "=========================================================" -ForegroundColor Cyan
    Write-Host ""
    exit $(if ($script:TestsPassed -eq $script:TestsTotal) { 0 } else { 1 })
}

# ──────────────────────────────────────────────
#  MODE INTERACTIF (-Menu, ou aucun paramètre fourni)
# ──────────────────────────────────────────────
function Show-TlsMenu {
    param([bool]$MenuDryRun)

    Clear-Host
    $States     = Get-TlsControlState
    $NbConforme = @($States | Where-Object { $_.Applied }).Count
    $Elevated   = Test-IsElevated

    Write-Host ""
    Write-Host "  ============================================================" -ForegroundColor Cyan
    Write-Host "   HARDEN-TLS WIN11  v$ScriptVersion  — MODE INTERACTIF" -ForegroundColor Cyan
    Write-Host "  ============================================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Conformité actuelle : " -NoNewline
    Write-Host "$NbConforme / $($States.Count)" -ForegroundColor $(if ($NbConforme -eq $States.Count) { "Green" } else { "Yellow" }) -NoNewline
    Write-Host "  contrôles TLS 1.0/1.1 déjà désactivés" -ForegroundColor DarkGray
    Write-Host "  Mode DryRun         : " -NoNewline
    Write-Host "$(if ($MenuDryRun) { 'ACTIVÉ (aucune écriture réelle)' } else { 'désactivé' })" -ForegroundColor $(if ($MenuDryRun) { "Magenta" } else { "DarkGray" })
    Write-Host "  Élévation           : " -NoNewline
    Write-Host "$(if ($Elevated) { 'Administrateur' } else { 'Utilisateur standard (application réelle impossible)' })" -ForegroundColor $(if ($Elevated) { "Green" } else { "Yellow" })
    Write-Host ""

    Show-TlsControlState -States $States

    Write-Host ""
    Write-Host "  [1] Afficher l'état détaillé (lecture seule)" -ForegroundColor White
    Write-Host "  [2] Appliquer le durcissement (uniquement ce qui manque)" -ForegroundColor Yellow
    Write-Host "  [3] Forcer une ré-application complète (même si déjà conforme)" -ForegroundColor Yellow
    Write-Host "  [4] Générer / rafraîchir le rapport JSON (sans rien modifier)" -ForegroundColor Cyan
    Write-Host "  [D] Basculer le mode DryRun (actuellement : $(if ($MenuDryRun) { 'activé' } else { 'désactivé' }))" -ForegroundColor DarkGray
    Write-Host "  [Q] Quitter" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  Choix : " -NoNewline
    return (Read-Host)
}

if ($InteractiveMode) {
    $MenuDryRun = [bool]$DryRun
    do {
        $Choice = Show-TlsMenu -MenuDryRun $MenuDryRun

        switch ($Choice.ToUpper()) {
            "1" {
                Clear-Host
                Write-Host ""
                Write-Host "  ============================================================" -ForegroundColor Cyan
                Write-Host "   ÉTAT DÉTAILLÉ DES CONTRÔLES TLS" -ForegroundColor Cyan
                Write-Host "  ============================================================" -ForegroundColor Cyan
                Write-Host ""
                Show-TlsControlState -States (Get-TlsControlState)
                Write-Host ""
                Read-Host "  Appuyez sur Entrée pour revenir au menu"
            }
            "2" {
                Clear-Host
                Write-Host ""
                Write-Host "  Application du durcissement (uniquement ce qui manque)..." -ForegroundColor Cyan
                Write-Host ""
                $States = Get-TlsControlState
                $Outcome = Invoke-TlsHardening -States $States -IsDryRun:$MenuDryRun -Elevated (Test-IsElevated)
                Write-Host ""
                Write-Host "  Terminé : $($Outcome.Applied) appliqué(s), $($Outcome.Skipped) déjà conforme(s), $($Outcome.Errors) erreur(s)." -ForegroundColor White
                Export-TlsReport -Results $Outcome.Results | Out-Null
                Write-Host ""
                Read-Host "  Appuyez sur Entrée pour revenir au menu"
            }
            "3" {
                Clear-Host
                Write-Host ""
                Write-Host "  Ré-application FORCÉE des 4 contrôles (même ceux déjà conformes)..." -ForegroundColor Yellow
                Write-Host ""
                $States = Get-TlsControlState
                $Outcome = Invoke-TlsHardening -States $States -ForceAll -IsDryRun:$MenuDryRun -Elevated (Test-IsElevated)
                Write-Host ""
                Write-Host "  Terminé : $($Outcome.Applied) appliqué(s), $($Outcome.Skipped) déjà conforme(s), $($Outcome.Errors) erreur(s)." -ForegroundColor White
                Export-TlsReport -Results $Outcome.Results | Out-Null
                Write-Host ""
                Read-Host "  Appuyez sur Entrée pour revenir au menu"
            }
            "4" {
                Clear-Host
                Write-Host ""
                Write-Host "  Génération du rapport JSON à partir de l'état actuel (rien n'est modifié)..." -ForegroundColor Cyan
                Write-Host ""
                $States  = Get-TlsControlState
                $Results = foreach ($S in $States) {
                    [PSCustomObject]@{
                        Categorie = "Protocole"
                        Element   = "$($S.Proto) ($($S.Role))"
                        Valeur    = if ($S.Applied) { "Enabled=0, DisabledByDefault=1" } elseif ($S.KeyExists) { "Enabled=$($S.Enabled), DisabledByDefault=$($S.Dbd)" } else { "Clé absente (défaut Windows)" }
                        Statut    = if ($S.Applied) { "OK" } else { "AVERTISSEMENT" }
                    }
                }
                Export-TlsReport -Results $Results | Out-Null
                Write-Host ""
                Read-Host "  Appuyez sur Entrée pour revenir au menu"
            }
            "D" {
                $MenuDryRun = -not $MenuDryRun
            }
            "Q" {
                Clear-Host
                Write-Host ""
                Write-Host "  Au revoir." -ForegroundColor Gray
                Write-Host ""
            }
            default {
                Write-Host "  Choix invalide." -ForegroundColor Red
                Start-Sleep -Seconds 1
            }
        }
    } while ($Choice.ToUpper() -ne "Q")

    exit 0
}

# ──────────────────────────────────────────────
#  MODE CLASSIQUE (paramètre(s) explicite(s) fourni(s))
# ──────────────────────────────────────────────

Write-Host ""
Write-Host ("═" * 55) -ForegroundColor DarkCyan
Write-Host "  Harden-TLS Win11 v$ScriptVersion" -ForegroundColor Cyan
if ($DryRun) {
    Write-Host "  MODE DRY-RUN — aucune modification ne sera appliquée" -ForegroundColor Magenta
}
if ($Force) {
    Write-Host "  MODE FORCE — ré-application même si déjà conforme" -ForegroundColor Yellow
}
Write-Host ("═" * 55) -ForegroundColor DarkCyan
Write-Host ""

# [NEW v1.2] État vérifié et affiché AVANT toute décision — que tout soit déjà conforme ou non.
Write-Step "Lecture de l'état actuel des clés SCHANNEL..." -Level INFO
Write-Host ""
$States = Get-TlsControlState
Show-TlsControlState -States $States
Write-Host ""

$NbConforme = @($States | Where-Object { $_.Applied }).Count
if ($NbConforme -eq $States.Count -and -not $Force) {
    Write-Step "Les $($States.Count) contrôles sont déjà conformes — aucune modification nécessaire (utiliser -Force pour ré-appliquer quand même)." -Level OK
} elseif (-not $DryRun -and -not (Test-IsElevated)) {
    Write-Step "Élévation administrateur requise pour appliquer les changements — relancer ce script en tant qu'Administrateur. Le rapport JSON sera tout de même généré avec l'état actuel." -Level WARN
}

Write-Host ""
Write-Host ("═" * 55) -ForegroundColor DarkCyan
Write-Host "  APPLICATION" -ForegroundColor Cyan
Write-Host ("═" * 55) -ForegroundColor DarkCyan
Write-Host ""

$Outcome = Invoke-TlsHardening -States $States -ForceAll:$Force -IsDryRun:$DryRun -Elevated (Test-IsElevated)

Write-Host ""
Write-Host ("═" * 55) -ForegroundColor DarkCyan
if ($Outcome.Errors -eq 0) {
    if ($Outcome.Applied -eq 0) {
        Write-Host "  ✅  RIEN À FAIRE — TOUT ÉTAIT DÉJÀ CONFORME" -ForegroundColor Green
    } else {
        Write-Host "  ✅  DURCISSEMENT TLS APPLIQUÉ" -ForegroundColor Green
    }
} else {
    Write-Host "  ⚠   DURCISSEMENT PARTIEL ($($Outcome.Errors) erreur(s))" -ForegroundColor Yellow
}
Write-Host ("═" * 55) -ForegroundColor DarkCyan
Write-Host "  Clés appliquées      : $($Outcome.Applied) / $($States.Count)" -ForegroundColor White
Write-Host "  Déjà conformes       : $($Outcome.Skipped) / $($States.Count)" -ForegroundColor White
Write-Host "  Protocoles concernés : $($ProtosToDisable -join ', ') (Client + Server)" -ForegroundColor White
Write-Host "  TLS 1.2 / TLS 1.3    : non touchés (défauts Windows conservés)" -ForegroundColor White
if (-not $DryRun -and $Outcome.Applied -gt 0) {
    Write-Host ""
    Write-Host "  ⚠  Un redémarrage est requis pour que SCHANNEL" -ForegroundColor Yellow
    Write-Host "     recharge sa configuration." -ForegroundColor Yellow
}
Write-Host ("═" * 55) -ForegroundColor DarkCyan
Write-Host ""

# Export JSON systématique — y compris quand tout était déjà conforme et qu'aucune
# écriture n'a eu lieu, pour que Dashboard-Global_Win11 dispose d'un état à jour.
Export-TlsReport -Results $Outcome.Results | Out-Null

Write-Host ""

if (-not $Silent) {
    Write-Host "  ╔═══════════════════════════════════════════════════╗" -ForegroundColor DarkCyan
    Write-Host "  ║  Appuyez sur ENTRÉE pour fermer cette fenêtre...  ║" -ForegroundColor DarkCyan
    Write-Host "  ╚═══════════════════════════════════════════════════╝" -ForegroundColor DarkCyan
    $null = Read-Host
}


# SIG # Begin signature block
# MIIFwgYJKoZIhvcNAQcCoIIFszCCBa8CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAQm0rPxbTe42Bc
# dnSlrn49TRzvtRk39HICWIcCtG/awqCCAygwggMkMIICDKADAgECAhB6X4r8AlBU
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
# ARUwLwYJKoZIhvcNAQkEMSIEIFQo3dHdGJh23qaqMvcmCpQ+cIm73Ev96lnlFzK0
# LXW9MA0GCSqGSIb3DQEBAQUABIIBAMAJ1XMUkLusB0v88zB5b48LpDK3nCkkAJKm
# v8R/TNnpl6HxUl65TjFoMvpP2XnTwtwBSYEiRFsUBnDS40MEYG8w2+2k0mKl4udv
# 1nZ1w1WUYJ787tp5ItdjDwmnTvDAIMKzIMl4ad0RrXdI9fw4L+A6ccNVQnC25YF6
# PZ0pvGmXtRdktciZChQs+Tx+fAIKlCIsEQ8BZKg8FTKFjE4AgXFWicaxNRaxZ7K8
# 2eFqE0I/HX40OU+6oa99Vo5jR157oS+ST+mTnSN6IQxUSu3KcwipBB7YRdoW8SPu
# yZs1JP3GnymQgzHgzS+4oNTZFFDVjPU1Pe4FP+Wt+/TlsrsvM+Q=
# SIG # End signature block
