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
    Harden-TLS — Durcissement TLS/SCHANNEL pour Windows 11 : protocoles,
    suites de chiffrement, hachages, Diffie-Hellman et .NET Framework.
    Pensé pour un déploiement multi-postes / multi-utilisateurs (idempotent,
    réversible, informatif sur les GPO).
.DESCRIPTION
    [v1.x] Désactive TLS 1.0 et TLS 1.1 (Client + Server) via SCHANNEL.
    TLS 1.2 et TLS 1.3 ne sont PAS touchés (défauts Windows conservés).

    [NEW v2.0] Le périmètre est étendu à toute la surface SCHANNEL pertinente,
    avec la même philosophie "vérifier avant d'agir, ne jamais réécrire ce qui
    est déjà conforme" que le reste du script :
      - Suites de chiffrement obsolètes désactivées (RC4 toutes variantes,
        DES 56/56, RC2 toutes variantes, Triple DES 168, NULL). AES 128/256
        et les suites GCM/ChaCha modernes ne sont jamais touchées.
      - Algorithmes de hachage faibles désactivés (MD5, SHA-1). SHA-256/384/512
        ne sont jamais touchés.
      - Longueur de clé Diffie-Hellman minimale relevée à 2048 bits
        (Client + Server), recommandation Microsoft en vigueur depuis 2016 —
        aucun impact de compatibilité attendu sur une flotte 2026.
      - Renforcement .NET Framework (SchUseStrongCrypto=1,
        SystemDefaultTlsVersions=1) sur les emplacements HKLM natif/Wow6432Node
        présents sur la machine — sans jamais inventer une installation .NET
        absente. Ce point comble un angle mort réel : sans lui, une appli .NET
        (ou WinRM) peut continuer à négocier via sa propre pile plutôt que via
        les réglages SCHANNEL ci-dessus.

    Toutes ces valeurs sont des DWORD sous HKLM (jamais HKCU) : le résultat est
    identique quel que soit l'utilisateur qui exécute le script ou qui se
    connecte ensuite sur la machine — condition nécessaire pour un déploiement
    multi-utilisateurs cohérent.

    [NEW v2.0] Test-TlsGpoOverride : vérification en LECTURE SEULE de la
    présence d'une stratégie de groupe ("SSL Cipher Suite Order"). Une machine
    jointe à un domaine peut voir ses réglages SCHANNEL redéfinis au prochain
    rafraîchissement de policy (même chemin registre) — ce script ne modifie
    jamais de policy, il informe seulement.

    [NEW v2.0] -Undo : retire proprement tout ce que ce script a pu créer
    (clés Protocoles/Ciphers/Hashes entières, valeurs Diffie-Hellman/.NET
    individuelles) pour revenir aux défauts Windows — filet de sécurité
    indispensable en déploiement multi-postes si un équipement ou une appli
    legacy s'avère incompatible sur une machine en particulier.

    [NEW v2.0] Support natif -WhatIf (CmdletBinding SupportsShouldProcess) :
    -WhatIf équivaut désormais à -DryRun (bascule automatique), et -Undo est
    explicitement gardé par $PSCmdlet.ShouldProcess() vu son impact plus large.

    Un redémarrage est requis pour que SCHANNEL recharge sa configuration
    (protocoles/ciphers/hachages/Diffie-Hellman). Pour les clés .NET, un
    redémarrage des applications concernées suffit techniquement, mais un
    redémarrage complet reste recommandé en déploiement de flotte pour repartir
    d'un état propre et homogène.

    Compatibilité : ce changement n'affecte que les applications Windows qui
    utilisent la pile TLS système (WinHTTP, SChannel, .NET Framework). Les
    navigateurs modernes (Brave, Chrome, Firefox) gèrent TLS indépendamment et
    ne sont pas concernés. Les équipements réseau anciens (NAS, imprimantes,
    VPN legacy) peuvent être affectés s'ils ne supportent que TLS 1.0/1.1 ou
    les suites de chiffrement désormais désactivées — utiliser -Undo sur la
    machine concernée si besoin.

    Pour vérifier l'effet : relancer Check-Security_Win11.ps1 après redémarrage.

    Export JSON aligné sur les conventions du reste de la suite
    (Baseline_<Module>.json + Rapport_<Module>_*.json dans
    Desktop\Rapports_Maintenance\TLS), pour que Dashboard-Global_Win11 puisse
    lire ce script (Get-TLSModule). Le score reflète désormais l'ensemble des
    catégories (Protocoles + Ciphers + Hachages + Diffie-Hellman + .NET), pas
    seulement les 4 contrôles TLS 1.0/1.1 d'origine.
.PARAMETER DryRun
    Affiche les clés registre qui seraient écrites sans les appliquer.
.PARAMETER Force
    Force la ré-application de tous les contrôles même s'ils sont déjà
    conformes (utile après une restauration système, par exemple).
.PARAMETER Undo
    [NEW v2.0] Retire les clés/valeurs créées par ce script (toutes
    catégories) et revient aux défauts Windows. Gardé par
    $PSCmdlet.ShouldProcess() : respecte -WhatIf et -Confirm.
.PARAMETER Html
    [NEW v2.1.0] Génère en plus un rapport visuel HTML (Rapport_TLS_*.html
    dans Desktop\Rapports_Maintenance\TLS), même identité graphique que la
    Toolbox Commandes Système. Toujours en complément du JSON, jamais à la
    place — le JSON reste la source lue par Dashboard-Global_Win11.
.PARAMETER Menu
    Force l'ouverture du mode interactif, même si d'autres paramètres sont
    fournis (ex : -Menu -DryRun pour un menu qui simule).
.PARAMETER Silent
    Supprime la pause "Appuyez sur ENTRÉE" finale (mode classique uniquement)
    — utile en tâche planifiée / déploiement silencieux multi-postes.
.PARAMETER RetainReportsDays
    Purge les Rapport_TLS_*.json plus vieux que N jours (défaut 30).
    Baseline_TLS.json n'est jamais purgé.
.PARAMETER SelfTest
    Exécute une suite de tests internes sur la logique de notation et de
    persistance de l'historique (aucune lecture/écriture registre), puis
    quitte.
.NOTES
    Projet  : Harden-TLS
    Auteur  : Nephren (github.com/NephVx2)
    Version : 2.2.2
    Date    : 2026-08-25

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

    CHANGELOG v2.0.0 :
      [NEW] Durcissement des suites de chiffrement obsolètes (SCHANNEL\Ciphers)
        et des algorithmes de hachage faibles (SCHANNEL\Hashes), via les
        fonctions génériques Get-BinaryHardeningState / Show-BinaryState /
        Invoke-BinaryHardening (même pattern idempotent que les protocoles).
        Uniquement les éléments strictement obsolètes/dangereux (RC4, RC2,
        DES 56/56, Triple DES 168, NULL, MD5, SHA-1) — AES et SHA-256+ ne sont
        jamais touchés, pour rester sans risque de compatibilité sur une
        flotte hétérogène.
      [NEW] Longueur de clé Diffie-Hellman minimale relevée à 2048 bits
        (Get-DhState / Invoke-DhHardening), recommandation Microsoft stable
        depuis 2016 — impact de compatibilité négligeable en 2026.
      [NEW] Renforcement .NET Framework (SchUseStrongCrypto,
        SystemDefaultTlsVersions) via Get-DotNetPaths / Get-DotNetState /
        Invoke-DotNetHardening. Ne touche que les emplacements .NET
        réellement présents sur la machine (v4.0.30319 natif + Wow6432Node
        s'il existe ; v2.0.50727 seulement si déjà installé) — jamais de
        clé .NET inventée.
      [NEW] Test-TlsGpoOverride : détection en lecture seule d'une policy de
        domaine sur l'ordre des suites de chiffrement, affichée dans l'état
        et tracée dans le rapport JSON (catégorie "Stratégie de groupe"),
        pour éviter un faux sentiment de conformité sur un poste joint AD.
      [NEW] -Undo : retire les clés Protocoles/Ciphers/Hashes créées et les
        valeurs Diffie-Hellman/.NET ajoutées, machine par machine — filet de
        sécurité pour un déploiement multi-postes (Remove-Item pour les clés
        dédiées au script, Remove-ItemProperty pour les valeurs isolées dans
        des clés partagées avec d'autres réglages, afin de ne jamais supprimer
        autre chose que ce que ce script a pu écrire).
      [NEW] Support natif -WhatIf/-Confirm : [CmdletBinding(SupportsShouldProcess)].
        $WhatIfPreference bascule automatiquement en DryRun ; -Undo est en
        plus gardé par un $PSCmdlet.ShouldProcess() explicite vu son impact.
      [Refactor] Get-AllHardeningStates / Show-AllHardeningStates /
        Invoke-AllHardening orchestrent désormais les 5 catégories
        (Protocoles, Ciphers, Hachages, Diffie-Hellman, .NET) avec les mêmes
        compteurs Applied/Skipped/Errors qu'avant, réutilisés à l'identique
        par le mode classique et le mode menu.
      [Note sécurité] La signature Authenticode de la v1.2.1 est retirée en
        fin de fichier : le contenu ayant changé, l'ancienne signature ne
        correspondrait plus au hash du fichier. Re-signer via
        Manage-ScriptSignatures.ps1 avant tout déploiement en flotte.

    CHANGELOG v2.1.0 :
      [NEW] -Html : export d'un rapport visuel HTML (Rapport_TLS_*.html),
        même identité graphique que la Toolbox Commandes Système (fond
        sombre, accent cyan, logo Windows en dégradé, cartes de stats,
        tableau groupé/filtrable). Fichier autonome (CSS/JS inline), toujours
        généré en complément du JSON, jamais à sa place.
      [NEW] Menu [7] : export HTML à la demande sur l'état actuel (lecture
        seule), avec proposition d'ouverture immédiate dans le navigateur.
      [Refactor] Get-AllResultsSnapshot centralise la construction du
        tableau Results en lecture seule (Categorie/Element/Valeur/Statut),
        auparavant dupliquée en dur dans le menu [4] — désormais réutilisée
        par le menu [4]/[7] ET par Export-TlsHtmlReport.
      [Refactor] ConvertTo-HtmlSafe (System.Net.WebUtility) échappe toute
        valeur avant insertion dans le HTML — aucune valeur registre ou
        message d'erreur n'est jamais injecté tel quel.

    CHANGELOG v2.1.1 :
      [FIX] Ligne "Stratégie de groupe" affichant littéralement
        "System.Object[]" au lieu du texte de l'avertissement, dans
        Invoke-AllHardening ET Get-AllResultsSnapshot. Cause : ces deux
        appelants enveloppaient "Test-TlsGpoOverride" dans un @() de trop —
        la fonction garantit déjà un tableau via "return ,$Findings" (fix
        v2.0.0 précédent pour le crash ".Count" sur un résultat à 1 élément),
        donc le @() supplémentaire créait un tableau DANS un tableau. Le
        Statut (AVERTISSEMENT/OK) restait correct par accident (.Count
        valait 1 ou 0 dans les deux cas), seul le texte "-join" était
        corrompu. Correction : suppression du @() en trop aux deux points
        d'appel — Test-TlsGpoOverride seule suffit et reste la source unique
        de vérité du tableau.

    CHANGELOG v2.1.2 :
      [FIX] Faux positif "Stratégie de groupe" : Test-TlsGpoOverride ne
        vérifiait que l'EXISTENCE de la clé
        SSL\00010002 (SSL Cipher Suite Order), pas la présence de la valeur
        "Functions" qui définit réellement un ordre de suites. Constaté en
        conditions réelles sur NEPH-DESKTOP : la clé existe (probablement un
        résidu d'une installation passée) mais est vide — aucune policy
        active — ce qui déclenchait un avertissement à chaque run alors que
        rien ne menaçait de redéfinir les réglages de ce script. Corrigé via
        Test-RegValueExists -Name "Functions" plutôt qu'un simple Test-Path
        sur la clé.

    CHANGELOG v2.1.3 :
      [FIX CRITIQUE] Diffie-Hellman (Client) et (Server) s'effaçaient l'un
        l'autre entre deux exécutions, de façon apparemment aléatoire —
        symptôme observé et investigué en profondeur sur NEPH-DESKTOP
        (audit registre, tests d'isolation logiciel par logiciel) avant
        d'être reproduit et confirmé en 3 lignes de commande isolées, sans
        aucun facteur externe : "New-Item -Path -Force" sur une clé qui
        EXISTE DÉJÀ recrée la clé et efface toute autre valeur qu'elle
        contenait. Diffie-Hellman est la SEULE clé du script où deux valeurs
        indépendantes (ClientMinKeyBitLength/ServerMinKeyBitLength)
        cohabitent et sont écrites lors de PASSAGES SÉPARÉS de la boucle
        (une par rôle) — dès que l'une était déjà conforme et sautée par la
        logique idempotente, traiter l'autre rappelait New-Item -Force sur
        la clé partagée et effaçait silencieusement celle qui n'avait
        pourtant pas besoin d'être touchée. Corrigé dans Invoke-DhHardening
        (et, par prudence, dans les 3 autres fonctions d'application) : la
        clé n'est désormais créée QUE si elle n'existe pas encore
        (Test-Path avant New-Item), jamais recréée sur une clé déjà
        présente. Aucune autre catégorie n'était structurellement exposée
        (une seule valeur par clé, ou toutes les valeurs d'une clé écrites
        ensemble dans le même passage) mais la garde a été ajoutée partout
        par cohérence.

    CHANGELOG v2.1.4 :
      [FIX] Rapport HTML : bannière renommée en "Harden-TLS vX.X.X" (titre
        principal) avec "by Nephren" en sous-titre, au lieu de "Durcissement
        TLS/SCHANNEL" / "by Harden-TLS_Win11 vX.X.X" — identité de projet
        cohérente pour la publication GitHub.
      [FIX] Champ "Windows" du rapport HTML affichant parfois "Windows 10"
        sur un poste réellement en Windows 11 — bug connu de la clé registre
        ProductName, jamais mise à jour par Microsoft après une migration
        10→11. Lecture désormais via Win32_OperatingSystem (WMI/CIM), fiable
        dans tous les cas observés ; repli sur le registre uniquement si WMI
        est indisponible.

    CHANGELOG v2.2.2 :
      [FIX CRITIQUE] Le script refusait de se lancer sous Windows PowerShell
        5.1 ("Jeton inattendu", "Accolade fermante manquante", etc.), alors
        qu'il fonctionnait normalement sous PowerShell 7 (pwsh). Cause :
        le fichier était enregistré en UTF-8 SANS marqueur BOM. PowerShell 7
        lit toujours les .ps1 en UTF-8 par défaut, BOM ou pas — mais Windows
        PowerShell 5.1 se fie à la présence du BOM pour détecter l'encodage
        et, en son absence, retombe sur l'ANSI/Windows-1252 du système. Tous
        les caractères multi-octets ajoutés en v2.2.0 (icônes ✓ ! ✗ · »,
        cadres de bannière ╔═╗║╚╝, séparateurs │─) étaient alors mal
        décodés en plusieurs caractères parasites chacun, cassant la syntaxe
        PowerShell (guillemets et accolades comptés en trop). Corrigé en
        réenregistrant le fichier en UTF-8 AVEC BOM — transparent pour
        PowerShell 7, qui l'ignore, et rend le fichier de nouveau lisible
        par PowerShell 5.1. Attention pour la suite : toute réédition de ce
        fichier hors de cet environnement (Bloc-notes, VS Code mal
        configuré, etc.) doit impérativement conserver l'enregistrement en
        "UTF-8 avec BOM" sous peine de réintroduire ce bug.
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

# [NEW v2.0] -WhatIf natif : simple alias vers le pipeline -DryRun déjà
# éprouvé, plutôt que de dupliquer la logique d'affichage "ce qui serait fait".
if ($WhatIfPreference) { $DryRun = $true }

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ──────────────────────────────────────────────
#  CONFIGURATION
# ──────────────────────────────────────────────
$ScriptVersion = "2.2.2"
$SchannelRoot  = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL"
$SchannelBase  = "$SchannelRoot\Protocols"          # conservé pour compat (protocoles)
$ProtocolBase  = $SchannelBase
$CipherBase    = "$SchannelRoot\Ciphers"
$HashBase      = "$SchannelRoot\Hashes"
$DhPath        = "$SchannelRoot\KeyExchangeAlgorithms\Diffie-Hellman"

# Protocoles à désactiver explicitement.
# TLS 1.2 et TLS 1.3 sont volontairement absents de cette liste.
$ProtosToDisable = @("TLS 1.0", "TLS 1.1")
$Roles           = @("Client", "Server")

# [NEW v2.0] Suites de chiffrement obsolètes/dangereuses (RFC 7465 pour RC4,
# recommandations NIST/Microsoft pour DES/RC2/3DES/NULL). AES 128/256 et les
# suites GCM/ChaCha modernes sont volontairement absentes de cette liste.
$WeakCiphers = @(
    "RC4 40/128", "RC4 56/128", "RC4 64/128", "RC4 128/128",
    "DES 56/56", "RC2 40/128", "RC2 56/128", "RC2 128/128",
    "Triple DES 168", "NULL"
)

# [NEW v2.0] Algorithmes de hachage faibles. SHA-256/384/512 volontairement
# absents — ce sont les défauts modernes, jamais désactivés par ce script.
$WeakHashes = @("MD5", "SHA")

# [NEW v2.0] Longueur de clé Diffie-Hellman minimale (recommandation Microsoft
# depuis 2016, cf. Logjam). Impact de compatibilité négligeable en 2026.
$DhMinKeyBitLength = 2048

# Même racine que le reste de la suite (Dashboard-Global, Check-Boot, etc.).
$ReportsRoot   = "$env:USERPROFILE\Desktop\Rapports_Maintenance\TLS"
$BaselinePath  = "$ReportsRoot\Baseline_TLS.json"

# [NEW v2.1.0] Ordre de lecture logique pour le rapport HTML (pas alphabétique) —
# toute catégorie imprévue (ex. "Rollback" après un -Undo) est ajoutée à la suite
# automatiquement par Export-TlsHtmlReport, sans jamais perdre une ligne.
$CategoryDisplayOrder = @("Protocole", "Chiffrement", "Hachage", "Diffie-Hellman", ".NET Framework", "Stratégie de groupe", "Rollback")

# [NEW v1.2] Mode interactif par défaut si AUCUN paramètre n'a été fourni (double-clic) ;
# tout paramètre explicite bascule en mode classique non-interactif (compatibilité tâche
# planifiée / appel scripté depuis Dashboard-Global inchangée).
$InteractiveMode = $Menu -or ($PSBoundParameters.Count -eq 0)

# [NEW v2.2.0] Identité visuelle console alignée sur Check-Security_Win11 /
# Toolbox-SystemCommands : icônes courtes + colonne fixe (rendu stable quel
# que soit le glyphe), largeur de colonne "catégorie" pour aligner tous les
# résultats en tableau lisible plutôt qu'en texte au kilomètre.
$script:LogIcons        = @{ "OK"="✓"; "WARN"="!"; "FAIL"="✗"; "INFO"="·"; "DRY"="»" }
$script:LogIconWidth    = 2
$script:LogCategoryWidth = 16
$script:LogItemWidth    = 20
$script:BannerWidth     = 55

# ──────────────────────────────────────────────
#  FONCTIONS UTILITAIRES
# ──────────────────────────────────────────────

# [FIX v2.0] Sous Set-StrictMode -Version Latest, "(Get-ItemProperty -Name X
# -ErrorAction SilentlyContinue).X" est dangereux dans les deux sens :
#   - si la clé existe mais que la valeur X n'existe pas encore (cas normal
#     au tout premier passage, ex. clés .NET jamais durcies), l'objet renvoyé
#     par Get-ItemProperty existe mais n'a pas la propriété X : y accéder lève
#     "The property 'X' cannot be found on this object" au lieu de $null ;
#   - un simple test "$null -ne (Get-ItemProperty ...)" est également faux :
#     l'objet retourné n'est PAS $null même quand X est absent, ce qui aurait
#     faussé la détection d'existence utilisée par le rollback.
# Get-RegValue centralise une lecture sûre : $null si la clé ou la valeur
# n'existe pas, la valeur sinon — jamais d'exception, quel que soit le mode strict.
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

# [NEW v2.1.0] Échappement HTML pour le rapport visuel — System.Net.WebUtility
# fait partie de l'assembly System (chargée par défaut), pas besoin d'Add-Type.
function ConvertTo-HtmlSafe {
    param([string]$Text)
    if ($null -eq $Text) { return "" }
    return [System.Net.WebUtility]::HtmlEncode($Text)
}

function Write-Step {
    # [REDESIGN v2.2.0] Même esprit qu'avant (horodatage + niveau coloré),
    # mais rendu aligné en colonnes façon Check-Security_Win11 (Write-Log) :
    #   heure · icône · [catégorie · [item ·]] message
    # [FIX v2.2.1] -Category seul ne suffisait pas à aligner la barre "│"
    # quand la catégorie combinait un groupe fixe ET un nom d'élément de
    # longueur variable (ex. "Chiffrement : Triple DES 168" vs "Chiffrement :
    # NULL") : PadRight ne compense que jusqu'à sa largeur, donc toute entrée
    # plus longue que ce seuil décalait la barre pour cette seule ligne. Le
    # groupe (-Category, toujours un mot fixe : "Protocole", "Chiffrement",
    # ".NET Framework"...) et l'élément variable (-Item) sont maintenant deux
    # colonnes DISTINCTES, chacune avec sa propre largeur fixe — la barre
    # reste à la même colonne quelle que soit la longueur du nom affiché.
    # -Item est optionnel : sans lui, le rendu garde 2 colonnes (catégorie +
    # message), pour les cas où il n'y a pas de sous-élément à aligner
    # (Rollback, Stratégie GPO, résumés).
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

# [NEW v2.2.0] Bannière encadrée ╔═╗ pour les titres de section — même style
# que Check-Security_Win11 (Write-Log -Level SECTION), pour une identité
# visuelle cohérente à travers toute la suite de scripts. $Color s'applique
# au cadre ET au titre (le vert "AUDIT TERMINÉ" de Check-Security, le rouge
# "-Undo-" ici, etc.).
function Write-Banner {
    param([string]$Title, [string]$Color = "Cyan", [int]$Width = $script:BannerWidth)
    Write-Host ""
    Write-Host ("  ╔" + ("═" * $Width) + "╗") -ForegroundColor $Color
    Write-Host "  ║" -NoNewline -ForegroundColor $Color
    Write-Host (" $Title").PadRight($Width) -NoNewline -ForegroundColor $Color
    Write-Host "║" -ForegroundColor $Color
    Write-Host ("  ╚" + ("═" * $Width) + "╝") -ForegroundColor $Color
}

# [NEW v2.2.0] Mini-jauge visuelle (façon Check-Security_Win11) — utilisée en
# résumé final pour visualiser d'un coup d'œil la proportion de contrôles
# conformes, sans avoir à faire le calcul mental à partir des chiffres bruts.
function Write-ComplianceGauge {
    param([int]$Compliant, [int]$Total, [int]$Blocks = 20)
    $ratio  = if ($Total -gt 0) { $Compliant / $Total } else { 0 }
    $filled = [math]::Round($ratio * $Blocks)
    $gauge  = ("█" * $filled) + ("░" * ($Blocks - $filled))
    $color  = if ($ratio -eq 1) { "Green" } elseif ($ratio -ge 0.5) { "Yellow" } else { "Red" }
    Write-Host "  Conformité globale  " -NoNewline -ForegroundColor Gray
    Write-Host "$gauge" -NoNewline -ForegroundColor $color
    Write-Host "  $Compliant/$Total" -ForegroundColor $color
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
    # [NEW v1.2] Affichage console de l'état actuel — utilisé aussi bien en préambule du
    # mode classique qu'en option [1] du menu interactif : "cela permet de savoir si les
    # éléments sont appliqués ou non" sans avoir à lancer une application pour le voir.
    param([array]$States)
    foreach ($S in $States) {
        $Item = "$($S.Proto) ($($S.Role))"
        if ($S.Applied) {
            Write-Step "déjà conforme (Enabled=0, DisabledByDefault=1)" -Level OK -Category "Protocole" -Item $Item
        } elseif (-not $S.KeyExists) {
            Write-Step "clé absente (défaut Windows — sera créée et forcée)" -Level INFO -Category "Protocole" -Item $Item
        } elseif ($null -eq $S.Enabled -and $null -eq $S.Dbd) {
            Write-Step "clé présente mais valeurs absentes (défaut Windows implicite)" -Level WARN -Category "Protocole" -Item $Item
        } else {
            Write-Step "ACTIVÉ (Enabled=$($S.Enabled)) — sera désactivé" -Level WARN -Category "Protocole" -Item $Item
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
            Write-Step "déjà conforme, aucune modification" -Level OK -Category "Protocole" -Item "$($S.Proto) ($($S.Role))"
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
            Write-Step "[DRY-RUN] $Action (état actuel : $AvantTxt)" -Level DRY -Category "Protocole" -Item "$($S.Proto) ($($S.Role))"
            $Results += [PSCustomObject]@{
                Categorie = "Protocole"; Element = "$($S.Proto) ($($S.Role))"
                Valeur    = "État actuel : $AvantTxt [DRY-RUN, non modifié]"
                Statut    = if ($S.Applied) { "OK" } else { "AVERTISSEMENT" }
            }
            continue
        }

        if (-not $Elevated) {
            Write-Step "élévation requise pour appliquer (relancer en Administrateur)" -Level FAIL -Category "Protocole" -Item "$($S.Proto) ($($S.Role))"
            $Errors++
            $Results += [PSCustomObject]@{
                Categorie = "Protocole"; Element = "$($S.Proto) ($($S.Role))"
                Valeur    = "Non appliqué : élévation administrateur requise (état actuel : $AvantTxt)"
                Statut    = "ERREUR"
            }
            continue
        }

        try {
            # [FIX v2.1.1] Créer la clé UNIQUEMENT si absente — ne jamais rappeler
            # New-Item -Force sur une clé existante (voir note détaillée dans
            # Invoke-DhHardening : ce comportement peut effacer le contenu existant
            # de la clé sur certains systèmes). Chaque sous-clé de protocole n'a
            # qu'un seul jeu de valeurs écrit d'un coup ici, donc non exposée en
            # pratique, mais gardée par cohérence et prudence.
            if (-not (Test-Path -LiteralPath $path)) {
                New-Item -Path $path -Force | Out-Null
            }

            # NOTE : New-ItemProperty -PropertyType DWord est la syntaxe portable
            # (fonctionne sur PS 5.1 et PS 7+). -Force écrase silencieusement si la
            # valeur existe déjà.
            New-ItemProperty -Path $path -Name "Enabled"           -Value 0 -PropertyType DWord -Force | Out-Null
            New-ItemProperty -Path $path -Name "DisabledByDefault" -Value 1 -PropertyType DWord -Force | Out-Null

            # Re-lecture APRES écriture : ne pas supposer que l'absence d'exception veut
            # dire que la valeur a bien été appliquée.
            $VerifEnabled = Get-RegValue -Path $path -Name "Enabled"
            $VerifDbd     = Get-RegValue -Path $path -Name "DisabledByDefault"

            if ([int]$VerifEnabled -eq 0 -and [int]$VerifDbd -eq 1) {
                Write-Step "Enabled=0, DisabledByDefault=1 ✔" -Level OK -Category "Protocole" -Item "$($S.Proto) ($($S.Role))"
                $Applied++
                $Results += [PSCustomObject]@{
                    Categorie = "Protocole"; Element = "$($S.Proto) ($($S.Role))"
                    Valeur    = "Enabled=0, DisabledByDefault=1 (avant : $AvantTxt)"
                    Statut    = "OK"
                }
            } else {
                Write-Step "écriture sans exception mais valeur relue inattendue (Enabled=$VerifEnabled, DisabledByDefault=$VerifDbd)" -Level FAIL -Category "Protocole" -Item "$($S.Proto) ($($S.Role))"
                $Errors++
                $Results += [PSCustomObject]@{
                    Categorie = "Protocole"; Element = "$($S.Proto) ($($S.Role))"
                    Valeur    = "Valeur relue inattendue : Enabled=$VerifEnabled, DisabledByDefault=$VerifDbd"
                    Statut    = "ERREUR"
                }
            }
        } catch {
            Write-Step "ERREUR : $($_.Exception.Message)" -Level FAIL -Category "Protocole" -Item "$($S.Proto) ($($S.Role))"
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

# ──────────────────────────────────────────────
#  [NEW v2.0] CIPHERS / HASHES — fonctions génériques
#  (même pattern que les protocoles : lecture pure, puis application
#  idempotente. Ciphers et Hashes ne connaissent qu'une valeur "Enabled",
#  pas de "DisabledByDefault" — contrairement aux protocoles.)
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
            Write-Step "déjà désactivé" -Level OK -Category $S.Label -Item $S.Item
        } elseif (-not $S.KeyExists) {
            Write-Step "clé absente (sera créée et désactivée)" -Level INFO -Category $S.Label -Item $S.Item
        } else {
            Write-Step "ACTIVÉ (Enabled=$($S.Enabled)) — sera désactivé" -Level WARN -Category $S.Label -Item $S.Item
        }
    }
}

function Invoke-BinaryHardening {
    # Écrit uniquement "Enabled"=0. Même logique idempotente (vérifier avant
    # d'agir) et même contrat de retour {Results;Applied;Errors;Skipped} que
    # Invoke-TlsHardening, pour rester interchangeable dans les orchestrateurs.
    param([array]$States, [switch]$ForceAll, [switch]$IsDryRun, [bool]$Elevated)

    $Results = @(); $Applied = 0; $Errors = 0; $Skipped = 0

    foreach ($S in $States) {
        $NeedsChange = (-not $S.Applied) -or $ForceAll
        $AvantTxt    = if ($S.KeyExists) { "Enabled=$($S.Enabled)" } else { "clé absente" }

        if (-not $NeedsChange) {
            Write-Step "déjà désactivé, aucune modification" -Level OK -Category $S.Label -Item $S.Item
            $Skipped++
            $Results += [PSCustomObject]@{
                Categorie = $S.Label; Element = $S.Item
                Valeur    = "Enabled=0 (déjà conforme, non modifié)"; Statut = "OK"
            }
            continue
        }

        if ($IsDryRun) {
            Write-Step "[DRY-RUN] serait désactivé (état actuel : $AvantTxt)" -Level DRY -Category $S.Label -Item $S.Item
            $Results += [PSCustomObject]@{
                Categorie = $S.Label; Element = $S.Item
                Valeur    = "État actuel : $AvantTxt [DRY-RUN, non modifié]"
                Statut    = if ($S.Applied) { "OK" } else { "AVERTISSEMENT" }
            }
            continue
        }

        if (-not $Elevated) {
            Write-Step "élévation requise pour appliquer" -Level FAIL -Category $S.Label -Item $S.Item
            $Errors++
            $Results += [PSCustomObject]@{
                Categorie = $S.Label; Element = $S.Item
                Valeur    = "Non appliqué : élévation administrateur requise (état actuel : $AvantTxt)"
                Statut    = "ERREUR"
            }
            continue
        }

        try {
            # [FIX v2.1.1] Voir note détaillée dans Invoke-DhHardening.
            if (-not (Test-Path -LiteralPath $S.Path)) {
                New-Item -Path $S.Path -Force | Out-Null
            }
            New-ItemProperty -Path $S.Path -Name "Enabled" -Value 0 -PropertyType DWord -Force | Out-Null
            $Verif = Get-RegValue -Path $S.Path -Name "Enabled"

            if ([int]$Verif -eq 0) {
                Write-Step "Enabled=0 ✔" -Level OK -Category $S.Label -Item $S.Item
                $Applied++
                $Results += [PSCustomObject]@{
                    Categorie = $S.Label; Element = $S.Item
                    Valeur    = "Enabled=0 (avant : $AvantTxt)"; Statut = "OK"
                }
            } else {
                Write-Step "valeur relue inattendue (Enabled=$Verif)" -Level FAIL -Category $S.Label -Item $S.Item
                $Errors++
                $Results += [PSCustomObject]@{
                    Categorie = $S.Label; Element = $S.Item
                    Valeur    = "Valeur relue inattendue : Enabled=$Verif"; Statut = "ERREUR"
                }
            }
        } catch {
            Write-Step "ERREUR : $($_.Exception.Message)" -Level FAIL -Category $S.Label -Item $S.Item
            $Errors++
            $Results += [PSCustomObject]@{
                Categorie = $S.Label; Element = $S.Item
                Valeur    = "Échec d'écriture : $($_.Exception.Message)"; Statut = "ERREUR"
            }
        }
    }

    return [PSCustomObject]@{ Results = $Results; Applied = $Applied; Errors = $Errors; Skipped = $Skipped }
}

# ──────────────────────────────────────────────
#  [NEW v2.0] DIFFIE-HELLMAN — longueur de clé minimale
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
            Write-Step "déjà >= $DhMinKeyBitLength bits (actuel : $($S.Value))" -Level OK -Category "Diffie-Hellman" -Item $S.Role
        } elseif (-not $S.KeyExists -or $null -eq $S.Value) {
            Write-Step "non défini (sera fixé à $DhMinKeyBitLength bits)" -Level INFO -Category "Diffie-Hellman" -Item $S.Role
        } else {
            Write-Step "insuffisant (actuel : $($S.Value)) — sera relevé à $DhMinKeyBitLength" -Level WARN -Category "Diffie-Hellman" -Item $S.Role
        }
    }
}

function Invoke-DhHardening {
    param([array]$States, [switch]$ForceAll, [switch]$IsDryRun, [bool]$Elevated)

    $Results = @(); $Applied = 0; $Errors = 0; $Skipped = 0

    foreach ($S in $States) {
        $NeedsChange = (-not $S.Applied) -or $ForceAll
        $AvantTxt    = if ($null -ne $S.Value) { "$($S.Value) bits" } else { "non défini" }
        $Element     = "Longueur mini clé ($($S.Role))"

        if (-not $NeedsChange) {
            Write-Step "déjà >= $DhMinKeyBitLength bits, aucune modification" -Level OK -Category "Diffie-Hellman" -Item $S.Role
            $Skipped++
            $Results += [PSCustomObject]@{
                Categorie = "Diffie-Hellman"; Element = $Element
                Valeur    = "$DhMinKeyBitLength bits (déjà conforme, non modifié)"; Statut = "OK"
            }
            continue
        }

        if ($IsDryRun) {
            Write-Step "[DRY-RUN] serait fixé à $DhMinKeyBitLength bits (actuel : $AvantTxt)" -Level DRY -Category "Diffie-Hellman" -Item $S.Role
            $Results += [PSCustomObject]@{
                Categorie = "Diffie-Hellman"; Element = $Element
                Valeur    = "Actuel : $AvantTxt [DRY-RUN, non modifié]"
                Statut    = if ($S.Applied) { "OK" } else { "AVERTISSEMENT" }
            }
            continue
        }

        if (-not $Elevated) {
            Write-Step "élévation requise pour appliquer" -Level FAIL -Category "Diffie-Hellman" -Item $S.Role
            $Errors++
            $Results += [PSCustomObject]@{
                Categorie = "Diffie-Hellman"; Element = $Element
                Valeur    = "Non appliqué : élévation administrateur requise (actuel : $AvantTxt)"; Statut = "ERREUR"
            }
            continue
        }

        try {
            # [FIX v2.1.1] BUG CRITIQUE identifié en test terrain sur NEPH-DESKTOP :
            # "New-Item -Path -Force" sur une clé qui EXISTE DÉJÀ recrée la clé et
            # efface toute autre valeur qu'elle contenait — confirmé par test isolé
            # (deux New-ItemProperty suivis d'un simple New-Item -Force sans aucune
            # autre écriture : les deux valeurs disparaissent). Diffie-Hellman est la
            # SEULE clé du script où deux valeurs indépendantes (Client/Server)
            # cohabitent et sont écrites lors de passages SÉPARÉS — dès que l'une est
            # déjà conforme et sautée, traiter l'autre réexécutait New-Item -Force et
            # effaçait la première sans la toucher explicitement. Ne créer la clé que
            # si elle n'existe pas encore : ne JAMAIS rappeler New-Item -Force dessus
            # une fois qu'elle existe.
            if (-not (Test-Path -LiteralPath $DhPath)) {
                New-Item -Path $DhPath -Force | Out-Null
            }
            New-ItemProperty -Path $DhPath -Name $S.ValueName -Value $DhMinKeyBitLength -PropertyType DWord -Force | Out-Null
            $Verif = Get-RegValue -Path $DhPath -Name $S.ValueName

            if ([int]$Verif -ge $DhMinKeyBitLength) {
                Write-Step "$Verif bits ✔" -Level OK -Category "Diffie-Hellman" -Item $S.Role
                $Applied++
                $Results += [PSCustomObject]@{
                    Categorie = "Diffie-Hellman"; Element = $Element
                    Valeur    = "$Verif bits (avant : $AvantTxt)"; Statut = "OK"
                }
            } else {
                Write-Step "valeur relue inattendue ($Verif)" -Level FAIL -Category "Diffie-Hellman" -Item $S.Role
                $Errors++
                $Results += [PSCustomObject]@{
                    Categorie = "Diffie-Hellman"; Element = $Element
                    Valeur    = "Valeur relue inattendue : $Verif"; Statut = "ERREUR"
                }
            }
        } catch {
            Write-Step "ERREUR : $($_.Exception.Message)" -Level FAIL -Category "Diffie-Hellman" -Item $S.Role
            $Errors++
            $Results += [PSCustomObject]@{
                Categorie = "Diffie-Hellman"; Element = $Element
                Valeur    = "Échec d'écriture : $($_.Exception.Message)"; Statut = "ERREUR"
            }
        }
    }

    return [PSCustomObject]@{ Results = $Results; Applied = $Applied; Errors = $Errors; Skipped = $Skipped }
}

# ──────────────────────────────────────────────
#  [NEW v2.0] .NET FRAMEWORK — SchUseStrongCrypto / SystemDefaultTlsVersions
#  Machine-wide (HKLM uniquement) — jamais HKCU, pour un résultat identique
#  quel que soit l'utilisateur qui se connecte ensuite sur le poste.
# ──────────────────────────────────────────────
function Get-DotNetPaths {
    # Ne touche que les emplacements .NET réellement présents sur la machine.
    # v4.0.30319 fait partie de l'OS (toujours présent sur Win11) ; le
    # pendant Wow6432Node n'existe que sur OS 64-bit ; .NET 2.0/3.5 n'est
    # ajouté que s'il est déjà installé — jamais une clé inventée.
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
    # [FIX v2.0] Même précaution que Test-TlsGpoOverride : sur un OS 32-bit
    # sans Wow6432Node ni .NET legacy, $Paths ne contiendrait qu'1 élément et
    # serait aplati en simple chaîne au retour — un "foreach" sur une chaîne
    # itère caractère par caractère, ce qui casserait Get-DotNetState en
    # silence. L'opérateur unaire "," garantit un vrai tableau.
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

# [NEW v2.2.1] Étiquette console compacte — le chemin registre complet
# ("Wow6432Node\Microsoft\.NETFramework\v4.0.30319", 48 caractères) est
# gardé tel quel dans le JSON/HTML (traçabilité de l'export), mais rendait
# la colonne "Item" du tableau console ingérable (il aurait fallu une
# largeur fixe de ~50 caractères, gaspillée sur toutes les AUTRES
# catégories). Cette version ne garde que ce qui distingue vraiment les
# emplacements entre eux : la version .NET et natif/Wow64.
function Get-DotNetConsoleTag {
    param([string]$Path)
    $VerMatch = [regex]::Match($Path, 'v[\d\.]+$')
    $Ver      = if ($VerMatch.Success) { $VerMatch.Value } else { $Path }
    $Bits     = if ($Path -match "Wow6432Node") { "Wow64" } else { "natif" }
    return "$Ver ($Bits)"
}

function Show-DotNetState {
    param([array]$States)
    foreach ($S in $States) {
        $Tag = Get-DotNetConsoleTag -Path $S.Path
        if ($S.Applied) {
            Write-Step "Strong Crypto déjà actif" -Level OK -Category ".NET Framework" -Item $Tag
        } else {
            Write-Step "absent ou incomplet (sera activé)" -Level WARN -Category ".NET Framework" -Item $Tag
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
        $AvantTxt    = "SchUseStrongCrypto=$($S.Ssc), SystemDefaultTlsVersions=$($S.Sdtv)"

        if (-not $NeedsChange) {
            Write-Step "Strong Crypto déjà actif, aucune modification" -Level OK -Category ".NET Framework" -Item $Tag
            $Skipped++
            $Results += [PSCustomObject]@{
                Categorie = ".NET Framework"; Element = $Label
                Valeur    = "SchUseStrongCrypto=1, SystemDefaultTlsVersions=1 (déjà conforme)"; Statut = "OK"
            }
            continue
        }

        if ($IsDryRun) {
            Write-Step "[DRY-RUN] Strong Crypto serait activé (état actuel : $AvantTxt)" -Level DRY -Category ".NET Framework" -Item $Tag
            $Results += [PSCustomObject]@{
                Categorie = ".NET Framework"; Element = $Label
                Valeur    = "État actuel : $AvantTxt [DRY-RUN, non modifié]"
                Statut    = if ($S.Applied) { "OK" } else { "AVERTISSEMENT" }
            }
            continue
        }

        if (-not $Elevated) {
            Write-Step "élévation requise pour appliquer" -Level FAIL -Category ".NET Framework" -Item $Tag
            $Errors++
            $Results += [PSCustomObject]@{
                Categorie = ".NET Framework"; Element = $Label
                Valeur    = "Non appliqué : élévation administrateur requise (état actuel : $AvantTxt)"; Statut = "ERREUR"
            }
            continue
        }

        try {
            # [FIX v2.1.1] Voir note détaillée dans Invoke-DhHardening.
            if (-not (Test-Path -LiteralPath $S.Path)) {
                New-Item -Path $S.Path -Force | Out-Null
            }
            New-ItemProperty -Path $S.Path -Name "SchUseStrongCrypto"       -Value 1 -PropertyType DWord -Force | Out-Null
            New-ItemProperty -Path $S.Path -Name "SystemDefaultTlsVersions" -Value 1 -PropertyType DWord -Force | Out-Null
            $VerifSsc  = Get-RegValue -Path $S.Path -Name "SchUseStrongCrypto"
            $VerifSdtv = Get-RegValue -Path $S.Path -Name "SystemDefaultTlsVersions"

            if ([int]$VerifSsc -eq 1 -and [int]$VerifSdtv -eq 1) {
                Write-Step "Strong Crypto activé ✔" -Level OK -Category ".NET Framework" -Item $Tag
                $Applied++
                $Results += [PSCustomObject]@{
                    Categorie = ".NET Framework"; Element = $Label
                    Valeur    = "SchUseStrongCrypto=1, SystemDefaultTlsVersions=1 (avant : $AvantTxt)"; Statut = "OK"
                }
            } else {
                Write-Step "valeurs relues inattendues (Ssc=$VerifSsc, Sdtv=$VerifSdtv)" -Level FAIL -Category ".NET Framework" -Item $Tag
                $Errors++
                $Results += [PSCustomObject]@{
                    Categorie = ".NET Framework"; Element = $Label
                    Valeur    = "Valeurs relues inattendues : SchUseStrongCrypto=$VerifSsc, SystemDefaultTlsVersions=$VerifSdtv"; Statut = "ERREUR"
                }
            }
        } catch {
            Write-Step "ERREUR : $($_.Exception.Message)" -Level FAIL -Category ".NET Framework" -Item $Tag
            $Errors++
            $Results += [PSCustomObject]@{
                Categorie = ".NET Framework"; Element = $Label
                Valeur    = "Échec d'écriture : $($_.Exception.Message)"; Statut = "ERREUR"
            }
        }
    }

    return [PSCustomObject]@{ Results = $Results; Applied = $Applied; Errors = $Errors; Skipped = $Skipped }
}

# ──────────────────────────────────────────────
#  [NEW v2.0] DÉTECTION GPO — lecture seule, jamais bloquant
# ──────────────────────────────────────────────
function Test-TlsGpoOverride {
    # [FIX v2.1.1] Vérifie la présence de la VALEUR "Functions" dans la clé de
    # policy "SSL Cipher Suite Order", pas seulement l'existence de la clé
    # elle-même. Une clé vide (sans valeur Functions) ne définit aucun ordre
    # de suites — un simple Test-Path sur la clé donnait un faux positif
    # (constaté en conditions réelles : la clé existe, vide, sans policy
    # active). Ne modifie jamais rien : sert uniquement à éviter un faux
    # sentiment de conformité sur un poste où une policy pourrait redéfinir
    # l'ordre des suites de chiffrement au prochain rafraîchissement.
    $Findings = @()
    $GpoCipherOrderPath = "HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002"
    if (Test-RegValueExists -Path $GpoCipherOrderPath -Name "Functions") {
        $Findings += "Une stratégie (locale ou de groupe) définit l'ordre des suites de chiffrement SSL/TLS ('SSL Cipher Suite Order', valeur Functions active). Elle peut se superposer aux réglages de ce script."
    }
    # [FIX v2.0] "return $Findings" aplatit un tableau à 1 élément en simple
    # chaîne (comportement standard de PowerShell en sortie de fonction) —
    # le opérateur unaire "," force la sortie à rester un vrai tableau, quel
    # que soit le nombre d'éléments (0, 1 ou plusieurs), pour que tout appelant
    # puisse utiliser .Count sans risque sous Set-StrictMode.
    return ,$Findings
}

function Show-GpoFindings {
    param([array]$Findings)
    if ($Findings.Count -gt 0) {
        foreach ($F in $Findings) { Write-Step $F -Level WARN -Category "Stratégie GPO" }
    } else {
        Write-Step "aucune GPO connue sur l'ordre des suites de chiffrement" -Level OK -Category "Stratégie GPO"
    }
    # Note statique : les protocoles/ciphers/hachages désactivés par ce script
    # partagent le MÊME chemin registre que certaines policies "Turn off
    # TLS 1.0/1.1" — sur un poste joint à un domaine, un doute sur une
    # éventuelle redéfinition se lève avec `gpresult /h`.
    Write-Step "en cas de doute sur un poste joint à un domaine : 'gpresult /h'" -Level INFO -Category "Stratégie GPO"
}

# ──────────────────────────────────────────────
#  [NEW v2.0] ORCHESTRATION — regroupe les 5 catégories
# ──────────────────────────────────────────────
function Get-AllHardeningStates {
    return [PSCustomObject]@{
        Protocols = Get-TlsControlState
        Ciphers   = Get-BinaryHardeningState -BasePath $CipherBase -Items $WeakCiphers -Label "Chiffrement"
        Hashes    = Get-BinaryHardeningState -BasePath $HashBase   -Items $WeakHashes  -Label "Hachage"
        Dh        = Get-DhState
        DotNet    = Get-DotNetState
    }
}

function Show-AllHardeningStates {
    param([PSCustomObject]$All)
    Write-Host "  ── Protocoles (TLS 1.0/1.1) ──────────────────" -ForegroundColor DarkGray
    Show-TlsControlState -States $All.Protocols
    Write-Host ""
    Write-Host "  ── Suites de chiffrement obsolètes ──────────" -ForegroundColor DarkGray
    Show-BinaryState -States $All.Ciphers
    Write-Host ""
    Write-Host "  ── Algorithmes de hachage obsolètes ─────────" -ForegroundColor DarkGray
    Show-BinaryState -States $All.Hashes
    Write-Host ""
    Write-Host "  ── Diffie-Hellman (longueur mini de clé) ────" -ForegroundColor DarkGray
    Show-DhState -States $All.Dh
    Write-Host ""
    Write-Host "  ── .NET Framework (Strong Crypto) ───────────" -ForegroundColor DarkGray
    Show-DotNetState -States $All.DotNet
    Write-Host ""
    Write-Host "  ── Stratégie de groupe ───────────────────────" -ForegroundColor DarkGray
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
    # [FIX v2.1.0] PAS de @() ici : Test-TlsGpoOverride garantit déjà un vrai
    # tableau via "return ,$Findings" (opérateur unaire comma). L'envelopper
    # une seconde fois avec @() créait un tableau DANS un tableau — $Findings
    # avait alors .Count=1 par accident (donc la détection fonctionnait), mais
    # "-join" sur ce tableau imbriqué retombait sur .ToString() de son unique
    # élément (l'array interne), produisant littéralement "System.Object[]"
    # dans le rapport au lieu du texte de l'avertissement.
    $Findings   = Test-TlsGpoOverride
    $AllResults += [PSCustomObject]@{
        Categorie = "Stratégie de groupe"; Element = "SSL Cipher Suite Order (GPO)"
        Valeur    = if ($Findings.Count -gt 0) { $Findings -join " " } else { "Aucune GPO connue détectée" }
        Statut    = if ($Findings.Count -gt 0) { "AVERTISSEMENT" } else { "OK" }
    }

    $Applied = $ProtoOutcome.Applied + $CipherOutcome.Applied + $HashOutcome.Applied + $DhOutcome.Applied + $DotNetOutcome.Applied
    $Skipped = $ProtoOutcome.Skipped + $CipherOutcome.Skipped + $HashOutcome.Skipped + $DhOutcome.Skipped + $DotNetOutcome.Skipped
    $Errors  = $ProtoOutcome.Errors  + $CipherOutcome.Errors  + $HashOutcome.Errors  + $DhOutcome.Errors  + $DotNetOutcome.Errors

    return [PSCustomObject]@{ Results = $AllResults; Applied = $Applied; Errors = $Errors; Skipped = $Skipped }
}

# ──────────────────────────────────────────────
#  [NEW v2.0] ROLLBACK (-Undo) — retour aux défauts Windows
#  Remove-Item sur les clés dédiées à ce script (Protocoles/Ciphers/Hashes —
#  sous-clés à usage unique, sans risque de supprimer autre chose).
#  Remove-ItemProperty sur les valeurs isolées dans des clés PARTAGÉES avec
#  d'autres réglages (Diffie-Hellman, .NET) — la clé elle-même n'est jamais
#  supprimée dans ce cas.
# ──────────────────────────────────────────────
function Get-TlsRollbackActions {
    $Actions = @()
    foreach ($proto in $ProtosToDisable) {
        foreach ($role in $Roles) {
            $Actions += [PSCustomObject]@{ Type = "Key"; Path = "$ProtocolBase\$proto\$role"; Description = "Protocole $proto ($role)" }
        }
    }
    foreach ($c in $WeakCiphers) {
        $Actions += [PSCustomObject]@{ Type = "Key"; Path = "$CipherBase\$c"; Description = "Chiffrement $c" }
    }
    foreach ($h in $WeakHashes) {
        $Actions += [PSCustomObject]@{ Type = "Key"; Path = "$HashBase\$h"; Description = "Hachage $h" }
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
            $Results += [PSCustomObject]@{ Categorie = "Rollback"; Element = $A.Description; Valeur = "Déjà absent (rien à annuler)"; Statut = "OK" }
            continue
        }

        if ($IsDryRun) {
            Write-Step "[DRY-RUN] $($A.Description) — serait supprimé" -Level DRY -Category "Rollback"
            $Results += [PSCustomObject]@{ Categorie = "Rollback"; Element = $A.Description; Valeur = "Présent [DRY-RUN, non supprimé]"; Statut = "AVERTISSEMENT" }
            continue
        }

        if (-not $Elevated) {
            Write-Step "$($A.Description) — élévation requise pour annuler" -Level FAIL -Category "Rollback"
            $Errors++
            $Results += [PSCustomObject]@{ Categorie = "Rollback"; Element = $A.Description; Valeur = "Non annulé : élévation administrateur requise"; Statut = "ERREUR" }
            continue
        }

        try {
            if ($A.Type -eq "Key") {
                Remove-Item -LiteralPath $A.Path -Recurse -Force -ErrorAction Stop
            } else {
                Remove-ItemProperty -LiteralPath $A.Path -Name $A.ValueName -Force -ErrorAction Stop
            }
            Write-Step "$($A.Description) — supprimé, retour au défaut Windows" -Level OK -Category "Rollback"
            $Removed++
            $Results += [PSCustomObject]@{ Categorie = "Rollback"; Element = $A.Description; Valeur = "Supprimé (retour au défaut Windows)"; Statut = "OK" }
        } catch {
            Write-Step "$($A.Description) — ERREUR : $($_.Exception.Message)" -Level FAIL -Category "Rollback"
            $Errors++
            $Results += [PSCustomObject]@{ Categorie = "Rollback"; Element = $A.Description; Valeur = "Échec de suppression : $($_.Exception.Message)"; Statut = "ERREUR" }
        }
    }

    return [PSCustomObject]@{ Results = $Results; Removed = $Removed; Errors = $Errors; Skipped = $Skipped }
}

function Get-AllResultsSnapshot {
    # [NEW v2.1.0] Lecture seule : construit le même schéma de résultats
    # (Categorie/Element/Valeur/Statut) qu'Invoke-AllHardening, mais sans rien
    # appliquer — pour les rapports "état actuel" (menu [4]/[7]) sans avoir à
    # relancer une application réelle ou un DryRun complet. Remplace la
    # construction qui était dupliquée en dur dans le menu (option JSON).
    param([PSCustomObject]$All)

    $Results = @()
    foreach ($S in $All.Protocols) {
        $Results += [PSCustomObject]@{
            Categorie = "Protocole"; Element = "$($S.Proto) ($($S.Role))"
            Valeur    = if ($S.Applied) { "Enabled=0, DisabledByDefault=1" } elseif ($S.KeyExists) { "Enabled=$($S.Enabled), DisabledByDefault=$($S.Dbd)" } else { "Clé absente (défaut Windows)" }
            Statut    = if ($S.Applied) { "OK" } else { "AVERTISSEMENT" }
        }
    }
    foreach ($S in (@($All.Ciphers) + @($All.Hashes))) {
        $Results += [PSCustomObject]@{
            Categorie = $S.Label; Element = $S.Item
            Valeur    = if ($S.Applied) { "Enabled=0" } elseif ($S.KeyExists) { "Enabled=$($S.Enabled)" } else { "Clé absente (défaut Windows)" }
            Statut    = if ($S.Applied) { "OK" } else { "AVERTISSEMENT" }
        }
    }
    foreach ($S in $All.Dh) {
        $Results += [PSCustomObject]@{
            Categorie = "Diffie-Hellman"; Element = "Longueur mini clé ($($S.Role))"
            Valeur    = if ($null -ne $S.Value) { "$($S.Value) bits" } else { "Non défini (défaut Windows)" }
            Statut    = if ($S.Applied) { "OK" } else { "AVERTISSEMENT" }
        }
    }
    foreach ($S in $All.DotNet) {
        $Results += [PSCustomObject]@{
            Categorie = ".NET Framework"; Element = (Get-DotNetShortLabel -Path $S.Path)
            Valeur    = "SchUseStrongCrypto=$($S.Ssc), SystemDefaultTlsVersions=$($S.Sdtv)"
            Statut    = if ($S.Applied) { "OK" } else { "AVERTISSEMENT" }
        }
    }
    $Findings = Test-TlsGpoOverride
    $Results += [PSCustomObject]@{
        Categorie = "Stratégie de groupe"; Element = "SSL Cipher Suite Order (GPO)"
        Valeur    = if ($Findings.Count -gt 0) { $Findings -join " " } else { "Aucune GPO connue détectée" }
        Statut    = if ($Findings.Count -gt 0) { "AVERTISSEMENT" } else { "OK" }
    }
    return $Results
}

# [NEW v2.1.0] Gabarit HTML statique — identité graphique reprise à l'identique
# de la Toolbox Commandes Système (fond sombre, accent cyan, logo Windows en
# dégradé, cartes de stats, tableau groupé/filtrable). Here-string à quotes
# SIMPLES (@'...'@) : aucune interpolation PowerShell dans le CSS/JS statique,
# les jetons {{...}} sont remplacés explicitement par Export-TlsHtmlReport.
# Fichier autonome (CSS/JS inline) : s'ouvre dans n'importe quel navigateur,
# hors ligne, sur n'importe quel poste de la flotte.
$script:TlsHtmlTemplate = @'
<!DOCTYPE html>
<html lang="fr">
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
tr.row.sensible{background:rgba(255,179,71,.06)}
tr.row.sensible:hover{background:rgba(255,179,71,.12)}
tr.row.erreur{background:rgba(239,112,102,.08)}
tr.row.erreur:hover{background:rgba(239,112,102,.14)}
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
    <span><span class="meta-dot"></span>Généré le <b>{{DATE}}</b></span>
    <span>Machine : <b>{{MACHINE}}</b></span>
    <span>Utilisateur : <b>{{USER}}</b></span>
    <span>Windows : <b>{{WINDOWS}}</b></span>
    <span>Mode : <b>{{MODE}}</b></span>
  </div>
</header>

<main>
  <div class="stats">
    <div class="stat-card ok"><div class="num">{{NB_OK}} / {{NB_TOTAL}}</div><div class="lbl">Contrôles conformes</div></div>
    <div class="stat-card warn"><div class="num">{{NB_WARN}}</div><div class="lbl">Avertissements</div></div>
    <div class="stat-card err"><div class="num">{{NB_ERR}}</div><div class="lbl">Erreurs</div></div>
    <div class="stat-card"><div class="num">{{SCORE}} / 100</div><div class="lbl">Score de conformité</div></div>
  </div>

  <div class="searchbar"><input type="text" id="searchBox" placeholder="Filtrer (catégorie, élément, statut...)" onkeyup="filterReport()"></div>

  <table>
    <tr><th>Catégorie</th><th>Élément</th><th>Détail</th><th>Statut</th></tr>
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
  var filtre = document.getElementById('searchBox').value.toLowerCase();
  var groups = document.querySelectorAll('tr.daysep');
  if (filtre === '') {
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
  document.querySelectorAll('tr.row').forEach(function(ligne) {
    var texte = ligne.textContent.toLowerCase();
    ligne.style.display = texte.indexOf(filtre) !== -1 ? '' : 'none';
  });
}
</script>
</body>
</html>
'@

function Export-TlsHtmlReport {
    # [NEW v2.1.0] Rapport visuel HTML — même identité graphique que la Toolbox
    # Commandes Système. Fichier autonome (CSS/JS inline), écrit à côté du JSON
    # dans le même dossier ($ReportsRoot), jamais à la place de lui : le JSON
    # reste la source consommée par Dashboard-Global_Win11.
    param([array]$Results, [int]$Score, [string]$ModeLabel = "Application")

    try {
        if (-not (Test-Path $ReportsRoot)) {
            New-Item -ItemType Directory -Path $ReportsRoot -Force | Out-Null
        }

        $NbOk    = @($Results | Where-Object { $_.Statut -eq "OK" }).Count
        $NbWarn  = @($Results | Where-Object { $_.Statut -eq "AVERTISSEMENT" }).Count
        $NbErr   = @($Results | Where-Object { $_.Statut -eq "ERREUR" }).Count
        $NbTotal = @($Results).Count

        # [FIX v2.1.4] La clé registre "ProductName" affiche encore "Windows 10"
        # sur de nombreux postes migrés vers Windows 11 — bug connu, jamais
        # corrigé par Microsoft, la clé n'est simplement pas mise à jour lors
        # de la migration. Win32_OperatingSystem (WMI/CIM) reste correct dans
        # tous les cas observés ; le registre sert uniquement de repli si WMI
        # est indisponible (rare, mais évite un plantage sur un poste atypique).
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

        # Regroupement dans l'ordre défini par $CategoryDisplayOrder, puis toute
        # catégorie imprévue à la suite (jamais de ligne perdue).
        $Categories = @()
        foreach ($cat in $CategoryDisplayOrder) {
            if (@($Results | Where-Object { $_.Categorie -eq $cat }).Count -gt 0) { $Categories += $cat }
        }
        foreach ($cat in @($Results | Select-Object -ExpandProperty Categorie -Unique)) {
            if ($Categories -notcontains $cat) { $Categories += $cat }
        }

        $RowsHtml = New-Object System.Text.StringBuilder
        $GroupIdx = 0
        foreach ($cat in $Categories) {
            $GroupItems = @($Results | Where-Object { $_.Categorie -eq $cat })
            $CatSafe    = ConvertTo-HtmlSafe $cat
            [void]$RowsHtml.AppendLine("<tr class=`"daysep`" data-group=`"$GroupIdx`" onclick=`"toggleGroup($GroupIdx)`"><td colspan=`"4`"><span class=`"chevron`">&#9662;</span>$CatSafe<span class=`"count`">($($GroupItems.Count) contrôle(s))</span></td></tr>")
            foreach ($item in $GroupItems) {
                $ElemSafe    = ConvertTo-HtmlSafe $item.Element
                $ValSafe     = ConvertTo-HtmlSafe $item.Valeur
                $StatutClass = switch ($item.Statut) {
                    "OK"            { "ok" }
                    "AVERTISSEMENT" { "warn" }
                    "ERREUR"        { "err" }
                    default         { "warn" }
                }
                $RowClass = switch ($item.Statut) {
                    "ERREUR"        { "row erreur" }
                    "AVERTISSEMENT" { "row sensible" }
                    default         { "row" }
                }
                [void]$RowsHtml.AppendLine("<tr class=`"$RowClass`" data-group=`"$GroupIdx`"><td>$CatSafe</td><td>$ElemSafe</td><td><code>$ValSafe</code></td><td><span class=`"label-$StatutClass`">$(ConvertTo-HtmlSafe $item.Statut)</span></td></tr>")
            }
            $GroupIdx++
        }

        $Horodatage   = Get-Date -Format "yyyyMMdd_HHmmss"
        $DateAffichee = Get-Date -Format "dd/MM/yyyy HH:mm:ss"
        $HtmlPath     = "$ReportsRoot\Rapport_TLS_$Horodatage.html"

        $Html = $script:TlsHtmlTemplate
        $Html = $Html.Replace("{{TITLE}}",    "Harden-TLS v$ScriptVersion")
        $Html = $Html.Replace("{{SUBTITLE}}", "by <b>Nephren</b>")
        $Html = $Html.Replace("{{DATE}}",     $DateAffichee)
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
        Write-Step "Export HTML écrit : $HtmlPath" -Level INFO
        return $HtmlPath
    } catch {
        Write-Step "Export HTML impossible : $($_.Exception.Message)" -Level WARN
        return $null
    }
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
    Write-Host " SELFTEST - Harden-TLS v$ScriptVersion"
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

    # --- [NEW v2.0] Invoke-BinaryHardening (Ciphers/Hashes, logique pure) ---
    $FakeCipherOk  = [PSCustomObject]@{ Label="Chiffrement"; Item="RC4 128/128"; Path="HKLM:\FAKE\RC4"; KeyExists=$true;  Enabled=0;    Applied=$true }
    $FakeCipherKo  = [PSCustomObject]@{ Label="Chiffrement"; Item="NULL";        Path="HKLM:\FAKE\NUL"; KeyExists=$false; Enabled=$null; Applied=$false }
    $CipherDryRes  = Invoke-BinaryHardening -States @($FakeCipherOk, $FakeCipherKo) -IsDryRun -Elevated $false
    Assert-True "Invoke-BinaryHardening (DryRun) : deja conforme -> Skipped, pas Applied" ($CipherDryRes.Skipped -eq 1 -and $CipherDryRes.Applied -eq 0)
    Assert-True "Invoke-BinaryHardening (DryRun) : aucune ecriture (Errors=0)" ($CipherDryRes.Errors -eq 0)

    # --- [NEW v2.0] Invoke-DhHardening (logique pure) ---
    $FakeDhOk = [PSCustomObject]@{ Role="Client"; ValueName="ClientMinKeyBitLength"; KeyExists=$true;  Value=2048; Applied=$true }
    $FakeDhKo = [PSCustomObject]@{ Role="Server"; ValueName="ServerMinKeyBitLength"; KeyExists=$true;  Value=1024; Applied=$false }
    $DhDryRes = Invoke-DhHardening -States @($FakeDhOk, $FakeDhKo) -IsDryRun -Elevated $false
    Assert-True "Invoke-DhHardening (DryRun) : 1024 bits -> non conforme, pas d'ecriture" ($DhDryRes.Skipped -eq 1 -and $DhDryRes.Applied -eq 0 -and $DhDryRes.Errors -eq 0)

    # --- [NEW v2.0] Invoke-TlsRollback : une action deja absente ne compte pas comme Removed ---
    # (verification indirecte via Get-TlsRollbackActions : la liste doit couvrir les 5 categories)
    $RollbackActions = Get-TlsRollbackActions
    Assert-True "Get-TlsRollbackActions : couvre Protocoles + Ciphers + Hashes + DH + .NET" (
        (@($RollbackActions | Where-Object { $_.Description -like "Protocole*" }).Count -eq 4) -and
        (@($RollbackActions | Where-Object { $_.Description -like "Chiffrement*" }).Count -eq $WeakCiphers.Count) -and
        (@($RollbackActions | Where-Object { $_.Description -like "Hachage*" }).Count -eq $WeakHashes.Count) -and
        (@($RollbackActions | Where-Object { $_.Description -like "Diffie-Hellman*" }).Count -eq 2)
    )

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
    $All        = Get-AllHardeningStates
    $AllStates  = @($All.Protocols) + @($All.Ciphers) + @($All.Hashes) + @($All.Dh) + @($All.DotNet)
    $NbConforme = @($AllStates | Where-Object { $_.Applied }).Count
    $Elevated   = Test-IsElevated

    Write-Banner -Title "HARDEN-TLS  v$ScriptVersion  — MODE INTERACTIF" -Color Cyan
    Write-Host ""
    Write-ComplianceGauge -Compliant $NbConforme -Total $AllStates.Count
    Write-Host "                      (protocoles + ciphers + hachages + DH + .NET)" -ForegroundColor DarkGray
    Write-Host "  Mode DryRun         " -NoNewline -ForegroundColor Gray
    Write-Host "$(if ($MenuDryRun) { 'ACTIVÉ (aucune écriture réelle)' } else { 'désactivé' })" -ForegroundColor $(if ($MenuDryRun) { "Magenta" } else { "DarkGray" })
    Write-Host "  Élévation           " -NoNewline -ForegroundColor Gray
    Write-Host "$(if ($Elevated) { 'Administrateur' } else { 'Utilisateur standard (application réelle impossible)' })" -ForegroundColor $(if ($Elevated) { "Green" } else { "Yellow" })
    Write-Host ""

    Show-AllHardeningStates -All $All

    Write-Host ""
    Write-Host ("  " + ("─" * $script:BannerWidth)) -ForegroundColor DarkCyan
    Write-Host "   [1] " -NoNewline -ForegroundColor White
    Write-Host "Afficher l'état détaillé (lecture seule)" -ForegroundColor Gray
    Write-Host "   [2] " -NoNewline -ForegroundColor Yellow
    Write-Host "Appliquer le durcissement (uniquement ce qui manque)" -ForegroundColor Gray
    Write-Host "   [3] " -NoNewline -ForegroundColor Yellow
    Write-Host "Forcer une ré-application complète (même si déjà conforme)" -ForegroundColor Gray
    Write-Host "   [4] " -NoNewline -ForegroundColor Cyan
    Write-Host "Générer / rafraîchir le rapport JSON (sans rien modifier)" -ForegroundColor Gray
    Write-Host "   [5] " -NoNewline -ForegroundColor Cyan
    Write-Host "Vérifier les conflits de stratégie de groupe (lecture seule)" -ForegroundColor Gray
    Write-Host "   [6] " -NoNewline -ForegroundColor Red
    Write-Host "Annuler le durcissement -Undo- (retour aux défauts Windows)" -ForegroundColor Gray
    Write-Host "   [7] " -NoNewline -ForegroundColor Cyan
    Write-Host "Exporter en HTML (rapport visuel, style Toolbox)" -ForegroundColor Gray
    Write-Host ("  " + ("─" * $script:BannerWidth)) -ForegroundColor DarkCyan
    Write-Host "   [D] " -NoNewline -ForegroundColor DarkGray
    Write-Host "Basculer le mode DryRun (actuellement : $(if ($MenuDryRun) { 'activé' } else { 'désactivé' }))" -ForegroundColor DarkGray
    Write-Host "   [Q] " -NoNewline -ForegroundColor DarkGray
    Write-Host "Quitter" -ForegroundColor DarkGray
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
                Write-Banner -Title "ÉTAT DÉTAILLÉ DES CONTRÔLES" -Color Cyan
                Write-Host ""
                Show-AllHardeningStates -All (Get-AllHardeningStates)
                Write-Host ""
                Read-Host "  Appuyez sur Entrée pour revenir au menu"
            }
            "2" {
                Clear-Host
                Write-Host ""
                Write-Host "  Application du durcissement (uniquement ce qui manque)..." -ForegroundColor Cyan
                Write-Host ""
                $All = Get-AllHardeningStates
                $Outcome = Invoke-AllHardening -All $All -IsDryRun:$MenuDryRun -Elevated (Test-IsElevated)
                Write-Host ""
                Write-Host "  Terminé : " -NoNewline -ForegroundColor Gray
                Write-Host "$($Outcome.Applied) appliqué(s)" -NoNewline -ForegroundColor Green
                Write-Host ", $($Outcome.Skipped) déjà conforme(s), " -NoNewline -ForegroundColor White
                Write-Host "$($Outcome.Errors) erreur(s)" -ForegroundColor $(if ($Outcome.Errors -gt 0) { "Red" } else { "White" })
                Export-TlsReport -Results $Outcome.Results | Out-Null
                Write-Host ""
                Read-Host "  Appuyez sur Entrée pour revenir au menu"
            }
            "3" {
                Clear-Host
                Write-Host ""
                Write-Host "  Ré-application FORCÉE de tous les contrôles (même ceux déjà conformes)..." -ForegroundColor Yellow
                Write-Host ""
                $All = Get-AllHardeningStates
                $Outcome = Invoke-AllHardening -All $All -ForceAll -IsDryRun:$MenuDryRun -Elevated (Test-IsElevated)
                Write-Host ""
                Write-Host "  Terminé : " -NoNewline -ForegroundColor Gray
                Write-Host "$($Outcome.Applied) appliqué(s)" -NoNewline -ForegroundColor Green
                Write-Host ", $($Outcome.Skipped) déjà conforme(s), " -NoNewline -ForegroundColor White
                Write-Host "$($Outcome.Errors) erreur(s)" -ForegroundColor $(if ($Outcome.Errors -gt 0) { "Red" } else { "White" })
                Export-TlsReport -Results $Outcome.Results | Out-Null
                Write-Host ""
                Read-Host "  Appuyez sur Entrée pour revenir au menu"
            }
            "4" {
                Clear-Host
                Write-Host ""
                Write-Host "  Génération du rapport JSON à partir de l'état actuel (rien n'est modifié)..." -ForegroundColor Cyan
                Write-Host ""
                $All     = Get-AllHardeningStates
                $Results = Get-AllResultsSnapshot -All $All
                Export-TlsReport -Results $Results | Out-Null
                Write-Host ""
                Read-Host "  Appuyez sur Entrée pour revenir au menu"
            }
            "5" {
                Clear-Host
                Write-Banner -Title "VÉRIFICATION DES STRATÉGIES DE GROUPE (lecture seule)" -Color Cyan
                Write-Host ""
                Show-GpoFindings -Findings (Test-TlsGpoOverride)
                Write-Host ""
                Read-Host "  Appuyez sur Entrée pour revenir au menu"
            }
            "6" {
                Clear-Host
                Write-Banner -Title "ANNULATION DU DURCISSEMENT (-Undo)" -Color Red
                Write-Host ""
                Write-Host "  Ceci va supprimer les clés/valeurs créées par ce script sur CETTE machine" -ForegroundColor Yellow
                Write-Host "  et revenir aux défauts Windows pour tous les contrôles." -ForegroundColor Yellow
                Write-Host ""
                $Confirm = Read-Host "  Confirmer l'annulation ? (O/N)"
                if ($Confirm.ToUpper() -eq "O") {
                    $Outcome = Invoke-TlsRollback -IsDryRun:$MenuDryRun -Elevated (Test-IsElevated)
                    Write-Host ""
                    Write-Host "  Terminé : " -NoNewline -ForegroundColor Gray
                    Write-Host "$($Outcome.Removed) supprimé(s)" -NoNewline -ForegroundColor Green
                    Write-Host ", $($Outcome.Skipped) déjà absent(s), " -NoNewline -ForegroundColor White
                    Write-Host "$($Outcome.Errors) erreur(s)" -ForegroundColor $(if ($Outcome.Errors -gt 0) { "Red" } else { "White" })
                    Export-TlsReport -Results $Outcome.Results | Out-Null
                } else {
                    Write-Host "  Annulation abandonnée." -ForegroundColor Gray
                }
                Write-Host ""
                Read-Host "  Appuyez sur Entrée pour revenir au menu"
            }
            "7" {
                Clear-Host
                Write-Banner -Title "EXPORT HTML — état actuel (rien n'est modifié)" -Color Cyan
                Write-Host ""
                $All      = Get-AllHardeningStates
                $Results  = Get-AllResultsSnapshot -All $All
                $ScoreVal = Export-TlsReport -Results $Results
                if ($null -eq $ScoreVal) { $ScoreVal = 0 }
                $HtmlPath = Export-TlsHtmlReport -Results $Results -Score $ScoreVal -ModeLabel "État actuel (lecture seule)"
                if ($HtmlPath) {
                    Write-Host ""
                    Write-Host "  Ouvrir dans le navigateur par défaut ? (O/N)" -ForegroundColor Cyan
                    $OpenIt = Read-Host "  Choix"
                    if ($OpenIt.ToUpper() -eq "O") { Start-Process $HtmlPath }
                }
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

$HeaderColor = if ($Undo) { "Red" } elseif ($DryRun) { "Magenta" } else { "Cyan" }
Write-Banner -Title "HARDEN-TLS  v$ScriptVersion" -Color $HeaderColor
if ($DryRun) {
    Write-Host "  MODE DRY-RUN — aucune modification ne sera appliquée" -ForegroundColor Magenta
}
if ($Force) {
    Write-Host "  MODE FORCE — ré-application même si déjà conforme" -ForegroundColor Yellow
}
if ($Undo) {
    Write-Host "  MODE UNDO — retour aux défauts Windows" -ForegroundColor Red
}
Write-Host ""

# [NEW v2.0] -Undo est traité en premier et sort du script : c'est un chemin
# distinct de l'application normale, jamais combiné avec elle. Gardé par
# ShouldProcess (impact plus large qu'une application classique), en plus du
# -DryRun/-WhatIf déjà géré en amont.
if ($Undo) {
    Write-Step "Lecture des clés/valeurs éligibles à la suppression..." -Level INFO
    Write-Host ""

    $Elevated = Test-IsElevated
    if (-not $DryRun -and -not $Elevated) {
        Write-Step "Élévation administrateur requise pour annuler le durcissement — relancer en tant qu'Administrateur." -Level WARN
    }

    $RollbackOutcome = $null
    if ($DryRun -or $PSCmdlet.ShouldProcess("$env:COMPUTERNAME", "Annuler le durcissement TLS/SCHANNEL (suppression des clés créées, retour aux défauts Windows)")) {
        $RollbackOutcome = Invoke-TlsRollback -IsDryRun:$DryRun -Elevated $Elevated
    } else {
        Write-Step "Annulation abandonnée (ShouldProcess refusé)." -Level WARN
        $RollbackOutcome = Invoke-TlsRollback -IsDryRun -Elevated $Elevated
    }

    $RollbackBannerColor = if ($RollbackOutcome.Errors -eq 0) { "Green" } else { "Yellow" }
    $RollbackTitle       = if ($RollbackOutcome.Errors -eq 0) { "✓ ANNULATION TERMINÉE" } else { "! ANNULATION PARTIELLE" }
    Write-Banner -Title $RollbackTitle -Color $RollbackBannerColor
    Write-Host "  Supprimés     " -NoNewline -ForegroundColor Gray
    Write-Host "$($RollbackOutcome.Removed)" -NoNewline -ForegroundColor Green
    Write-Host "   ·   " -NoNewline -ForegroundColor DarkGray
    Write-Host "Déjà absents " -NoNewline -ForegroundColor Gray
    Write-Host "$($RollbackOutcome.Skipped)" -NoNewline -ForegroundColor White
    Write-Host "   ·   " -NoNewline -ForegroundColor DarkGray
    Write-Host "Erreurs " -NoNewline -ForegroundColor Gray
    Write-Host "$($RollbackOutcome.Errors)" -ForegroundColor $(if ($RollbackOutcome.Errors -eq 0) { "Green" } else { "Red" })
    Write-Host ""

    Export-TlsReport -Results $RollbackOutcome.Results | Out-Null
    if ($Html) {
        $RollbackScore = if ($RollbackOutcome.Results.Count -gt 0) { [int][Math]::Round(100 * (@($RollbackOutcome.Results | Where-Object { $_.Statut -eq "OK" }).Count) / $RollbackOutcome.Results.Count) } else { 0 }
        Export-TlsHtmlReport -Results $RollbackOutcome.Results -Score $RollbackScore -ModeLabel "Annulation (-Undo)" | Out-Null
    }

    if (-not $Silent) {
        Write-Host "  ╔═══════════════════════════════════════════════════╗" -ForegroundColor DarkCyan
        Write-Host "  ║  Appuyez sur ENTRÉE pour fermer cette fenêtre...  ║" -ForegroundColor DarkCyan
        Write-Host "  ╚═══════════════════════════════════════════════════╝" -ForegroundColor DarkCyan
        $null = Read-Host
    }
    exit $(if ($RollbackOutcome.Errors -eq 0) { 0 } else { 1 })
}

# [NEW v1.2] État vérifié et affiché AVANT toute décision — que tout soit déjà conforme ou non.
Write-Step "Lecture de l'état actuel (protocoles, ciphers, hachages, Diffie-Hellman, .NET)..." -Level INFO
Write-Host ""
$All       = Get-AllHardeningStates
$AllStates = @($All.Protocols) + @($All.Ciphers) + @($All.Hashes) + @($All.Dh) + @($All.DotNet)
Show-AllHardeningStates -All $All
Write-Host ""

$NbConforme = @($AllStates | Where-Object { $_.Applied }).Count
if ($NbConforme -eq $AllStates.Count -and -not $Force) {
    Write-Step "Les $($AllStates.Count) contrôles sont déjà conformes — aucune modification nécessaire (utiliser -Force pour ré-appliquer quand même)." -Level OK
} elseif (-not $DryRun -and -not (Test-IsElevated)) {
    Write-Step "Élévation administrateur requise pour appliquer les changements — relancer ce script en tant qu'Administrateur. Le rapport JSON sera tout de même généré avec l'état actuel." -Level WARN
}

Write-Banner -Title "APPLICATION" -Color Cyan
Write-Host ""

$Outcome  = Invoke-AllHardening -All $All -ForceAll:$Force -IsDryRun:$DryRun -Elevated (Test-IsElevated)

# [FIX v2.0] $Outcome.Applied vaut TOUJOURS 0 en -DryRun (rien n'est réellement
# écrit) — tester "Applied -eq 0" seul confondait alors "rien à faire" avec
# "beaucoup à faire mais -DryRun empêche l'écriture". $NbEnAttente distingue
# les deux : contrôles ni appliqués, ni déjà conformes, ni en erreur.
$NbEnAttente = $AllStates.Count - $Outcome.Applied - $Outcome.Skipped - $Outcome.Errors

if ($Outcome.Errors -eq 0) {
    if ($DryRun -and $NbEnAttente -gt 0) {
        Write-Banner -Title "» DRY-RUN — $NbEnAttente CHANGEMENT(S) IDENTIFIÉ(S)" -Color Magenta
    } elseif ($Outcome.Applied -eq 0 -and $NbEnAttente -eq 0) {
        Write-Banner -Title "✓ RIEN À FAIRE — TOUT ÉTAIT DÉJÀ CONFORME" -Color Green
    } else {
        Write-Banner -Title "✓ DURCISSEMENT TLS APPLIQUÉ" -Color Green
    }
} else {
    Write-Banner -Title "! DURCISSEMENT PARTIEL ($($Outcome.Errors) erreur(s))" -Color Yellow
}
Write-Host ""

$NbConformeApres = $Outcome.Applied + $Outcome.Skipped
Write-ComplianceGauge -Compliant $NbConformeApres -Total $AllStates.Count
Write-Host ""

Write-Host "  Appliqués             " -NoNewline -ForegroundColor Gray
Write-Host "$($Outcome.Applied) / $($AllStates.Count)" -ForegroundColor Green
Write-Host "  Déjà conformes        " -NoNewline -ForegroundColor Gray
Write-Host "$($Outcome.Skipped) / $($AllStates.Count)" -ForegroundColor White
if ($NbEnAttente -gt 0) {
    Write-Host "  En attente (DryRun)   " -NoNewline -ForegroundColor Gray
    Write-Host "$NbEnAttente / $($AllStates.Count)" -NoNewline -ForegroundColor Magenta
    Write-Host "  — relancer SANS -DryRun (en Administrateur) pour appliquer" -ForegroundColor DarkGray
}
if ($Outcome.Errors -gt 0) {
    Write-Host "  Erreurs               " -NoNewline -ForegroundColor Gray
    Write-Host "$($Outcome.Errors) / $($AllStates.Count)" -ForegroundColor Red
}
Write-Host ""
Write-Host "  ── Détail du périmètre ──────────────────────" -ForegroundColor DarkGray
Write-Host "  Protocoles            " -NoNewline -ForegroundColor Gray
Write-Host "$($ProtosToDisable -join ', ') (Client + Server)" -ForegroundColor White
Write-Host "  Chiffrements          " -NoNewline -ForegroundColor Gray
Write-Host "$($WeakCiphers.Count) suites obsolètes désactivées" -ForegroundColor White
Write-Host "  Hachages              " -NoNewline -ForegroundColor Gray
Write-Host "$($WeakHashes -join ', ')" -ForegroundColor White
Write-Host "  Diffie-Hellman        " -NoNewline -ForegroundColor Gray
Write-Host "longueur mini $DhMinKeyBitLength bits (Client + Server)" -ForegroundColor White
Write-Host "  .NET Framework        " -NoNewline -ForegroundColor Gray
Write-Host "Strong Crypto sur $($All.DotNet.Count) emplacement(s) détecté(s)" -ForegroundColor White
Write-Host "  Non touchés           " -NoNewline -ForegroundColor Gray
Write-Host "TLS 1.2 / TLS 1.3, AES, SHA-256+ (défauts Windows conservés)" -ForegroundColor DarkGray
if (-not $DryRun -and $Outcome.Applied -gt 0) {
    Write-Host ""
    Write-Host "  ! Redémarrage requis  " -NoNewline -ForegroundColor Yellow
    Write-Host "pour que SCHANNEL recharge sa configuration" -ForegroundColor Yellow
    Write-Host "                        (protocoles/ciphers/hachages/DH). En cas d'incompatibilité" -ForegroundColor Yellow
    Write-Host "                        sur un poste précis : relancer avec -Undo." -ForegroundColor Yellow
}
Write-Host ""
Write-Host ("  " + ("─" * $script:BannerWidth)) -ForegroundColor DarkCyan
Write-Host ""

# Export JSON systématique — y compris quand tout était déjà conforme et qu'aucune
# écriture n'a eu lieu, pour que Dashboard-Global_Win11 dispose d'un état à jour.
$ScoreValue = Export-TlsReport -Results $Outcome.Results
if ($Html) {
    if ($null -eq $ScoreValue) { $ScoreValue = 0 }
    $ModeLabelClassic = if ($DryRun) { "DRY-RUN (aucune modification)" } elseif ($Force) { "Application forcée" } else { "Application" }
    $HtmlPath = Export-TlsHtmlReport -Results $Outcome.Results -Score $ScoreValue -ModeLabel $ModeLabelClassic
    if ($HtmlPath -and -not $Silent) {
        Write-Step "Ouvrir le rapport HTML : $HtmlPath" -Level INFO
    }
}

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
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCD6lkIUmUW76vXv
# wRm4libSiMPoOa6Tz2fmE2gpTuFYKqCCAygwggMkMIICDKADAgECAhB6X4r8AlBU
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
# ARUwLwYJKoZIhvcNAQkEMSIEIJWnSSG1twPJ3vGkzKsPrTLwbiMBkV9NJQjN1yqM
# ZGf8MA0GCSqGSIb3DQEBAQUABIIBAAPZa/K4bNLP9V127TXgZ1K0zcoMqp02cz3m
# ku7zUQC1UU6kW4XU1MtAGkEbYMtaXBuuAk5BglNBAHpgEm+voipoINEYB5rMhEVA
# D9xt7GFMAKNr6FRMccL9te/EU/6wT+5nTLF2T7eH0io60QlDiiSjgPAPYWociOfx
# QWySs10O9Ndn+uXN2ohJ20gHTUA1UOO/HHZyWbpdITLUonzvxS1MJZj2pjxmoSJl
# A0kHizqfe3DENQT8F7mAjB3J6D4WgIGzQSck0ESxqHo+vq91BYgpuVFdUHdJOUXn
# rJkbWYaZJ6TYkcKbfIQYaSnoyEOgyfbPCtA0AhzlLlwUKgTIsb0=
# SIG # End signature block
