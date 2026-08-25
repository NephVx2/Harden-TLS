# Harden-TLS

**Durcissement TLS/SCHANNEL idempotent pour Windows 11 — avec des explications accessibles, des rapports visuels, et une annulation en une commande.**

[🇬🇧 Read in English](README.md)

> Désactive les technologies de chiffrement obsolètes et non sécurisées intégrées à Windows, pour qu'aucun logiciel de votre PC (les navigateurs exclus, qui gèrent cela eux-mêmes) ne puisse les utiliser accidentellement. Peut être relancé autant de fois que nécessaire, sans risque. Réversible.

---

## Sommaire

- [Pourquoi ce script existe](#pourquoi-ce-script-existe)
- [Ce que fait réellement ce script](#ce-que-fait-réellement-ce-script)
- [Comprendre le sujet : qu'est-ce que TLS, et pourquoi est-ce important ?](#comprendre-le-sujet--quest-ce-que-tls-et-pourquoi-est-ce-important-)
  - [TLS en un paragraphe](#tls-en-un-paragraphe)
  - [Les protocoles (TLS 1.0 / 1.1 / 1.2 / 1.3)](#les-protocoles-tls-10--11--12--13)
  - [Les suites de chiffrement](#les-suites-de-chiffrement)
  - [Les algorithmes de hachage](#les-algorithmes-de-hachage)
  - [L'échange de clés Diffie-Hellman](#léchange-de-clés-diffie-hellman)
  - [.NET Framework et le "Strong Crypto"](#net-framework-et-le-strong-crypto)
- [Ce que ce script NE touche PAS](#ce-que-ce-script-ne-touche-pas)
- [Prérequis](#prérequis)
- [Premiers pas — votre premier lancement](#premiers-pas--votre-premier-lancement)
- [Tous les paramètres, expliqués](#tous-les-paramètres-expliqués)
- [Le menu interactif](#le-menu-interactif)
- [Tout annuler (-Undo)](#tout-annuler--undo)
- [Rapports (JSON & HTML)](#rapports-json--html)
- [Stratégie de groupe / postes joints à un domaine](#stratégie-de-groupe--postes-joints-à-un-domaine)
- [Questions fréquentes](#questions-fréquentes)
- [Avertissement](#avertissement)

---

## Pourquoi ce script existe

Windows embarque, par défaut, la prise en charge d'anciennes versions — devenues faibles — de la technologie qui chiffre votre trafic internet. La raison est simple : les désactiver par défaut casserait la compatibilité avec certains matériels et logiciels très anciens encore en service. C'est un choix raisonnable pour Microsoft, mais cela signifie aussi que chaque PC Windows 11, dès sa sortie de boîte, reste techniquement *capable* d'utiliser un chiffrement aujourd'hui considéré comme cassé.

En pratique, rien n'oblige un attaquant à utiliser le chiffrement moderne et robuste que votre PC prend en charge. Si les anciennes options faibles restent activées, un attaquant présent sur le même réseau (un Wi-Fi public, un routeur compromis, etc.) peut parfois forcer une connexion à "revenir" vers l'option la plus faible que les deux parties acceptent techniquement, puis la casser. C'est une catégorie d'attaque connue et documentée — c'est d'ailleurs pour cette raison que des technologies comme SSL 3.0 ou le chiffrement RC4 ont été formellement bannies des standards internet il y a plusieurs années.

**Harden-TLS ne désactive que ce qui est réellement obsolète**, et laisse tout ce qui est moderne exactement tel que Windows l'a configuré par défaut. C'est le même type de durcissement que recommandent les référentiels de sécurité (comme le CIS Benchmark pour Windows), packagé sous forme de script que vous pouvez lancer, vérifier, exporter en rapport, et annuler — en toute sécurité, autant de fois que nécessaire, sur autant de machines que vous le souhaitez.

## Ce que fait réellement ce script

Harden-TLS applique cinq catégories de modifications, toutes sous `HKLM` (registre au niveau de la machine, pas lié à un compte utilisateur en particulier) — le résultat est donc identique quel que soit l'utilisateur qui se connecte ensuite :

| Catégorie | Ce qui est désactivé | Ce qui n'est pas touché |
|---|---|---|
| **Protocoles** | TLS 1.0, TLS 1.1 (Client + Server) | TLS 1.2, TLS 1.3 |
| **Suites de chiffrement** | RC4 (toutes longueurs de clé), DES 56/56, RC2 (toutes longueurs), Triple DES 168, NULL | AES 128/256, et les suites modernes GCM / ChaCha20 |
| **Hachage** | MD5, SHA-1 | SHA-256, SHA-384, SHA-512 |
| **Diffie-Hellman** | Tout échange de clé inférieur à 2048 bits est relevé à 2048 bits | Les machines déjà conformes ne sont pas touchées |
| **.NET Framework** | Active le "Strong Crypto" (`SchUseStrongCrypto`, `SystemDefaultTlsVersions`) sur chaque installation .NET Framework détectée sur la machine | N'invente jamais une installation .NET qui n'existe pas |

En complément, le script :

- **Vérifie avant d'écrire.** Chaque contrôle est d'abord lu ; s'il est déjà conforme, il n'est absolument pas touché — rien n'est réécrit inutilement à chaque exécution.
- **Détecte les conflits de Stratégie de Groupe** (en lecture seule) — utile sur un poste joint à un domaine, où une policy pourrait silencieusement redéfinir ces mêmes réglages au prochain `gpupdate`.
- **Peut s'annuler lui-même** (`-Undo`) — retire exactement ce qu'il a créé, rien de plus, et remet la machine dans son état par défaut Windows.
- **Prend en charge `-WhatIf`/`-DryRun`** — voir précisément ce qui changerait avant que quoi que ce soit ne soit écrit.
- **Exporte un rapport JSON** à chaque exécution, et en option un **rapport HTML** autonome, au thème sombre, consultable dans n'importe quel navigateur.
- **Ne touche jamais votre navigateur web.** Chrome, Firefox, Brave, Edge, etc. gèrent leur propre chiffrement indépendamment de Windows et ne sont pas concernés.

## Comprendre le sujet : qu'est-ce que TLS, et pourquoi est-ce important ?

Cette section ne suppose aucune connaissance préalable en sécurité informatique. Si vous connaissez déjà ces notions, passez directement à [Premiers pas](#premiers-pas--votre-premier-lancement).

### TLS en un paragraphe

**TLS (Transport Layer Security)** est la technologie qui affiche le petit cadenas dans la barre d'adresse de votre navigateur. Chaque fois que votre ordinateur communique avec un site web, un serveur mail, le VPN de votre entreprise, ou presque n'importe quoi d'autre sur internet, c'est TLS qui brouille cette conversation, afin que toute personne interceptant le trafic entre les deux (votre fournisseur d'accès, quelqu'un sur le même Wi-Fi public, un attaquant ayant compromis un routeur) ne voie qu'un bruit incompréhensible, et non vos mots de passe, messages ou informations bancaires. TLS n'est pas une chose unique : c'est une **négociation** entre votre ordinateur et l'autre partie, où les deux se mettent d'accord sur **quelle version du protocole**, **quelle méthode de chiffrement** et **quelle méthode de hachage** utiliser pour cette conversation précise. Ce script réduit la liste des options que Windows accepte de proposer pendant cette négociation, pour ne laisser sur la table que les choix modernes et sûrs.

### Les protocoles (TLS 1.0 / 1.1 / 1.2 / 1.3)

La "version du protocole" est en quelque sorte l'édition du règlement TLS que les deux parties acceptent de suivre.

- **TLS 1.0** (1999) et **TLS 1.1** (2006) sont suffisamment anciens pour précéder la plupart des attaques que l'on sait aujourd'hui mener contre eux. Les deux ont été **officiellement dépréciés** par l'organisme qui régit les standards internet (l'IETF, dans la RFC 8996, publiée en 2021) et par tous les principaux éditeurs de navigateurs. C'est l'équivalent numérique d'un cadenas que le fabricant a cessé de recommander il y a vingt ans : il fonctionne encore, mais c'est une faiblesse connue.
- **TLS 1.2** (2008) est encore considéré comme sûr aujourd'hui lorsqu'il est correctement configuré, et reste extrêmement répandu.
- **TLS 1.3** (2018) est le standard actuel : plus rapide, et il supprime par conception des catégories entières d'options faibles (mauvaises suites de chiffrement, hachages faibles) de la négociation.

**Ce script désactive uniquement TLS 1.0 et TLS 1.1.** TLS 1.2 et TLS 1.3 restent exactement tels que Windows les configure par défaut.

### Les suites de chiffrement

Une fois la version du protocole choisie, les deux parties doivent encore s'accorder sur **la méthode de chiffrement des données elles-mêmes**. Ce choix s'appelle un "cipher" (ou "suite de chiffrement" lorsqu'il regroupe plusieurs choix liés).

- **RC4** : un chiffrement de flux extrêmement populaire pendant plus d'une décennie, jusqu'à ce que des chercheurs démontrent des attaques pratiques permettant à un espion de récupérer des fragments du trafic. Il est formellement banni de TLS par les standards internet (RFC 7465, 2015).
- **DES / Triple DES ("3DES")** : DES (1977) utilise une clé si courte selon les standards actuels qu'un matériel dédié peut la casser par force brute en quelques heures ; 3DES était un correctif qui applique DES trois fois pour compenser, mais reste lent et présente ses propres faiblesses bien documentées (l'attaque "Sweet32"). Les deux sont considérés comme obsolètes tant par le NIST (l'institut américain de standardisation) que par Microsoft.
- **RC2** : un autre chiffrement daté, de la même époque que DES, avec le même type de faiblesses.
- **Chiffrement NULL** : c'est le "chiffrement" qui signifie *aucun chiffrement du tout* — la connexion garde le format TLS, mais le contenu n'est pas brouillé. Il existe à des fins de test et ne devrait jamais être accessible en conditions réelles.

**Ce script désactive tout ce qui précède.** Il ne touche jamais **AES** (128 ou 256 bits) ni les suites modernes **GCM** ou **ChaCha20** — ce sont les méthodes de chiffrement recommandées par toutes les directives de sécurité actuelles, et Windows continuera de les proposer exactement comme avant.

### Les algorithmes de hachage

Une **fonction de hachage** prend n'importe quelle quantité de données et en produit une empreinte courte, de taille fixe. Dans TLS, les hachages servent à garantir que les données arrivées sont exactement celles qui ont été envoyées — qu'aucune n'a été modifiée en chemin (un rôle appelé "intégrité").

- **MD5** (1992) et **SHA-1** (1995) sont deux fonctions de hachage dont des chercheurs ont depuis démontré qu'elles peuvent être délibérément "cassées" : un attaquant peut construire deux données différentes produisant la *même* empreinte, ce qui annule tout l'intérêt du contrôle. Les deux ont été formellement retirées de l'usage TLS (MD5 dans la RFC 6151 ; l'usage de SHA-1 dans les certificats TLS progressivement abandonné par tous les grands navigateurs depuis 2017).

**Ce script désactive MD5 et SHA-1.** SHA-256, SHA-384 et SHA-512 — les membres modernes et non cassés de la même famille — ne sont absolument pas touchés.

### L'échange de clés Diffie-Hellman

Avant que votre ordinateur et un serveur puissent commencer à chiffrer des données avec un secret partagé, ils doivent d'abord se mettre d'accord sur *quel est ce secret* — sans jamais transmettre ce secret lui-même d'une façon qu'un espion pourrait intercepter. **Diffie-Hellman (DH)** est l'astuce mathématique classique (publiée en 1976, et toujours la base conceptuelle de la plupart des échanges de clés modernes) qui rend cela possible : les deux parties peuvent arriver au même nombre secret via des échanges de calculs publics, sans que quiconque observant cet échange ne puisse reconstituer ce nombre par lui-même.

La sécurité de cette astuce dépend entièrement de la taille des nombres utilisés — ce que l'on appelle la **longueur de clé**, mesurée en bits. Un échange DH utilisant une **clé de moins de 2048 bits** peut, avec la puissance de calcul actuelle (et certainement par un attaquant disposant de ressources conséquentes, comme l'a démontré la recherche "Logjam" en 2015), être cassé. **2048 bits est le minimum recommandé par Microsoft depuis 2016.**

**Ce script relève à 2048 bits toute configuration d'échange DH inférieure à ce seuil.** Il n'abaisse jamais un réglage déjà plus élevé.

### .NET Framework et le "Strong Crypto"

Ce dernier point est un peu différent — il ne concerne pas la négociation réseau elle-même, mais le fait de s'assurer que les applications Windows utilisent réellement les réglages sécurisés ci-dessus.

De nombreuses applications Windows reposent sur **.NET Framework**, la plateforme applicative de Microsoft. Pour des raisons de compatibilité historique, les anciennes versions de .NET Framework peuvent être configurées pour gérer **leur propre** liste de versions TLS et de chiffrements autorisés — totalement indépendamment des réglages SCHANNEL que ce script vient de durcir. En pratique, cela signifie qu'une ancienne application .NET (ou même un composant Windows comme WinRM) pourrait continuer à négocier en TLS 1.0 ou avec des chiffrements faibles, même après que ce script les a désactivés au niveau du système d'exploitation — simplement parce que cette application n'a jamais demandé à Windows ce qu'il fallait utiliser.

**Le "Strong Crypto" est un réglage de .NET Framework** (`SchUseStrongCrypto` + `SystemDefaultTlsVersions`, deux DWORD de registre) qui indique à chaque application .NET de la machine : *arrête de gérer ta propre liste, utilise simplement ce que Windows lui-même autorise.* Ce script l'active sur chaque installation .NET Framework détectée sur votre machine (aussi bien l'emplacement natif 64 bits que l'emplacement 32 bits "Wow6432Node", si présents) — il n'invente jamais une installation .NET qui n'existe pas déjà.

Sans cette étape, durcir uniquement SCHANNEL laisse un angle mort réel et documenté pour les logiciels basés sur .NET.

## Ce que ce script NE touche PAS

- **TLS 1.2 et TLS 1.3** — laissés exactement tels que Windows les configure.
- **Le chiffrement AES**, et les suites modernes **GCM / ChaCha20**.
- **Le hachage SHA-256, SHA-384, SHA-512**.
- **Les navigateurs web** (Chrome, Firefox, Brave, Edge...) — ils gèrent tous TLS indépendamment de Windows et ne sont absolument pas concernés par ce script.
- **Tout ce qui est déjà conforme** — chaque contrôle est lu avant d'être écrit ; un réglage déjà durci est laissé tel quel plutôt que réécrit.
- **La Stratégie de Groupe** — le script ne fait que *lire* les clés de registre liées aux GPO pour vous avertir d'un conflit potentiel ; il ne modifie jamais une policy.

## Prérequis

- **Windows 11** (le script cible les chemins de registre SCHANNEL présents sur Windows 11 ; il n'a pas été validé sur d'autres versions de Windows).
- **PowerShell 5.1 ou supérieur** (inclus par défaut dans Windows 11).
- **Droits administrateur** pour appliquer réellement les changements. Sans eux, le script fonctionne quand même et affiche l'état actuel ainsi que ce qu'il *changerait* (lecture seule) — il ne peut simplement pas écrire dans le registre.
- **Un redémarrage** est nécessaire ensuite pour que SCHANNEL recharge sa configuration (protocoles/chiffrements/hachages/Diffie-Hellman). Le changement .NET Strong Crypto ne nécessite techniquement que le redémarrage des applications concernées, mais un redémarrage complet reste le moyen le plus simple de garantir un état propre, en particulier sur plusieurs machines.

## Premiers pas — votre premier lancement

Suivez ces étapes dans l'ordre. Chaque commande ci-dessous peut être copiée-collée telle quelle sans risque — les trois premières ne modifient rien du tout sur votre PC.

1. **Copiez `Harden-TLS.ps1`** sur la machine cible.

2. **Ouvrez PowerShell en tant qu'administrateur.** Vous pouvez aussi lancer le script sans droits administrateur — il bascule alors en mode lecture seule et ne peut rien appliquer (les étapes 3 et 4 ci-dessous fonctionnent dans les deux cas).

3. **Lancez d'abord le self-test.** Il n'écrit rien et ne modifie rien sur votre système — il vérifie seulement que le script lui-même fonctionne correctement sur votre machine :

   ```powershell
   .\Harden-TLS.ps1 -SelfTest
   ```

   Cela exécute la suite de tests internes du script (logique de notation, gestion des rapports — aucun accès au registre). Code de sortie `0` = tout est passé.

4. **Prévisualisez ce qui changerait**, toujours sans rien écrire :

   ```powershell
   .\Harden-TLS.ps1 -DryRun
   ```

   Cela liste chaque réglage qui n'est pas encore conforme et ce qui serait précisément écrit pour le corriger — rien n'est réellement appliqué.

5. **Lancez le menu interactif** — exécutez simplement le script sans aucun paramètre :

   ```powershell
   .\Harden-TLS.ps1
   ```

   Depuis le menu, procédez dans cet ordre :
   - **Choisissez `1`** en premier — *"Afficher l'état détaillé"*. C'est en lecture seule : cela vous montre exactement où en est votre PC actuellement, contrôle par contrôle, avant que quoi que ce soit ne soit touché.
   - Une fois que vous êtes à l'aise avec ce qui va changer, **choisissez `2`** — *"Appliquer le durcissement"*. Seul ce qui manque réellement est modifié ; tout ce qui est déjà conforme est laissé tel quel.

6. **Redémarrez l'ordinateur** une fois terminé, pour que SCHANNEL prenne en compte les nouveaux réglages.

7. **Pour une tâche planifiée ou un déploiement sur plusieurs machines**, passez directement en mode silencieux avec génération d'un rapport à consulter après coup, plutôt que de suivre la console en direct :

   ```powershell
   .\Harden-TLS.ps1 -Silent -Html
   ```

8. *(Optionnel mais recommandé)* Quelques jours plus tard, ou après une mise à jour Windows, relancez le script — il affichera tout comme déjà conforme et n'appliquera aucun changement, confirmant que rien n'a réinitialisé votre durcissement.

Si vous préférez vous passer du menu et tout piloter en ligne de commande, voir tous les paramètres ci-dessous.

## Tous les paramètres, expliqués

| Paramètre | Ce qu'il fait |
|---|---|
| `-DryRun` | Affiche exactement ce qui *serait* écrit dans le registre, sans rien écrire. Toujours sans risque. |
| `-Force` | Réapplique chaque contrôle même s'il est déjà conforme (utile après une restauration système, par exemple). |
| `-Undo` | Retire tout ce que ce script a créé et restaure les valeurs par défaut de Windows. Voir [ci-dessous](#tout-annuler--undo). |
| `-Html` | Génère en plus un rapport HTML autonome, au thème sombre, consultable dans n'importe quel navigateur, en complément du rapport JSON. |
| `-Menu` | Force l'ouverture du menu interactif même si d'autres paramètres sont fournis (ex : `-Menu -DryRun` ouvre un menu qui simule chaque action). |
| `-Silent` | Supprime l'invite finale "Appuyez sur Entrée" — utile pour une tâche planifiée ou un déploiement silencieux sur plusieurs machines. |
| `-RetainReportsDays <N>` | Supprime les fichiers de rapport plus vieux que N jours (30 par défaut). Le fichier de référence utilisé pour le suivi des changements n'est jamais supprimé. |
| `-SelfTest` | Exécute la suite de tests internes du script (logique de notation, gestion de l'historique) puis quitte. Ne touche absolument pas au registre. |
| `-WhatIf` | Paramètre PowerShell standard ; se comporte ici de façon identique à `-DryRun`. |

Exemples :

```powershell
# Voir ce qui changerait, sans rien modifier
.\Harden-TLS.ps1 -DryRun

# Appliquer le durcissement et générer un rapport HTML
.\Harden-TLS.ps1 -Html

# Lancement silencieux pour tâche planifiée / déploiement de flotte
.\Harden-TLS.ps1 -Silent

# Annuler tout ce que ce script a fait sur cette machine
.\Harden-TLS.ps1 -Undo
```

## Le menu interactif

Lancer le script sans argument (ou avec `-Menu`) ouvre un menu qui affiche toujours votre niveau de conformité actuel en haut, puis vous permet de :

1. Afficher l'état détaillé de chaque contrôle (lecture seule)
2. Appliquer le durcissement (uniquement ce qui manque)
3. Forcer une réapplication complète (même si déjà conforme)
4. Générer/rafraîchir le rapport JSON sans rien modifier
5. Vérifier les conflits de Stratégie de Groupe (lecture seule)
6. Annuler le durcissement (`-Undo`)
7. Exporter un rapport HTML

Ainsi qu'un bouton pour activer/désactiver le mode simulation, et une option pour quitter. C'est la façon la plus simple d'explorer le script en toute sécurité avant de lui faire confiance pour des modifications réelles.

## Tout annuler (`-Undo`)

Si un équipement ou un logiciel ancien en particulier s'avère incompatible avec ce durcissement, lancez :

```powershell
.\Harden-TLS.ps1 -Undo
```

Cela retire exactement ce que le script a lui-même créé — les clés de registre dédiées aux protocoles/chiffrements/hachages, et les valeurs individuelles Diffie-Hellman/.NET qu'il a ajoutées — rien de plus. Il ne supprime jamais une clé de registre qui existait avant le passage du script, ni une valeur appartenant à un autre réglage. Cela vous offre un vrai retour, sûr, aux réglages par défaut de Windows, machine par machine.

## Rapports (JSON & HTML)

Chaque exécution écrit un rapport JSON dans `Desktop\Rapports_Maintenance\TLS\`, suivant la même convention que le reste de la suite de scripts de cet auteur — utile si vous utilisez également les scripts de tableau de bord/supervision associés. Ajoutez `-Html` pour un rapport visuel et partageable, consultable directement dans un navigateur, sans aucune dépendance.

## Stratégie de groupe / postes joints à un domaine

Si votre PC est joint à un domaine d'entreprise/organisation, une Stratégie de Groupe définie par un administrateur pourrait redéfinir ces mêmes réglages SCHANNEL au prochain rafraîchissement de policy (`gpupdate`) — écrasant silencieusement ce que ce script a configuré. Harden-TLS vérifie cela (en lecture seule) et vous avertira si une policy pertinente est présente. Il ne modifie jamais la Stratégie de Groupe lui-même. Si un avertissement s'affiche et que vous souhaitez confirmer ce qui est réellement en vigueur, lancez `gpresult /h` pour un rapport complet.

## Questions fréquentes

**Est-ce que ça risque de casser quelque chose ?**
Pour la quasi-totalité des logiciels modernes (applications Windows actuelles, navigateurs actuels, VPN/services d'entreprise actuels), non — TLS 1.2/1.3 avec AES/GCM est le standard de fait depuis des années. Un matériel réellement ancien (vieilles imprimantes, certains NAS, appliances VPN obsolètes) qui ne parle *que* TLS 1.0/1.1 ou les chiffrements désactivés pourrait perdre la connexion avec ce PC en particulier. Si cela arrive, lancez `-Undo` sur cette machine.

**Est-ce sans risque de le relancer plusieurs fois ?**
Oui — c'est toute la logique de conception du script. Il vérifie l'état actuel avant toute modification et ignore ce qui est déjà conforme. Le relancer dix fois de suite après un premier passage réussi ne devrait produire aucun changement à chaque fois.

**Faut-il redémarrer à chaque lancement ?**
Uniquement après un passage qui a réellement modifié quelque chose. Si tout était déjà conforme, aucun redémarrage n'est nécessaire.

**Est-ce que ça affecte mon navigateur ?**
Non. Chrome, Firefox, Brave, Edge et les autres navigateurs modernes gèrent leur propre configuration TLS indépendamment de Windows.

**Puis-je vérifier le résultat de façon indépendante ?**
Oui — après redémarrage, vous pouvez vérifier avec n'importe quel scanner TLS externe, avec des outils comme `nmap --script ssl-enum-ciphers`, ou simplement en consultant l'Observateur d'événements Windows / les journaux SCHANNEL.

## Avertissement

Ce script modifie des réglages de registre au niveau système (`HKLM`). Bien qu'il soit conçu pour être prudent, idempotent, et entièrement réversible via `-Undo`, vous l'utilisez sous votre propre responsabilité. Testez toujours d'abord avec `-DryRun`, et gardez à l'esprit qu'un matériel ou logiciel très ancien ou spécialisé sur votre réseau pourrait dépendre des protocoles et chiffrements que ce script désactive. En cas de doute, testez sur une seule machine avant de déployer sur une flotte entière.

---

*Harden-TLS fait partie d'une petite suite de scripts PowerShell de maintenance/sécurité pour Windows 11, par [Nephren](https://github.com/NephVx2).*
