# Harden-TLS_Win11

🇬🇧 [English version](README.md)

Un script PowerShell petit et cible qui desactive TLS 1.0 et TLS 1.1 au niveau SCHANNEL de Windows — rien d'autre. Lecture avant ecriture : un controle deja conforme n'est jamais reecrit, chaque run affiche l'etat actuel exact avant de toucher a quoi que ce soit, et un rapport JSON suit le score au fil des executions.

> Portee, pas ampleur. Quatre valeurs de registre, un seul objectif. TLS 1.2 et 1.3 sont volontairement laisses intacts — forcer des cles pour des protocoles que Windows 11 gere deja correctement eloignerait de la configuration par defaut de Microsoft, pas ne la rapprocherait de la securite.

---

## Sommaire

- [Presentation](#presentation)
- [En termes simples : qu'est-ce que TLS et pourquoi desactiver les anciennes versions](#en-termes-simples--quest-ce-que-tls-et-pourquoi-desactiver-les-anciennes-versions)
- [Pourquoi seulement TLS 1.0 et 1.1](#pourquoi-seulement-tls-10-et-11)
- [Impact sur la compatibilite](#impact-sur-la-compatibilite)
- [Fonctionnement](#fonctionnement)
- [Deux modes : menu interactif et classique](#deux-modes--menu-interactif-et-classique)
- [Modele d'elevation](#modele-delevation)
- [Prerequis](#prerequis)
- [Premier lancement](#premier-lancement-pas-a-pas)
- [Reference du menu](#reference-du-menu)
- [Parametres en ligne de commande](#parametres-en-ligne-de-commande)
- [Fichiers ecrits par le script](#fichiers-ecrits-par-le-script)
- [Deploiement multi-machines](#deploiement-multi-machines)
- [Depannage](#depannage)

---

## Presentation

`Harden-TLS_Win11_v1_2_1.ps1` ecrit quatre valeurs de registre sous `HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols`, une paire (`Enabled=0`, `DisabledByDefault=1`) chacune pour :

- TLS 1.0 — Client
- TLS 1.0 — Server
- TLS 1.1 — Client
- TLS 1.1 — Server

C'est l'integralite de ce que fait ce script. Il ne touche ni a TLS 1.2, ni a TLS 1.3, ni aux suites de chiffrement, ni a rien d'autre sous SCHANNEL.

Un **redemarrage est requis** pour que SCHANNEL recharge sa configuration apres une modification reelle.

---

## En termes simples : qu'est-ce que TLS et pourquoi desactiver les anciennes versions

**TLS (Transport Layer Security)** est le protocole de chiffrement qui protege quasiment toutes les connexions que votre ordinateur etablit vers internet — c'est le cadenas dans votre navigateur, la raison pour laquelle votre mot de passe bancaire n'est pas envoye en clair, la raison pour laquelle un inconnu sur le meme Wi-Fi ne peut pas lire vos emails au passage sur le reseau. Chaque fois que vous visitez un site en HTTPS, vous connectez quelque part, ou synchronisez une application avec le cloud, TLS fait discretement le travail de chiffrement en arriere-plan.

Comme tout protocole, TLS a connu plusieurs versions au fil des annees, chacune corrigeant des faiblesses trouvees dans la precedente :

- **TLS 1.0** (1999) et **TLS 1.1** (2006) — assez anciennes pour que des faiblesses cryptographiques connues y aient ete decouvertes au fil du temps (support de chiffrements faibles, vulnerabilite a des attaques specifiques de degradation et d'interception). Aucune des deux n'est plus consideree comme sure aujourd'hui.
- **TLS 1.2** (2008) et **TLS 1.3** (2018) — les standards actuels. Rapides, largement audites, et utilises par quasiment tous les sites, applications et services modernes aujourd'hui. C'est ce qui reste pleinement actif et intact avec ce script.

**Alors pourquoi est-ce important si les anciennes versions restent la, inutilisees ?** En usage quotidien normal, ca ne l'est generalement pas — votre navigateur et la plupart des applications preferent deja automatiquement TLS 1.2/1.3, donc TLS 1.0/1.1 sert rarement meme s'il est techniquement toujours disponible. Le risque tient dans ce mot *disponible* : tant que Windows accepte encore une connexion TLS 1.0 ou 1.1, une porte etroite reste ouverte — une **attaque de degradation** (forcer une connexion a retomber vers un protocole ancien et plus faible) ou un vieux serveur mal maintenu ne parlant que TLS 1.0 pourrait quand meme reussir a negocier une connexion faible et cassable, au lieu d'etre franchement refuse.

**Ce que ce script fait concretement :** il indique a Windows, au niveau du systeme d'exploitation, de refuser categoriquement toute connexion TLS 1.0 et TLS 1.1 — pas "preferer autre chose", mais "ne pas accepter ca du tout." Fermer cette porte signifie qu'il ne reste plus aucun repli a exploiter, point final. C'est l'equivalent numerique de retirer une serrure rouillee et facile a crocheter d'une porte que vous n'utilisez de toute facon jamais, plutot que d'esperer simplement que personne n'essaie.

---

## Pourquoi seulement TLS 1.0 et 1.1

La depreciation de TLS 1.0/1.1 est une recommandation stable et non controversee depuis que la [RFC 8996](https://www.rfc-editor.org/rfc/rfc8996) (2021) a formellement deprecie les deux protocoles pour toute l'industrie. Forcer des cles de registre pour TLS 1.2/1.3 egalement a ete volontairement ecarte — Windows 11 les gere deja correctement par defaut, et ecrire des cles de forcage explicites pour eux ne ferait que creer une configuration qui s'eloigne des defauts maintenus par Microsoft, sans reel gain de securite.

---

## Impact sur la compatibilite

- **Concerne :** toute application Windows utilisant directement la pile TLS systeme (WinHTTP, SChannel).
- **Non concerne :** les navigateurs modernes (Brave, Chrome, Firefox) — ils implementent TLS independamment de l'OS et ignorent totalement ce reglage.
- **A verifier au prealable :** les equipements reseau anciens (NAS, imprimantes, terminaisons VPN legacy) qui pourraient encore ne supporter que TLS 1.0/1.1. Peu probable en 2026, mais merite un instant de reflexion avant d'appliquer ce script sur une machine qui communique avec du materiel ancien.

---

## Fonctionnement

1. **Toujours lire d'abord.** `Get-TlsControlState` effectue une lecture pure des quatre valeurs de registre — aucune decision, aucune ecriture — et le resultat est affiche en console immediatement, en mode interactif comme en mode classique, avant que quoi que ce soit ne soit touche.

2. **Idempotence reelle.** Un controle deja a `Enabled=0` / `DisabledByDefault=1` n'est **jamais reecrit** lors d'un run normal. Les versions anterieures reecrivaient silencieusement les quatre cles a chaque run via `New-ItemProperty -Force`, ce qui masquait le fait que la plupart des runs n'avaient rien a faire — la v1.2 a rendu cela explicite, et `-Force` est desormais le seul moyen de forcer la reecriture de controles deja conformes (ex : apres restauration d'une sauvegarde anterieure).

3. **Le rapport JSON est toujours regenere**, meme lors d'un run ou litteralement rien n'a change — c'est delibere, pour que le rapport et l'historique de score refletent toujours un horodatage et un etat actuels, pas un fichier perime datant du dernier changement reel.

4. **Score.** `NbOk / NbTotal × 100`, converti explicitement en `[int]` (un correctif documente — `[Math]::Round()` renvoie un `[double]`, qui se serialiserait sinon en `83.0` au lieu de `83` dans la sortie JSON).

---

## Deux modes : menu interactif et classique

- **Aucun parametre du tout** (ex : double-clic sur le script) → ouvre un **menu interactif**, dans le meme esprit que `Manage-ScriptSignatures.ps1` ailleurs dans cette suite : une boucle persistante permettant de consulter l'etat, d'appliquer uniquement ce qui manque, de forcer une re-application complete, ou de regenerer le rapport JSON sans rien modifier — sans avoir a relancer le script depuis zero a chaque fois.

- **Tout parametre explicite** (`-DryRun`, `-Silent`, `-Force`, `-SelfTest`...) → s'execute une seule fois en **mode classique non-interactif** puis quitte. C'est ce que doit utiliser une tache planifiee, ou tout script appelant celui-ci de maniere programmatique.

- `-Menu` force le menu interactif meme si d'autres parametres sont egalement fournis (ex : `-Menu -DryRun` ouvre un menu qui simule chaque action au lieu de l'appliquer).

---

## Modele d'elevation

Contrairement a certains scripts de cette suite, celui-ci **ne necessite pas** les droits administrateur juste pour demarrer (pas de `#Requires -RunAsAdministrator`). L'elevation est verifiee dynamiquement, uniquement juste avant une ecriture reelle dans le registre :

- Lire l'etat actuel, `-DryRun`, et generer le rapport JSON fonctionnent tous **sans** droits administrateur.
- Une ecriture reelle necessite toujours l'elevation — si elle est absente, le script affiche un message clair et produit quand meme un rapport JSON reflétant l'etat reel (non modifie), plutot que d'echouer purement et simplement ou de ne rien faire silencieusement.

---

## Prerequis

- Windows 10 ou 11 (les cles de protocole SCHANNEL sont un mecanisme Windows global, pas specifique a Windows 11, meme si les notes de compatibilite de ce script sont ecrites en pensant a Windows 11).
- PowerShell 5.1 (integre a Windows) ou PowerShell 7+.
- Droits administrateur **uniquement** pour une ecriture reelle — voir [Modele d'elevation](#modele-delevation) ci-dessus.
- Si le script est signe numeriquement (recommande en environnement `-ExecutionPolicy AllSigned`/`RemoteSigned`) : le certificat de signature doit etre approuve sur la machine cible.

---

## Premier lancement (pas a pas)

1. Copier `Harden-TLS_Win11_v1_2_1.ps1` sur la machine cible.

2. Lancer d'abord le self-test — logique pure, aucun acces registre, aucun droit admin necessaire :

   ```powershell
   .\Harden-TLS_Win11_v1_2_1.ps1 -SelfTest
   ```

   Execute 13 assertions couvrant la logique d'historique de score (dont un test de regression specifique pour un bug de pollution par `$null` corrige en v1.2.1), la logique de decision de durcissement contre des etats factices en memoire (deja conforme, non conforme, cle absente, non eleve), et la conversion explicite du score en `[int]`. Code de sortie `0` = tout passe, `1` = au moins un echec.

3. Verifier l'etat actuel sans rien changer et sans besoin d'elevation :

   ```powershell
   .\Harden-TLS_Win11_v1_2_1.ps1 -DryRun
   ```

   Montre exactement ce qui est actuellement configure pour les quatre controles, et ce qui serait ecrit en cas d'execution reelle.

4. Appliquer le durcissement pour de vrai, depuis une session PowerShell elevee :

   ```powershell
   .\Harden-TLS_Win11_v1_2_1.ps1
   ```

   Sans parametre, ceci ouvre le menu interactif a la place (voir [Deux modes](#deux-modes--menu-interactif-et-classique)) — utiliser l'option `[2]` depuis la, ou passer un parametre explicite (ex : ajouter `-Silent`) pour aller directement en mode classique.

5. **Redemarrer la machine** — SCHANNEL ne recharge cette configuration qu'au demarrage.

6. Verifier l'effet : si vous utilisez aussi `Check-Security_Win11` de cette meme suite, le relancer apres le redemarrage — les 4 controles TLS 1.0/1.1 devraient passer de `WARN` a `OK`. Les 2 controles TLS 1.2 resteront affiches en `WARN` dans ce script (une cle de registre absente y signifie "defaut Windows," ce qui est correct sur une build Windows 11 recente, pas une vraie lacune).

---

## Reference du menu

S'ouvre automatiquement quand le script est lance sans parametre :

| Option | Action |
|---|---|
| `[1]` | Afficher l'etat detaille (lecture seule) |
| `[2]` | Appliquer le durcissement — uniquement ce qui n'est pas conforme actuellement |
| `[3]` | Forcer une re-application complete, meme pour les controles deja conformes |
| `[4]` | Generer/rafraichir le rapport JSON sans rien changer |
| `[D]` | Basculer le mode DryRun pour les actions propres au menu |
| `[Q]` | Quitter |

---

## Parametres en ligne de commande

| Parametre | Description |
|---|---|
| `-DryRun` | Affiche les cles de registre qui seraient ecrites, sans les appliquer. |
| `-Force` | Re-applique les quatre controles meme s'ils sont deja conformes (utile par exemple apres restauration d'une sauvegarde systeme anterieure). |
| `-Menu` | Force le menu interactif meme si d'autres parametres sont egalement fournis. |
| `-Silent` | Supprime la pause finale "appuyez sur ENTREE" (mode classique uniquement) — pour un usage via tache planifiee. |
| `-RetainReportsDays <n>` | Purge les fichiers `Rapport_TLS_*.json` plus vieux que N jours (par defaut : `30`). `Baseline_TLS.json` n'est jamais purge. |
| `-SelfTest` | Execute la batterie de tests internes a 13 assertions (logique pure, aucun acces registre) puis quitte. |

Tout parametre explicite bascule le script en mode classique non-interactif — voir [Deux modes](#deux-modes--menu-interactif-et-classique).

**Exemples :**

```powershell
.\Harden-TLS_Win11_v1_2_1.ps1 -SelfTest
.\Harden-TLS_Win11_v1_2_1.ps1 -DryRun
.\Harden-TLS_Win11_v1_2_1.ps1 -Force -Silent
.\Harden-TLS_Win11_v1_2_1.ps1 -RetainReportsDays 60
```

---

## Fichiers ecrits par le script

| Fichier | Contenu |
|---|---|
| `%USERPROFILE%\Desktop\Rapports_Maintenance\TLS\Baseline_TLS.json` | Score du dernier run, horodatage, et un historique glissant de jusqu'a 30 scores — jamais purge |
| `%USERPROFILE%\Desktop\Rapports_Maintenance\TLS\Rapport_TLS_<horodatage>.json` | Detail par run : une entree par controle (categorie, element, valeur, statut) — purge automatiquement apres `-RetainReportsDays` (30 par defaut) |

Meme racine de rapports (`Desktop\Rapports_Maintenance\TLS`) et meme convention de nommage (`Baseline_TLS.json` pour l'historique glissant, `Rapport_TLS_*.json` par run) que le reste des scripts de maintenance de cet auteur, conservee par coherence pour que les fichiers restent previsibles si vous en utilisez plusieurs — aucun autre script ou outil n'est necessaire pour les lire.

---

## Deploiement multi-machines

1. **Distribuer** le fichier `.ps1` vers chaque machine cible.

2. **Approuver le certificat de signature** si une politique d'execution stricte est en place (`-ExecutionPolicy AllSigned`/`RemoteSigned`).

3. **Executer `-SelfTest` en premier** — logique pure, aucun acces registre, aucun droit admin necessaire, sans risque sur n'importe quelle machine avant de decider de la suite.

4. **Planifier via le Planificateur de taches Windows** avec un parametre explicite (n'importe lequel fonctionne — meme juste `-Silent`) pour qu'il s'execute en mode classique plutot que d'ouvrir le menu interactif sans supervision :

   | Champ | Valeur |
   |---|---|
   | Programme/script | `pwsh.exe` (ou `powershell.exe`) |
   | Arguments | `-NoProfile -ExecutionPolicy Bypass -File "C:\Scripts\Security\Harden-TLS_Win11_v1_2_1.ps1" -Silent` |
   | Executer avec les autorisations maximales | Oui (necessaire pour l'ecriture registre reelle ; sans cela, la tache s'execute quand meme et produit un rapport JSON, simplement sans rien appliquer) |

5. Comme la plupart des machines n'ont besoin de cette application qu'**une seule fois** (l'idempotence signifie que les runs suivants ne font rien), une etape de provisionnement ponctuelle est sans doute plus naturelle ici qu'une planification recurrente — un run de verification recurrent de type `-SelfTest` est plus utile qu'un run de durcissement recurrent, puisqu'il n'y a plus rien a redurcir une fois la conformite atteinte.

6. Les rapports sont ecrits dans le profil de l'utilisateur qui execute le script — propres a chaque machine. Agreger les resultats sur un parc est laisse a l'outillage de votre choix a construire par-dessus, ce script ne produit que le JSON propre a chaque machine.

7. **Ne pas oublier le redemarrage.** Une tache planifiee qui applique ce script et quitte ne declenche pas elle-meme un redemarrage — integrer cela separement dans votre sequence de deploiement si le changement doit prendre effet immediatement plutot qu'au prochain redemarrage naturel de la machine.

---

## Depannage

<details>
<summary><strong>Le script indique qu'un controle a ete applique, mais Check-Security_Win11 affiche toujours WARN</strong></summary>

Redemarrer la machine — SCHANNEL ne recharge sa configuration de protocoles qu'au demarrage, pas en temps reel. Relancer l'audit de securite apres le redemarrage.
</details>

<details>
<summary><strong>L'execution sans droits admin n'applique rien</strong></summary>

Attendu — voir [Modele d'elevation](#modele-delevation). Lire l'etat, `-DryRun`, et le rapport JSON fonctionnent tous sans elevation, mais une ecriture registre reelle en a besoin. Relancer depuis une session PowerShell elevee (ou une tache planifiee elevee).
</details>

<details>
<summary><strong>-Force ne semble rien avoir change</strong></summary>

Si les quatre controles etaient deja a `Enabled=0` / `DisabledByDefault=1`, `-Force` les reecrit avec exactement les memes valeurs — il n'y a rien de visiblement different a constater, mais le rapport JSON affichera un compteur `Applied` au lieu de `Skipped` pour ce run, confirmant que la reecriture a bien eu lieu.
</details>

<details>
<summary><strong>Un appareil ancien (NAS, imprimante, VPN ancien) a cesse de se connecter apres ce script</strong></summary>

Voir [Impact sur la compatibilite](#impact-sur-la-compatibilite) — c'est le seul effet de bord realiste de la desactivation systeme de TLS 1.0/1.1. Pour revenir en arriere si necessaire, supprimer les valeurs `Enabled`/`DisabledByDefault` sous la ou les cle(s) `SCHANNEL\Protocols\TLS 1.0` ou `TLS 1.1` concernee(s), ou les regler sur `Enabled=1`/`DisabledByDefault=0`, puis redemarrer.
</details>

<details>
<summary><strong>-SelfTest signale un FAIL</strong></summary>

Les 13 assertions sont toutes des verifications de logique pure (gestion de tableau pour l'historique de score, fonction de decision de durcissement contre des etats factices, conversion explicite en `[int]` du score) — aucune ne touche au registre reel, donc un FAIL pointe vers la logique interne du script, pas vers la configuration TLS reelle de la machine. Lire le nom de l'assertion pour identifier le probleme precis.
</details>

---

<sub>Harden-TLS_Win11 — 4 valeurs de registre, idempotence lecture-avant-ecriture, historique de score en JSON, self-test a 13 assertions.</sub>
