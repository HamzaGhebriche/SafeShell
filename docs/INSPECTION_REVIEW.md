# Vérification avant fusion — 25 novembre 2026

Branche vérifiée : `codex/repository-trust-inspection`. Cette revue locale a été
effectuée avant le commit et la publication de la PR. Aucun merge ou release
n'a été effectué pendant cette revue.
Le diff suivi **et les nouveaux fichiers non suivis** ont été relus. Aucun
`AGENTS.md` applicable trouvé ; `CONTRIBUTING.md`, la CI et les documents
d'architecture/sandbox ont été pris en compte.

## Problèmes trouvés et corrigés

1. **Couverture native seule trompeuse.** `adapters=[]` pouvait produire LOW RISK
   avec une couverture déclarée complète alors qu'aucun moteur externe n'avait
   tourné. Les moteurs non sélectionnés sont maintenant DISABLED. L'option
   répétable `--disable-scanner trivy|osv|yara-x|scorecard` rend cette décision
   explicite. Sans chaîne forte, couverture incomplète signifie UNKNOWN.
2. **Invocations inventées.** Des noms de fichiers dans `echo`, des commentaires
   ou des données créaient des arêtes invokes. Seuls les contextes de lancement
   reconnus sont suivis : interpréteurs shell, appels Node littéraux et appels
   Python subprocess/os.system analysés par AST, sans importer le code cible.
3. **Amplification des preuves.** Les signaux de commandes distinctes partageaient
   des nœuds, notamment pour plusieurs scripts sur la même ligne JSON. Le contexte
   et la ligne distinguent maintenant ces nœuds. Un script manuel ne prête plus
   ses preuves à un hook automatique. Les commentaires sont exclus des signaux ;
   `fetch(url); // .aws` ne forme plus une chaîne d'accès aux identifiants.
4. **Répertoire de travail supposé.** Un sous-processus était recherché à côté
   du fichier source, alors qu'il hérite normalement du cwd du processus. Cette
   supposition est supprimée. Les cwd explicites/dynamiques, changements de
   répertoire et contextes de paquets imbriqués non résolus deviennent des lacunes.
5. **Chaînes npm manquantes et lignes absentes.** Les `npm run` littéraux sont
   suivis ; hooks et commandes JSON ont une ligne lorsqu'elle est identifiable
   sans ambiguïté. Les déclencheurs automatiques sont explicites dans le graphe.
6. **Doublons réels Trivy/OSV.** Trivy utilise `pip`, OSV `PyPI`. Leur équivalence
   manquait. Les 15 entrées réelles de la fixture requests deviennent 5 avis,
   avec 10 doublons supprimés. Les lignes et métadonnées des preuves secondaires
   sont conservées ; les compteurs par moteur restent ceux d'avant déduplication.
7. **Compteur natif vide et diagnostics insuffisants.** Les findings SafeShell
   sont comptés ; le JSON expose le code de sortie du scanner. Cache absent,
   absence de source reconnue, timeout et sortie invalide restent PARTIAL avec
   un diagnostic explicite, sans exporter stderr susceptible de contenir des secrets.
8. **Entrées scanner mal typées et commandes malformées.** Un champ fichier
   structuré pouvait faire planter l'orchestration. Les champs normalisés sont
   validés ; les commandes littérales non analysables produisent une lacune.
9. **Contrat JSON et couverture des outils.** Le schéma reconnaît DISABLED,
   exit_code, contexte/ligne des nœuds et interdit LOW RISK lorsque la couverture
   est incomplète. OSV reçoit `--no-ignore` pour empêcher .gitignore de masquer
   les dépendances de la copie analysée. Les lignes IaC Trivy sont lues depuis
   CauseMetadata lorsque nécessaire ; aucune ligne n'est inventée pour une règle
   portant sur l'absence d'une instruction.

10. **Encodages Windows et fichiers ignorés silencieusement.** Les fichiers
    d'exécution reconnus mais illisibles/NUL produisent maintenant une lacune.
    Les scripts PowerShell UTF-16 avec BOM et les extensions `.PS1` sont analysés.

21 cas de régression utiles ont été ajoutés dans `tests/test_inspection_review.py`.
Les fixtures initiales utilisant une référence relative au mauvais cwd ou un
commentaire comme preuve ont été corrigées. Aucun assouplissement des politiques
ou du sandbox existants.

## Validation sur un vrai dépôt local

Dépôt : SafeShell, commit local **d149272023cc19370045c68f0ad0078dce82381f**.
Une archive de `main` a été extraite dans `.build-tmp/trust-review-repository`.
Les 58 fichiers sont restés identiques octet par octet à l'archive, sans fichier
supplémentaire. Aucun code, hook ou script d'installation de **cette cible** n'a
été lancé. Les tests du produit SafeShell corrigé ont été exécutés dans une copie
distincte sous WSL, comme requis pour vérifier son exécution et son confinement.

`inspect`, `map` et `inspect --format json` ont été lancés sur cette copie réelle,
d'abord sans scanners puis avec les deux vrais moteurs et leurs caches. Verdict :
**UNKNOWN**, 67 findings natifs, aucune corrélation forte. Le backend Python,
les commandes dynamiques et l'extraction YAML partielle limitent l'analyse.
Trivy : COMPLETE, zéro finding externe. OSV : PARTIAL/exit 128, aucune source de
dépendances reconnue dans ce projet sans dépendance runtime/lockfile. Ce résultat
n'est pas présenté comme une garantie de sécurité.

Les codes CLI réellement observés : inspect texte **0**, inspect JSON **0**, map
**0**, cible absente **2** avec erreur JSON. **0 signifie rapport généré**, y
compris pour UNKNOWN/HIGH RISK ; il ne constitue pas une approbation d'exécution.
Les codes des scanners sont exposés séparément dans engines[].exit_code.

Les rapports réels, le rapport DISABLED, le graphe et les références d'identifiants
ont été contrôlés. Les rapports ont été validés avec Draft202012Validator contre
`schemas/inspection-v1.schema.json`.

## Vrais outils, données contrôlées et fonctionnement hors ligne

Binaires Windows officiels téléchargés dans `.build-tmp/trust-review-tools` :

| Moteur | Version exécutée | Résultat réel sur requirements.txt contrôlé |
| --- | --- | --- |
| Trivy | 0.76.2 | COMPLETE, exit 0, 5 avis |
| OSV-Scanner | 2.7.1, osv-scalibr 0.5.3, commit 02f96a40691c2d155fdda799af436e111231e365 | COMPLETE, exit 1, 10 entrées/alias |

Les SHA-256 correspondent aux digests des releases GitHub officielles **et** aux
fichiers de sommes de contrôle publiés. Aucune installation système, modification
persistante du PATH ou dépendance de la cible installée. Les téléchargements et
la préparation des bases sont séparés de l'inspection.

Cache préparé explicitement sous `.build-tmp/trust-review-cache` :

- `trivy/db/trivy.db` et `metadata.json`, schéma 2 ; base téléchargée le 25/11/2026,
  UpdatedAt 2026-11-25T13:07:24.554567818Z. Archive annoncée 136,93 MiB ; base
  extraite 1 820 958 720 octets.
- `osv/osv-scalibr/PyPI/all.zip`, 38 317 203 octets.

La fixture synthétique contient uniquement `requests==2.19.0` ; aucun pip install.
Les vrais outils analysent ces données. Après corrélation : **5 avis**, pas 15.
Le verdict reste UNKNOWN du fait des autres moteurs indisponibles ; une dépendance
vulnérable n'est pas qualifiée de malveillante.

Les mêmes adaptateurs fonctionnent avec caches préchargés et proxies HTTP(S)
injoignables (`127.0.0.1:9`), sans option de téléchargement. Avec cache vide :
Trivy PARTIAL/exit 1, OSV PARTIAL/exit 127 ; verdict UNKNOWN. Les options utilisées
sont `--offline-scan --skip-db-update --skip-java-db-update --skip-check-update
--skip-version-check --disable-telemetry` pour Trivy et `--offline` pour OSV.
**Ces essais prouvent le fonctionnement à partir des caches dans cette
configuration, pas une interdiction réseau au niveau OS ni l'absence de toute
tentative réseau. Aucune capture réseau exhaustive n'a été effectuée.**

Une seconde fixture contrôlée, jamais construite/exécutée, contient un Dockerfile
et un jeton GitHub factice. Trivy réel produit trois findings IaC et un secret :
DS-0001 à Dockerfile:1 ; DS-0002/DS-0026 sans ligne puisqu'une instruction manque ;
github-pat à dummy-token.txt:1. Le jeton factice n'apparaît pas dans le rapport
normalisé. Les commandes RUN/CMD sont seulement inspectées statiquement.

Le bac à sable Windows de l'outil empêchait initialement la résolution DNS et la
traversée des ancêtres de C:\ par le walker OSV. Les essais récursifs ont été
relancés avec autorisation hors de ce bac à sable ; aucune erreur n'a été
transformée en scan réussi. Un passage explicite par --lockfile fonctionnait
déjà dans l'environnement restreint. Les logs conservent les échecs initiaux.

## Matrice synthétique des verdicts

| Cas contrôlé | Résultat vérifié |
| --- | --- |
| Aucun finding, tous moteurs simulés COMPLETE | LOW RISK, avertissement explicite qu'il ne s'agit pas d'une garantie |
| Aucun finding, moteurs absents/désactivés/non sélectionnés | UNKNOWN, couverture incomplète |
| Signaux suspects sans chemin automatique, moteurs simulés complets | CAUTION |
| Hook automatique atteignant téléchargement et accès sensible | HIGH RISK avec références de preuves |
| Scanner absent | UNAVAILABLE, UNKNOWN sans chaîne forte |
| Timeout / JSON invalide / champ scanner mal typé | PARTIAL, UNKNOWN sans chaîne forte |
| Caches absents avec vrais binaires | PARTIAL, UNKNOWN |

Les simulations de timeout/sortie invalide ne sont pas présentées comme des
échecs constatés dans Trivy ou OSV. Les tests subprocess de délai/sortie bornée
utilisent un processus Python contrôlé. Le benchmark à sept cas utilise des
preuves de scanners enregistrées synthétiques : TP=2, FP=0, TN=5, FN=0 sur ces
seuls cas. Ce n'est pas une mesure comparative réelle de supériorité.

## Exécution et sandbox existants

`git diff --exit-code main -- safeshell/backend.py safeshell/policy.py
safeshell/runtime.py safeshell/audit.py safeshell/analysis.py` : aucun changement.
Les nouveaux chemins CLI retournent avant la logique existante d'exécution.

Le harnais officiel `tools/validate_linux.py --as-user nobody` a été lancé dans
une copie temporaire du produit corrigé sous Ubuntu WSL2, kernel
6.18.58.1-microsoft-standard-WSL2-x86_64, Python **3.12.3**, Bubblewrap **0.9.0**.
Les tests tournent sous UID **65534**, jamais root ; le harnais provisionne puis
supprime ses seuls contrôles factices prévus. Aucune protection globale désactivée.

**165 tests réussis, zéro ignoré**, dont les **23 tests réels de confinement** :
accès fichiers/écriture autorisée, refus des fichiers hors sandbox et secrets
factices, sockets réseau, privilèges/setuid, descripteurs hérités et cycle de vie
des processus/timeout. Le probe doctor seul n'est pas utilisé comme preuve de
confinement. XML, inventaire effectif et métadonnées du harnais sont conservés.

## Contrôles du projet et commandes exécutées

Windows/Python 3.14.0 : **140 réussis, 25 ignorés attendus**, avec la garde CI
portable active. Les 25 ignorés sont 23 cas Linux, un FIFO POSIX et un hardlink
que l'environnement Windows ne permet pas de créer. Aucun échec masqué.
Ruff lint/format : passent. Mypy limité aux neuf modules d'inspection : passe
avec `--ignore-missing-imports --follow-imports=silent`. Il n'existe pas de
configuration mypy stricte globale dans le projet. `git diff --check` : passe.
Couverture Windows : **74,86 % globale**, **88,83 %** du paquet inspection
(692/779 instructions couvertes) ; les chiffres ne prouvent pas les garanties OS.

Commandes principales réellement exécutées, depuis le workspace sauf indication :

```powershell
git status --short
git branch --show-current
git diff --stat
git rev-parse main
git archive --format=zip --output=.build-tmp/trust-review-tools/safeshell-main.zip main
python .build-tmp/trust-review-tools/releases.py
python .build-tmp/trust-review-tools/download.py
.\.build-tmp\trust-review-tools\trivy.exe --version
.\.build-tmp\trust-review-tools\osv-scanner.exe --version
python .build-tmp/trust-review-tools/prepare_databases.py
python .build-tmp/trust-review-tools/validate_real.py
python .build-tmp/trust-review-tools/check_cli.py
python .build-tmp/trust-review-tools/check_trivy_signals.py
$env:PYTEST_DISABLE_PLUGIN_AUTOLOAD='1'
$env:SAFESHELL_PORTABLE_CI='1'
python -m coverage run --source=safeshell -m pytest -q --basetemp .test-trust-review-final-encoding
python -m coverage json -o validation-results/trust-review/coverage.json
python -m ruff check .
python -m ruff format --check .
python -m mypy safeshell/inspection --ignore-missing-imports --follow-imports=silent
git diff --check
python -m build --no-isolation
python tools/smoke_installed.py dist/safeshell_cli-0.1.0a1-py3-none-any.whl
```

Les scripts temporaires consignent les vrais argv de téléchargement, préparation,
scans et commandes CLI dans `validation-results/trust-review/`. La préparation
utilise Trivy `fs --download-db-only` et OSV `scan source --offline
--download-offline-databases --no-ignore --lockfile <requirements.txt>` avec HOME/
cache isolés. La validation CLI a exécuté inspect texte, inspect JSON, map et une
cible absente. Le harnais Linux a été lancé via :

```powershell
wsl --distribution Ubuntu --exec python3 /mnt/c/Users/kali/SafeShell/.build-tmp/trust-review-tools/linux_runner.py
```

Il exécute réellement `python3 tools/validate_linux.py --as-user nobody` dans sa
copie temporaire Linux. Wheel/sdist et smoke installé font l'objet des artefacts
`build.log` et `installed-smoke.json` du même dossier de validation.

## Finalisation et corrections CI de la PR

La première CI de la PR a utilisé Ruff **0.17.3**, version fixée par le projet,
alors que les contrôles locaux ci-dessus utilisaient **0.15.21**. Les 19 erreurs
signalées ont été corrigées sans désactiver de règles : littéraux dictionnaires,
imports, noms complets des flags regex, removeprefix, TypeError pour les types
invalides et paramètres explicites pour le parcours des configurations d'agents.

Le job natif Ubuntu a réussi les tests de confinement et le smoke installé, puis
échoué au contrôle des distributions : celui-ci attendait seulement les modules
Python à la racine. Il vérifie désormais aussi les modules imbriqués. Quatre cas
de régression vérifient le sous-paquet valide, le refus d'un fichier wheel
inattendu, d'un module source manquant et d'un fichier source privé.

Après ces correctifs : Ruff **0.17.3** lint/format et mypy ciblé réussis ;
**144 tests Windows réussis, 25 ignorés attendus**. Les mesures de scanners réels
et de couverture précédentes restent celles de la revue locale initiale ; elles
ne sont pas présentées comme de nouvelles exécutions. Les résultats CI du commit
final sont consultables dans la PR.

## Limites restantes

- Une seule origine de dépôt réel : la copie du commit local SafeShell. Les
  dépendances vulnérables, Dockerfile, jeton et chaînes dangereuses sont des
  fixtures contrôlées, pas des dépôts malveillants réels.
- YARA-X et Scorecard restent feature-gated ; aucune validation réelle de ces
  outils. Autres versions Trivy/OSV, bases autres que PyPI, base Java, scanners
  Linux/macOS, Python 3.11 et confinement natif Ubuntu/AppArmor hors WSL non testés
  dans cette revue. Les tests Windows/macOS ne peuvent pas certifier l'isolation Linux.
- L'analyse reste statique : appels/imports calculés, cwd non résolus, code généré,
  YAML multiligne/JSONC, contrôle de flux et chaînes d'interpréteurs complexes
  restent partiels. Certains littéraux ou usages légitimes de chemins sensibles
  peuvent encore provoquer des faux positifs ; aucune garantie contre les faux négatifs.
- Les scanners tournent avec l'autorité OS de l'utilisateur, hors du backend
  d'exécution ; pas de quota mémoire/CPU ni de garantie de terminaison de tout
  arbre descendant. Le timeout documenté porte sur le scanner direct. Les copies
  doivent être immuables/disposables ; les courses avec écrivains hostiles ne sont
  pas supprimées. Les exports de preuves restent potentiellement sensibles.
- Les codes 0 d'inspection ne doivent pas servir de feu vert CI/exécution sans lire
  verdict et coverage. LOW RISK n'est jamais une garantie de sécurité.

Toutes les preuves et les outils/caches temporaires sont locaux et gitignorés.
Ces artefacts ne font pas partie du commit et ne sont pas publiés avec la PR.
