# php2scan

Assistant d'évaluation externe pour CVE-2026-109618 et CVE-2026-109619.

Ce projet est fondé sur
[php2shell-scanner d'Assetnote](https://github.com/assetnote/php2shell-scanner)
et conserve sa licence MIT. Cette version ajoute des verdicts prudents, des
modes découverte et actif, le test de chaque adresse d'un FQDN, une politique
sûre de redirection, un diagnostic TLS, un mode batch, une synthèse exploitable
et des tests automatisés.

## Avertissement de sécurité important

Le mode actif n'est **pas un scan passif**. Il envoie des requêtes multipart
construites pour provoquer une pression mémoire dans PHP. Un chemin peut
recevoir jusqu'à trois sondes, soit environ 29 Mio au total. Ces sondes peuvent
provoquer des réponses HTTP 500, le redémarrage de workers, des alertes de
ressources ou une dégradation du service.

N'utilisez `--active` que sur des cibles explicitement autorisées, de préférence
pendant une fenêtre de maintenance. Commencez avec un seul thread, surveillez le
service et conservez les journaux PHP et serveur web du fournisseur.

## Ce que php2scan peut établir — et ses limites

php2scan est un **assistant d'évaluation externe**, pas une preuve définitive de
vulnérabilité. Les sondes actives exercent l'analyseur multipart de PHP et
recherchent la séquence observable suivante :

```text
requête de contrôle réussie
        -> sonde multipart construite
        -> réponse évoquant une défaillance
        -> requête de contrôle de récupération réussie
```

Un résultat positif constitue un élément utile pour ouvrir une investigation
avec un fournisseur. Il ne démontre pas une exécution de code arbitraire et ne
prouve pas laquelle des deux CVE est exploitable sur le serveur.

Le scanner ne peut pas déterminer à distance :

- le paquet et la révision de sécurité réellement chargés par le worker web ;
- si une version apparemment ancienne contient un rétroportage éditeur ;
- si une version publiée dans un en-tête HTTP correspond au runtime exécuté ;
- la SAPI exacte lorsque le fournisseur ne la communique pas ;
- si deux requêtes ont atteint le même worker PHP persistant ;
- si un backend masqué derrière un répartiteur a été atteint ;
- si un code HTTP 500, 502, 503 ou 504 provient de PHP, d'un proxy, d'un WAF,
  d'une limitation de débit ou d'une panne indépendante ;
- si un comportement de type crash peut être transformé en exécution de code.

Inversement, l'absence de signal ne prouve pas l'absence de vulnérabilité. Un
WAF, un proxy inverse, une limite de taille, un répartiteur, un pool de workers,
un allocateur différent, une chaîne de version ancienne mais corrigée, une
réponse d'erreur masquée ou un chemin applicatif non testé peuvent empêcher le
signal observable.

### Principe des deux vulnérabilités

- **CVE-2026-109618 — corruption lors d'un épuisement mémoire :** l'épuisement
  mémoire peut interrompre PHP alors que l'état de la requête n'est que
  partiellement initialisé. La phase d'arrêt peut ensuite traiter un état
  invalide. Les sondes multipart exercent principalement cette surface OOM
  observable depuis l'extérieur.
- **CVE-2026-109619 — état global périmé :** un état appartenant à une requête
  peut subsister dans un worker persistant après la libération de sa mémoire.
  Une requête ultérieure traitée par le même worker peut consommer cet état avant
  sa réinitialisation normale. Une confirmation externe fiable est plus
  difficile, car elle dépend du producteur, du consommateur, de la réutilisation
  du worker, de la configuration et de l'état du tas mémoire.

Avis officiels :

- [CVE-2026-109618 / GHSA-w8hw-w9fx-j79w](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w)
- [CVE-2026-109619 / GHSA-6wmf-4rv5-p3rp](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp)

### Interprétation selon la SAPI

La SAPI est l'interface entre le serveur web et PHP :

- `mod_php` : PHP s'exécute dans le worker Apache. Il s'agit de l'environnement
  de risque le plus élevé et le mieux confirmé dans l'avis PHP.
- `fpm` : Nginx ou Apache transmet la requête à un worker PHP-FPM persistant. Un
  worker défaillant peut apparaître comme une réponse vide ou un code HTTP
  502/503/504, puis être remplacé par le processus maître FPM.
- `auto` : applique les deux familles d'heuristiques externes. La couverture est
  plus large, mais l'ambiguïté et le risque de faux positif sont supérieurs.

Utilisez `--sapi mod_php` ou `--sapi fpm` lorsque le fournisseur a confirmé la
SAPI. Ne déduisez pas la SAPI du seul en-tête HTTP `Server`.

## Verdicts

Les identifiants restent en anglais afin de préserver la stabilité des rapports
JSON et des automatisations.

| Verdict | Interprétation |
| --- | --- |
| `LIKELY_VULNERABLE` | Signal actif compatible avec la vulnérabilité ; les journaux et le runtime du fournisseur doivent le confirmer. |
| `SUSPICIOUS_SIGNAL` | Signal de défaillance contradictoire avec une version annoncée corrigée ; faux positif de limite de ressources ou de proxy possible. |
| `AT_RISK_VERSION` | HTTP annonce une branche PHP prise en charge, mais antérieure à la version amont corrigée ; un rétroportage reste possible. |
| `LEGACY_VERSION_REVIEW` | HTTP annonce une branche PHP en fin de vie ; demander la preuve du rétroportage fournisseur. |
| `PATCHED_VERSION_ADVERTISED` | HTTP annonce une version amont corrigée ; c'est un indice, pas la preuve du runtime réellement exécuté. |
| `PARTIAL_MULTI_IP_COVERAGE` | Un FQDN possédant plusieurs adresses n'a pas été testé sur chaque adresse. |
| `REDIRECT_OUT_OF_SCOPE` | La découverte s'est arrêtée parce que la redirection changeait de nom d'hôte. Aucune sonde n'a été envoyée à la destination. |
| `REDIRECT_DURING_PROBE` | Le point final a redirigé une sonde active ; le corps volumineux n'a pas été rejoué. |
| `INCONCLUSIVE` | Aucune conclusion externe fiable n'est possible. |
| `ERROR` | L'évaluation n'a pas pu être effectuée. |

L'absence de signal de défaillance n'est jamais présentée comme « non
vulnérable ».

## Prérequis et installation

- Python 3.9 ou supérieur ;
- `h11` ;
- `tqdm`.

```bash
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install -r requirements.txt
```

## Utilisation

Découverte à faible impact — une petite requête multipart, donc pas une simple
observation réseau passive :

```bash
python3 scanner.py -u https://exemple.fr
```

Évaluation active autorisée d'un hôte :

```bash
python3 scanner.py -u https://exemple.fr --active -o resultat.json
```

Test de chemins PHP précis :

```bash
python3 scanner.py -u https://exemple.fr --active \
  --path /index.php --path /admin/index.php
```

Les corps de réponse sont omis des preuves par défaut. Pour les inclure dans une
investigation autorisée :

```bash
python3 scanner.py -u https://exemple.fr --active --include-response-body
```

Les corps peuvent contenir des données applicatives sensibles. Les en-têtes
d'authentification sont masqués dans les rapports, mais un secret fourni sur la
ligne de commande peut rester visible dans l'historique du shell ou la liste des
processus.

## Mode batch et synthèse

`--batch` et `--list` sont deux noms de la même option. Le fichier accepte une
cible par ligne : FQDN, IPv4, IPv6 ou URL HTTP/HTTPS. Les lignes vides et celles
commençant par `#` sont ignorées. Une cible sans schéma utilise HTTPS par défaut.

Exemple `cibles.txt` :

```text
# FQDN : HTTPS par défaut
app.exemple.fr

# IPv4 et IPv6 littérales : HTTPS par défaut
192.0.2.10
2001:db8::10

# Un port avec une IPv6 exige les crochets usuels
[2001:db8::20]:8443

# URL et protocole explicites
http://192.0.2.30:8080/index.php
https://portail.exemple.fr/admin/index.php
```

Exécution recommandée pour commencer, avec une concurrence volontairement
faible :

```bash
python3 scanner.py --batch cibles.txt --scan-each-ip \
  --threads 2 --output resultats.json
```

Ajoutez `--active` uniquement après validation du périmètre et de la fenêtre de
test :

```bash
python3 scanner.py --batch cibles.txt --active --scan-each-ip \
  --sapi mod_php --threads 1 --output resultats.json
```

La synthèse console contient :

- le nombre d'entrées, de doublons et de cibles uniques ;
- la répartition FQDN/IPv4/IPv6 ;
- le nombre de points de terminaison effectivement testés ;
- les totaux par verdict ;
- les états TLS par point de terminaison ;
- les couvertures multi-IP partielles.

Le fichier JSON conserve les résultats détaillés dans l'ordre du fichier
d'entrée et ajoute un objet `summary` structuré avec les mêmes indicateurs :

```json
{
  "schema_version": 2,
  "scan_time": "2026-10-26T17:00:00Z",
  "total_results": 3,
  "summary": {
    "input_entries": 4,
    "unique_targets": 3,
    "tested_endpoints": 5,
    "duplicate_entries_ignored": 1,
    "target_types": {"dns": 1, "ipv4": 1, "ipv6": 1},
    "outcomes": {
      "likely_vulnerable": 1,
      "patched_version_advertised": 0,
      "review_inconclusive_or_error": 2
    },
    "verdicts": {"INCONCLUSIVE": 2, "LIKELY_VULNERABLE": 1},
    "tls_by_target": {"MIXED": 1, "TLS_VALID": 2},
    "tls_by_endpoint": {
      "SELF_SIGNED_CERTIFICATE": 1,
      "TLS_VALID": 4
    },
    "coverage": {
      "multi_address_targets": 1,
      "partial_multi_ip_targets": 0
    },
    "configuration": {
      "mode": "discovery",
      "sapi": "auto",
      "scan_each_ip": true,
      "follow_same_host_redirects": true,
      "initial_tls_verification": true,
      "threads": 2,
      "paths": ["/"]
    }
  },
  "results": []
}
```

Avec `--vulnerable-only`, le tableau `results` est filtré, mais `summary`
continue de décrire l'ensemble du scan afin de conserver la piste d'audit.

## Politique de redirection

Les redirections vers le même nom d'hôte sont suivies par défaut. Les changements
HTTP vers HTTPS, de port et de chemin sont autorisés tant que le nom d'hôte ne
change pas. Une redirection vers un autre nom d'hôte est arrêtée et signalée par
`REDIRECT_OUT_OF_SCOPE` ; ajoutez cette destination comme cible autorisée
distincte si nécessaire.

Dans php2scan, « même équipement » est volontairement traduit par **même nom
d'hôte canonique** — casse ignorée et point terminal supprimé. Une IP partagée ne
suffit pas : elle peut héberger plusieurs clients ou services. Cette règle ne
garantit toutefois pas que deux requêtes atteignent le même serveur physique
derrière un répartiteur.

Lors d'un changement de schéma ou de port, les en-têtes sensibles sont retirés.
Pour désactiver toutes les redirections :

```bash
python3 scanner.py -u https://exemple.fr --no-follow-redirects
```

Seule la petite requête de découverte ou de contrôle suit les redirections
autorisées. Les sondes actives de pression mémoire sont envoyées directement à
l'URL finale découverte et ne sont jamais rejouées après une nouvelle
redirection.

## Diagnostic TLS et poursuite du test

La validation TLS est tentée automatiquement pour chaque cible HTTPS. Si le
certificat est expiré, autosigné, non reconnu ou ne correspond pas au nom
d'hôte, php2scan enregistre l'échec puis recommence sans validation du
certificat afin que le test PHP autorisé puisse continuer. Le rapport indique
explicitement cette poursuite non vérifiée. Un échec de négociation de protocole
ou de suite cryptographique peut toujours empêcher le test HTTP.

| État TLS | Interprétation et recommandation |
| --- | --- |
| `TLS_VALID` | Le certificat est valide. Les protocoles, suites cryptographiques et durées de vie nécessitent néanmoins un audit TLS distinct. |
| `SELF_SIGNED_CERTIFICATE` | Le test a continué sans validation. Utiliser un certificat public reconnu ou l'autorité privée approuvée. |
| `EXPIRED_CERTIFICATE` | Le test a continué sans validation. Renouveler le certificat et déployer la chaîne intermédiaire correcte. |
| `HOSTNAME_MISMATCH` | Le test a continué sans validation. Ajouter le FQDN testé au SAN du certificat. |
| `UNTRUSTED_CERTIFICATE` | Le test a continué sans validation. Réparer la chaîne ou utiliser l'autorité d'entreprise approuvée. |
| `TLS_VERIFICATION_DISABLED` | `--insecure` a empêché le diagnostic normal ; relancer sans cette option pour obtenir une preuve exploitable. |
| `TLS_HANDSHAKE_FAILED` | Aucun test HTTP possible. Examiner protocoles, suites cryptographiques, SNI et journaux serveur. |
| `TLS_CONNECTION_FAILED` | Vérifier le service en écoute, le pare-feu, le proxy et l'accessibilité HTTPS. |
| `HTTPS_TO_HTTP_DOWNGRADE` | Supprimer la redirection vers HTTP et conserver le chiffrement de bout en bout. |
| `PLAINTEXT_HTTP` | Activer HTTPS et rediriger HTTP vers HTTPS sur le même nom d'hôte. |
| `MIXED` | Les adresses résolues ont des états TLS différents ; corriger et retester chaque IP. |

`--insecure` reste disponible pour compatibilité, mais saute la validation
initiale et produit donc une preuve TLS moins utile. Le comportement par défaut
« validation puis poursuite contrôlée » est recommandé.

Chaque résultat contient des `guidelines` en français pour son verdict et son
état TLS. La sortie standard affiche l'état TLS de chaque cible et la synthèse
compte les états de tous les points de terminaison.

## Comportement multi-IP

La résolution DNS normale peut ne sélectionner qu'un seul backend. Si un FQDN
possède plusieurs adresses et que `--scan-each-ip` n'est pas utilisé, php2scan
refuse de considérer le FQDN comme couvert et retourne
`PARTIAL_MULTI_IP_COVERAGE`.

`--scan-each-ip` se connecte directement à chaque adresse résolue tout en
conservant le FQDN dans l'en-tête HTTP `Host` et le SNI TLS :

```bash
python3 scanner.py -u https://exemple.fr --active \
  --scan-each-ip --output resultat.json
```

Cette option ne découvre pas les FQDN inconnus hébergés sur une adresse IP. La
liste d'adresses est un instantané fourni par le résolveur et le point réseau du
scanner. Le Geo-DNS, les TTL courts et le DNS à vues séparées peuvent fournir
d'autres adresses ailleurs. Tester toutes les adresses résolues n'énumère pas :

- plusieurs serveurs applicatifs cachés derrière la même IP de répartiteur ;
- les origines d'un CDN ou d'un proxy inverse ;
- les sites anycast partageant la même adresse ;
- les backends choisis selon les cookies, l'adresse cliente, l'état de santé ou
  la persistance de session.

Pour un FQDN multi-adresse, utilisez `--scan-each-ip --verbose` et conservez tous
les `endpoint_results`.

## Codes de sortie

- `0` : toutes les cibles annoncent une version amont corrigée ;
- `1` : au moins un résultat actif est `LIKELY_VULNERABLE` ;
- `2` : vérification requise, résultat non concluant, erreur ou échec d'écriture.

## Exploitation des constats externes

Les indices externes doivent être rapprochés des informations du fournisseur :

1. runtime PHP servant réellement l'URL testée ;
2. version du paquet et révision de sécurité fournisseur ;
3. statut d'un éventuel rétroportage ;
4. SAPI utilisée (`mod_php`, PHP-FPM, CGI, etc.) ;
5. journaux du serveur web et de PHP à l'heure exacte de la sonde ;
6. preuve de redémarrage ou de crash d'un worker.

Les versions amont corrigées sont PHP 8.2.35, 8.3.36, 8.4.27 et 8.5.12. Une
chaîne de version seule ne permet pas d'identifier les rétroportages d'une
distribution ou d'un fournisseur.

### Liste de vérification à transmettre au fournisseur

Communiquez le FQDN, l'IP résolue, le chemin, l'horodatage UTC, le mode, le
numéro de sonde, la séquence HTTP et la preuve JSON. Demandez confirmation de :

1. la version binaire et le paquet PHP utilisés par le pool web testé ;
2. la SAPI et l'architecture frontale ;
3. la révision de sécurité et le statut de rétroportage pour les deux CVE ;
4. les journaux PHP, serveur web, WAF et proxy à l'heure de la sonde ;
5. tout arrêt, redémarrage, OOM ou événement de contrôle de santé d'un worker ;
6. chaque backend desservant le FQDN, pas seulement l'adresse frontale ;
7. la remédiation appliquée et la preuve du runtime après correction.

Formulation suggérée :

> Notre évaluation externe autorisée a observé un comportement compatible avec
> la surface d'attaque PHP2Shell. Ce constat ne constitue pas une preuve
> d'exploitation. Merci de confirmer le runtime PHP effectif, la SAPI, le paquet,
> le statut des rétroportages fournisseur et les journaux serveur pour
> CVE-2026-109618 et CVE-2026-109619.

## Remédiation

La mise à jour est la seule remédiation complète :

| Branche | Version amont corrigée |
| --- | --- |
| PHP 8.2 | 8.2.35 |
| PHP 8.3 | 8.3.36 |
| PHP 8.4 | 8.4.27 |
| PHP 8.5 | 8.5.12 |

PHP 8.1 et les branches antérieures sont en fin de vie en amont. Migrez vers une
branche prise en charge ou obtenez la preuve explicite d'un rétroportage
fournisseur/LTS. Ne concluez jamais à partir de la seule version de base.

Après une mise à jour ou l'installation d'un paquet fournisseur :

1. redémarrer tous les workers PHP et serveur web ;
2. vérifier le runtime utilisé par le pool web réel, pas seulement le binaire CLI ;
3. consigner la version du paquet, l'avis fournisseur et la révision du rétroportage ;
4. tester chaque SAPI, pool, chemin et backend pertinent ;
5. rechercher une éventuelle compromission si le service était exposé avant correction.

### Réduction temporaire du risque pour CVE-2026-109618

Ces mesures réduisent certains chemins, mais **ne remplacent pas la mise à jour** :

- imposer administrativement `memory_limit=-1` afin que les applications ne
  puissent pas rétablir une limite PHP finie ;
- imposer au frontal des limites prudentes sur les requêtes décodées, parties
  multipart, en-têtes, téléversements, entrées et niveaux d'imbrication ;
- bloquer `multipart/form-data` avant PHP lorsque les téléversements sont inutiles ;
- n'utiliser les limites conteneur/cgroup que comme protection de disponibilité ;
- ne pas employer `RLIMIT_AS` ou `RLIMIT_DATA` comme contournement, car l'échec
  d'allocation peut atteindre le chemin vulnérable.

### Réduction temporaire du risque pour CVE-2026-109619

Ces mesures réduisent les chemins producteur/consommateur confirmés, mais restent
incomplètes :

- définir `session.upload_progress.enabled=0` dans une configuration
  administrative appliquée avant l'analyse de la requête, puis redémarrer tous
  les workers ;
- ne pas compter sur `ini_set()` applicatif ou `.user.ini` FPM pour cette mesure ;
- avec PHP 8.5, définir `fatal_error_backtraces=0` puis redémarrer les workers ;
- supprimer les réglages INI invalides, obsolètes ou contradictoires qui émettent
  des diagnostics pendant l'initialisation ;
- corriger les erreurs fatales, délais dépassés et échecs atteignables par un
  attaquant dans les chemins de téléversement, import ou nettoyage.

Les recommandations courantes du projet PHP sont publiées sur
[php.net](https://www.php.net/) et dans les deux avis officiels liés plus haut.

## Docker

```bash
docker build -t php2scan .
docker run --rm php2scan -u https://exemple.fr
docker run --rm php2scan -u https://exemple.fr --active
```

Lecture d'un fichier batch et écriture du rapport JSON :

```bash
docker run --rm --user "$(id -u):$(id -g)" \
  -v "$PWD:/data" -w /data php2scan \
  --batch cibles.txt --active --scan-each-ip -o resultats.json
```

## Tests

```bash
python3 -m unittest discover -s tests -v
```
