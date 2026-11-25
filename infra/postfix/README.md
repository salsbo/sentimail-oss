---
author: J. Martin
lastModifiedBy: J. Martin
---

# Contrat de santé du MX

Le healthcheck exécute `python3 /usr/local/bin/mx-health.py` toutes les trente
secondes. Il conserve `postfix status`, puis examine l'âge d'arrivée des
messages décrits par `postqueue -j`. Une file vide est saine. Un message dont
l'arrivée remonte à plus de **600 secondes (dix minutes)** rend le contrôle
négatif, même si une nouvelle sonde SMTP traverse correctement le MX.

Ce contrôle porte sur la file entrante de cette instance, y compris ses
éventuelles routes directes explicitement configurées. Il ne sert pas à noter
les délais d'un relais SMTP sortant généraliste. Un message hors délai à
expéditeur vide (`MAILER-DAEMON` dans `postqueue -j`) dont aucun destinataire
n'appartient à `relay_domains` est une
notification rédigée par Postfix lui-même : il est compté dans
`outbound_notices_deferred`, avec la raison `outbound_notices_deferred`, et ne
rend pas le contrôle négatif. Les domaines sont vérifiés avec `postmap -q`
sur les tables de `relay_domains`, et seulement quand un tel message existe.
Une table qui ne répond pas laisse le message compté comme entrant. Le MX
n'accepte aucune demande d'accusé de livraison (DSN) venue d'Internet
(`smtpd_discard_ehlo_keywords = silent-discard, dsn`). Il ne force aucune reprise,
ne vide pas la file et ne modifie aucun message. Docker signale `unhealthy`
après trois échecs consécutifs ; ce statut seul ne redémarre pas le service.

Le code de sortie est `0` si Postfix tourne et que tous les messages lus sont
dans le délai, `1` sinon. La sortie JSON contient seulement l'état, une raison
technique fixe, le nombre de messages lus, le nombre hors délai et l'âge le
plus élevé en secondes. Les identifiants, expéditeurs, destinataires et erreurs
SMTP du listing ne sont jamais écrits. Un horodatage d'arrivée futur vaut un
âge nul et est compté séparément, pour éviter une fausse alerte d'ancienneté.

L'exécution de `postfix status` est limitée à une seconde. La lecture de la
file est limitée à deux secondes, quatre Mio de JSON et dix mille messages.
Une commande en échec, un dépassement de ces plafonds ou un JSON/horodatage
invalide rend le contrôle négatif : une lecture impossible ne prouve pas que
la file est vide. Le plafond Docker reste de cinq secondes. Le script utilise
uniquement la bibliothèque standard de Python et les commandes Postfix du
conteneur ; il n'accède ni au socket Docker ni à une interface privilégiée de
l'hôte.

Tests locaux, sans service ni courrier de production :

```sh
.venv-test/bin/python -m pytest infra/postfix/tests -q
```
