# Recevoir le courrier avec SentiMail V3

SentiMail V3 sait désormais recevoir seul. Trois services suffisent : `mx`
(Postfix), `rspamd` (le milter qui produit la preuve d'authentification) et
`valkey` (le stockage de travail de rspamd). Aucun d'eux n'a besoin de
SentiMail V2.

Le chemin d'un message est court :

```
Internet ──25──► mx ──milter──► rspamd ──► mx ──2525──► collector ──► pipeline
```

## Ce qui décide qu'un message est accepté

Un seul fait : le domaine du destinataire est-il **actif** dans la table
`domains` ?

Postfix ne contient aucune liste de domaines. Ses maps `relay_domains` et
`transport_maps` sont des requêtes SQL, exécutées à chaque destinataire de
chaque message, contre la vue `mx_relay_domains` — qui n'expose que les lignes
`status = 'active'`.

Conséquences directes, sans redémarrage ni rechargement :

- passer un domaine en `active` le rend recevable dans la seconde ;
- le repasser en `pending` ou `suspended` fait aussitôt refuser son courrier,
  avec un `554 Relay access denied` ;
- un domaine jamais enrôlé n'est jamais accepté, ce qui est aussi la garantie
  que ce MX n'est pas un relais ouvert.

Enrôler un domaine protège **tous** ses destinataires. Il n'y a pas de liste
d'adresses à tenir.

## Enrôler un domaine

1. Insérer le domaine, d'abord en attente :

   ```sql
   INSERT INTO domains (fqdn, status, admin_email)
   VALUES ('exemple.fr', 'pending', 'postmaster@exemple.fr');
   ```

   Le `fqdn` doit être en minuscules — une contrainte le vérifie, car le SMTP
   ne distingue pas la casse alors qu'une comparaison de texte le ferait.

2. Lire le jeton généré et le faire publier par le titulaire du domaine :

   ```sql
   SELECT verification_token FROM domains WHERE fqdn = 'exemple.fr';
   ```

   Enregistrement à publier :
   `_sentimail.exemple.fr. IN TXT "<verification_token>"`

   Cette étape existe pour qu'on ne puisse pas détourner le courrier d'un
   domaine tiers en l'inscrivant simplement dans la base.

3. Une fois le TXT constaté, activer :

   ```sql
   UPDATE domains
   SET status = 'active', verified_at = now(), updated_at = now()
   WHERE fqdn = 'exemple.fr';
   ```

4. Faire basculer le MX du domaine :

   ```
   exemple.fr. IN MX 10 mx.sentinel.mondomaine.example.
   ```

   Baisser d'abord le TTL de l'enregistrement MX (300 s) la veille du
   basculement : le retour arrière est alors immédiat si quelque chose cloche.

5. Vérifier que la destination finale accepte bien le courrier réémis par
   SentiMail V3 (SPF/autorisation d'IP côté boîte de destination). Le pipeline
   livre via `RELAY_HOST`/`RELAY_PORT`, pas par ce MX.

## Prérequis côté hôte

- **Un nom et une PTR.** `SENTINEL_V3_MX_HOSTNAME` doit être le nom publié dans
  l'enregistrement MX, et la reverse DNS de l'adresse publique doit renvoyer ce
  même nom. Sans cela, une part notable des expéditeurs refuse la connexion.
- **Le port 25 ouvert en entrée**, et sortant si la même machine réémet.
- **Un certificat.** Monter l'arborescence Let's Encrypt de l'hôte via
  `SENTINEL_V3_MX_TLS_SOURCE` et pointer `SENTINEL_V3_MX_TLS_CERT` / `_KEY` sur
  le bon `live/`. Sans certificat lisible, le MX démarre quand même, avec un
  auto-signé temporaire : STARTTLS fonctionne, mais aucun correspondant ne peut
  vérifier l'identité du serveur. C'est un mode de dépannage, pas une cible.
- **La publication du port.** Par défaut, `mx` n'écoute que sur
  `127.0.0.1:2525` : rien n'arrive du monde et aucun conflit n'est possible
  avec un MX déjà en écoute sur le port 25 de la machine. Une instance qui
  reçoit vraiment pose :

  ```
  SENTINEL_V3_MX_BIND_HOST=<adresse publique>
  SENTINEL_V3_MX_BIND_PORT=25
  ```

  Si un autre MX occupe déjà le port 25 de cet hôte, il faut le déplacer ou
  l'arrêter avant : deux processus ne peuvent pas partager le même couple
  adresse/port.

## Ce que le MX refuse

- Tout destinataire hors des domaines actifs (`reject_unauth_destination`).
- `mynetworks` se limite à la boucle locale du conteneur : y ajouter le
  sous-réseau Docker ouvrirait le relais à tous les conteneurs voisins.
- Aucune authentification SMTP n'est proposée (`smtpd_sasl_auth_enable = no`),
  aucun service `submission` ni `smtps` n'est déclaré : ce nœud est entrant, il
  n'a pas de clients à relayer.

## Les en-têtes qu'un expéditeur ne peut pas se donner

`infra/postfix/header_checks` efface, à l'entrée, les en-têtes qui sont des
assertions de l'infrastructure et jamais de l'expéditeur :
`Authentication-Results`, les scores antispam et les en-têtes d'état
`X-Sentimail-*` / `X-Sentinel-*`.

Ce nettoyage a lieu dans `cleanup`, donc **avant** que le milter n'écrive les
siens. Sans lui, il suffirait à un attaquant d'écrire lui-même
`Authentication-Results: rspamd.sentimail; dmarc=pass` pour obtenir de
l'analyse une preuve d'authenticité qu'il n'a pas.

`ARC-Authentication-Results` est conservé : c'est une chaîne de témoignages
distincte, évaluée comme telle.

## L'identifiant qui doit rester exact

Le hook d'authentification de V3 n'accorde sa confiance qu'à un
`Authentication-Results` dont l'authserv-id vaut **exactement**
`rspamd.sentimail`. Toute autre valeur — y compris le nom d'hôte du conteneur —
rend l'en-tête invisible et le message est analysé comme non authentifié, ce
qui le fait retenir sans raison.

La valeur est fixée à deux endroits, volontairement :

- `milter_macro_daemon_name = rspamd.sentimail` dans `main.cf.tmpl` ;
- `authserv_id = "rspamd.sentimail"` dans
  `infra/rspamd/conf.d/local.d/milter_headers.conf`.

Après tout changement touchant rspamd ou le milter, vérifier sur un message
réel :

```
docker compose exec mx sh -c 'postconf milter_macro_daemon_name'
# puis, sur un message reçu, la première ligne Authentication-Results
```

## rspamd ici : un témoin, pas un juge

Les seuils de `local.d/actions.conf` sont volontairement hors d'atteinte
(`reject = 100`). rspamd produit un score et une authentification ; c'est le
pipeline de SentiMail V3 qui tranche, journalise et laisse la main à un humain.
Un rejet au milter court-circuiterait tout cela et rendrait la décision
invisible dans la console.

Contrairement à V2, ce rspamd n'interroge aucune base de données : pas de
réglages par domaine à rendre, donc pas de dépendance à Postgres ni de
processus de rendu à surveiller.

## Vérifications utiles

```sh
# La map voit-elle le domaine ?
docker compose exec mx postmap -q exemple.fr pgsql:/etc/postfix/relay_domains.cf
# Vers où route-t-elle ?
docker compose exec mx postmap -q exemple.fr pgsql:/etc/postfix/transport.cf
# Un domaine non enrôlé ne doit rien renvoyer :
docker compose exec mx postmap -q pas-enrole.fr pgsql:/etc/postfix/relay_domains.cf
# La file est-elle vide ?
docker compose exec mx postqueue -p
```
