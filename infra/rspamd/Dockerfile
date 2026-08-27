# Milter rspamd de SentiMail V3.
# Contexte de build attendu : racine du dépôt (infra/rspamd/Dockerfile).
#
# Version épinglée sur la série stable 3.14.x. Les images 4.0.x publiées à ce
# jour sont des builds -git dont la glu Lua des statistiques Redis casse le
# Bayes (tout appel de script stat échoue en « attempt to call a nil value »).
FROM rspamd/rspamd:3.14.3

# Contrairement à SentiMail V2, cette image n'embarque ni Python ni psycopg2 :
# rspamd n'interroge aucune base ici. Il note, il n'arbitre pas, et la seule
# donnée dont il a besoin — le domaine protégé — est déjà tranchée en amont
# par le MX, qui n'accepte que les destinataires des domaines actifs.
COPY infra/rspamd/conf.d /etc/rspamd/

EXPOSE 11332

CMD ["rspamd", "-f", "-u", "_rspamd", "-g", "_rspamd"]
