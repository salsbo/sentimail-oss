FROM postgres:16.11-alpine3.23

# Les versions de paquets sont épinglées à la branche mineure, pas au correctif.
# Alpine retire ses anciens correctifs dès qu'un nouveau paraît : figer
# « 3.12.13-r0 » garantissait un build cassé à la première mise à jour de
# sécurité de Python - c'est arrivé le 16 août, et le service de sauvegarde ne
# se reconstruisait plus. La branche Alpine, elle, reste fixée par l'image de
# base ci-dessus, et la version de pyzipper reste exacte : elle vient de PyPI,
# qui ne supprime pas ses versions.
RUN apk add --no-cache 'python3~=3.12' 'py3-pip~=25.1' \
    && python3 -m pip install --break-system-packages --no-cache-dir pyzipper==0.4.0 \
    && install -d -o postgres -g postgres -m 0700 /backups

WORKDIR /app
COPY --chmod=0644 backup.py /app/backup.py
COPY entrypoint.sh /usr/local/bin/sentimail-backup-entrypoint

RUN chmod 0755 /usr/local/bin/sentimail-backup-entrypoint

ENTRYPOINT ["/usr/local/bin/sentimail-backup-entrypoint"]
CMD ["python3", "/app/backup.py"]
