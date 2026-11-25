#!/usr/bin/env bash
# Installe les routes SMTP opérateur, séparées des domaines protégés en base.
set -euo pipefail
source_dir="${1:-/etc/postfix/direct-source}"
output_dir="${2:-/etc/postfix}"

# Les clés peuvent être un domaine exact ou une adresse exacte. Un joker
# autoriserait un relais arbitraire ; Postfix utilise l'adresse avant le domaine
# dans transport_maps, tout en gardant relay_domains résolu par domaine.
domain_re='^[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?\.[a-zA-Z]{2,63}$'
recipient_re='^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?\.[a-zA-Z]{2,63}$'
while read -r domain transport extra; do
    [[ -z "${domain}" || "${domain}" == \#* ]] && continue
    if [[ ! "${domain}" =~ ${domain_re} && ! "${domain}" =~ ${recipient_re} ]] \
       || [[ "${domain}" == *..* ]] \
       || [[ ! "${transport}" =~ ^smtp:\[[a-zA-Z0-9.-]+\]:[0-9]{1,5}$ ]] \
       || [[ -n "${extra:-}" ]]; then
        echo 'Route SMTP directe invalide : domaine ou adresse exacts et smtp:[hote]:port requis' >&2
        exit 1
    fi
done < "${source_dir}/routes"

for name in routes recipient_access; do
    cp "${source_dir}/${name}" "${output_dir}/direct_${name}"
    chmod 0644 "${output_dir}/direct_${name}"
    postmap "${output_dir}/direct_${name}"
done
