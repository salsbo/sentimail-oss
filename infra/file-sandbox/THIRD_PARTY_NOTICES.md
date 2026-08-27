# Composants tiers

SentiMail assemble des logiciels libres qui conservent leurs propres licences.
La liste exacte dépend de la version verrouillée dans les lockfiles et des
images Docker utilisées.

Composants structurants :

| Composant | Rôle | Licence amont |
|---|---|---|
| Postfix | transport SMTP | IBM Public License 1.0 / Eclipse Public License 2.0 |
| Rspamd | analyse antispam | Apache-2.0 |
| PostgreSQL | base de données | PostgreSQL License |
| Valkey 8.1.9 | cache compatible Redis | BSD-3-Clause |
| redis-py | client Python compatible Valkey | MIT |
| FastAPI | API | MIT |
| Next.js / React | administration web | MIT |
| uv 0.8.3 | resolution, installation et execution Python | MIT OR Apache-2.0 |
| age | format et implementation de chiffrement | BSD-3-Clause |
| pyrage | bindings Python age | MIT |
| YARA | règles de détection | BSD-3-Clause |
| Tesseract OCR | OCR local | Apache-2.0 |
| libzbar | lecture QR / codes-barres | LGPL-2.1-or-later |
| libvips (paquets `@img/sharp-libvips-*`) | traitement d'images web | LGPL-3.0-or-later |
| sharp | bindings images Node.js | Apache-2.0 |
| Lightning CSS | compilation CSS de l'admin | MPL-2.0 |
| psycopg2 | client PostgreSQL des outils Rspamd/API | LGPL-3.0-or-later avec exceptions |
| asyncpg | client PostgreSQL asynchrone | Apache-2.0 |
| dnspython | résolution DNS | ISC |
| httpx | client HTTP | BSD-3-Clause |
| SQLAlchemy | accès aux données | MIT |
| Pydantic | validation de schémas | MIT |
| RapidFuzz | distances de chaînes | MIT |
| confusable-homoglyphs | détection Unicode | MIT |
| tldextract 5.3.2 | extraction eTLD+1 locale | BSD-3-Clause |
| Mozilla Public Suffix List (snapshot embarqué par tldextract) | frontières de domaines ICANN et PRIVATE | MPL-2.0 |
| oletools 0.60.2 | analyse statique de documents Office | BSD-2-Clause |
| pcodedmp 1.2.6 (transitif oletools) | extraction de macros VBA | GPL-3.0-only |
| pdfminer.six | extraction PDF locale | MIT |
| python-magic | identification de fichiers | MIT |
| pyzbar | bindings codes-barres | MIT |
| Pillow | traitement raster | HPND |
| Playwright | pilotage du navigateur de rendu isolé | Apache-2.0 |
| Chromium | moteur de rendu de la capture d'email | BSD-3-Clause et licences tierces |
| Beautiful Soup | assainissement HTML préalable au rendu | MIT |

Images de base distribuees :

| Image | Version de reference | Licence du composant principal |
|---|---|---|
| Python | 3.12.13-slim | PSF-2.0 |
| Node.js | 22.22.3-alpine | MIT |
| Debian | 12.13-slim | ensemble de licences libres par paquet |
| PostgreSQL | 16.11-alpine3.23 | PostgreSQL License |
| Valkey | 8.1.9-alpine3.24 | BSD-3-Clause |
| Rspamd | 3.14.3 | Apache-2.0 |
| Playwright Python | 1.55.0-noble | Apache-2.0 et licences des composants embarqués |

Les paquets transitifs Python des sandboxes sont figes avec leurs hashes dans
`infra/*-sandbox/requirements.lock`; les autres transitifs restent enumeres
par les lockfiles uv et npm. Ce
fichier n'est pas un substitut aux notices livrees par chaque dependance. Avant
une distribution binaire, generez le SBOM et les rapports de licences a partir
des versions reellement construites ; en cas d'ecart, les notices amont et le
SBOM de la release font foi.
