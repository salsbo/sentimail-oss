# SentiMail

*Version française : [README.md](README.md). The codebase, tests and detailed
documentation are in French, structured so AI coding agents can navigate them
(see `AGENTS.md`). This page covers everything you need in English to install
and operate an instance.*

Self-hosted email protection gateway: an autonomous MX receives your mail, a
multi-stage exam (deterministic signals + a configurable LLM judge) decides to
deliver, hold or classify each message, and an assistant, MAIA (Mail
Authentication Intelligence Agent), talks to the user by email. End users
never touch a dashboard: their gateway writes to them, explains every
decision, and they answer with one click or in natural language, behind
strict locks (single-use signed tokens, anti-spoofing checks on the reply
path, directives parsed by strict rules rather than a credulous LLM). The
admin console exists for the operator only.

## Warnings

- **Message content is sent to the LLM provider you configure** (DeepSeek,
  OpenAI, Mistral, Anthropic, or a local endpoint via Ollama/vLLM). The
  privacy banner in the console (`/reglages`, `/etat`) permanently shows,
  role by role, where that content goes: the configured remote provider's
  URL, or the local model when nothing leaves your machine.
- **Putting an MX in front of your mail flow requires real mail-server
  skills**: MX record, PTR for the public address, TLS certificate. A bad
  DNS/TLS setup makes senders refuse your mail.
- Note that MAIA's user-facing emails are currently written in French.

## Architecture

Docker Compose services (`docker-compose.yml`):

| Service | Role |
|---|---|
| `db` | PostgreSQL, the instance database |
| `migrate` | Applies SQL migrations at startup (append-only, checksum-verified) |
| `backup` | Periodic encrypted database backups |
| `collector` | Internal SMTP intake (`observation.smtp_server`) and analysis pipeline orchestration |
| `assistant` | MAIA: email dialogue with the user (`conversation.assistant`) |
| `verdict` | LLM judgment stage (`judgment.verdict_engine`): weighs favorable and adverse evidence, renders the verdict |
| `enricher` | Asynchronous deep analysis (`observation.enricher`): sandboxes, domain age, DNS, RDAP, ASN, country |
| `retention` | Content redaction then deletion along the retention window (`execution.retention`) |
| `watchdog` | Anti-soft-fail supervisor (`supervision.watchdog`): every accepted message is either delivered or accompanied by a MAIA notice |
| `caretaker` | Diagnostics and supervision guardrails (`supervision.caretaker`) |
| `admin` | Operator console (identity, LLM engine, domains, lists) |
| `relay` | Internal Postfix: relays accepted mail toward `collector` |
| `url-sandbox` | URL analysis sandbox (redirects, forms) |
| `file-sandbox` | Attachment analysis sandbox (YARA, macros, PDF, archives, OCR) |
| `render-sandbox` | Rendering sandbox (screenshots, hidden content) |
| `valkey` | rspamd working storage (Bayes, caches), disposable |
| `rspamd` | Milter producing the authentication evidence (SPF/DKIM/DMARC) |
| `mx` | Autonomous public Postfix: SMTP intake from the Internet (port 25) |

Public reception chain: `Internet -> mx -> rspamd (milter) -> mx ->
collector -> pipeline`. Full details in `docs/mx-autonome.md` (French).

Code layout (`collector/src/sentimail_v3/`): `observation/` captures and
describes mail, `code/` holds the applicable rules, `judgment/` decides,
`execution/` acts on a rendered verdict, `conversation/` talks to the user
over SMTP, `supervision/` watches the whole. See `docs/code-sentinel.md`
(French) for the complete functional reference.

## Quickstart

1. Clone the repository.
2. Copy `.env.example` to `.env` and adjust the values (domain, service
   identity, admin console address). Comments in the file are in French;
   any AI assistant will translate them instantly.
3. Create the secret files under `secrets/` (0700 directory, 0600 files):

   ```
   scripts/bootstrap-secrets.sh
   ```

   The script is idempotent (it never touches an existing non-empty file).
   It generates `db_password`, `assistant_token_secret` and
   `backup_password` as 32-byte hex, and `raw_eml_key` as 32-byte hex (64
   hex characters, the format `crypto.load_key` requires). It prompts for
   `deepseek_api_key`; left empty (Enter), the file is created empty and
   the LLM engine must be configured from the `/reglages` console before
   verdicts can be rendered.
4. Start the stack:

   ```
   docker compose up -d --build
   ```

5. Open the admin console at `SENTINEL_ADMIN_ADDR` (an `.env` variable).
   The console has no password: reachability of that address is the
   authorization. Any private address whose access you alone control works
   (any VPN, a filtered LAN); Tailscale is the documented default choice.
   `0.0.0.0` is refused unless you explicitly opt in with
   `ADMIN_BIND_UNRESTRICTED=true`.
6. Enroll a domain (detailed procedure in `docs/mx-autonome.md`).
7. Configure the LLM engine from `/reglages` (presets: `deepseek`,
   `openai`, `mistral`, `ollama`, `anthropic`, or `custom`). Ollama preset:
   on Linux, `host.docker.internal` does not resolve from a container by
   default; use the host IP or add
   `extra_hosts: host.docker.internal:host-gateway` to the service in
   `docker-compose.yml`.

## Configuration

Every commented variable lives in `.env.example`. Live configuration tables
(`llm_role_providers`, `instance_identity`, editable from `/reglages`
without a restart) and the routing precedence (per-role local routing >
the role's `llm_role_providers` row > environment variables) are documented
in the engine-and-identity configuration section of `docs/code-sentinel.md`.

## Tests

```
cd collector && PYTHONPATH=src uv run --with pytest --with-requirements requirements.txt python -m pytest tests/ -q
cd admin && PYTHONPATH=src uv run --with pytest --with-requirements requirements.txt python -m pytest tests/ -q
```

## Documentation

- `docs/code-sentinel.md` (French): complete functional reference (hook
  contract, decision mode, SMTP conversation, sender lists, engine
  configuration, retention, anti-poisoning locks).
- `docs/mx-autonome.md` (French): how the autonomous MX works.
- `AGENTS.md` (French): bearings for AI agents working on this code.

## License

Personal and other noncommercial use is free, under the PolyForm
Noncommercial License 1.0.0 (see `LICENSE`). Any commercial use requires the
author's prior written permission. Contact: https://github.com/salsbo
