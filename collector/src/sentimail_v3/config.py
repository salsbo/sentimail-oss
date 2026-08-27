from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import quote


@dataclass(frozen=True)
class Settings:
    database_url: str
    smtp_host: str
    smtp_port: int
    relay_host: str
    relay_port: int
    enrichment_interval_seconds: int
    conversation_enabled: bool
    action_address: str
    action_aliases: tuple[str, ...]
    assistant_sender: str
    operator_address: str
    operator_addresses: tuple[str, ...]
    assistant_token_secret: str
    assistant_interval_seconds: int
    deepseek_api_key: str
    # Recherche des domaines officiels d'une organisation. Vide = pas de
    # recherche : le soupçon reste ce que le modèle en a dit, rien ne sort.
    search_api_key: str
    search_base_url: str
    deepseek_base_url: str
    deepseek_verdict_model: str
    deepseek_assistant_model: str
    deepseek_timeout_seconds: int
    verdict_interval_seconds: int
    verdict_not_before: str | None
    decision_mode: bool
    auto_delivery_confidence: float
    analysis_wait_seconds: int
    url_sandbox_url: str
    file_sandbox_url: str
    render_sandbox_url: str
    provider_secrets_dir: str
    anthropic_model: str
    openai_model: str
    assistant_llm_hourly_limit: int
    assistant_llm_daily_limit: int
    assistant_llm_conversation_limit: int
    verdict_llm_hourly_limit: int
    verdict_llm_daily_limit: int
    verdict_concurrency: int
    watchdog_ingress_host: str
    watchdog_ingress_port: int
    watchdog_smtp_preflight_enabled: bool
    probe_enabled: bool
    probe_recipient: str
    probe_timeout_seconds: int
    probe_interval_seconds: int
    retention_enabled: bool
    retention_redact_after_days: int
    retention_delete_after_days: int
    retention_interval_seconds: int
    retention_batch_size: int
    hold_lifecycle_enabled: bool
    hold_reminder_after_days: int
    hold_decision_after_days: int
    hold_lifecycle_interval_seconds: int
    raw_eml_key_file: str | None
    digest_enabled: bool
    digest_interval_hours: int
    digest_minimum_cases: int
    local_llm_url: str
    caretaker_interval_hours: int
    console_url: str
    knowledge_path: str
    knowledge_embedding_url: str
    knowledge_embedding_model: str


def _secret(name: str) -> str:
    path = os.environ.get(f"{name}_FILE")
    if path:
        return Path(path).read_text(encoding="utf-8").strip()
    return os.environ.get(name, "")


def _database_url() -> str:
    password_file = os.environ.get("DATABASE_PASSWORD_FILE")
    if password_file:
        password = Path(password_file).read_text(encoding="utf-8").strip()
        if not password:
            raise RuntimeError("DATABASE_PASSWORD_FILE is empty")
        user = os.environ.get("DATABASE_USER", "sentimail_v3")
        host = os.environ.get("DATABASE_HOST", "db")
        port = os.environ.get("DATABASE_PORT", "5432")
        database = os.environ.get("DATABASE_NAME", "sentimail_v3")
        return (
            f"postgresql://{quote(user, safe='')}:{quote(password, safe='')}"
            f"@{host}:{port}/{quote(database, safe='')}"
        )
    return os.environ["DATABASE_URL"]


def _operators(brut: str) -> tuple[str, tuple[str, ...]]:
    """Lit la liste des exploitants et rend la référence puis la liste.

    Écrire deux fois la même adresse - par une casse différente, par exemple -
    ferait partir deux courriers identiques : l'ordre de la déclaration est
    conservé, les répétitions ne le sont pas.
    """
    vues: list[str] = []
    for morceau in brut.replace(";", ",").split(","):
        adresse = morceau.strip().casefold()
        if adresse and adresse not in vues:
            vues.append(adresse)
    return (vues[0] if vues else "", tuple(vues))


def load_settings() -> Settings:
    return Settings(
        database_url=_database_url(),
        smtp_host=os.environ.get("SMTP_HOST", "0.0.0.0"),
        smtp_port=int(os.environ.get("SMTP_PORT", "2525")),
        relay_host=os.environ.get("RELAY_HOST", "172.20.0.1"),
        relay_port=int(os.environ.get("RELAY_PORT", "10027")),
        enrichment_interval_seconds=int(
            os.environ.get("ENRICHMENT_INTERVAL_SECONDS", "30")
        ),
        conversation_enabled=os.environ.get("CONVERSATION_ENABLED", "false").lower()
        == "true",
        action_address=os.environ.get(
            "ACTION_ADDRESS", "maia@sentinel.sentimail.example"
        ).casefold(),
        action_aliases=tuple(
            value.strip().casefold()
            for value in os.environ.get(
                "ACTION_ALIASES", "kitt@sentinel.sentimail.example"
            ).split(",")
            if value.strip()
        ),
        assistant_sender=os.environ.get(
            "ASSISTANT_SENDER", "MAIA - SentiMail <maia@sentimail.example>"
        ),
        # Les exploitants de l'instance : ils reçoivent les alertes techniques
        # et les rapports d'entretien. Les destinataires protégés, eux, se
        # résolvent en base à partir des domaines enrôlés.
        #
        # La variable en accepte plusieurs, séparées par une virgule ou un
        # point-virgule : une exploitation portée par une seule adresse s'arrête
        # de fonctionner dès que cette personne est absente. La première reste
        # l'exploitant de référence, pour les rôles qui n'admettent qu'une
        # adresse - la sonde SMTP, le participant par défaut d'une conversation.
        operator_address=_operators(
            os.environ.get(
                "OPERATOR_ADDRESS", os.environ.get("AUTHORIZED_USER_ADDRESS", "")
            )
        )[0],
        operator_addresses=_operators(
            os.environ.get(
                "OPERATOR_ADDRESS", os.environ.get("AUTHORIZED_USER_ADDRESS", "")
            )
        )[1],
        assistant_token_secret=_secret("ASSISTANT_TOKEN_SECRET"),
        assistant_interval_seconds=int(
            os.environ.get("ASSISTANT_INTERVAL_SECONDS", "5")
        ),
        deepseek_api_key=_secret("DEEPSEEK_API_KEY"),
        search_api_key=_secret("SEARCH_API_KEY"),
        search_base_url=os.environ.get(
            "SEARCH_BASE_URL", "https://api.tavily.com"
        ),
        deepseek_base_url=os.environ.get(
            "DEEPSEEK_BASE_URL", "https://api.deepseek.com"
        ),
        deepseek_verdict_model=os.environ.get(
            "DEEPSEEK_VERDICT_MODEL", "deepseek-v4-pro"
        ),
        deepseek_assistant_model=os.environ.get(
            "DEEPSEEK_ASSISTANT_MODEL", "deepseek-v4-pro"
        ),
        deepseek_timeout_seconds=int(
            os.environ.get("DEEPSEEK_TIMEOUT_SECONDS", "180")
        ),
        verdict_interval_seconds=int(
            os.environ.get("VERDICT_INTERVAL_SECONDS", "5")
        ),
        verdict_not_before=os.environ.get("VERDICT_NOT_BEFORE") or None,
        decision_mode=os.environ.get("DECISION_MODE", "false").lower() == "true",
        auto_delivery_confidence=float(
            os.environ.get("AUTO_DELIVERY_CONFIDENCE", "0.90")
        ),
        analysis_wait_seconds=int(os.environ.get("ANALYSIS_WAIT_SECONDS", "30")),
        url_sandbox_url=os.environ.get(
            "URL_SANDBOX_URL", "http://url-sandbox:8090"
        ).rstrip("/"),
        file_sandbox_url=os.environ.get(
            "FILE_SANDBOX_URL", "http://file-sandbox:8091"
        ).rstrip("/"),
        render_sandbox_url=os.environ.get(
            "RENDER_SANDBOX_URL", "http://render-sandbox:8092"
        ).rstrip("/"),
        provider_secrets_dir=os.environ.get(
            "PROVIDER_SECRETS_DIR", "/run/sentinel-provider-secrets"
        ),
        anthropic_model=os.environ.get(
            "ANTHROPIC_MODEL", "claude-sonnet-4-5"
        ),
        openai_model=os.environ.get("OPENAI_MODEL", "gpt-5.4"),
        assistant_llm_hourly_limit=int(
            os.environ.get("ASSISTANT_LLM_HOURLY_LIMIT", "20")
        ),
        assistant_llm_daily_limit=int(
            os.environ.get("ASSISTANT_LLM_DAILY_LIMIT", "100")
        ),
        assistant_llm_conversation_limit=int(
            os.environ.get("ASSISTANT_LLM_CONVERSATION_LIMIT", "10")
        ),
        verdict_llm_hourly_limit=int(
            os.environ.get("VERDICT_LLM_HOURLY_LIMIT", "100")
        ),
        verdict_llm_daily_limit=int(
            os.environ.get("VERDICT_LLM_DAILY_LIMIT", "500")
        ),
        verdict_concurrency=max(1, min(4, int(os.environ.get("VERDICT_CONCURRENCY", "2")))),
        watchdog_ingress_host=os.environ.get("WATCHDOG_INGRESS_HOST", "collector"),
        watchdog_ingress_port=int(os.environ.get("WATCHDOG_INGRESS_PORT", "2525")),
        watchdog_smtp_preflight_enabled=os.environ.get(
            "WATCHDOG_SMTP_PREFLIGHT_ENABLED", "true"
        ).lower()
        == "true",
        probe_enabled=os.environ.get("PROBE_ENABLED", "true").lower() == "true",
        probe_recipient=os.environ.get(
            "PROBE_RECIPIENT", "sentinel-probe@sentimail.example"
        ).casefold(),
        probe_timeout_seconds=max(
            5, min(120, int(os.environ.get("PROBE_TIMEOUT_SECONDS", "45")))
        ),
        probe_interval_seconds=max(
            60, int(os.environ.get("PROBE_INTERVAL_SECONDS", "300"))
        ),
        retention_enabled=os.environ.get("RETENTION_ENABLED", "true").lower() == "true",
        retention_redact_after_days=int(
            os.environ.get("RETENTION_REDACT_AFTER_DAYS", "30")
        ),
        retention_delete_after_days=int(
            os.environ.get("RETENTION_DELETE_AFTER_DAYS", "180")
        ),
        retention_interval_seconds=int(
            os.environ.get("RETENTION_INTERVAL_SECONDS", "3600")
        ),
        retention_batch_size=max(
            1, min(2000, int(os.environ.get("RETENTION_BATCH_SIZE", "500")))
        ),
        hold_lifecycle_enabled=os.environ.get("HOLD_LIFECYCLE_ENABLED", "true").lower()
        == "true",
        hold_reminder_after_days=int(os.environ.get("HOLD_REMINDER_AFTER_DAYS", "3")),
        hold_decision_after_days=int(os.environ.get("HOLD_DECISION_AFTER_DAYS", "7")),
        hold_lifecycle_interval_seconds=int(
            os.environ.get("HOLD_LIFECYCLE_INTERVAL_SECONDS", "3600")
        ),
        raw_eml_key_file=os.environ.get("RAW_EML_KEY_FILE") or None,
        digest_enabled=os.environ.get("DIGEST_ENABLED", "true").lower() == "true",
        # Même moteur local que les embeddings : un seul point à joindre.
        local_llm_url=os.environ.get(
            "LOCAL_LLM_URL", os.environ.get("KNOWLEDGE_EMBEDDING_URL", "")
        ),
        # Le corpus figé est monté en lecture seule ; l'embedding est local et
        # facultatif, son absence n'empêche pas de chercher.
        caretaker_interval_hours=int(
            os.environ.get("CARETAKER_INTERVAL_HOURS", "6")
        ),
        # L'adresse de la console d'administration, pour que les courriers
        # d'exploitation pointent vers la page des écarts. Vide : pas de lien.
        console_url=os.environ.get("CONSOLE_URL", "").rstrip("/"),
        knowledge_path=os.environ.get("KNOWLEDGE_PATH", "/app/knowledge"),
        knowledge_embedding_url=os.environ.get("KNOWLEDGE_EMBEDDING_URL", ""),
        knowledge_embedding_model=os.environ.get(
            "KNOWLEDGE_EMBEDDING_MODEL", "bge-m3"
        ),
        digest_interval_hours=int(os.environ.get("DIGEST_INTERVAL_HOURS", "24")),
        digest_minimum_cases=int(os.environ.get("DIGEST_MINIMUM_CASES", "2")),
    )
