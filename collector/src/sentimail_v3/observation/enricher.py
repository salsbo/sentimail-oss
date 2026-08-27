from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import quote

import asyncpg
import dns.asyncresolver
import httpx
import tldextract

from sentimail_v3.config import load_settings
from sentimail_v3.supervision.health import pulse
from sentimail_v3.code.reference import nommer_dossier

logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger("sentimail-v3-enricher")
_extract_domain = tldextract.TLDExtract(suffix_list_urls=())


def _json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), default=str)


def _log(event: str, **fields: object) -> None:
    fields = nommer_dossier(dict(fields))
    logger.info(_json({"event": event, **fields}))


def _rdap_events(data: dict[str, Any]) -> dict[str, list[str]]:
    result: dict[str, list[str]] = {}
    for event in data.get("events", []):
        if not isinstance(event, dict):
            continue
        action = str(event.get("eventAction") or "unknown")
        date = event.get("eventDate")
        if date:
            result.setdefault(action, []).append(str(date))
    return result


def _rdap_countries(data: object) -> list[str]:
    countries: set[str] = set()

    def visit(value: object) -> None:
        if isinstance(value, dict):
            country = value.get("country")
            if isinstance(country, str) and len(country) <= 3:
                countries.add(country.upper())
            cc = value.get("cc")
            if isinstance(cc, str) and len(cc) == 2:
                countries.add(cc.upper())
            for child in value.values():
                visit(child)
        elif isinstance(value, list):
            for child in value:
                visit(child)

    visit(data)
    return sorted(countries)


async def _rdap(client: httpx.AsyncClient, kind: str, value: str) -> dict[str, Any]:
    response = await client.get(f"https://rdap.org/{kind}/{quote(value, safe=':.')}")
    response.raise_for_status()
    body = response.json()
    if not isinstance(body, dict):
        raise TypeError("RDAP response is not an object")
    return {
        "url": str(response.url),
        "events": _rdap_events(body),
        "countries": _rdap_countries(body),
        "raw": body,
    }


async def _dns_domain(domain: str) -> dict[str, object]:
    resolver = dns.asyncresolver.Resolver()
    resolver.timeout = 3
    resolver.lifetime = 5
    queries = {
        "a": (domain, "A"),
        "aaaa": (domain, "AAAA"),
        "mx": (domain, "MX"),
        "ns": (domain, "NS"),
        "txt": (domain, "TXT"),
        "caa": (domain, "CAA"),
        "dnskey": (domain, "DNSKEY"),
        "dmarc": (f"_dmarc.{domain}", "TXT"),
    }
    result: dict[str, object] = {}
    for name, (query_name, record_type) in queries.items():
        try:
            answers = await resolver.resolve(query_name, record_type)
            result[name] = [answer.to_text() for answer in answers]
        except Exception as exc:  # noqa: BLE001 - chaque source DNS est fail-soft
            result[name] = {"error": type(exc).__name__}
    return result


async def _cymru_ip(
    ip: ipaddress.IPv4Address | ipaddress.IPv6Address,
) -> dict[str, object]:
    resolver = dns.asyncresolver.Resolver()
    resolver.timeout = 3
    resolver.lifetime = 5
    if ip.version == 4:
        query = ".".join(reversed(ip.exploded.split("."))) + ".origin.asn.cymru.com"
    else:
        query = (
            ".".join(reversed(ip.exploded.replace(":", ""))) + ".origin6.asn.cymru.com"
        )
    answers = await resolver.resolve(query, "TXT")
    raw = answers[0].to_text().strip('"')
    fields = [field.strip() for field in raw.split("|")]
    names = ("asn", "prefix", "country", "registry", "allocated_at")
    return {
        name: fields[index] for index, name in enumerate(names) if index < len(fields)
    }


async def _enrich_domain(client: httpx.AsyncClient, value: str) -> dict[str, object]:
    extracted = _extract_domain(value)
    registered = ".".join(part for part in (extracted.domain, extracted.suffix) if part)
    target = registered or value
    result: dict[str, object] = {
        "fqdn": value,
        "registered_domain": registered or None,
        "subdomain": extracted.subdomain or None,
        "suffix": extracted.suffix or None,
    }
    if not extracted.suffix:
        result["public_suffix"] = False
        return result
    result["public_suffix"] = True
    result["dns"] = await _dns_domain(value)
    try:
        rdap = await _rdap(client, "domain", target)
        result["rdap"] = rdap
        creation_dates = rdap["events"].get("registration", [])
        if creation_dates:
            result["creation_date"] = min(creation_dates)
            try:
                created = datetime.fromisoformat(
                    min(creation_dates).replace("Z", "+00:00")
                )
                result["age_days"] = (datetime.now(UTC) - created).days
            except ValueError:
                pass
        result["countries"] = rdap["countries"]
    except Exception as exc:  # noqa: BLE001 - RDAP est un enrichissement fail-soft
        result["rdap_error"] = {"type": type(exc).__name__, "detail": str(exc)[:500]}
    return result


async def _enrich_ip(client: httpx.AsyncClient, value: str) -> dict[str, object]:
    ip = ipaddress.ip_address(value)
    result: dict[str, object] = {
        "ip": ip.compressed,
        "version": ip.version,
        "is_global": ip.is_global,
        "is_private": ip.is_private,
        "is_reserved": ip.is_reserved,
    }
    if not ip.is_global:
        return result
    try:
        result["rdap"] = await _rdap(client, "ip", ip.compressed)
        result["countries"] = result["rdap"]["countries"]
    except Exception as exc:  # noqa: BLE001 - RDAP est un enrichissement fail-soft
        result["rdap_error"] = {"type": type(exc).__name__, "detail": str(exc)[:500]}
    try:
        result["asn"] = await _cymru_ip(ip)
    except Exception as exc:  # noqa: BLE001 - ASN est un enrichissement fail-soft
        result["asn_error"] = {"type": type(exc).__name__}
    try:
        reverse = await dns.asyncresolver.resolve(ip.reverse_pointer, "PTR")
        result["reverse_dns"] = [answer.to_text() for answer in reverse]
    except Exception as exc:  # noqa: BLE001 - PTR est un enrichissement fail-soft
        result["reverse_dns_error"] = {"type": type(exc).__name__}
    return result


async def _next_entities(pool: asyncpg.Pool[Any]) -> list[asyncpg.Record]:
    return await pool.fetch(
        """
        SELECT entity_type, value_normalized
        FROM entities
        WHERE enrichment_id IS NULL AND entity_type IN ('domain', 'ip')
        GROUP BY entity_type, value_normalized
        ORDER BY min(id)
        LIMIT 20
        """
    )


async def _save(
    pool: asyncpg.Pool[Any],
    entity_type: str,
    value: str,
    status: str,
    data: dict[str, object],
    error: str | None = None,
) -> None:
    expires = datetime.now(UTC) + (
        timedelta(days=7) if status == "ok" else timedelta(hours=1)
    )
    async with pool.acquire() as connection, connection.transaction():
        enrichment_id = await connection.fetchval(
            """
            INSERT INTO enrichments (
                entity_type, value_normalized, source, expires_at, status, data, error
            ) VALUES ($1,$2,'rdap+dns',$3,$4,$5::jsonb,$6) RETURNING id
            """,
            entity_type,
            value,
            expires,
            status,
            _json(data),
            error,
        )
        await connection.execute(
            """UPDATE entities SET enrichment_id=$1
               WHERE enrichment_id IS NULL AND entity_type=$2 AND value_normalized=$3""",
            enrichment_id,
            entity_type,
            value,
        )


async def main() -> None:
    settings = load_settings()
    pool = await asyncpg.create_pool(settings.database_url, min_size=1, max_size=3)
    async with httpx.AsyncClient(
        follow_redirects=True,
        timeout=httpx.Timeout(12),
        headers={"Accept": "application/rdap+json, application/json"},
    ) as client:
        while True:
            pulse("enricher")
            rows = await _next_entities(pool)
            if not rows:
                await asyncio.sleep(settings.enrichment_interval_seconds)
                continue
            for row in rows:
                entity_type = row["entity_type"]
                value = row["value_normalized"]
                try:
                    data = (
                        await _enrich_domain(client, value)
                        if entity_type == "domain"
                        else await _enrich_ip(client, value)
                    )
                    await _save(pool, entity_type, value, "ok", data)
                    _log("entity.enriched", type=entity_type, value=value)
                except Exception as exc:  # noqa: BLE001 - la boucle doit continuer
                    await _save(pool, entity_type, value, "error", {}, str(exc)[:500])
                    _log("entity.error", type=entity_type, error=type(exc).__name__)
                await asyncio.sleep(0.5)
            pulse("enricher")


if __name__ == "__main__":
    asyncio.run(main())
