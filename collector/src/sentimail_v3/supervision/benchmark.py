"""Évaluer un modèle candidat sur un export figé, sans effet sur le courrier.

Le candidat reçoit uniquement le dossier compact et désensibilisé. Sa réponse
est validée par le même parseur que le verdict de production, puis comparée aux
annotations humaines. Aucun accès à PostgreSQL, aucune livraison et aucune
mutation opérationnelle ne sont possibles depuis ce module.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import time
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any

import httpx

from sentimail_v3.judgment.verdict_engine import _parse_verdict, _prompt
from sentimail_v3.llm import (
    ProviderRoute,
    local_chat_json,
    openai_compatible_chat_json,
)
from sentimail_v3.supervision.evaluation import (
    ASK,
    DELIVER,
    JUNK,
    confusion_matrix,
    generalized_risk,
    hold_precision,
    labelling_coverage,
    lam_percent,
    trec_rates,
    utility_score,
)
from sentimail_v3.supervision.training import canonical_dossier, safe_teacher_target

CandidateCall = Callable[[list[dict[str, str]]], Awaitable[tuple[str, dict[str, Any]]]]


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    samples: list[dict[str, Any]] = []
    with path.open(encoding="utf-8") as source:
        for line_number, line in enumerate(source, start=1):
            if not line.strip():
                continue
            try:
                value = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"JSONL invalide à la ligne {line_number}") from exc
            if not isinstance(value, dict):
                raise TypeError(f"échantillon non objet à la ligne {line_number}")
            value["dossier"] = canonical_dossier(value.get("dossier"))
            samples.append(value)
    return samples


def _truth(label: object) -> str:
    if label == "legitimate":
        return "legitimate"
    if label in {"spam", "dangerous", "suspect"}:
        return "spam"
    return "ambiguous"


def _outcome(decision: object) -> str:
    if decision == "deliver":
        return DELIVER
    if decision == "junk":
        return JUNK
    return ASK


def _usage(metadata: dict[str, Any]) -> tuple[int, int]:
    usage = metadata.get("usage") if isinstance(metadata.get("usage"), dict) else {}
    prompt = usage.get("prompt_tokens", usage.get("prompt_eval_count", 0))
    completion = usage.get("completion_tokens", usage.get("eval_count", 0))
    try:
        return int(prompt or 0), int(completion or 0)
    except (TypeError, ValueError):
        return 0, 0


async def evaluate_sample(
    sample: dict[str, Any], call: CandidateCall
) -> dict[str, Any]:
    started = time.perf_counter()
    truth = _truth(sample.get("human_label"))
    dossier = canonical_dossier(sample["dossier"])
    try:
        content, metadata = await call(_prompt(dossier))
        result = _parse_verdict(content, dossier)
        valid = True
        error = None
    except Exception as exc:  # noqa: BLE001 - une sortie invalide est une mesure
        metadata = {}
        result = {
            "classification": "undetermined",
            "delivery_decision": "ask_user",
            "confidence": 0.0,
            "verdict_doubt": True,
        }
        valid = False
        error = f"{type(exc).__name__}: {str(exc)[:300]}"
    prompt_tokens, completion_tokens = _usage(metadata)
    target = safe_teacher_target(result)
    teacher = sample.get("teacher_target")
    teacher = teacher if isinstance(teacher, dict) else None
    teacher_agreement = bool(
        valid
        and teacher
        and target.get("classification") == teacher.get("classification")
        and target.get("delivery_decision") == teacher.get("delivery_decision")
    )
    unsafe_teacher_divergence = bool(
        valid
        and teacher
        and target.get("delivery_decision") == "deliver"
        and teacher.get("delivery_decision") != "deliver"
    )
    return {
        "sample_id": sample.get("sample_id"),
        "dossier_sha256": sample.get("dossier_sha256"),
        "split_group_hash": sample.get("split_group_hash"),
        "truth": truth,
        "label_authority": sample.get("label_authority"),
        "valid": valid,
        "error": error,
        "candidate": target,
        "teacher_available": teacher is not None,
        "teacher_agreement": teacher_agreement,
        "unsafe_teacher_divergence": unsafe_teacher_divergence,
        "outcome": _outcome(target.get("delivery_decision")),
        "latency_ms": round((time.perf_counter() - started) * 1000, 3),
        "prompt_tokens": prompt_tokens,
        "completion_tokens": completion_tokens,
        "model_reported": metadata.get("model"),
        "finish_reason": metadata.get("finish_reason"),
    }


def _percentile(values: list[float], proportion: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, round((len(ordered) - 1) * proportion)))
    return round(ordered[index], 3)


def summarize(
    results: list[dict[str, Any]],
    *,
    dataset_manifest: dict[str, Any],
    model: str,
    provider: str,
    input_price_per_million: float = 0.0,
    output_price_per_million: float = 0.0,
) -> dict[str, Any]:
    rows = [{"outcome": row["outcome"], "truth": row["truth"]} for row in results]
    rates = trec_rates(rows)
    prompt_tokens = sum(int(row["prompt_tokens"]) for row in results)
    completion_tokens = sum(int(row["completion_tokens"]) for row in results)
    valid = sum(1 for row in results if row["valid"])
    unsafe = sum(
        1
        for row in results
        if row["valid"] and row["truth"] == "spam" and row["outcome"] == DELIVER
    )
    false_non_delivery = sum(
        1
        for row in results
        if row["truth"] == "legitimate" and row["outcome"] != DELIVER
    )
    teacher_samples = sum(1 for row in results if row.get("teacher_available"))
    teacher_agreements = sum(1 for row in results if row.get("teacher_agreement"))
    unsafe_teacher = sum(1 for row in results if row.get("unsafe_teacher_divergence"))
    authorities: dict[str, int] = {}
    for row in results:
        authority = str(row.get("label_authority") or "missing")
        authorities[authority] = authorities.get(authority, 0) + 1
    expert_rows = [row for row in results if row.get("label_authority") == "expert"]
    expert_unsafe = sum(
        1
        for row in expert_rows
        if row["valid"] and row["truth"] == "spam" and row["outcome"] == DELIVER
    )
    latencies = [float(row["latency_ms"]) for row in results]
    return {
        "dataset_id": dataset_manifest.get("dataset_id"),
        "dataset_schema": dataset_manifest.get("schema_version"),
        "candidate": {"provider": provider, "model": model},
        "samples": len(results),
        "valid": valid,
        "valid_rate": valid / len(results) if results else None,
        "unsafe_deliveries": unsafe,
        "false_non_delivery": false_non_delivery,
        "label_authorities": authorities,
        "teacher_comparison": {
            "samples": teacher_samples,
            "agreements": teacher_agreements,
            "agreement_rate": (
                teacher_agreements / teacher_samples if teacher_samples else None
            ),
            "unsafe_delivery_divergences": unsafe_teacher,
        },
        "coverage": labelling_coverage(rows),
        "matrix": confusion_matrix(rows),
        "hold_precision": hold_precision(rows),
        "generalized_risk": generalized_risk(rows, sampled_delivered=True),
        "trec_rates": rates,
        "lam_optimistic": lam_percent(rates["hm_optimistic"], rates["sm_optimistic"]),
        "lam_pessimistic": lam_percent(
            rates["hm_pessimistic"], rates["sm_pessimistic"]
        ),
        "utility": utility_score(rows),
        "latency_ms": {
            "p50": _percentile(latencies, 0.50),
            "p95": _percentile(latencies, 0.95),
            "total": round(sum(latencies), 3),
        },
        "tokens": {"input": prompt_tokens, "output": completion_tokens},
        "estimated_cost": (
            prompt_tokens * input_price_per_million / 1_000_000
            + completion_tokens * output_price_per_million / 1_000_000
        ),
        "prices_per_million": {
            "input": input_price_per_million,
            "output": output_price_per_million,
        },
        "operational_gate": {
            "passed": bool(results) and valid == len(results) and unsafe == 0,
            "requires": "100% de sorties valides et aucune livraison indésirable",
        },
        "security_gate": {
            "eligible": bool(expert_rows),
            "passed": bool(expert_rows)
            and all(row["valid"] for row in expert_rows)
            and expert_unsafe == 0,
            "expert_samples": len(expert_rows),
            "unsafe_deliveries": expert_unsafe,
            "requires": "des annotations expertisées, valides et sans livraison dangereuse",
        },
    }


def _write_json(path: Path, value: object) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True, default=str)
        + "\n",
        encoding="utf-8",
    )
    temporary.replace(path)


def _write_jsonl(path: Path, values: list[dict[str, Any]]) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        "".join(
            json.dumps(value, ensure_ascii=False, sort_keys=True, default=str) + "\n"
            for value in values
        ),
        encoding="utf-8",
    )
    temporary.replace(path)


async def run(
    samples: list[dict[str, Any]],
    call: CandidateCall,
    *,
    dataset_manifest: dict[str, Any],
    model: str,
    provider: str,
    input_price_per_million: float = 0.0,
    output_price_per_million: float = 0.0,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    results = [await evaluate_sample(sample, call) for sample in samples]
    return results, summarize(
        results,
        dataset_manifest=dataset_manifest,
        model=model,
        provider=provider,
        input_price_per_million=input_price_per_million,
        output_price_per_million=output_price_per_million,
    )


async def _main() -> None:
    parser = argparse.ArgumentParser(
        prog="python -m sentimail_v3.supervision.benchmark",
        description="Évalue hors ligne un modèle sur un corpus SentiMail figé.",
    )
    parser.add_argument("dataset", help="répertoire contenant manifest.json")
    parser.add_argument("output", help="répertoire de résultats")
    parser.add_argument("--split", choices=("train", "valid", "test"), default="test")
    parser.add_argument(
        "--provider", choices=("ollama", "openai_compatible"), required=True
    )
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--model", required=True)
    parser.add_argument("--api-key-file")
    parser.add_argument("--token-limit-param", default="max_tokens")
    parser.add_argument("--max-tokens", type=int, default=2400)
    parser.add_argument("--max-samples", type=int)
    parser.add_argument("--input-price-per-million", type=float, default=0.0)
    parser.add_argument("--output-price-per-million", type=float, default=0.0)
    parser.add_argument("--force", action="store_true")
    arguments = parser.parse_args()

    dataset = Path(arguments.dataset)
    manifest = json.loads((dataset / "manifest.json").read_text(encoding="utf-8"))
    if manifest.get("personal_data") != "absent by construction":
        parser.error("le manifeste ne garantit pas un corpus désensibilisé")
    samples = read_jsonl(dataset / f"{arguments.split}.jsonl")
    if arguments.max_samples is not None:
        samples = samples[: max(0, arguments.max_samples)]

    output = Path(arguments.output)
    output.mkdir(parents=True, exist_ok=True)
    known = (output / "results.jsonl", output / "summary.json")
    if not arguments.force and any(path.exists() for path in known):
        parser.error(
            "résultat déjà présent : utiliser --force ou un nouveau répertoire"
        )

    api_key = ""
    if arguments.api_key_file:
        api_key = Path(arguments.api_key_file).read_text(encoding="utf-8").strip()
    client = httpx.AsyncClient(timeout=300.0)

    async def call(messages: list[dict[str, str]]) -> tuple[str, dict[str, Any]]:
        if arguments.provider == "ollama":
            return await local_chat_json(
                client,
                base_url=arguments.base_url,
                model=arguments.model,
                messages=messages,
                max_tokens=arguments.max_tokens,
            )
        route = ProviderRoute(
            "openai_compatible",
            arguments.base_url,
            arguments.model,
            api_key,
            arguments.token_limit_param,
            {},
        )
        content, metadata = await openai_compatible_chat_json(
            client,
            route=route,
            messages=messages,
            max_tokens=arguments.max_tokens,
        )
        metadata["provider"] = "openai_compatible"
        return content, metadata

    try:
        results, summary = await run(
            samples,
            call,
            dataset_manifest=manifest,
            model=arguments.model,
            provider=arguments.provider,
            input_price_per_million=arguments.input_price_per_million,
            output_price_per_million=arguments.output_price_per_million,
        )
    finally:
        await client.aclose()

    _write_jsonl(output / "results.jsonl", results)
    _write_json(output / "summary.json", summary)
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))


if __name__ == "__main__":
    asyncio.run(_main())
