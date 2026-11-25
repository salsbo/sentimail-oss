"""L'ancienneté réelle de la file prime sur le passage d'un nouveau message."""

from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

spec = importlib.util.spec_from_file_location("mx_health", Path(__file__).resolve().parents[1]/"health.py")
health = importlib.util.module_from_spec(spec)
spec.loader.exec_module(health)
NOW = 2_000_000_000


def queue(*ages):
    return b"\n".join(json.dumps({
        "queue_name": "deferred", "arrival_time": NOW-age,
        "sender": "private-sender@example.invalid",
        "recipients": [{"address": "private-recipient@example.invalid", "delay_reason": "capture failure"}],
    }).encode() for age in ages)


def test_file_vide_est_saine():
    result = health.queue_snapshot(b"", now=NOW)
    assert result["status"] == "ok"
    assert result["queue_messages"] == 0
    assert result["blocked_messages"] == 0


def test_un_ancien_message_bloque_meme_avec_des_messages_recents():
    result = health.queue_snapshot(queue(601, 30, 599, 600), now=NOW)
    assert result["status"] == "blocked"
    assert result["queue_messages"] == 4
    assert result["blocked_messages"] == 1
    assert result["oldest_age_seconds"] == 601
    assert result["threshold_seconds"] == 600
    assert "private-" not in json.dumps(result)


def test_arrivee_future_ne_devient_pas_une_alerte_ancienne():
    result = health.queue_snapshot(queue(-60), now=NOW)
    assert result["status"] == "ok"
    assert result["oldest_age_seconds"] == 0
    assert result["future_timestamps"] == 1


@pytest.mark.parametrize("data", [
    b"{broken", b"[]", b"null", b'{}', b'{"arrival_time":true}',
    b'{"arrival_time":"yesterday"}', b'{"arrival_time":NaN}',
    b'{"arrival_time":-1}',
])
def test_listing_inexploitable_ne_prouve_pas_que_la_file_est_vide(data):
    with pytest.raises(health.ProbeFailure):
        health.queue_snapshot(data, now=NOW)


def test_le_nombre_de_messages_est_borne():
    with pytest.raises(health.ProbeFailure, match="queue_message_limit"):
        health.queue_snapshot(queue(30, 60), now=NOW, max_messages=1)


def postqueue_program(monkeypatch, tmp_path, code):
    executable = tmp_path/"postqueue"
    executable.write_text("#!"+sys.executable+"\n"+code)
    executable.chmod(0o700)
    monkeypatch.setenv("PATH", str(tmp_path)+os.pathsep+os.environ.get("PATH", ""))


def test_lecture_de_la_vraie_commande_json(monkeypatch, tmp_path):
    data = queue(20, 700)
    postqueue_program(monkeypatch, tmp_path, f"import sys\nassert sys.argv[1:]==['-j']\nsys.stdout.buffer.write({data!r})\n")
    result = health.queue_snapshot(health.read_queue(), now=NOW)
    assert result["blocked_messages"] == 1


def test_code_echec_postqueue_ne_laisse_pas_passer_un_listing_partiel(monkeypatch, tmp_path):
    postqueue_program(monkeypatch, tmp_path, "import sys\nprint('{}')\nsys.exit(3)\n")
    with pytest.raises(health.ProbeFailure, match="postqueue_failed"):
        health.read_queue()


def test_sortie_bornee_avant_de_lire_tout_le_flux(monkeypatch, tmp_path):
    postqueue_program(monkeypatch, tmp_path, "import sys,time\nsys.stdout.write('x'*1000000)\nsys.stdout.flush()\ntime.sleep(60)\n")
    with pytest.raises(health.ProbeFailure, match="queue_output_limit"):
        health.read_queue(max_bytes=20)


def test_commande_suspendue_est_tuee_a_expiration(monkeypatch, tmp_path):
    marker = tmp_path/"pid"
    postqueue_program(monkeypatch, tmp_path, f"import os,time\nopen({str(marker)!r},'w').write(str(os.getpid()))\ntime.sleep(60)\n")
    with pytest.raises(health.ProbeFailure, match="postqueue_timeout"):
        health.read_queue(timeout_seconds=1.0)
    with pytest.raises(ProcessLookupError):
        os.kill(int(marker.read_text()), 0)


def test_postfix_arrete_reste_un_echec_et_n_interroge_pas_la_file(monkeypatch, capsys):
    status = Mock(return_value=SimpleNamespace(returncode=1))
    listing = Mock(side_effect=AssertionError("ne pas lire une file sans maître"))
    monkeypatch.setattr(health.subprocess, "run", status)
    monkeypatch.setattr(health, "read_queue", listing)
    assert health.main() == 1
    result = json.loads(capsys.readouterr().out)
    assert result == {"status": "error", "reason": "postfix_not_running"}
    assert status.call_args.args[0] == ["postfix", "status"]
    listing.assert_not_called()


def test_timeout_status_postfix_ne_divulgue_pas_sortie_de_commande(monkeypatch, capsys):
    def timeout(*_args, **_kwargs):
        raise subprocess.TimeoutExpired("private-sender@example.invalid", 1)
    monkeypatch.setattr(health.subprocess, "run", timeout)
    assert health.main() == 1
    output = capsys.readouterr().out
    assert json.loads(output)["reason"] == "postfix_status_unavailable"
    assert "private-" not in output


def test_sortie_json_sans_adresses_et_code_retour_bloque(monkeypatch, capsys):
    monkeypatch.setattr(health.subprocess, "run", lambda *_a, **_k: SimpleNamespace(returncode=0))
    monkeypatch.setattr(health, "read_queue", lambda: queue(700))
    monkeypatch.setattr(health.time, "time", lambda: NOW)
    assert health.main() == 1
    output = capsys.readouterr().out
    assert json.loads(output)["reason"] == "inbound_queue_stalled"
    assert "private-" not in output


# Le 3 novembre 2026, un accusé de « livraison réussie » rédigé par le MX pour
# un faux « Interactive Brokers » est resté 5 jours en file : le serveur du
# fraudeur ne répondait pas. Le contrôle l'a pris pour un courrier entrant
# bloqué, et l'inventaire du serveur est resté rouge.
def notice(age, recipient="fraudeur@expediteur.invalid", sender="MAILER-DAEMON"):
    return json.dumps({
        "queue_name": "deferred", "arrival_time": NOW-age, "sender": sender,
        "recipients": [{"address": recipient, "delay_reason": "connect timed out"}],
    }).encode()


PROTEGES = {"protege.example"}


def relais(domain):
    return domain in PROTEGES


def test_une_notification_sortante_ne_bloque_pas_mais_reste_visible():
    result = health.queue_snapshot(notice(34_870), now=NOW, is_relay_domain=relais)
    assert result["status"] == "ok"
    assert result["reason"] == "outbound_notices_deferred"
    assert result["blocked_messages"] == 0
    assert result["outbound_notices_deferred"] == 1
    assert result["oldest_outbound_notice_age_seconds"] == 34_870


def test_un_rebond_entrant_vers_un_domaine_protege_reste_un_blocage():
    # Un rebond venu d'Internet pour un client a lui aussi un expéditeur vide.
    data = notice(700, recipient="client@protege.example")
    result = health.queue_snapshot(data, now=NOW, is_relay_domain=relais)
    assert result["reason"] == "inbound_queue_stalled"
    assert result["blocked_messages"] == 1


def test_un_expediteur_ordinaire_vers_l_exterieur_reste_un_blocage():
    # Le MX ne relaie rien vers l'extérieur : un tel message est une anomalie.
    data = notice(700, sender="quelqu-un@ailleurs.invalid")
    result = health.queue_snapshot(data, now=NOW, is_relay_domain=relais)
    assert result["reason"] == "inbound_queue_stalled"


def test_un_domaine_impossible_a_verifier_reste_un_blocage():
    result = health.queue_snapshot(notice(700), now=NOW, is_relay_domain=lambda _d: None)
    assert result["reason"] == "inbound_queue_stalled"


def test_sans_moyen_de_verifier_tout_compte_comme_entrant():
    result = health.queue_snapshot(notice(700), now=NOW)
    assert result["reason"] == "inbound_queue_stalled"


def test_un_destinataire_protege_parmi_d_autres_reste_un_blocage():
    data = json.dumps({
        "queue_name": "deferred", "arrival_time": NOW-700, "sender": "",
        "recipients": [{"address": "x@expediteur.invalid"}, {"address": "client@protege.example"}],
    }).encode()
    result = health.queue_snapshot(data, now=NOW, is_relay_domain=relais)
    assert result["reason"] == "inbound_queue_stalled"


def test_une_notification_recente_n_est_pas_comptee():
    result = health.queue_snapshot(notice(30), now=NOW, is_relay_domain=relais)
    assert result["reason"] == "queue_within_deadline"
    assert result["outbound_notices_deferred"] == 0


def postfix_programs(monkeypatch, tmp_path, *, relay_domains, found, postmap_code=None):
    postconf = tmp_path/"postconf"
    postconf.write_text("#!"+sys.executable+f"\nimport sys\nassert sys.argv[1:]==['-h','relay_domains']\nprint({relay_domains!r})\n")
    postmap = tmp_path/"postmap"
    code = postmap_code or (
        "import sys\nassert sys.argv[1]=='-q'\n"
        f"sys.exit(0 if (sys.argv[2], sys.argv[3]) in {found!r} else 1)\n"
    )
    postmap.write_text("#!"+sys.executable+"\n"+code)
    for program in (postconf, postmap):
        program.chmod(0o700)
    monkeypatch.setenv("PATH", str(tmp_path)+os.pathsep+os.environ.get("PATH", ""))


def test_les_tables_de_relais_de_postfix_sont_interrogees(monkeypatch, tmp_path):
    postfix_programs(
        monkeypatch, tmp_path,
        relay_domains="hash:/etc/postfix/direct_routes, pgsql:/etc/postfix/relay_domains.cf",
        found={("protege.example", "pgsql:/etc/postfix/relay_domains.cf")},
    )
    lookup = health.relay_domain_lookup()
    assert lookup("protege.example") is True
    assert lookup("expediteur.invalid") is False


def test_une_table_en_erreur_rend_le_domaine_inconnu(monkeypatch, tmp_path):
    postfix_programs(
        monkeypatch, tmp_path, relay_domains="pgsql:/etc/postfix/relay_domains.cf",
        found=set(), postmap_code="import sys\nsys.exit(75)\n",
    )
    assert health.relay_domain_lookup()("expediteur.invalid") is None


def test_un_domaine_ecrit_en_clair_dans_relay_domains_est_reconnu(monkeypatch, tmp_path):
    postfix_programs(monkeypatch, tmp_path, relay_domains="protege.example", found=set())
    lookup = health.relay_domain_lookup()
    assert lookup("PROTEGE.example") is True
    assert lookup("expediteur.invalid") is False


def test_la_sortie_reste_sans_adresse_avec_une_notification(monkeypatch, capsys):
    monkeypatch.setattr(health.subprocess, "run", lambda *_a, **_k: SimpleNamespace(returncode=0))
    monkeypatch.setattr(health, "read_queue", lambda: notice(700))
    monkeypatch.setattr(health, "relay_domain_lookup", lambda: relais)
    monkeypatch.setattr(health.time, "time", lambda: NOW)
    assert health.main() == 0
    output = capsys.readouterr().out
    assert json.loads(output)["reason"] == "outbound_notices_deferred"
    assert "fraudeur" not in output and "expediteur" not in output


def test_le_budget_de_verification_epuise_rend_le_domaine_inconnu(monkeypatch, tmp_path):
    # Une table lente ne doit pas faire dépasser les 5 s du healthcheck.
    postfix_programs(
        monkeypatch, tmp_path, relay_domains="pgsql:/etc/postfix/relay_domains.cf",
        found=set(), postmap_code="import time\ntime.sleep(5)\n",
    )
    lookup = health.relay_domain_lookup(budget_seconds=0.5)
    started = health.time.monotonic()
    assert lookup("expediteur.invalid") is None
    assert lookup("autre.invalid") is None
    assert health.time.monotonic()-started < 2.0


def test_l_expediteur_vide_ecrit_vide_est_aussi_reconnu():
    # postqueue -j écrit « MAILER-DAEMON » ; une chaîne vide reste comprise.
    result = health.queue_snapshot(notice(700, sender=""), now=NOW, is_relay_domain=relais)
    assert result["reason"] == "outbound_notices_deferred"


def test_un_mailer_daemon_qualifie_n_est_pas_un_expediteur_vide():
    data = notice(700, sender="MAILER-DAEMON@ailleurs.invalid")
    result = health.queue_snapshot(data, now=NOW, is_relay_domain=relais)
    assert result["reason"] == "inbound_queue_stalled"
