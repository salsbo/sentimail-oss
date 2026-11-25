"""Une contradiction positive ne se confond ni avec un détour ni avec un manque."""

import json
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest

from sentimail_v3.code.action_destination import EXPLANATION_MAX, LABEL_MAX, QUOTE_MAX, conclusion, destinations, observe_destinations, observed_url
from sentimail_v3.code.correlation import correlations
from sentimail_v3.code.sender_relation import published_activity
from sentimail_v3.judgment.verdict_engine import JudgmentContradiction, _judgment_rules, _validate_final_judgment, waiting_judgment
from sentimail_v3.observation.deep_hooks import SenderActivityHook, SenderRelationHook, run_deep_hooks


def analysis(**changes):
    return {
        "role": "html_link", "link_context": "primary", "visible_text": "View my options",
        "redirect_chain": [{"url": "https://tracking.example/click?token=private"}, {"url": "https://video.example/watch?v=clip"}],
        "final_status": 200, "body_excerpt": "Video player: a music video", **changes,
    }


def contradiction(**changes):
    return {
        "status": "contradictory", "link_id": 0,
        "promise_quote": "Choose a new delivery date", "destination_quote": "Video player: a music video",
        "expected_operation": "reprogrammer un colis", "observed_function": "regarder une vidéo musicale",
        "explanation": "Le bouton de reprogrammation aboutit à une vidéo musicale.", **changes,
    }


def test_contradiction_exige_deux_faits_observes():
    links = destinations([analysis()])
    clue, _ = conclusion(contradiction(), message="Choose a new delivery date", links=links)
    assert clue["direction"] == "adverse"
    for false_claim in [{"promise_quote": "Pay customs charges"}, {"destination_quote": "Steal credit card"}, {"link_id": 9}]:
        clue, _ = conclusion(contradiction(**false_claim), message="Choose a new delivery date", links=links)
        assert clue["direction"] == "neutral"
        assert clue["clue_code"] == "URL_ACTION_DESTINATION_UNVERIFIED"


@pytest.mark.parametrize("changes", [{"analysis_incomplete": True}, {"error": "timeout"}, {"final_status": 403}, {"analysis_skipped": True}])
def test_inspection_non_concluante_n_accuse_pas(changes):
    clue, _ = conclusion(contradiction(), message="Choose a new delivery date", links=destinations([analysis(**changes)]))
    assert clue["direction"] == "neutral"


def test_images_et_liens_secondaires_ne_contredisent_pas_l_operation():
    # Les contextes que le parseur HTML écrit réellement : jusqu'au
    # 15 octobre 2026, la liste d'exclusion portait des noms jamais émis, et
    # 56 contrôles sur 178 ont reçu des liens de pied de page ou de réseaux.
    assert destinations([
        analysis(role="render_resource"),
        analysis(link_context="footer"),
        analysis(link_context="secondary_navigation"),
    ]) == []


# M-e36c20, 15 octobre 2026 : un courrier de gestionnaire RH demande de
# s'affilier à une mutuelle sans donner de lien. Les seuls liens sont ceux de
# la signature : une URL nue et une adresse affichée vers l'accueil du site
# de l'employeur, une icône vers un réseau social. Le juge a confronté la
# demande à la signature et a conclu à une contradiction.
SIGNATURE = [
    analysis(role="plain_text", visible_text="", redirect_chain=[
        {"url": "https://signature.example/r/abc"}, {"url": "https://www.employeur.example/"},
    ], body_excerpt="Employeur : portage salarial, simulation, notre offre"),
    analysis(visible_text="https://www.employeur.example/", redirect_chain=[
        {"url": "https://www.employeur.example/"},
    ], body_excerpt="Employeur : portage salarial, simulation, notre offre"),
    analysis(visible_text="", redirect_chain=[
        {"url": "https://signature.example/r/def"}, {"url": "https://social.example/login?next=company"},
    ], body_excerpt="Connexion au réseau social, identifiez-vous"),
]
DEMANDE_SANS_LIEN = (
    "Adhésion mutuelle\nBonjour, je vous laisse vous affilier OU vous dispenser "
    "si vous ne souhaitez pas en bénéficier. Bien à vous, Eva"
)


@pytest.mark.parametrize("link_id", [0, 1])
def test_un_lien_sans_libelle_vers_l_accueil_d_un_site_ne_porte_aucune_promesse(link_id):
    # Un logo ou une signature : aucun libellé propre, et l'accueil d'un site.
    links = destinations(SIGNATURE)
    clue, facts = conclusion(contradiction(
        link_id=link_id,
        promise_quote="vous affilier OU vous dispenser",
        destination_quote="Employeur : portage salarial",
    ), message=DEMANDE_SANS_LIEN, links=links)
    assert clue["direction"] == "neutral"
    assert facts["status"] == "unverified"
    assert facts["contradiction_refused"] == "unlabeled_site_home"


# Revue de sécurité du 15 octobre 2026 : écarter tout lien sans libellé
# laissait passer le formulaire, le bouton-image sans texte alternatif et
# l'URL seule sur sa ligne, trois formes que l'expéditeur choisit.
@pytest.mark.parametrize("changes", [
    {"visible_text": ""},
    {"role": "plain_text", "visible_text": ""},
    {"role": "html_form", "visible_text": "", "redirect_chain": [{"url": "https://video.example/"}]},
])
def test_un_bouton_sans_libelle_vers_une_page_precise_reste_confronte(changes):
    links = destinations([analysis(**changes)])
    clue, facts = conclusion(contradiction(), message="Choose a new delivery date", links=links)
    assert clue["clue_code"] == "URL_ACTION_DESTINATION_MISMATCH"
    assert "contradiction_refused" not in facts


def test_un_leurre_a_la_racine_de_son_domaine_reste_une_contradiction():
    # Revue de sécurité du 15 octobre 2026 : refuser toute page d'accueil
    # laissait l'usurpateur héberger son leurre à la racine de son propre
    # domaine. Seul le libellé propre départage la signature du bouton.
    links = destinations([analysis(redirect_chain=[
        {"url": "https://tracking.example/click?token=private"}, {"url": "https://video.example/?utm_source=mail"},
    ])])
    clue, facts = conclusion(contradiction(), message="Choose a new delivery date", links=links)
    assert clue["clue_code"] == "URL_ACTION_DESTINATION_MISMATCH"
    assert "contradiction_refused" not in facts


@pytest.mark.parametrize("role", ["plain_text", "html_link", "html_form"])
def test_les_roles_reellement_emis_par_le_bac_a_sable_sont_confrontes(role):
    assert len(destinations([analysis(role=role)])) == 1


@pytest.mark.parametrize("excerpt", ["Verification Required Please verify you are human Slide to verify", "Verification Human Verification Continue Security Check", "Loading... Privacy & Terms"])
def test_un_sas_ou_un_chargeur_ne_prouve_pas_une_fonction_incompatible(excerpt):
    links = destinations([analysis(body_excerpt=excerpt)])
    clue, _ = conclusion(contradiction(destination_quote=excerpt), message="Choose a new delivery date", links=links)
    assert clue["direction"] == "neutral"


def test_la_recherche_ne_prete_pas_l_activite_d_un_homonyme():
    assert published_activity(None, [{"url": "https://other.example", "content": "Albert operates supermarkets in Europe."}], from_apex="albertovo.store") == ("", "")
    text, source = published_activity(None, [{"url": "https://shop.example/about", "content": "A small shop selling handmade clothing and accessories."}], from_apex="shop.example")
    assert source == "search" and "handmade" in text


def test_les_jetons_de_navigation_ne_partent_pas_au_modele():
    value = observed_url("https://tracking.example/click?token=private&recipient=alice@example.org")
    assert "private" not in value and "alice" not in value and "token" in value


@pytest.mark.parametrize("unknown", ["SENDER_WITHOUT_PUBLIC_FOOTPRINT", "SENDER_RELATION_UNVERIFIED"])
def test_identite_non_etablie_et_contradiction_imposent_avis_meme_authentifie(unknown):
    base = {unknown, "URL_ACTION_DESTINATION_MISMATCH", "AUTH_DMARC_PASS"}
    clues = correlations(base)
    assert any(c["article_code"] == "CORR-019" for c in clues)
    dossier = {"message": {"investigation_status": "complete"}, "clues": clues, "code_articles": []}
    rules = _judgment_rules(dossier, {"complete": True, "attachments_complete": True}, SimpleNamespace(auto_delivery_confidence=0.9))
    dossier["judgment_rules"] = rules
    assert rules["identity_destination_conflict"]
    with pytest.raises(JudgmentContradiction) as raised:
        _validate_final_judgment({"classification": "legitimate", "delivery_decision": "deliver", "confidence": 1}, dossier)
    assert raised.value.structural
    waiting = waiting_judgment(raised.value)
    assert waiting["delivery_decision"] == "ask_user"
    assert "destination" in waiting["rationale"]
    for classification in ("spam", "dangerous"):
        _validate_final_judgment({"classification": classification, "delivery_decision": "junk", "confidence": 0.95}, dossier)
    _validate_final_judgment({"classification": "suspect", "delivery_decision": "ask_user", "confidence": 0.8}, dossier)


@pytest.mark.parametrize("codes", [{"SENDER_WITHOUT_PUBLIC_FOOTPRINT"}, {"SENDER_RELATION_UNVERIFIED"}, {"URL_ACTION_DESTINATION_MISMATCH"}, {"SENDER_WITHOUT_PUBLIC_FOOTPRINT", "URL_SANDBOX_CROSS_APEX"}])
def test_un_manque_ou_un_domaine_tiers_seul_ne_cree_pas_la_barriere(codes):
    assert not any(c["article_code"] == "CORR-019" for c in correlations(codes))


def test_une_preuve_materielle_independante_conserve_le_classement_en_indesirables():
    dossier = {"judgment_rules": {
        "verdict_is_final": True, "identity_destination_conflict": True,
        "confidence_required": 0.9, "deep_execution_complete": True,
        "static_investigation_complete": True,
        "material_danger_evidence": [{"article_code": "DEEP-024"}],
    }}
    _validate_final_judgment({"classification": "dangerous", "delivery_decision": "junk", "confidence": 1}, dossier)


class RuntimeTests(unittest.IsolatedAsyncioTestCase):
    async def test_le_metier_d_une_messagerie_publique_n_est_pas_celui_de_l_auteur(self):
        context = SimpleNamespace(sender_apex="gmail.com", sender_site={"text": "Google provides email and productivity software for personal use."})
        clues, facts = await SenderActivityHook().observe(context)
        assert clues[0]["clue_code"] == "SENDER_ACTIVITY_UNVERIFIED"
        assert facts["reason"] == "shared_infrastructure_not_sender_activity"

    async def test_une_panne_du_modele_reste_neutre_et_tracee(self):
        context = SimpleNamespace(pool=None, client=None, settings=None, subject="Parcel", body="Choose a new delivery date", url_analyses=[analysis() for _ in range(9)])
        with patch("sentimail_v3.code.action_destination.provider_chat_json", AsyncMock(side_effect=TimeoutError())) as call:
            clues, facts = await observe_destinations(context)
        assert clues[0]["direction"] == "neutral"
        assert facts["failure_types"] == ["TimeoutError"]
        assert facts["unreviewed_action_links"] == 1
        call.assert_awaited_once()

    async def test_le_plafond_contient_la_plus_longue_reponse_admise(self):
        # 9 novembre 2026 : une réponse coupée net à 600 jetons, le plafond,
        # n'était plus du JSON. Le superviseur est resté dégradé une heure.
        # À deux caractères par jeton, la plus longue réponse que `conclusion`
        # accepte doit tenir entière.
        context = SimpleNamespace(pool=None, client=None, settings=None, subject="Parcel", body="Choose a new delivery date", url_analyses=[analysis()])
        call = AsyncMock(return_value=(json.dumps({"status": "consistent"}), {}))
        with patch("sentimail_v3.code.action_destination.provider_chat_json", call):
            await observe_destinations(context)
        longest = json.dumps(contradiction(
            promise_quote="é" * QUOTE_MAX, destination_quote="é" * QUOTE_MAX,
            expected_operation="é" * LABEL_MAX, observed_function="é" * LABEL_MAX,
            explanation="é" * EXPLANATION_MAX,
        ), ensure_ascii=False)
        assert call.await_args.kwargs["max_tokens"] * 2 >= len(longest)

    async def test_les_liens_apres_le_premier_groupe_sont_aussi_confrontes(self):
        context = SimpleNamespace(pool=None, client=None, settings=None, subject="Parcel", body="Choose a new delivery date", url_analyses=[analysis() for _ in range(9)])
        call = AsyncMock(side_effect=[(json.dumps({"status": "consistent"}), {}), (json.dumps(contradiction(link_id=8)), {})])
        with patch("sentimail_v3.code.action_destination.provider_chat_json", call):
            clues, _ = await observe_destinations(context)
        assert call.await_count == 2
        assert clues[0]["clue_code"] == "URL_ACTION_DESTINATION_MISMATCH"


    async def test_la_concordance_du_nom_n_empeche_pas_l_examen_du_metier(self):
        context = SimpleNamespace(pool=None, client=None, settings=None, sender_apex="school.example", display_name="School", from_address="info@school.example", subject="Parcel delivery", body="School: choose a new parcel delivery date", sender_site={"text": "An English language school providing lessons for international students."}, clue_codes=set(), organisations={})
        adverse = {"clue_code": "SENDER_ACTIVITY_INCOHERENT", "article_code": "DEEP-019", "direction": "adverse", "strength": 55}
        with patch("sentimail_v3.observation.deep_analysis._claimed_organisation", AsyncMock(return_value=("School", {}))), patch("sentimail_v3.observation.deep_analysis._activity_coherence", AsyncMock(return_value=adverse)) as comparison:
            results = await run_deep_hooks([SenderRelationHook(), SenderActivityHook()], context)
        assert results[0].clues[0]["clue_code"] == "SENDER_RELATION_CONSISTENT"
        assert results[1].clues[0]["clue_code"] == "SENDER_ACTIVITY_INCOHERENT"
        comparison.assert_awaited_once()
