from domain_name import normalize_hostname, registrable_domain


def test_psl_separates_unrelated_multilevel_registry_domains() -> None:
    assert registrable_domain("click.victim.co.uk") == "victim.co.uk"
    assert registrable_domain("login.evil.co.uk") == "evil.co.uk"
    assert registrable_domain("mx.example.com.au") == "example.com.au"


def test_private_psl_separates_unrelated_github_pages_tenants() -> None:
    assert registrable_domain("assets.victim.github.io") == "victim.github.io"
    assert registrable_domain("login.evil.github.io") == "evil.github.io"


def test_psl_boundary_normalizes_idna_before_extraction() -> None:
    assert normalize_hostname("BÜCHER.DE.") == "xn--bcher-kva.de"
    assert registrable_domain("WWW.BÜCHER.DE.") == "xn--bcher-kva.de"


def test_fetch_result_uses_psl_boundary_for_cloaking() -> None:
    from server import FetchResult

    result = FetchResult(
        initial_url="https://click.victim.co.uk/",
        initial_host="click.victim.co.uk",
        final_host="login.evil.co.uk",
    ).as_dict()
    assert result["initial_apex"] == "victim.co.uk"
    assert result["final_apex"] == "evil.co.uk"
    assert result["cloaking"] is True


def test_fetch_result_treats_private_suffix_tenants_as_distinct() -> None:
    from server import FetchResult

    result = FetchResult(
        initial_url="https://victim.github.io/",
        initial_host="victim.github.io",
        final_host="evil.github.io",
    ).as_dict()
    assert result["initial_apex"] == "victim.github.io"
    assert result["final_apex"] == "evil.github.io"
    assert result["cloaking"] is True
