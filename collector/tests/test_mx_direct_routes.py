"""Les routes opérateur ne doivent jamais ouvrir un relais SMTP arbitraire."""
from pathlib import Path
import os
import subprocess
import pytest

SCRIPT = Path(__file__).resolve().parents[2] / 'infra/postfix/direct-routes.sh'


def run_routes(tmp_path, text):
    source = tmp_path / 'source'
    output = tmp_path / 'output'
    commands = tmp_path / 'bin'
    for directory in (source, output, commands):
        directory.mkdir()
    (source / 'routes').write_text(text)
    (source / 'recipient_access').write_text('no-reply@example.org 550 Envoi seulement\n')
    postmap = commands / 'postmap'
    postmap.write_text('#!/bin/sh\ncp "$1" "$1.db"\n')
    postmap.chmod(0o755)
    result = subprocess.run(['bash', str(SCRIPT), str(source), str(output)],
                            capture_output=True, text=True,
                            env={**os.environ, 'PATH': str(commands) + ':' + os.environ['PATH']})
    return result, output


@pytest.mark.parametrize('key', ['example.org', 'bob@example.org'])
def test_route_exacte_et_refus_recipient(tmp_path, key):
    # Le MX autorise aussi les routes par destinataire exact depuis le 29 septembre.
    route = key + ' smtp:[192.0.2.1]:25'
    result, output = run_routes(tmp_path, '# commentaire\n' + route + '\n')
    assert result.returncode == 0, result.stderr
    assert route in (output / 'direct_routes.db').read_text()
    assert '550' in (output / 'direct_recipient_access.db').read_text()


def test_routes_vides_ne_changent_pas_les_domaines_proteges(tmp_path):
    result, output = run_routes(tmp_path, '# aucun domaine direct\n')
    assert result.returncode == 0
    assert (output / 'direct_routes.db').read_text().startswith('#')


@pytest.mark.parametrize('route', [
    '* smtp:[192.0.2.1]:25',
    '.example.org smtp:[192.0.2.1]:25',
    'example.org smtp:192.0.2.1',
    'example.org smtp:[192.0.2.1]:25 trailing',
    'ex..ample.org smtp:[192.0.2.1]:25',
])
def test_route_invalide_refusee_avant_modification(tmp_path, route):
    result, output = run_routes(tmp_path, route + '\n')
    assert result.returncode != 0
    assert not list(output.iterdir())
