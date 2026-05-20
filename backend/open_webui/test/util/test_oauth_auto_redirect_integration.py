"""Integration tests for OAUTH_AUTO_REDIRECT through the real FastAPI app.

Each test boots ``open_webui.main`` in a subprocess (the env must be in place
*before* ``open_webui.config`` is imported — ``OAUTH_PROVIDERS`` is built at
import time) with one of four configurations:

  * ``sso_only`` — the canonical happy path: single OAuth provider,
    ``ENABLE_LOGIN_FORM=false``, ``ENABLE_LDAP=false``,
    ``OAUTH_AUTO_REDIRECT=true``.  The frontend will redirect.
  * ``blocked_by_login_form`` — same, but ``ENABLE_LOGIN_FORM=true``.  The
    backend honestly reports ``features.enable_login_form=true`` so the
    frontend's pure-function guard suppresses the redirect.
  * ``blocked_by_ldap`` — same, but ``ENABLE_LDAP=true``.
  * ``blocked_by_multiple_providers`` — adds a second OAuth provider (Google).
    ``oauth.providers`` carries both entries so the frontend's
    ``providers.length === 1`` guard suppresses the redirect.

Asserting on the backend payload is the contract — vitest covers the
frontend decision logic against equivalent config shapes; together they pin
both halves of the gate.
"""

import os
import subprocess
import sys


def _probe(scenario: str) -> None:
    """Runs in the subprocess: boot the app with ``scenario``'s env, assert."""
    import json
    import shutil
    import tempfile
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    issuer: dict = {}

    class _DiscoveryHandler(BaseHTTPRequestHandler):
        def log_message(self, *args):  # silence
            return

        def do_GET(self):
            if self.path == '/.well-known/openid-configuration':
                doc = json.dumps(
                    {
                        'issuer': issuer['url'],
                        'authorization_endpoint': f'{issuer["url"]}/authorize',
                        'token_endpoint': f'{issuer["url"]}/token',
                        'jwks_uri': f'{issuer["url"]}/jwks',
                        'userinfo_endpoint': f'{issuer["url"]}/userinfo',
                        'response_types_supported': ['code'],
                        'id_token_signing_alg_values_supported': ['RS256'],
                        'scopes_supported': ['openid', 'email', 'profile'],
                    }
                ).encode()
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(doc)))
                self.end_headers()
                self.wfile.write(doc)
            else:
                self.send_response(404)
                self.send_header('Content-Length', '0')
                self.end_headers()

    server = ThreadingHTTPServer(('127.0.0.1', 0), _DiscoveryHandler)
    issuer['url'] = f'http://127.0.0.1:{server.server_address[1]}'
    threading.Thread(target=server.serve_forever, daemon=True).start()

    data_dir = tempfile.mkdtemp(prefix='owui-oidc-it-')
    base_env = {
        'DATA_DIR': data_dir,
        'WEBUI_AUTH': 'true',
        'WEBUI_SECRET_KEY': 'integration-test-secret',
        'ENABLE_PERSISTENT_CONFIG': 'false',
        'OAUTH_AUTO_REDIRECT': 'true',
        # SSO-only baseline; each scenario flips exactly one thing.
        'ENABLE_LOGIN_FORM': 'false',
        'ENABLE_LDAP': 'false',
        'OAUTH_CLIENT_ID': 'integration-test',
        'OAUTH_CLIENT_SECRET': 'integration-secret',
        'OAUTH_PROVIDER_NAME': 'SSO',
        'OPENID_PROVIDER_URL': f'{issuer["url"]}/.well-known/openid-configuration',
        # Keep app boot offline / fast — irrelevant to the auth flow.
        'RAG_EMBEDDING_ENGINE': 'ollama',
        'HF_HUB_OFFLINE': '1',
    }
    overrides = {
        'sso_only': {},
        'blocked_by_login_form': {'ENABLE_LOGIN_FORM': 'true'},
        'blocked_by_ldap': {'ENABLE_LDAP': 'true'},
        'blocked_by_multiple_providers': {
            # A second configured provider — exposed under oauth.providers,
            # which is what the frontend's single-provider guard reads.
            'GOOGLE_CLIENT_ID': 'second-provider-id',
            'GOOGLE_CLIENT_SECRET': 'second-provider-secret',
        },
    }[scenario]
    os.environ.update({**base_env, **overrides})

    from fastapi.testclient import TestClient
    from open_webui.main import app

    try:
        with TestClient(app) as client:
            config = client.get('/api/config').json()
            oauth = config.get('oauth', {})
            features = config.get('features', {})
            providers = oauth.get('providers', {})

            # The feature flag itself is exposed in every scenario — that's
            # the contract the frontend reads.
            assert oauth.get('auto_redirect') is True, (
                f'/api/config oauth.auto_redirect: {oauth}'
            )
            # The OIDC provider is always configured in the base env.
            assert 'oidc' in providers, f'/api/config oauth.providers: {oauth}'

            if scenario == 'sso_only':
                # Every guard the frontend reads must report the SSO-only shape.
                assert features.get('enable_login_form') is False, (
                    f'/api/config features.enable_login_form: {features}'
                )
                assert features.get('enable_ldap') is False, (
                    f'/api/config features.enable_ldap: {features}'
                )
                assert len(providers) == 1, (
                    f'/api/config oauth.providers should be single: {providers}'
                )
                # And the configured SSO entry point actually works.
                resp = client.get('/oauth/oidc/login', follow_redirects=False)
                assert resp.status_code in (302, 307), (
                    f'/oauth/oidc/login status: {resp.status_code}'
                )
                location = resp.headers.get('location', '')
                assert location.startswith(f'{issuer["url"]}/authorize'), (
                    f'/oauth/oidc/login Location: {location}'
                )

            elif scenario == 'blocked_by_login_form':
                assert features.get('enable_login_form') is True, (
                    f'/api/config features.enable_login_form: {features}'
                )

            elif scenario == 'blocked_by_ldap':
                assert features.get('enable_ldap') is True, (
                    f'/api/config features.enable_ldap: {features}'
                )

            elif scenario == 'blocked_by_multiple_providers':
                assert len(providers) >= 2, (
                    f'/api/config oauth.providers should expose both: {providers}'
                )
                assert 'oidc' in providers and 'google' in providers, (
                    f'/api/config oauth.providers missing one: {providers}'
                )

            else:
                raise AssertionError(f'unknown scenario: {scenario}')
    finally:
        server.shutdown()
        shutil.rmtree(data_dir, ignore_errors=True)

    print(f'OAUTH_AUTO_REDIRECT integration probe ({scenario}): OK')


def _run_scenario(scenario: str) -> None:
    """Spawn the subprocess that runs ``_probe(scenario)``."""
    backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', '..'))
    env = {**os.environ, 'PYTHONPATH': backend_dir + os.pathsep + os.environ.get('PYTHONPATH', '')}
    result = subprocess.run(
        [sys.executable, os.path.abspath(__file__), scenario],
        check=False,
        capture_output=True,
        text=True,
        timeout=300,
        env=env,
    )
    assert result.returncode == 0, (
        f'integration probe ({scenario}) failed\n'
        f'STDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}'
    )
    assert f'integration probe ({scenario}): OK' in result.stdout


def test_oauth_auto_redirect_integration():
    """Happy path: SSO-only deployment exposes auto_redirect + the OIDC login redirects."""
    _run_scenario('sso_only')


def test_oauth_auto_redirect_blocked_by_login_form():
    """`ENABLE_LOGIN_FORM=true` makes the backend report the blocking signal."""
    _run_scenario('blocked_by_login_form')


def test_oauth_auto_redirect_blocked_by_ldap():
    """`ENABLE_LDAP=true` makes the backend report the blocking signal."""
    _run_scenario('blocked_by_ldap')


def test_oauth_auto_redirect_blocked_by_multiple_providers():
    """A second configured provider exposes both entries under `oauth.providers`."""
    _run_scenario('blocked_by_multiple_providers')


if __name__ == '__main__':
    _probe(sys.argv[1])
