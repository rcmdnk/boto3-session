from __future__ import annotations

import base64
import datetime as dt
import hashlib
import json
import logging
import secrets
import string
import time
import uuid
import webbrowser
from dataclasses import dataclass
from functools import partial
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable
from urllib.parse import parse_qs, quote, urlparse

import botocore
from botocore.config import Config
from botocore.exceptions import ProfileNotFound
from botocore.session import Session as BotocoreSession

if TYPE_CHECKING:
    import socket
    from socketserver import BaseServer

    from botocore.client import BaseClient
else:  # pragma: no cover - typing helper
    BaseClient = Any

LOG = logging.getLogger(__name__)

_CACHE_DIR = Path('~/.aws/sso/cache').expanduser()
_DEVICE_GRANT_TYPE = 'urn:ietf:params:oauth:grant-type:device_code'
_AUTH_GRANT_TYPES = ('authorization_code', 'refresh_token')
_AUTH_DEFAULT_SCOPE = 'sso:account:access'
_AUTH_TIMEOUT_SECONDS = 600


class SSOLoginError(RuntimeError):
    """Base exception for SSO login failures."""


@dataclass(frozen=True)
class SSOConfig:
    """Minimal subset of SSO configuration required to authenticate."""

    start_url: str
    region: str
    session_name: str | None
    registration_scopes: list[str]


class AuthCodeFetcherError(SSOLoginError):
    """Raised when the local callback server cannot be started."""


class AuthorizationTimeoutError(SSOLoginError):
    """Raised when the authorization window expires before completion."""


class AuthorizationStateMismatchError(SSOLoginError):
    """Raised when the returned OAuth state does not match the expectation."""


def login(
    profile_name: str | None = None,
    *,
    open_browser: bool = True,
    print_fn: Callable[[str], None] | None = None,
    timeout_seconds: int = _AUTH_TIMEOUT_SECONDS,
    use_device_code: bool = False,
) -> dict[str, str]:
    """Perform an IAM Identity Center (SSO) login using PKCE or device flow.

    Parameters
    ----------
    profile_name : str | None
        The AWS config profile to use when resolving SSO settings.
    open_browser : bool
        Attempt to open the authorization URL in the default browser.
    print_fn : Callable[[str], None] | None
        Optional callback used to communicate instructions to the user.
    timeout_seconds : int
        Overall timeout when waiting for the authorization callback.
    use_device_code : bool
        Force using the device authorization flow even if authorization code
        (PKCE) would normally be used.

    Returns
    -------
    dict[str, str]
        The cached token payload that was written to disk.

    Raises
    ------
    SSOLoginError
        If the login flow fails for any reason.

    """
    printer = print if print_fn is None else print_fn

    try:
        botocore_session = BotocoreSession(profile=profile_name)
    except ProfileNotFound as exc:
        message = f'Profile not found: {profile_name!r}'
        raise SSOLoginError(message) from exc

    config = _load_sso_config(botocore_session)
    LOG.debug(
        'Loaded SSO config: session=%s region=%s',
        config.session_name,
        config.region,
    )

    client = botocore_session.create_client(
        'sso-oidc',
        region_name=config.region,
        config=Config(signature_version=botocore.UNSIGNED),
    )

    if config.session_name and not use_device_code:
        token = _authorization_code_flow(
            client,
            config,
            open_browser=open_browser,
            printer=printer,
            timeout_seconds=timeout_seconds,
        )
    else:
        token = _device_code_flow(
            client,
            config,
            open_browser=open_browser,
            printer=printer,
        )

    _write_token_cache(token, config)
    return token


def _load_sso_config(session: BotocoreSession) -> SSOConfig:
    scoped_config = session.get_scoped_config()
    session_name = scoped_config.get('sso_session')

    if session_name:
        full_config = session.full_config
        session_block = full_config.get('sso_sessions', {}).get(session_name)
        if session_block is None:
            message = f'sso-session "{session_name}" is not defined in the config file.'
            raise SSOLoginError(message)
        start_url = session_block.get('sso_start_url')
        region = session_block.get('sso_region')
        raw_scopes = session_block.get('sso_registration_scopes')
    else:
        start_url = scoped_config.get('sso_start_url')
        region = scoped_config.get('sso_region')
        raw_scopes = scoped_config.get('sso_registration_scopes')

    missing: list[str] = []
    if not start_url:
        missing.append('sso_start_url')
    if not region:
        missing.append('sso_region')
    if missing:
        missing_message = ', '.join(missing)
        message = (
            f'Missing required SSO configuration values: {missing_message}'
        )
        raise SSOLoginError(message)

    scopes = _parse_scopes(raw_scopes)
    return SSOConfig(
        start_url=start_url,
        region=region,
        session_name=session_name,
        registration_scopes=scopes,
    )


def _parse_scopes(raw_scopes: str | None) -> list[str]:
    if not raw_scopes:
        return []
    scopes: list[str] = []
    for scope in raw_scopes.split(','):
        scope_value = scope.strip()
        if scope_value:
            scopes.append(scope_value)
    return scopes


def _authorization_code_flow(
    client: BaseClient,
    config: SSOConfig,
    *,
    open_browser: bool,
    printer: Callable[[str], None],
    timeout_seconds: int,
) -> dict[str, str]:
    fetcher = _AuthCodeFetcher()
    code_verifier, code_challenge = _generate_pkce_pair()

    registration = client.register_client(
        clientName=_generate_client_name(config.session_name),
        clientType='public',
        grantTypes=list(_AUTH_GRANT_TYPES),
        redirectUris=[fetcher.redirect_uri_without_port()],
        issuerUrl=config.start_url,
        scopes=config.registration_scopes or [_AUTH_DEFAULT_SCOPE],
    )

    reg_expiry = _timestamp_to_datetime(registration['clientSecretExpiresAt'])
    registration_record = {
        'clientId': registration['clientId'],
        'clientSecret': registration['clientSecret'],
        'expiresAt': reg_expiry,
    }

    state = uuid.uuid4().hex
    base_endpoint = client.meta.endpoint_url.rstrip('/')
    query_params = {
        'response_type': 'code',
        'client_id': registration['clientId'],
        'redirect_uri': fetcher.redirect_uri_with_port(),
        'state': state,
        'code_challenge_method': 'S256',
        'code_challenge': code_challenge,
        'scope': ' '.join(config.registration_scopes)
        if config.registration_scopes
        else _AUTH_DEFAULT_SCOPE,
    }
    authorization_url = _build_authorization_url(base_endpoint, query_params)

    _announce_authorization(printer, authorization_url, open_browser)

    try:
        auth_code, returned_state = fetcher.get_auth_code(timeout_seconds)
    except TimeoutError as exc:
        message = 'Timed out waiting for authorization.'
        raise AuthorizationTimeoutError(message) from exc

    if returned_state != state:
        mismatch_message = 'Returned OAuth state did not match.'
        raise AuthorizationStateMismatchError(mismatch_message)
    if not auth_code:
        message = 'No authorization code received from the callback.'
        raise SSOLoginError(message)

    response = client.create_token(
        grantType='authorization_code',
        clientId=registration['clientId'],
        clientSecret=registration['clientSecret'],
        code=auth_code,
        codeVerifier=code_verifier,
        redirectUri=fetcher.redirect_uri_with_port(),
    )

    token_expires = _utcnow() + dt.timedelta(seconds=response['expiresIn'])
    token: dict[str, str] = {
        'startUrl': config.start_url,
        'region': config.region,
        'accessToken': response['accessToken'],
        'expiresAt': _datetime_to_iso(token_expires),
        'clientId': registration_record['clientId'],
        'clientSecret': registration_record['clientSecret'],
        'registrationExpiresAt': _datetime_to_iso(reg_expiry),
    }
    if 'refreshToken' in response:
        token['refreshToken'] = response['refreshToken']
    if 'tokenType' in response:
        token['tokenType'] = response['tokenType']
    return token


def _device_code_flow(
    client: BaseClient,
    config: SSOConfig,
    *,
    open_browser: bool,
    printer: Callable[[str], None],
) -> dict[str, str]:
    registration_kwargs: dict[str, object] = {
        'clientName': _generate_client_name(config.session_name),
        'clientType': 'public',
    }
    if config.registration_scopes:
        registration_kwargs['scopes'] = config.registration_scopes

    registration = client.register_client(**registration_kwargs)
    reg_expiry = _timestamp_to_datetime(registration['clientSecretExpiresAt'])

    authorization = client.start_device_authorization(
        clientId=registration['clientId'],
        clientSecret=registration['clientSecret'],
        startUrl=config.start_url,
    )

    verification_url = (
        authorization.get('verificationUriComplete')
        or authorization['verificationUri']
    )
    user_code = authorization.get('userCode')
    _announce_authorization(
        printer,
        verification_url,
        open_browser,
        user_code=user_code,
    )

    expiration = _utcnow() + dt.timedelta(seconds=authorization['expiresIn'])
    interval = authorization.get('interval', 5)

    while True:
        if _utcnow() >= expiration:
            timeout_message = 'Authorization flow expired before completion.'
            raise AuthorizationTimeoutError(timeout_message)
        try:
            response = client.create_token(
                grantType=_DEVICE_GRANT_TYPE,
                clientId=registration['clientId'],
                clientSecret=registration['clientSecret'],
                deviceCode=authorization['deviceCode'],
            )
            break
        except client.exceptions.AuthorizationPendingException:
            time.sleep(interval)
        except client.exceptions.SlowDownException:
            interval += 5
            time.sleep(interval)
        except client.exceptions.ExpiredTokenException as exc:
            message = 'The device authorization token expired.'
            raise AuthorizationTimeoutError(message) from exc

    token_expires = _utcnow() + dt.timedelta(seconds=response['expiresIn'])
    token: dict[str, str] = {
        'startUrl': config.start_url,
        'region': config.region,
        'accessToken': response['accessToken'],
        'expiresAt': _datetime_to_iso(token_expires),
        'clientId': registration['clientId'],
        'clientSecret': registration['clientSecret'],
        'registrationExpiresAt': _datetime_to_iso(reg_expiry),
    }
    if 'refreshToken' in response:
        token['refreshToken'] = response['refreshToken']
    if 'tokenType' in response:
        token['tokenType'] = response['tokenType']
    if 'idToken' in response:
        token['idToken'] = response['idToken']
    return token


def _write_token_cache(token: dict[str, str], config: SSOConfig) -> None:
    key_source = config.session_name or config.start_url
    digest = hashlib.sha256(key_source.encode('utf-8')).hexdigest()
    _CACHE_DIR.mkdir(parents=True, exist_ok=True)
    cache_path = _CACHE_DIR / f'{digest}.json'
    with cache_path.open('w', encoding='utf-8') as fp:
        json.dump(token, fp, ensure_ascii=False, indent=2)
        fp.write('\n')
    LOG.debug('Wrote SSO token cache to %s', cache_path)


def _generate_client_name(session_name: str | None) -> str:
    if session_name:
        return f'boto3-session-{session_name}'
    return f'boto3-session-{int(time.time())}'


def _generate_pkce_pair() -> tuple[str, str]:
    charset = string.ascii_letters + string.digits + '-._~'
    verifier = ''.join(secrets.choice(charset) for _ in range(64))
    challenge = (
        base64.urlsafe_b64encode(
            hashlib.sha256(verifier.encode('utf-8')).digest()
        )
        .decode('utf-8')
        .rstrip('=')
    )
    return verifier, challenge


def _build_authorization_url(
    base_endpoint: str, params: dict[str, str]
) -> str:
    query = '&'.join(
        f'{quote(str(key), safe="")}={quote(str(value), safe="")}'
        for key, value in params.items()
    )
    return f'{base_endpoint}/authorize?{query}'


def _announce_authorization(
    printer: Callable[[str], None],
    url: str,
    open_browser: bool,
    *,
    user_code: str | None = None,
) -> None:
    if user_code:
        printer('Complete device authorization for AWS IAM Identity Center:')
        printer(f'  Verification code: {user_code}')
    else:
        printer('Complete AWS IAM Identity Center sign-in in your browser:')
    printer(f'  Verification URL: {url}')

    if not open_browser:
        return

    try:
        opened = webbrowser.open(url, new=2, autoraise=True)
    except (
        webbrowser.Error,
        OSError,
    ) as err:  # pragma: no cover - best effort
        LOG.debug(
            'Failed to open browser automatically: %s', err, exc_info=True
        )
        opened = False

    if not opened:
        printer(
            'Unable to automatically open the browser. Please copy the URL above.'
        )


def _datetime_to_iso(value: dt.datetime) -> str:
    return value.astimezone(dt.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def _timestamp_to_datetime(timestamp: int) -> dt.datetime:
    return dt.datetime.fromtimestamp(timestamp, tz=dt.timezone.utc)


def _utcnow() -> dt.datetime:
    return dt.datetime.now(tz=dt.timezone.utc)


class _AuthCodeFetcher:
    _HANDLER_TIMEOUT = 1

    def __init__(self) -> None:
        try:
            handler = partial(_OAuthCallbackHandler, self)
            self._server = HTTPServer(('127.0.0.1', 0), handler)
            self._server.timeout = self._HANDLER_TIMEOUT
        except OSError as exc:  # pragma: no cover - platform dependent
            message = f'Failed to start callback server: {exc}'
            raise AuthCodeFetcherError(message) from exc
        self._auth_code: str | None = None
        self._state: str | None = None
        self._done = False

    def redirect_uri_without_port(self) -> str:
        return 'http://127.0.0.1/oauth/callback'

    def redirect_uri_with_port(self) -> str:
        return f'http://127.0.0.1:{self._server.server_port}/oauth/callback'

    def get_auth_code(
        self, timeout_seconds: int
    ) -> tuple[str | None, str | None]:
        deadline = time.monotonic() + timeout_seconds
        while not self._done and time.monotonic() < deadline:
            self._server.handle_request()
        self._server.server_close()

        if not self._done:
            raise TimeoutError
        return self._auth_code, self._state

    def set_auth_code(self, code: str | None, state: str | None) -> None:
        self._auth_code = code
        self._state = state
        self._done = True


class _OAuthCallbackHandler(BaseHTTPRequestHandler):
    _RESPONSE_BODY = (
        b'<html><head><title>AWS IAM Identity Center login</title></head>'
        b'<body><h1>You may now close this window.</h1></body></html>'
    )

    def __init__(
        self,
        fetcher: _AuthCodeFetcher,
        request: socket.socket,
        client_address: tuple[str, int],
        server: BaseServer,
    ) -> None:
        self._fetcher = fetcher
        super().__init__(request, client_address, server)

    def log_message(self, format_string: str, *args: object) -> None:
        LOG.debug(format_string, *args)

    def do_GET(self) -> None:
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Content-Length', str(len(self._RESPONSE_BODY)))
        self.end_headers()
        self.wfile.write(self._RESPONSE_BODY)

        query = parse_qs(urlparse(self.path).query)
        if 'code' in query and 'state' in query:
            self._fetcher.set_auth_code(query['code'][0], query['state'][0])
        elif 'error' in query:
            self._fetcher.set_auth_code(None, None)
