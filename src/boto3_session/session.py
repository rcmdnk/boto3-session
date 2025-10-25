from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

import boto3
from botocore.config import Config
from botocore.exceptions import (
    SSOTokenLoadError,
    TokenRetrievalError,
    UnauthorizedSSOTokenError,
)

if TYPE_CHECKING:
    from typing import Any

    from boto3.resources.base import ServiceResource
    from botocore.client import BaseClient


@dataclass
class Session:
    """Wrapper class for boto3.session.Session.

    Parameters
    ----------
    profile_name : str | None
        AWS profile name.
    aws_access_key_id : str | None
        AWS access key id.
    aws_secret_access_key : str | None
        AWS secret access key.
    aws_session_token : str | None
        AWS session token.
    region_name : str | None
        AWS region name.
    role_arn : str | None
        AWS role arn for Assume role. If this is set, aws_access_key_id,
        aws_secret_access_key, aws_session_token are replaced by Assume role.
    session_name : str
        AWS session name. Default is "boto3_session".
    retry_mode : str
        Retry mode for failed requests. Default is "standard".
    max_attempts : int
        Maximum number of retry attempts for failed requests. Default is 10.

    """

    profile_name: str | None = None
    aws_access_key_id: str | None = None
    aws_secret_access_key: str | None = None
    aws_session_token: str | None = None
    region_name: str | None = None
    role_arn: str | None = None
    session_name: str = 'boto3_session'
    retry_mode: str = 'standard'
    max_attempts: int = 10

    def __post_init__(self) -> None:
        self._config = Config(
            retries={
                'max_attempts': self.max_attempts,
                'mode': self.retry_mode,
            }
        )

    def sso_login(self) -> None:
        """Perform SSO login using boto3's sso-oidc client.

        This method implements the device authorization flow for AWS SSO login
        without requiring the AWS CLI to be installed.

        It reads SSO configuration from the AWS config file (using the specified
        profile or the default profile). If no SSO configuration is found, it
        falls back to subprocess call to aws CLI.
        """
        import botocore.session

        # Get SSO configuration from profile (or default profile if None)
        botocore_session = botocore.session.Session(profile=self.profile_name)
        config = botocore_session.get_scoped_config()

        # Check for SSO configuration
        sso_start_url = config.get('sso_start_url')
        sso_region = config.get('sso_region')
        sso_session_name = config.get('sso_session')

        # Track which format we're using (affects cache key)
        cache_key_name = None

        # If using sso_session, load from config
        if sso_session_name and not sso_start_url:
            full_config = botocore_session.full_config
            sso_sessions = full_config.get('sso_sessions', {})
            sso_session = sso_sessions.get(sso_session_name, {})
            sso_start_url = sso_session.get('sso_start_url')
            sso_region = sso_session.get('sso_region', sso_region)
            # For sso_session format, cache key is based on session name
            cache_key_name = sso_session_name

        if not sso_start_url or not sso_region:
            # No SSO config found, fall back to subprocess
            import subprocess

            _ = subprocess.run(['aws', 'sso', 'login'], check=False)  # noqa: S607
            return

        # Perform SSO login using boto3
        self._perform_sso_device_flow(
            sso_start_url, sso_region, cache_key_name
        )

    def _perform_sso_device_flow(
        self,
        start_url: str,
        sso_region: str,
        cache_key_name: str | None = None,
    ) -> None:
        """Perform the SSO device authorization flow.

        Parameters
        ----------
        start_url : str
            The SSO start URL.
        sso_region : str
            The AWS region for SSO.
        cache_key_name : str | None
            The name to use for cache key (e.g., session name for sso_session format).
            If None, start_url will be used (legacy format).

        """
        # Create SSO-OIDC client
        client = boto3.client('sso-oidc', region_name=sso_region)

        # Register client and start device authorization
        client_id, client_secret = self._register_sso_client(client)
        device_info = self._start_device_authorization(
            client, client_id, client_secret, start_url
        )

        # Poll for token and save to cache
        token_response = self._poll_for_token(
            client, client_id, client_secret, device_info
        )

        # Save token to cache
        self._save_sso_token(
            token_response, start_url, sso_region, cache_key_name
        )
        print('\nSSO login successful!')  # noqa: T201

    def _register_sso_client(self, client: BaseClient) -> tuple[str, str]:
        """Register SSO client.

        Parameters
        ----------
        client : BaseClient
            SSO-OIDC client.

        Returns
        -------
        tuple[str, str]
            Client ID and client secret.

        """
        response = client.register_client(
            clientName='boto3-session',
            clientType='public',
        )
        return response['clientId'], response['clientSecret']

    def _start_device_authorization(
        self,
        client: BaseClient,
        client_id: str,
        client_secret: str,
        start_url: str,
    ) -> dict[str, Any]:
        """Start device authorization.

        Parameters
        ----------
        client : BaseClient
            SSO-OIDC client.
        client_id : str
            Client ID.
        client_secret : str
            Client secret.
        start_url : str
            SSO start URL.

        Returns
        -------
        dict[str, Any]
            Device authorization response.

        """
        import webbrowser

        response = client.start_device_authorization(
            clientId=client_id,
            clientSecret=client_secret,
            startUrl=start_url,
        )

        # Display instructions and open browser
        user_code = response['userCode']
        verification_uri = response['verificationUri']
        verification_uri_complete = response.get('verificationUriComplete')

        print(f'\nInitiating SSO login for {start_url}')  # noqa: T201
        print(f'User code: {user_code}')  # noqa: T201
        print(f'Verification URL: {verification_uri}')  # noqa: T201
        print('\nOpening browser for authorization...')  # noqa: T201

        # Open browser
        try:
            url_to_open = verification_uri_complete or verification_uri
            webbrowser.open(url_to_open)
        except Exception:  # noqa: S110, BLE001
            # If browser cannot be opened, user can manually visit the URL
            pass

        print('Waiting for authorization... (press Ctrl+C to cancel)')  # noqa: T201

        return response

    def _poll_for_token(
        self,
        client: BaseClient,
        client_id: str,
        client_secret: str,
        device_info: dict[str, Any],
    ) -> dict[str, Any]:
        """Poll for SSO token.

        Parameters
        ----------
        client : BaseClient
            SSO-OIDC client.
        client_id : str
            Client ID.
        client_secret : str
            Client secret.
        device_info : dict[str, Any]
            Device authorization information.

        Returns
        -------
        dict[str, Any]
            Token response.

        """
        import time

        device_code = device_info['deviceCode']
        expires_in = device_info['expiresIn']
        interval = device_info.get('interval', 5)

        # Poll for token
        start_time = time.time()
        while time.time() - start_time < expires_in:
            time.sleep(interval)

            try:
                token_response = client.create_token(
                    clientId=client_id,
                    clientSecret=client_secret,
                    grantType='urn:ietf:params:oauth:grant-type:device_code',
                    deviceCode=device_code,
                )
            except client.exceptions.AuthorizationPendingException:
                # User hasn't authorized yet, continue polling
                continue
            except client.exceptions.SlowDownException:
                # Polling too fast, increase interval
                interval += 5
                continue
            except Exception as e:
                print(f'\nError during SSO login: {e}')  # noqa: T201
                msg = 'SSO login failed'
                raise RuntimeError(msg) from e
            else:
                return token_response

        # Timeout
        msg = 'SSO login timed out - authorization not completed in time'
        raise TimeoutError(msg)

    def _save_sso_token(
        self,
        token_response: dict[str, Any],
        start_url: str,
        sso_region: str,
        cache_key_name: str | None = None,
    ) -> None:
        """Save SSO token to cache.

        Parameters
        ----------
        token_response : dict[str, Any]
            Token response from create_token.
        start_url : str
            SSO start URL.
        sso_region : str
            SSO region.
        cache_key_name : str | None
            The name to use for cache key (e.g., session name for sso_session format).
            If None, start_url will be used (legacy format).

        """
        import hashlib
        import json
        from datetime import datetime, timezone
        from pathlib import Path

        access_token = token_response['accessToken']
        expires_in_seconds = token_response['expiresIn']
        expires_at = (
            datetime.now(timezone.utc).timestamp() + expires_in_seconds
        )

        # Calculate cache key
        # For sso_session format: SHA1 of session name
        # For legacy format: SHA1 of start URL
        if cache_key_name:
            cache_key = hashlib.sha1(
                cache_key_name.encode('utf-8'), usedforsecurity=False
            ).hexdigest()
        else:
            cache_key = hashlib.sha1(
                start_url.encode('utf-8'), usedforsecurity=False
            ).hexdigest()

        # Save to cache
        cache_dir = Path.home() / '.aws' / 'sso' / 'cache'
        cache_dir.mkdir(parents=True, exist_ok=True)
        cache_file = cache_dir / f'{cache_key}.json'

        cache_data = {
            'startUrl': start_url,
            'region': sso_region,
            'accessToken': access_token,
            'expiresAt': datetime.fromtimestamp(
                expires_at, tz=timezone.utc
            ).strftime('%Y-%m-%dT%H:%M:%SZ'),
        }

        with cache_file.open('w') as f:
            json.dump(cache_data, f, indent=2)

    def set_assume_role(self) -> None:
        client = boto3.client(
            'sts',
            aws_access_key_id=self.aws_access_key_id,
            aws_secret_access_key=self.aws_secret_access_key,
            aws_session_token=self.aws_session_token,
            config=self._config,
        )

        try:
            response = client.assume_role(
                RoleArn=self.role_arn, RoleSessionName=self.session_name
            )
        except (
            SSOTokenLoadError,
            UnauthorizedSSOTokenError,
            TokenRetrievalError,
        ):
            self.sso_login()
            response = client.assume_role(
                RoleArn=self.role_arn, RoleSessionName=self.session_name
            )

        self.aws_access_key_id = response['Credentials']['AccessKeyId']
        self.aws_secret_access_key = response['Credentials']['SecretAccessKey']
        self.aws_session_token = response['Credentials']['SessionToken']

    def session(self) -> boto3.Session:
        if _session := getattr(self, '_session', None):
            return _session

        if self.role_arn:
            self.set_assume_role()

        self._session = boto3.Session(
            profile_name=self.profile_name,
            aws_access_key_id=self.aws_access_key_id,
            aws_secret_access_key=self.aws_secret_access_key,
            aws_session_token=self.aws_session_token,
            region_name=self.region_name,
        )
        try:
            _ = self._session.get_credentials().access_key
        except (
            SSOTokenLoadError,
            UnauthorizedSSOTokenError,
            TokenRetrievalError,
        ):
            self.sso_login()
            _ = self._session.get_credentials().access_key
        return self._session

    def update_config(self, kwargs: dict[str, Any]) -> None:
        config = self._config
        if 'config' in kwargs:
            kwargs['config'] = config.merge(kwargs['config'])
        else:
            kwargs['config'] = config

    def client(self, *args: Any, **kwargs: Any) -> BaseClient:  # noqa: ANN401
        self.update_config(kwargs)
        return self.session().client(*args, **kwargs)

    def resource(self, *args: Any, **kwargs: Any) -> ServiceResource:  # noqa: ANN401
        self.update_config(kwargs)
        return self.session().resource(*args, **kwargs)
