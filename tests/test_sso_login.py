"""Tests for SSO login functionality."""

from unittest.mock import MagicMock, patch

import pytest

from boto3_session import Session


class TestSSOLogin:
    """Tests for SSO login methods."""

    def test_sso_login_without_profile_but_no_sso_config(self) -> None:
        """Test that SSO login without profile falls back to subprocess when no SSO config."""
        session = Session()

        with patch('botocore.session.Session') as mock_botocore_session:
            mock_instance = MagicMock()
            mock_instance.get_scoped_config.return_value = {}
            mock_botocore_session.return_value = mock_instance

            with patch('subprocess.run') as mock_run:
                session.sso_login()
                mock_run.assert_called_once()
                args = mock_run.call_args[0][0]
                assert args == ['aws', 'sso', 'login']

    def test_sso_login_without_profile_with_default_sso_config(self) -> None:
        """Test SSO login without profile but with SSO config in default profile."""
        session = Session()  # No profile_name

        with patch('botocore.session.Session') as mock_botocore_session:
            mock_instance = MagicMock()
            mock_instance.get_scoped_config.return_value = {
                'sso_start_url': 'https://example.awsapps.com/start',
                'sso_region': 'us-east-1',
            }
            mock_botocore_session.return_value = mock_instance

            with patch.object(
                session, '_perform_sso_device_flow'
            ) as mock_perform:
                session.sso_login()
                # Should use device flow, not subprocess
                mock_perform.assert_called_once_with(
                    'https://example.awsapps.com/start', 'us-east-1', None
                )

    def test_sso_login_with_profile_but_no_sso_config(self) -> None:
        """Test SSO login with profile but no SSO config falls back."""
        session = Session(profile_name='test-profile')

        with patch('botocore.session.Session') as mock_botocore_session:
            mock_instance = MagicMock()
            mock_instance.get_scoped_config.return_value = {}
            mock_botocore_session.return_value = mock_instance

            with patch('subprocess.run') as mock_run:
                session.sso_login()
                mock_run.assert_called_once()

    def test_sso_login_with_sso_config(self) -> None:
        """Test SSO login with proper SSO configuration."""
        session = Session(profile_name='test-profile')

        with patch('botocore.session.Session') as mock_botocore_session:
            mock_instance = MagicMock()
            mock_instance.get_scoped_config.return_value = {
                'sso_start_url': 'https://example.awsapps.com/start',
                'sso_region': 'us-east-1',
            }
            mock_botocore_session.return_value = mock_instance

            with patch.object(
                session, '_perform_sso_device_flow'
            ) as mock_perform:
                session.sso_login()
                mock_perform.assert_called_once_with(
                    'https://example.awsapps.com/start', 'us-east-1', None
                )

    def test_register_sso_client(self) -> None:
        """Test SSO client registration."""
        session = Session()
        mock_client = MagicMock()
        mock_client.register_client.return_value = {
            'clientId': 'test-client-id',
            'clientSecret': 'test-client-secret',
        }

        client_id, client_secret = session._register_sso_client(mock_client)  # noqa: SLF001

        assert client_id == 'test-client-id'
        assert client_secret == 'test-client-secret'  # noqa: S105
        mock_client.register_client.assert_called_once_with(
            clientName='boto3-session',
            clientType='public',
        )

    def test_start_device_authorization(self) -> None:
        """Test device authorization start."""
        session = Session()
        mock_client = MagicMock()
        mock_client.start_device_authorization.return_value = {
            'deviceCode': 'test-device-code',
            'userCode': 'TEST-CODE',
            'verificationUri': 'https://device.sso.us-east-1.amazonaws.com/',
            'expiresIn': 600,
            'interval': 5,
        }

        with patch('builtins.print'), patch('webbrowser.open'):
            result = session._start_device_authorization(  # noqa: SLF001
                mock_client,
                'test-client-id',
                'test-client-secret',
                'https://example.awsapps.com/start',
            )

        assert result['deviceCode'] == 'test-device-code'
        assert result['userCode'] == 'TEST-CODE'

    def test_poll_for_token_success(self) -> None:
        """Test successful token polling."""
        session = Session()
        mock_client = MagicMock()
        mock_client.create_token.return_value = {
            'accessToken': 'test-access-token',
            'expiresIn': 3600,
        }

        device_info = {
            'deviceCode': 'test-device-code',
            'expiresIn': 600,
            'interval': 1,
        }

        with patch('time.sleep'):
            result = session._poll_for_token(  # noqa: SLF001
                mock_client,
                'test-client-id',
                'test-client-secret',
                device_info,
            )

        assert result['accessToken'] == 'test-access-token'

    def test_poll_for_token_authorization_pending(self) -> None:
        """Test token polling with authorization pending."""
        session = Session()
        mock_client = MagicMock()

        # Create exception class
        authorization_pending_exception = type(
            'AuthorizationPendingException', (Exception,), {}
        )
        mock_client.exceptions.AuthorizationPendingException = (
            authorization_pending_exception
        )

        # First call raises AuthorizationPendingException, second succeeds
        mock_client.create_token.side_effect = [
            authorization_pending_exception(),
            {
                'accessToken': 'test-access-token',
                'expiresIn': 3600,
            },
        ]

        device_info = {
            'deviceCode': 'test-device-code',
            'expiresIn': 600,
            'interval': 1,
        }

        with patch('time.sleep'):
            result = session._poll_for_token(  # noqa: SLF001
                mock_client,
                'test-client-id',
                'test-client-secret',
                device_info,
            )

        assert result['accessToken'] == 'test-access-token'
        assert mock_client.create_token.call_count == 2

    def test_poll_for_token_timeout(self) -> None:
        """Test token polling timeout."""
        session = Session()
        mock_client = MagicMock()

        # Create exception class
        authorization_pending_exception = type(
            'AuthorizationPendingException', (Exception,), {}
        )
        mock_client.exceptions.AuthorizationPendingException = (
            authorization_pending_exception
        )

        # Always raise AuthorizationPendingException
        def raise_exception(*args, **kwargs):  # noqa: ANN002, ANN003, ANN202, ARG001
            raise authorization_pending_exception

        mock_client.create_token.side_effect = raise_exception

        device_info = {
            'deviceCode': 'test-device-code',
            'expiresIn': 1,  # Very short timeout
            'interval': 0.1,
        }

        with (
            patch('time.sleep'),
            patch('time.time', side_effect=[0, 0.5, 1.5]),
            pytest.raises(TimeoutError, match='timed out'),
        ):
            session._poll_for_token(  # noqa: SLF001
                mock_client,
                'test-client-id',
                'test-client-secret',
                device_info,
            )

    def test_save_sso_token(self) -> None:
        """Test SSO token saving to cache."""
        session = Session()

        token_response = {
            'accessToken': 'test-access-token',
            'expiresIn': 3600,
        }

        with (
            patch('pathlib.Path.mkdir'),
            patch('pathlib.Path.open', create=True) as mock_open,
        ):
            mock_file = MagicMock()
            mock_open.return_value.__enter__.return_value = mock_file

            with patch('json.dump') as mock_json_dump:
                session._save_sso_token(  # noqa: SLF001
                    token_response,
                    'https://example.awsapps.com/start',
                    'us-east-1',
                )

                # Verify json.dump was called with correct structure
                call_args = mock_json_dump.call_args
                cache_data = call_args[0][0]
                assert (
                    cache_data['startUrl']
                    == 'https://example.awsapps.com/start'
                )
                assert cache_data['region'] == 'us-east-1'
                assert cache_data['accessToken'] == 'test-access-token'
                assert 'expiresAt' in cache_data

    def test_save_sso_token_with_session_name(self) -> None:
        """Test SSO token saving with session name (sso_session format)."""
        session = Session()

        token_response = {
            'accessToken': 'test-access-token',
            'expiresIn': 3600,
        }

        with (
            patch('pathlib.Path.mkdir'),
            patch('pathlib.Path.open', create=True) as mock_open,
        ):
            mock_file = MagicMock()
            mock_open.return_value.__enter__.return_value = mock_file

            with patch('json.dump') as mock_json_dump:
                # Call with cache_key_name to test sso_session format
                session._save_sso_token(  # noqa: SLF001
                    token_response,
                    'https://example.awsapps.com/start',
                    'us-east-1',
                    'my-sso-session',
                )

                # Verify json.dump was called with correct structure
                call_args = mock_json_dump.call_args
                cache_data = call_args[0][0]
                assert (
                    cache_data['startUrl']
                    == 'https://example.awsapps.com/start'
                )
                assert cache_data['region'] == 'us-east-1'
                assert cache_data['accessToken'] == 'test-access-token'
                assert 'expiresAt' in cache_data

    def test_sso_login_with_sso_session(self) -> None:
        """Test SSO login with sso_session configuration."""
        session = Session(profile_name='test-profile')

        with patch('botocore.session.Session') as mock_botocore_session:
            mock_instance = MagicMock()
            mock_instance.get_scoped_config.return_value = {
                'sso_session': 'my-sso-session',
                'sso_region': 'us-west-2',
            }
            mock_instance.full_config = {
                'sso_sessions': {
                    'my-sso-session': {
                        'sso_start_url': 'https://session.awsapps.com/start',
                        'sso_region': 'us-east-1',
                    }
                }
            }
            mock_botocore_session.return_value = mock_instance

            with patch.object(
                session, '_perform_sso_device_flow'
            ) as mock_perform:
                session.sso_login()
                mock_perform.assert_called_once_with(
                    'https://session.awsapps.com/start',
                    'us-east-1',
                    'my-sso-session',
                )
