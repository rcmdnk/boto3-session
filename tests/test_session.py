from __future__ import annotations

from typing import TYPE_CHECKING
from unittest.mock import MagicMock, Mock, patch

from botocore.config import Config
from botocore.exceptions import (
    SSOTokenLoadError,
    TokenRetrievalError,
    UnauthorizedSSOTokenError,
)

from boto3_session.session import Session

if TYPE_CHECKING:
    from typing import Any


class TestSessionInit:
    """Test Session initialization."""

    def test_default_init(self) -> None:
        """Test Session with default parameters."""
        session = Session()
        assert session.profile_name is None
        assert session.aws_access_key_id is None
        assert session.aws_secret_access_key is None
        assert session.aws_session_token is None
        assert session.region_name is None
        assert session.role_arn is None
        assert session.session_name == 'boto3_session'
        assert session.retry_mode == 'standard'
        assert session.max_attempts == 10

    def test_custom_init(self) -> None:
        """Test Session with custom parameters."""
        session = Session(
            profile_name='test-profile',
            aws_access_key_id='test-key',
            aws_secret_access_key='test-secret',  # noqa: S106
            aws_session_token='test-token',  # noqa: S106
            region_name='us-west-2',
            role_arn='arn:aws:iam::123456789012:role/test-role',
            session_name='custom-session',
            retry_mode='adaptive',
            max_attempts=5,
        )
        assert session.profile_name == 'test-profile'
        assert session.aws_access_key_id == 'test-key'
        assert session.aws_secret_access_key == 'test-secret'  # noqa: S105
        assert session.aws_session_token == 'test-token'  # noqa: S105
        assert session.region_name == 'us-west-2'
        assert session.role_arn == 'arn:aws:iam::123456789012:role/test-role'
        assert session.session_name == 'custom-session'
        assert session.retry_mode == 'adaptive'
        assert session.max_attempts == 5

    def test_config_created(self) -> None:
        """Test that Config is created in __post_init__."""
        session = Session(max_attempts=15, retry_mode='adaptive')
        assert hasattr(session, '_config')
        assert isinstance(session._config, Config)  # noqa: SLF001


class TestSsoLogin:
    """Test sso_login method."""

    def test_sso_login_with_awscli(self) -> None:
        """Test sso_login when awscli is available."""
        import sys

        mock_awscli = MagicMock()
        mock_clidriver = MagicMock()
        mock_main = MagicMock()
        mock_clidriver.main = mock_main
        mock_awscli.clidriver = mock_clidriver

        with patch.dict(
            sys.modules,
            {'awscli': mock_awscli, 'awscli.clidriver': mock_clidriver},
        ):
            session = Session()
            session.sso_login()
            mock_main.assert_called_once_with(['sso', 'login'])

    def test_sso_login_without_awscli(self) -> None:
        """Test sso_login when awscli is not available."""
        import subprocess
        import sys

        # Remove awscli from modules if it exists
        with (
            patch.dict(
                sys.modules, {'awscli': None, 'awscli.clidriver': None}
            ),
            patch.object(subprocess, 'run') as mock_run,
        ):
            session = Session()
            session.sso_login()
            mock_run.assert_called_once_with(
                ['aws', 'sso', 'login'], check=False
            )


class TestSetAssumeRole:
    """Test set_assume_role method."""

    @patch('boto3_session.session.boto3.client')
    def test_set_assume_role_success(self, mock_client: Mock) -> None:
        """Test successful assume role."""
        mock_sts_client = MagicMock()
        mock_sts_client.assume_role.return_value = {
            'Credentials': {
                'AccessKeyId': 'assumed-key',
                'SecretAccessKey': 'assumed-secret',
                'SessionToken': 'assumed-token',
            }
        }
        mock_client.return_value = mock_sts_client

        session = Session(
            role_arn='arn:aws:iam::123456789012:role/test-role',
            session_name='test-session',
        )
        session.set_assume_role()

        assert session.aws_access_key_id == 'assumed-key'
        assert session.aws_secret_access_key == 'assumed-secret'  # noqa: S105
        assert session.aws_session_token == 'assumed-token'  # noqa: S105
        mock_sts_client.assume_role.assert_called_once_with(
            RoleArn='arn:aws:iam::123456789012:role/test-role',
            RoleSessionName='test-session',
        )

    @patch('boto3_session.session.boto3.client')
    def test_set_assume_role_with_sso_token_error(
        self, mock_client: Mock
    ) -> None:
        """Test assume role with SSO token error."""
        mock_sts_client = MagicMock()
        mock_sts_client.assume_role.side_effect = [
            SSOTokenLoadError(error_msg='test error'),
            {
                'Credentials': {
                    'AccessKeyId': 'assumed-key',
                    'SecretAccessKey': 'assumed-secret',
                    'SessionToken': 'assumed-token',
                }
            },
        ]
        mock_client.return_value = mock_sts_client

        session = Session(role_arn='arn:aws:iam::123456789012:role/test-role')

        with patch.object(session, 'sso_login') as mock_sso_login:
            session.set_assume_role()
            mock_sso_login.assert_called_once()

        assert session.aws_access_key_id == 'assumed-key'
        assert session.aws_secret_access_key == 'assumed-secret'  # noqa: S105
        assert session.aws_session_token == 'assumed-token'  # noqa: S105

    @patch('boto3_session.session.boto3.client')
    def test_set_assume_role_with_unauthorized_error(
        self, mock_client: Mock
    ) -> None:
        """Test assume role with unauthorized SSO token error."""
        mock_sts_client = MagicMock()
        mock_sts_client.assume_role.side_effect = [
            UnauthorizedSSOTokenError(),
            {
                'Credentials': {
                    'AccessKeyId': 'assumed-key',
                    'SecretAccessKey': 'assumed-secret',
                    'SessionToken': 'assumed-token',
                }
            },
        ]
        mock_client.return_value = mock_sts_client

        session = Session(role_arn='arn:aws:iam::123456789012:role/test-role')

        with patch.object(session, 'sso_login') as mock_sso_login:
            session.set_assume_role()
            mock_sso_login.assert_called_once()

    @patch('boto3_session.session.boto3.client')
    def test_set_assume_role_with_token_retrieval_error(
        self, mock_client: Mock
    ) -> None:
        """Test assume role with token retrieval error."""
        mock_sts_client = MagicMock()
        mock_sts_client.assume_role.side_effect = [
            TokenRetrievalError(provider='test', error_msg='test error'),
            {
                'Credentials': {
                    'AccessKeyId': 'assumed-key',
                    'SecretAccessKey': 'assumed-secret',
                    'SessionToken': 'assumed-token',
                }
            },
        ]
        mock_client.return_value = mock_sts_client

        session = Session(role_arn='arn:aws:iam::123456789012:role/test-role')

        with patch.object(session, 'sso_login') as mock_sso_login:
            session.set_assume_role()
            mock_sso_login.assert_called_once()


class TestSession:
    """Test session method."""

    @patch('boto3_session.session.boto3.Session')
    def test_session_basic(self, mock_boto_session: Mock) -> None:
        """Test basic session creation."""
        mock_session_instance = MagicMock()
        mock_credentials = MagicMock()
        mock_credentials.access_key = 'test-key'
        mock_session_instance.get_credentials.return_value = mock_credentials
        mock_boto_session.return_value = mock_session_instance

        session = Session(profile_name='test-profile', region_name='us-west-2')
        result = session.session()

        assert result == mock_session_instance
        mock_boto_session.assert_called_once_with(
            profile_name='test-profile',
            aws_access_key_id=None,
            aws_secret_access_key=None,
            aws_session_token=None,
            region_name='us-west-2',
        )

    @patch('boto3_session.session.boto3.Session')
    def test_session_cached(self, mock_boto_session: Mock) -> None:
        """Test that session is cached after first call."""
        mock_session_instance = MagicMock()
        mock_credentials = MagicMock()
        mock_credentials.access_key = 'test-key'
        mock_session_instance.get_credentials.return_value = mock_credentials
        mock_boto_session.return_value = mock_session_instance

        session = Session()
        result1 = session.session()
        result2 = session.session()

        assert result1 == result2
        mock_boto_session.assert_called_once()

    @patch('boto3_session.session.boto3.Session')
    def test_session_with_assume_role(self, mock_boto_session: Mock) -> None:
        """Test session creation with assume role."""
        mock_session_instance = MagicMock()
        mock_credentials = MagicMock()
        mock_credentials.access_key = 'test-key'
        mock_session_instance.get_credentials.return_value = mock_credentials
        mock_boto_session.return_value = mock_session_instance

        session = Session(role_arn='arn:aws:iam::123456789012:role/test-role')

        with patch.object(session, 'set_assume_role') as mock_assume:
            result = session.session()
            mock_assume.assert_called_once()

        assert result == mock_session_instance

    @patch('boto3_session.session.boto3.Session')
    def test_session_with_sso_error(self, mock_boto_session: Mock) -> None:
        """Test session creation with SSO error."""
        mock_session_instance = MagicMock()
        mock_credentials = MagicMock()
        mock_credentials.access_key = 'test-key'
        mock_session_instance.get_credentials.side_effect = [
            SSOTokenLoadError(error_msg='test error'),
            mock_credentials,
        ]
        mock_boto_session.return_value = mock_session_instance

        session = Session()

        with patch.object(session, 'sso_login') as mock_sso_login:
            _ = session.session()
            mock_sso_login.assert_called_once()

    @patch('boto3_session.session.boto3.Session')
    def test_session_with_unauthorized_sso_error(
        self, mock_boto_session: Mock
    ) -> None:
        """Test session creation with unauthorized SSO error."""
        mock_session_instance = MagicMock()
        mock_credentials = MagicMock()
        mock_credentials.access_key = 'test-key'
        mock_session_instance.get_credentials.side_effect = [
            UnauthorizedSSOTokenError(),
            mock_credentials,
        ]
        mock_boto_session.return_value = mock_session_instance

        session = Session()

        with patch.object(session, 'sso_login') as mock_sso_login:
            _ = session.session()
            mock_sso_login.assert_called_once()

    @patch('boto3_session.session.boto3.Session')
    def test_session_with_token_retrieval_error(
        self, mock_boto_session: Mock
    ) -> None:
        """Test session creation with token retrieval error."""
        mock_session_instance = MagicMock()
        mock_credentials = MagicMock()
        mock_credentials.access_key = 'test-key'
        mock_session_instance.get_credentials.side_effect = [
            TokenRetrievalError(provider='test', error_msg='test error'),
            mock_credentials,
        ]
        mock_boto_session.return_value = mock_session_instance

        session = Session()

        with patch.object(session, 'sso_login') as mock_sso_login:
            _ = session.session()
            mock_sso_login.assert_called_once()


class TestUpdateConfig:
    """Test update_config method."""

    def test_update_config_without_existing_config(self) -> None:
        """Test update_config when kwargs has no config."""
        session = Session(max_attempts=15)
        kwargs: dict[str, Any] = {}
        session.update_config(kwargs)

        assert 'config' in kwargs
        assert kwargs['config'] == session._config  # noqa: SLF001

    def test_update_config_with_existing_config(self) -> None:
        """Test update_config when kwargs has existing config."""
        session = Session(max_attempts=15)
        existing_config = Config(region_name='us-east-1')
        kwargs: dict[str, Any] = {'config': existing_config}
        session.update_config(kwargs)

        assert 'config' in kwargs
        assert kwargs['config'] != existing_config
        assert kwargs['config'] != session._config  # noqa: SLF001


class TestClient:
    """Test client method."""

    @patch.object(Session, 'session')
    def test_client_basic(self, mock_session: Mock) -> None:
        """Test basic client creation."""
        mock_boto_session = MagicMock()
        mock_client = MagicMock()
        mock_boto_session.client.return_value = mock_client
        mock_session.return_value = mock_boto_session

        session = Session()
        result = session.client('s3')

        assert result == mock_client
        mock_boto_session.client.assert_called_once()
        args, kwargs = mock_boto_session.client.call_args
        assert args[0] == 's3'
        assert 'config' in kwargs

    @patch.object(Session, 'session')
    def test_client_with_kwargs(self, mock_session: Mock) -> None:
        """Test client creation with additional kwargs."""
        mock_boto_session = MagicMock()
        mock_client = MagicMock()
        mock_boto_session.client.return_value = mock_client
        mock_session.return_value = mock_boto_session

        session = Session()
        result = session.client('s3', region_name='us-west-2')

        assert result == mock_client
        args, kwargs = mock_boto_session.client.call_args
        assert args[0] == 's3'
        assert 'config' in kwargs
        assert kwargs['region_name'] == 'us-west-2'

    @patch.object(Session, 'session')
    def test_client_with_existing_config(self, mock_session: Mock) -> None:
        """Test client creation with existing config in kwargs."""
        mock_boto_session = MagicMock()
        mock_client = MagicMock()
        mock_boto_session.client.return_value = mock_client
        mock_session.return_value = mock_boto_session

        session = Session()
        existing_config = Config(region_name='us-east-1')
        result = session.client('s3', config=existing_config)

        assert result == mock_client
        _, kwargs = mock_boto_session.client.call_args
        assert 'config' in kwargs
        assert kwargs['config'] != existing_config


class TestResource:
    """Test resource method."""

    @patch.object(Session, 'session')
    def test_resource_basic(self, mock_session: Mock) -> None:
        """Test basic resource creation."""
        mock_boto_session = MagicMock()
        mock_resource = MagicMock()
        mock_boto_session.resource.return_value = mock_resource
        mock_session.return_value = mock_boto_session

        session = Session()
        result = session.resource('s3')

        assert result == mock_resource
        mock_boto_session.resource.assert_called_once()
        args, kwargs = mock_boto_session.resource.call_args
        assert args[0] == 's3'
        assert 'config' in kwargs

    @patch.object(Session, 'session')
    def test_resource_with_kwargs(self, mock_session: Mock) -> None:
        """Test resource creation with additional kwargs."""
        mock_boto_session = MagicMock()
        mock_resource = MagicMock()
        mock_boto_session.resource.return_value = mock_resource
        mock_session.return_value = mock_boto_session

        session = Session()
        result = session.resource('s3', region_name='us-west-2')

        assert result == mock_resource
        args, kwargs = mock_boto_session.resource.call_args
        assert args[0] == 's3'
        assert 'config' in kwargs
        assert kwargs['region_name'] == 'us-west-2'

    @patch.object(Session, 'session')
    def test_resource_with_existing_config(self, mock_session: Mock) -> None:
        """Test resource creation with existing config in kwargs."""
        mock_boto_session = MagicMock()
        mock_resource = MagicMock()
        mock_boto_session.resource.return_value = mock_resource
        mock_session.return_value = mock_boto_session

        session = Session()
        existing_config = Config(region_name='us-east-1')
        result = session.resource('s3', config=existing_config)

        assert result == mock_resource
        _, kwargs = mock_boto_session.resource.call_args
        assert 'config' in kwargs
        assert kwargs['config'] != existing_config
