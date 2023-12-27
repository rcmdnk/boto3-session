from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

import boto3
from botocore.config import Config
from botocore.exceptions import SSOTokenLoadError, UnauthorizedSSOTokenError

if TYPE_CHECKING:
    from typing import Any

    from boto3.resources.base import ServiceResource
    from botocore.client import BaseClient


@dataclass
class Session:
    """
    Wrapper class for boto3.session.Session.

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
    session_name: str = "boto3_session"
    retry_mode: str = "standard"
    max_attempts: int = 10

    def __post_init__(self) -> None:
        self._config = Config(
            retries={
                "max_attempts": self.max_attempts,
                "mode": self.retry_mode,
            }
        )
        self._session = self.session()

    def sso_login(self) -> None:
        import subprocess  # nosec

        _ = subprocess.run(["aws", "sso", "login"])  # nosec

    def set_assume_role(self) -> None:
        client = boto3.client(
            "sts",
            aws_access_key_id=self.aws_access_key_id,
            aws_secret_access_key=self.aws_secret_access_key,
            aws_session_token=self.aws_session_token,
            config=self._config,
        )

        try:
            response = client.assume_role(
                RoleArn=self.role_arn, RoleSessionName=self.session_name
            )
        except (SSOTokenLoadError, UnauthorizedSSOTokenError):
            self.sso_login()
            response = client.assume_role(
                RoleArn=self.role_arn, RoleSessionName=self.session_name
            )

        self.aws_access_key_id = response["Credentials"]["AccessKeyId"]
        self.aws_secret_access_key = response["Credentials"]["SecretAccessKey"]
        self.aws_session_token = response["Credentials"]["SessionToken"]

    def session(self) -> boto3.Session:
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
        except (SSOTokenLoadError, UnauthorizedSSOTokenError):
            self.sso_login()
            _ = self._session.get_credentials().access_key
        return self._session

    def update_config(self, kwargs: dict[str, Any]) -> None:
        config = self._config
        if "config" in kwargs:
            kwargs["config"] = config.merge(kwargs["config"])
        else:
            kwargs["config"] = config

    def client(self, *args: Any, **kwargs: Any) -> BaseClient:
        self.update_config(kwargs)
        return self._session.client(*args, **kwargs)

    def resource(self, *args: Any, **kwargs: Any) -> ServiceResource:
        self.update_config(kwargs)
        return self._session.resource(*args, **kwargs)
