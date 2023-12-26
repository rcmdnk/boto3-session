# boto3-session

[![test](https://github.com/rcmdnk/boto3-session/actions/workflows/test.yml/badge.svg)](https://github.com/rcmdnk/boto3-session/actions/workflows/test.yml)
[![test coverage](https://img.shields.io/badge/coverage-check%20here-blue.svg)](https://github.com/rcmdnk/boto3-session/tree/coverage)

A wrapper library for the boto3.session.Session class in Python.

## Requirement

- Python versions 3.9, 3.10, 3.11, 3.12
- Poetry (for development purposes)

## Installation

To install boto3-session, run the following command:

```bash
$ pip install boto3-session
```

## Usage

boto3_session.Session can be used similarly to boto3.Session:

```python
from boto3_session import Session

session = Session()
s3 = session.resource("s3")
bucket = s3.Bucket(...)
...
```

The some of parameters for boto3_session.Session are akin to those for boto3.Session:

- `profile_name`: The AWS profile name.
- `aws_access_key_id`: The AWS access key ID.
- `aws_secret_access_key`: The AWS secret access key.
- `aws_session_token`: The AWS session token.
- `region_name`: The AWS region name.

Additionally, boto3_session.Session supports management of AssumeRole:

- `role_arn`: The AWS role ARN for AssumeRole. If set, aws_access_key_id, aws_secret_access_key, and aws_session_token are replaced with the AssumeRole credentials.
- `session_name`: The AWS session name, defaulting to "boto3_session".

boto3_session.Session includes `client` and `resource` methods, like boto3.Session. By default, the following configuration is passed to them:

```python
Config(retries={"max_attempts": self.max_attempts, "mode": self.retry_mode})
```

In boto3, the default values for `max_attempts` and `mode` are 5 and legacy, respectively. In boto3_session, they default to 3 and "standard".

These defaults can be overridden by passing the following parameters to boto3_session.Session:

- `retry_mode`: The retry mode for failed requests, defaulting to "standard".
- `max_attempts`: The maximum number of retry attempts for failed requests, defaulting to 10.

## SSO Login

For configurations with SSO login, if the token is absent or expired, boto3_session.Session automatically executes aws sso login.

Note: The aws command-line tool must be installed.

- [Install or update the latest version of the AWS CLI - AWS Command Line Interface](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html)
  Install or update the latest version of the AWS CLI - AWS Command Line Interface
