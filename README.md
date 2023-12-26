# boto3-session

[![test](https://github.com/rcmdnk/boto3-session/actions/workflows/test.yml/badge.svg)](https://github.com/rcmdnk/boto3-session/actions/workflows/test.yml)
[![test coverage](https://img.shields.io/badge/coverage-check%20here-blue.svg)](https://github.com/rcmdnk/boto3-session/tree/coverage)

Wrapper library for python boto3.session.Session.

## Requirement

- Python 3.12, 3.11, 3.10, 3.9
- Poetry (For development)

## Installation

```bash
$ pip install boto3-session
```

## Usage

You can use `boto3_session.Session` like `boto3.Session`.

```
from boto3_session import Session

session = Session()
s3 = session('s3')
bucket = s3.Bucket(...)
...
