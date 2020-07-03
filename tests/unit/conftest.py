from datetime import datetime
from http import HTTPStatus
from unittest.mock import MagicMock

from authlib.jose import jwt
from pytest import fixture

from api.errors import PERMISSION_DENIED, INVALID_ARGUMENT, UNAUTHORIZED
from app import app


@fixture(scope='session')
def secret_key():
    # Generate some string based on the current datetime.
    return datetime.utcnow().isoformat()


@fixture(scope='session')
def client(secret_key):
    app.secret_key = secret_key

    app.testing = True

    with app.test_client() as client:
        yield client


@fixture(scope='session')
def valid_jwt(client):
    header = {'alg': 'HS256'}

    payload = {'username': 'gdavoian', 'superuser': False}

    secret_key = client.application.secret_key

    return jwt.encode(header, payload, secret_key).decode('ascii')


@fixture(scope='session')
def invalid_jwt(valid_jwt):
    header, payload, signature = valid_jwt.split('.')

    def jwt_decode(s: str) -> dict:
        from authlib.common.encoding import urlsafe_b64decode, json_loads
        return json_loads(urlsafe_b64decode(s.encode('ascii')))

    def jwt_encode(d: dict) -> str:
        from authlib.common.encoding import json_dumps, urlsafe_b64encode
        return urlsafe_b64encode(json_dumps(d).encode('ascii')).decode('ascii')

    payload = jwt_decode(payload)

    # Corrupt the valid JWT by tampering with its payload.
    payload['superuser'] = True

    payload = jwt_encode(payload)

    return '.'.join([header, payload, signature])


def apivoid_api_response_mock(status_code, payload=None, reason=None):
    mock_response = MagicMock()

    mock_response.status_code = status_code
    mock_response.ok = status_code == HTTPStatus.OK

    mock_response.json = lambda: payload
    mock_response.reason = reason

    return mock_response


def expected_payload(route, body):
    if route.endswith('/deliberate/observables'):
        return {'data': {}}

    if route.endswith('/refer/observables'):
        return {'data': []}

    return body


@fixture(scope='function')
def apivoid_health_response_ok():
    return apivoid_api_response_mock(
        HTTPStatus.OK, payload={
            "elapsed_time": "0.01",
            "credits_remained": 2517.01,
            "estimated_queries": "31,462",
            "success": "true"
        }
    )


@fixture(scope='function')
def apivoid_internal_server_error():
    return apivoid_api_response_mock(
        HTTPStatus.INTERNAL_SERVER_ERROR, reason='Internal Server Error'
    )


@fixture(scope='session')
def apivoid_response_unauthorized_creds(secret_key):
    return apivoid_api_response_mock(
        HTTPStatus.OK,
        {
            "elapsed_time": "0.00",
            "error": "API key is not valid"
        }
    )


@fixture(scope='module')
def invalid_jwt_expected_payload(route):
    return expected_payload(
        route,
        {
            "errors": [
                {
                    "code": PERMISSION_DENIED,
                    "message": "Invalid Authorization Bearer JWT.",
                    "type": "fatal"
                }
            ]
        }
    )


@fixture(scope='module')
def invalid_json_expected_payload(route):
    return expected_payload(
        route,
        {
            "errors": [
                {"code": INVALID_ARGUMENT,
                 "message":
                     "Invalid JSON payload received. "
                     "{0: {'value': ['Missing data for required field.']}}",
                 "type": "fatal"
                 }
            ]
        }
    )


@fixture(scope='module')
def unauthorized_creds_expected_payload(route):
    return expected_payload(
        route,
        {
            "errors": [
                {
                    "code": UNAUTHORIZED,
                    "message": "API key is not valid",
                    "type": "fatal"
                }
            ]
        }
    )


@fixture(scope='module')
def internal_server_error_expected_payload(route):
    return expected_payload(
        route,
        {
            "errors": [
                {
                    "code": "internal server error",
                    "message": "An error occurred on the APIVoid side.",
                    "type": "fatal"
                }
            ]
        }
    )
