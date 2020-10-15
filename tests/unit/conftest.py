from datetime import datetime
from http import HTTPStatus
from unittest.mock import MagicMock
from requests.exceptions import SSLError

from authlib.jose import jwt
from pytest import fixture

from api.errors import INVALID_ARGUMENT, AUTH_ERROR
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

    payload = {'key': 'test_api_key'}

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


def apivoid_response_mock(status_code, payload=None, reason=None):
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
    return apivoid_response_mock(
        HTTPStatus.OK, payload={
            "elapsed_time": "0.01",
            "credits_remained": 2517.01,
            "estimated_queries": "31,462",
            "success": "true"
        }
    )


@fixture(scope='function')
def apivoid_success_response():
    return apivoid_response_mock(
        HTTPStatus.OK, payload={
                "data": {
                    "report": {
                        "ip": "1.1.1.1",
                        "blacklists": {
                            "engines": {
                                "15": {
                                    "engine": "Blacklists_co",
                                    "detected": True,
                                    "reference": "http://blacklists.co/",
                                    "elapsed": "0.00"
                                },
                                "45": {
                                    "engine": "LAPPS Grid Blacklist",
                                    "detected": True,
                                    "reference": "http://www.lappsgrid.org/",
                                    "elapsed": "0.00"
                                },
                                "65": {
                                    "engine": "PhishTank",
                                    "detected": False,
                                    "reference": "http://www.phishtank.com/",
                                    "elapsed": "0.00"
                                },
                                "72": {
                                    "engine": "Rutgers Drop List",
                                    "detected": False,
                                    "reference": "http://www.rutgers.edu/",
                                    "elapsed": "0.00"
                                },
                            },
                            "detections": 2,
                            "engines_count": 88,
                            "detection_rate": "3%",
                            "scantime": "0.58"
                        },
                    }
                },
                "credits_remained": 2511.65,
                "estimated_queries": "31,395",
                "elapsed_time": "0.68",
                "success": "true"
            }
    )


@fixture(scope='function')
def apivoid_internal_server_error():
    return apivoid_response_mock(
        HTTPStatus.INTERNAL_SERVER_ERROR, reason='Internal Server Error'
    )


@fixture(scope='session')
def apivoid_response_unauthorized_creds(secret_key):
    return apivoid_response_mock(
        HTTPStatus.OK,
        {
            "elapsed_time": "0.00",
            "error": "API key is not valid"
        }
    )


@fixture(scope='session')
def apivoid_response_invalid_host(secret_key):
    return apivoid_response_mock(
        HTTPStatus.OK,
        {
            "elapsed_time": "0.00",
            "error": "Host is not valid"
        }
    )


@fixture(scope='module')
def invalid_jwt_expected_payload(route):
    return expected_payload(
        route,
        {
            "errors": [
                {
                    "code": AUTH_ERROR,
                    "message": "Authorization failed: "
                               "Failed to decode JWT with provided key",
                    "type": "fatal"
                }
            ]
        }
    )


@fixture(scope='module')
def authorization_header_is_missing_expected_payload(route):
    return expected_payload(
        route,
        {
            "errors": [
                {
                    "code": "authorization error",
                    "message": "Authorization failed: "
                               "Authorization header is missing",
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
                {
                    "code": INVALID_ARGUMENT,
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
                    "code": AUTH_ERROR,
                    "message": "Authorization failed: API key is not valid",
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


@fixture(scope='session')
def apivoid_ssl_exception_mock(secret_key):
    mock_exception = MagicMock()
    mock_exception.reason.args.__getitem__().verify_message \
        = 'self signed certificate'
    return SSLError(mock_exception)


@fixture(scope='module')
def ssl_error_expected_payload(route, client):
    if route in ('/observe/observables', '/health'):
        return {
            'errors': [
                {
                    'code': 'unknown',
                    'message': 'Unable to verify SSL certificate: '
                               'Self signed certificate',
                    'type': 'fatal'
                }
            ]
        }

    if route.endswith('/deliberate/observables'):
        return {'data': {}}

    return {'data': []}


@fixture(scope='module')
def success_enrich_body():
    return {
        "data": {
            "indicators": {
                "count": 2,
                "docs": [
                    {
                        "confidence": "High",
                        "producer": "APIVoid",
                        "schema_version": "1.0.17",
                        "short_description": "Feed: Blacklists_co",
                        "tlp": "white",
                        "type": "indicator",
                        "title": "Feed: Blacklists_co",
                        "valid_time": {}
                    },
                    {
                        "confidence": "High",
                        "producer": "APIVoid",
                        "schema_version": "1.0.17",
                        "short_description": "Feed: LAPPS Grid Blacklist",
                        "tlp": "white",
                        "type": "indicator",
                        "title": "Feed: LAPPS Grid Blacklist",
                        "valid_time": {}
                    }
                ]
            },
            "sightings": {
                "count": 2,
                "docs": [
                    {
                        "confidence": "High",
                        "count": 1,
                        "description": "Detected on blocklist",
                        "schema_version": "1.0.17",
                        "source": "Blacklists_co",
                        "source_uri": "http://blacklists.co/",
                        "observables": [
                            {
                                "type": "ip",
                                "value": "1.1.1.1"
                            }
                        ],
                        "type": "sighting"
                    },
                    {
                        "confidence": "High",
                        "count": 1,
                        "description": "Detected on blocklist",
                        "schema_version": "1.0.17",
                        "source": "LAPPS Grid Blacklist",
                        "source_uri": "http://www.lappsgrid.org/",
                        "observables": [
                            {
                                "type": "ip",
                                "value": "1.1.1.1"
                            }
                        ],
                        "type": "sighting"
                    }
                ]
            },
            "relationships": {
                "count": 2,
                "docs": [
                    {
                        "relationship_type": "member-of",
                        "schema_version": "1.0.17",
                        "type": "relationship"
                    },
                    {
                        "relationship_type": "member-of",
                        "schema_version": "1.0.17",
                        "type": "relationship"
                    }
                ]
            }
        }
    }


@fixture(scope='module')
def success_enrich_expected_payload(route, success_enrich_body):
    return expected_payload(route, success_enrich_body)
