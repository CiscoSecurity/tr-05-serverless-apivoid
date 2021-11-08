import jwt

from app import app
from pytest import fixture
from http import HTTPStatus
from api.utils import WRONG_KEY
from unittest.mock import MagicMock
from requests.exceptions import SSLError
from tests.unit.mock_for_tests import PRIVATE_KEY
from api.errors import INVALID_ARGUMENT, AUTH_ERROR


@fixture(scope='session')
def client():
    app.rsa_private_key = PRIVATE_KEY

    app.testing = True

    with app.test_client() as client:
        yield client


@fixture(scope='session')
def valid_jwt(client):
    def _make_jwt(
            key='some_key',
            jwks_host='visibility.amp.cisco.com',
            aud='http://localhost',
            kid='02B1174234C29F8EFB69911438F597FF3FFEE6B7',
            ctr_entities_limit=0,
            wrong_structure=False,
            wrong_jwks_host=False,
    ):
        payload = {
            'key': key,
            'jwks_host': jwks_host,
            'aud': aud,
            'CTR_ENTITIES_LIMIT': ctr_entities_limit
        }

        if wrong_jwks_host:
            payload.pop('jwks_host')

        if wrong_structure:
            payload.pop('key')

        return jwt.encode(
            payload, client.application.rsa_private_key, algorithm='RS256',
            headers={
                'kid': kid
            }
        )

    return _make_jwt


@fixture(scope='module')
def valid_json():
    return [{'type': 'ip', 'value': '1.1.1.1'}]


@fixture(scope='module')
def invalid_json():
    return [{'type': 'ip'}]


def apivoid_response_mock(status_code, payload=None, reason=None):
    mock_response = MagicMock()

    mock_response.status_code = status_code
    mock_response.ok = status_code == HTTPStatus.OK

    mock_response.json = lambda: payload
    mock_response.reason = reason

    return mock_response


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
def apivoid_response_unauthorized_creds():
    return apivoid_response_mock(
        HTTPStatus.OK,
        {
            "elapsed_time": "0.00",
            "error": "API key is not valid"
        }
    )


@fixture(scope='session')
def apivoid_response_invalid_host():
    return apivoid_response_mock(
        HTTPStatus.OK,
        {
            "elapsed_time": "0.00",
            "error": "Host is not valid"
        }
    )


@fixture(scope='module')
def invalid_jwt_expected_payload():
    return {
        "errors": [
            {
                "code": AUTH_ERROR,
                "message": f"Authorization failed: {WRONG_KEY}",
                "type": "fatal"
            }
        ]
    }


@fixture(scope='module')
def authorization_header_is_missing_expected_payload():
    return {
            "errors": [
                {
                    "code": "authorization error",
                    "message": "Authorization failed: "
                               "Authorization header is missing",
                    "type": "fatal"
                }
            ]
        }


@fixture(scope='module')
def invalid_json_expected_payload():
    return {
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


@fixture(scope='module')
def unauthorized_creds_expected_payload():
    return {
            "errors": [
                {
                    "code": AUTH_ERROR,
                    "message": "Authorization failed: API key is not valid",
                    "type": "fatal"
                }
            ]
        }


@fixture(scope='module')
def internal_server_error_expected_payload():
    return {
            "errors": [
                {
                    "code": "internal server error",
                    "message": "An error occurred on the APIVoid side.",
                    "type": "fatal"
                }
            ]
        }


@fixture(scope='session')
def apivoid_ssl_exception_mock():
    mock_exception = MagicMock()
    mock_exception.reason.args.__getitem__().verify_message \
        = 'self signed certificate'
    return SSLError(mock_exception)


@fixture(scope='module')
def ssl_error_expected_payload():
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


@fixture(scope='module')
def success_enrich_expected_payload():
    return {
        "data": {
            "indicators": {
                "count": 2,
                "docs": [
                    {
                        "confidence": "High",
                        "producer": "APIVoid",
                        "schema_version": "1.0.22",
                        "short_description": "Feed: Blacklists_co",
                        "tlp": "white",
                        "type": "indicator",
                        "title": "Feed: Blacklists_co",
                        "valid_time": {}
                    },
                    {
                        "confidence": "High",
                        "producer": "APIVoid",
                        "schema_version": "1.0.22",
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
                        "schema_version": "1.0.22",
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
                        "schema_version": "1.0.22",
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
                        "schema_version": "1.0.22",
                        "type": "relationship"
                    },
                    {
                        "relationship_type": "member-of",
                        "schema_version": "1.0.22",
                        "type": "relationship"
                    }
                ]
            }
        }
    }
