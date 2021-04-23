from unittest.mock import patch

from .utils import headers
from pytest import fixture
from http import HTTPStatus
from api.errors import AUTH_ERROR
from ..conftest import apivoid_response_mock
from requests.exceptions import InvalidURL, ConnectionError
from ..mock_for_tests import (
    EXPECTED_RESPONSE_OF_JWKS_ENDPOINT,
    RESPONSE_OF_JWKS_ENDPOINT_WITH_WRONG_KEY
)
from api.utils import (
    NO_AUTH_HEADER,
    WRONG_AUTH_TYPE,
    WRONG_JWKS_HOST,
    WRONG_PAYLOAD_STRUCTURE,
    JWKS_HOST_MISSING,
    WRONG_KEY,
    WRONG_JWT_STRUCTURE,
    WRONG_AUDIENCE,
    KID_NOT_FOUND
)


def routes():
    yield '/health'
    yield '/observe/observables'


@fixture(scope='module', params=routes(), ids=lambda route: f'POST {route}')
def route(request):
    return request.param


@fixture(scope='module')
def authorization_errors_expected_payload(route):
    def _make_payload_message(message):
        payload = {
            'errors':
                [
                    {
                        'code': AUTH_ERROR,
                        'message': f'Authorization failed: {message}',
                        'type': 'fatal'
                    }
                ]

        }
        return payload

    return _make_payload_message


def test_call_with_authorization_header_failure(
        route, client, valid_json,
        authorization_errors_expected_payload
):
    response = client.post(route, json=valid_json)

    assert response.status_code == HTTPStatus.OK
    assert response.json == authorization_errors_expected_payload(
        NO_AUTH_HEADER
    )


def test_call_with_wrong_auth_type(
        route, client, valid_json, valid_jwt,
        authorization_errors_expected_payload
):
    response = client.post(
        route, json=valid_json,
        headers=headers(valid_jwt(), auth_type='not')
    )

    assert response.status_code == HTTPStatus.OK
    assert response.json == authorization_errors_expected_payload(
        WRONG_AUTH_TYPE
    )


@patch('requests.get')
def test_call_with_wrong_jwks_host(
        mock_request, route, client, valid_json, valid_jwt,
        authorization_errors_expected_payload
):
    for error in (ConnectionError, InvalidURL):
        mock_request.side_effect = error()

        response = client.post(
            route, json=valid_json, headers=headers(valid_jwt())
        )

        assert response.status_code == HTTPStatus.OK
        assert response.json == authorization_errors_expected_payload(
            WRONG_JWKS_HOST
        )


@patch('requests.get')
def test_call_with_wrong_jwt_payload_structure(
        mock_request, route, client, valid_json, valid_jwt,
        authorization_errors_expected_payload
):
    mock_request.return_value = \
        apivoid_response_mock(status_code=HTTPStatus.OK,
                              payload=EXPECTED_RESPONSE_OF_JWKS_ENDPOINT)

    response = client.post(
        route, json=valid_json,
        headers=headers(valid_jwt(wrong_structure=True))
    )
    assert response.status_code == HTTPStatus.OK
    assert response.json == authorization_errors_expected_payload(
        WRONG_PAYLOAD_STRUCTURE
    )


@patch('requests.get')
def test_call_with_missing_jwks_host(
        mock_request, route, client, valid_json, valid_jwt,
        authorization_errors_expected_payload
):
    mock_request.return_value = \
        apivoid_response_mock(status_code=HTTPStatus.OK,
                              payload=EXPECTED_RESPONSE_OF_JWKS_ENDPOINT)

    response = client.post(
        route, json=valid_json,
        headers=headers(valid_jwt(jwks_host=''))
    )
    assert response.status_code == HTTPStatus.OK
    assert response.json == authorization_errors_expected_payload(
        JWKS_HOST_MISSING
    )


@patch('requests.get')
def test_call_with_wrong_key(
        mock_request, route, client, valid_json, valid_jwt,
        authorization_errors_expected_payload
):
    mock_request.return_value = \
        apivoid_response_mock(status_code=HTTPStatus.OK,
                              payload=RESPONSE_OF_JWKS_ENDPOINT_WITH_WRONG_KEY)

    response = client.post(
        route, json=valid_json,
        headers=headers(valid_jwt())
    )
    assert response.status_code == HTTPStatus.OK
    assert response.json == authorization_errors_expected_payload(
        WRONG_KEY
    )


@patch('requests.get')
def test_call_with_wrong_jwt_structure(
        mock_request, route, client, valid_json,
        authorization_errors_expected_payload
):
    mock_request.return_value = \
        apivoid_response_mock(status_code=HTTPStatus.OK,
                              payload=EXPECTED_RESPONSE_OF_JWKS_ENDPOINT)

    response = client.post(
        route, json=valid_json,
        headers=headers('valid_jwt()')
    )
    assert response.status_code == HTTPStatus.OK
    assert response.json == authorization_errors_expected_payload(
        WRONG_JWT_STRUCTURE
    )


@patch('requests.get')
def test_call_with_wrong_audience(
        mock_request, route, client, valid_json, valid_jwt,
        authorization_errors_expected_payload
):
    mock_request.return_value = \
        apivoid_response_mock(status_code=HTTPStatus.OK,
                              payload=EXPECTED_RESPONSE_OF_JWKS_ENDPOINT)

    response = client.post(
        route, json=valid_json,
        headers=headers(valid_jwt(aud='wrong_aud'))
    )
    assert response.status_code == HTTPStatus.OK
    assert response.json == authorization_errors_expected_payload(
        WRONG_AUDIENCE
    )


@patch('requests.get')
def test_call_with_wrong_kid(
        mock_request, route, client, valid_json, valid_jwt,
        authorization_errors_expected_payload
):
    mock_request.return_value = \
        apivoid_response_mock(status_code=HTTPStatus.OK,
                              payload=EXPECTED_RESPONSE_OF_JWKS_ENDPOINT)

    response = client.post(
        route, json=valid_json,
        headers=headers(valid_jwt(kid='wrong_kid'))
    )
    assert response.status_code == HTTPStatus.OK
    assert response.json == authorization_errors_expected_payload(
        KID_NOT_FOUND
    )
