from pytest import fixture
from .utils import headers
from http import HTTPStatus
from unittest.mock import patch
from ..conftest import apivoid_response_mock
from ..mock_for_tests import (
    EXPECTED_RESPONSE_OF_JWKS_ENDPOINT,
    RESPONSE_OF_JWKS_ENDPOINT_WITH_WRONG_KEY
)


def routes():
    yield '/health'


@fixture(scope='module', params=routes(), ids=lambda route: f'POST {route}')
def route(request):
    return request.param


def test_health_call_without_jwt_failure(
        route, client, authorization_header_is_missing_expected_payload
):
    response = client.post(route)

    assert response.status_code == HTTPStatus.OK
    assert response.json == authorization_header_is_missing_expected_payload


@patch('requests.get')
def test_health_call_with_invalid_jwt_failure(
        mock_request, route, client, valid_jwt,
        invalid_jwt_expected_payload):
    mock_request.return_value = \
        apivoid_response_mock(status_code=HTTPStatus.OK,
                              payload=RESPONSE_OF_JWKS_ENDPOINT_WITH_WRONG_KEY)
    response = client.post(route,
                           headers=headers(valid_jwt(wrong_structure=True)))

    assert response.status_code == HTTPStatus.OK
    assert response.json == invalid_jwt_expected_payload


@patch('requests.get')
def test_health_call_with_unauthorized_creds_failure(
        mock_request, route, client, valid_jwt,
        apivoid_response_unauthorized_creds,
        unauthorized_creds_expected_payload):
    mock_request.side_effect = (
        apivoid_response_mock(status_code=HTTPStatus.OK,
                              payload=EXPECTED_RESPONSE_OF_JWKS_ENDPOINT),
        apivoid_response_unauthorized_creds
    )
    response = client.post(
        route, headers=headers(valid_jwt())
    )

    assert response.status_code == HTTPStatus.OK
    assert response.json == unauthorized_creds_expected_payload


@patch('requests.get')
def test_health_call_success(
        mock_request, route, client, valid_jwt, apivoid_health_response_ok):
    mock_request.side_effect = (
        apivoid_response_mock(status_code=HTTPStatus.OK,
                              payload=EXPECTED_RESPONSE_OF_JWKS_ENDPOINT),
        apivoid_health_response_ok
    )
    response = client.post(route, headers=headers(valid_jwt()))

    assert response.status_code == HTTPStatus.OK
    assert response.json == {'data': {'status': 'ok'}}


@patch('requests.get')
def test_health_call_failure(
        mock_request, route, client, valid_jwt,
        apivoid_internal_server_error, internal_server_error_expected_payload):
    mock_request.side_effect = (
        apivoid_response_mock(status_code=HTTPStatus.OK,
                              payload=EXPECTED_RESPONSE_OF_JWKS_ENDPOINT),
        apivoid_internal_server_error
    )
    response = client.post(route, headers=headers(valid_jwt()))

    assert response.status_code == HTTPStatus.OK
    assert response.json == internal_server_error_expected_payload


@patch('requests.get')
def test_health_with_ssl_error(
        mock_request, route, client, valid_jwt,
        apivoid_ssl_exception_mock,
        ssl_error_expected_payload):

    mock_request.side_effect = (
        apivoid_response_mock(status_code=HTTPStatus.OK,
                              payload=EXPECTED_RESPONSE_OF_JWKS_ENDPOINT),
        apivoid_ssl_exception_mock
    )

    response = client.post(
        route, headers=headers(valid_jwt())
    )

    assert response.status_code == HTTPStatus.OK

    response = response.get_json()
    assert response == ssl_error_expected_payload
