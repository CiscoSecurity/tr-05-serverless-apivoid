from pytest import fixture
from .utils import headers
from http import HTTPStatus
from unittest.mock import patch
from ..conftest import apivoid_response_mock


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
        invalid_jwt_expected_payload, test_keys_and_token):
    mock_request.return_value = \
        apivoid_response_mock(status_code=HTTPStatus.OK,
                              payload=test_keys_and_token["jwks"])
    token = valid_jwt(private_key=test_keys_and_token["wrong_private_key"], wrong_structure=True)
    response = client.post(route,
                           headers=headers(token))

    assert response.status_code == HTTPStatus.OK
    assert response.json == invalid_jwt_expected_payload


@patch('requests.get')
def test_health_call_with_unauthorized_creds_failure(
        mock_request, route, client, valid_jwt,
        apivoid_response_unauthorized_creds,
        unauthorized_creds_expected_payload, test_keys_and_token):
    mock_request.side_effect = (
        apivoid_response_mock(status_code=HTTPStatus.OK,
                              payload=test_keys_and_token["jwks"]),
        apivoid_response_unauthorized_creds
    )
    response = client.post(
        route, headers=headers(valid_jwt())
    )

    assert response.status_code == HTTPStatus.OK
    assert response.json == unauthorized_creds_expected_payload


@patch('requests.get')
def test_health_call_success(
        mock_request, route, client, valid_jwt, apivoid_health_response_ok,
        test_keys_and_token):
    mock_request.side_effect = (
        apivoid_response_mock(status_code=HTTPStatus.OK,
                              payload=test_keys_and_token["jwks"]),
        apivoid_health_response_ok
    )
    response = client.post(route, headers=headers(valid_jwt()))

    assert response.status_code == HTTPStatus.OK
    assert response.json == {'data': {'status': 'ok'}}


@patch('requests.get')
def test_health_call_failure(
        mock_request, route, client, valid_jwt,
        apivoid_internal_server_error, internal_server_error_expected_payload,
        test_keys_and_token):
    mock_request.side_effect = (
        apivoid_response_mock(status_code=HTTPStatus.OK,
                              payload=test_keys_and_token["jwks"]),
        apivoid_internal_server_error
    )
    response = client.post(route, headers=headers(valid_jwt()))

    assert response.status_code == HTTPStatus.OK
    assert response.json == internal_server_error_expected_payload


@patch('requests.get')
def test_health_with_ssl_error(
        mock_request, route, client, valid_jwt,
        apivoid_ssl_exception_mock,
        ssl_error_expected_payload,
        test_keys_and_token):

    mock_request.side_effect = (
        apivoid_response_mock(status_code=HTTPStatus.OK,
                              payload=test_keys_and_token["jwks"]),
        apivoid_ssl_exception_mock
    )

    response = client.post(
        route, headers=headers(valid_jwt())
    )

    assert response.status_code == HTTPStatus.OK

    response = response.get_json()
    assert response == ssl_error_expected_payload
