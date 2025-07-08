from pytest import fixture
from .utils import headers
from http import HTTPStatus
from unittest.mock import patch
from ..conftest import apivoid_response_mock


def routes():
    yield '/observe/observables'


@fixture(scope='module', params=routes(), ids=lambda route: f'POST {route}')
def route(request):
    return request.param


@patch('requests.get')
def test_enrich_call_with_invalid_jwt_failure(
        mock_request, route, client, valid_jwt,
        invalid_jwt_expected_payload, test_keys_and_token
):
    mock_request.return_value = \
        apivoid_response_mock(status_code=HTTPStatus.OK,
                              payload=test_keys_and_token["jwks"])
    
    token = valid_jwt(private_key=test_keys_and_token["wrong_private_key"])
    response = client.post(route, headers=headers(token))

    assert response.status_code == HTTPStatus.OK
    assert response.json == invalid_jwt_expected_payload


def test_enrich_call_without_jwt_failure(
        route, client, authorization_header_is_missing_expected_payload
):
    response = client.post(route)

    assert response.status_code == HTTPStatus.OK
    assert response.json == authorization_header_is_missing_expected_payload


@patch('requests.get')
def test_enrich_call_with_valid_jwt_but_invalid_json_failure(
        mock_request, route, client, valid_jwt, invalid_json,
        invalid_json_expected_payload, test_keys_and_token
):
    mock_request.return_value = \
        apivoid_response_mock(status_code=HTTPStatus.OK,
                              payload=test_keys_and_token["jwks"])
    response = client.post(route,
                           headers=headers(valid_jwt()),
                           json=invalid_json)
    assert response.status_code == HTTPStatus.OK
    assert response.json == invalid_json_expected_payload


@patch('requests.get')
def test_enrich_call_success(
        mock_request, route, client, valid_jwt, valid_json,
        success_enrich_expected_payload, apivoid_success_response,
        test_keys_and_token):
    mock_request.side_effect = (
        apivoid_response_mock(status_code=HTTPStatus.OK,
                              payload=test_keys_and_token["jwks"]),
        apivoid_success_response)
    response = client.post(route, headers=headers(valid_jwt()),
                           json=valid_json)
    assert response.status_code == HTTPStatus.OK
    response = response.get_json()
    if response.get('data') and response['data'].get('sightings'):
        for doc in response['data']['sightings']['docs']:
            assert doc.pop('id')
            assert doc.pop('observed_time')
        for doc in response['data']['indicators']['docs']:
            assert doc.pop('id')
        for doc in response['data']['relationships']['docs']:
            assert doc.pop('id')
            assert doc.pop('source_ref').startswith('transient:sighting-')
            assert doc.pop('target_ref').startswith('transient:indicator-')
    assert response == success_enrich_expected_payload


@fixture(scope='module')
def valid_json_multiple():
    return [{'type': 'ip', 'value': '1.1.1.1'},
            {'type': 'domain', 'value': '1.1.1.1'},
            {'type': 'domain', 'value': 'cisco.com'}]


@patch('requests.get')
def test_enrich_call_with_extended_error_handling(
        mock_request, route, client, valid_jwt, valid_json_multiple,
        success_enrich_expected_payload, apivoid_success_response,
        apivoid_response_invalid_host, internal_server_error_expected_payload,
        apivoid_internal_server_error, test_keys_and_token):
    mock_request.side_effect = [
        apivoid_response_mock(status_code=HTTPStatus.OK,
                              payload=test_keys_and_token["jwks"]),
        apivoid_success_response,
        apivoid_response_invalid_host,
        apivoid_internal_server_error
    ]
    response = client.post(route,
                           headers=headers(valid_jwt()),
                           json=valid_json_multiple)
    assert response.status_code == HTTPStatus.OK
    response = response.get_json()
    for doc in response['data']['sightings']['docs']:
        assert doc.pop('id')
        assert doc.pop('observed_time')
    for doc in response['data']['indicators']['docs']:
        assert doc.pop('id')
    for doc in response['data']['relationships']['docs']:
        assert doc.pop('id')
        assert doc.pop('source_ref').startswith('transient:sighting-')
        assert doc.pop('target_ref').startswith('transient:indicator-')
    assert response['errors'] == \
        internal_server_error_expected_payload['errors']
    assert response['data'] == success_enrich_expected_payload['data']


@patch('requests.get')
def test_enrich_with_ssl_error(
        mock_request, route, client, valid_jwt,
        valid_json, apivoid_ssl_exception_mock,
        ssl_error_expected_payload, test_keys_and_token):

    mock_request.side_effect = (
        apivoid_response_mock(status_code=HTTPStatus.OK,
                              payload=test_keys_and_token["jwks"]),
        apivoid_ssl_exception_mock
    )

    response = client.post(
        route, headers=headers(valid_jwt()), json=valid_json
    )

    assert response.status_code == HTTPStatus.OK

    response = response.get_json()
    assert response == ssl_error_expected_payload
