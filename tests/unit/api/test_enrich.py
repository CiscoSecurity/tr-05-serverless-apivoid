from http import HTTPStatus

from pytest import fixture
from unittest.mock import patch

from .utils import headers


def routes():
    yield '/deliberate/observables'
    yield '/observe/observables'
    yield '/refer/observables'


@fixture(scope='module', params=routes(), ids=lambda route: f'POST {route}')
def route(request):
    return request.param


def test_health_call_with_invalid_jwt_failure(
        route, client, invalid_jwt, invalid_jwt_expected_payload
):
    response = client.post(route, headers=headers(invalid_jwt))

    assert response.status_code == HTTPStatus.OK
    assert response.json == invalid_jwt_expected_payload


@fixture(scope='module')
def invalid_json():
    return [{'type': 'ip'}]


def test_enrich_call_with_valid_jwt_but_invalid_json_failure(
        route, client, valid_jwt, invalid_json, invalid_json_expected_payload
):
    response = client.post(route,
                           headers=headers(valid_jwt),
                           json=invalid_json)
    assert response.status_code == HTTPStatus.OK
    assert response.json == invalid_json_expected_payload


@fixture(scope='module')
def valid_json():
    return [{'type': 'ip', 'value': '1.1.1.1'}]


@patch('requests.get')
def test_enrich_call_success(
        mock_request, route, client, valid_jwt, valid_json,
        success_enrich_expected_payload, apivoid_success_response
):
    mock_request.return_value = apivoid_success_response
    response = client.post(route, headers=headers(valid_jwt), json=valid_json)
    assert response.status_code == HTTPStatus.OK
    response = response.get_json()
    if response.get('data') and response['data'].get('sightings'):
        for doc in response['data']['sightings']['docs']:
            assert doc.pop('id')
            assert doc.pop('observed_time')
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
        apivoid_internal_server_error
):
    mock_request.side_effect = [
        apivoid_success_response,
        apivoid_response_invalid_host,
        apivoid_internal_server_error
    ]
    response = client.post(
        route, headers=headers(valid_jwt), json=valid_json_multiple
    )
    assert response.status_code == HTTPStatus.OK
    response = response.get_json()
    if route.startswith('/observe'):
        for doc in response['data']['sightings']['docs']:
            assert doc.pop('id')
            assert doc.pop('observed_time')
        assert response['errors'] == \
            internal_server_error_expected_payload['errors']
    assert response['data'] == success_enrich_expected_payload['data']

