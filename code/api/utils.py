import json
from json.decoder import JSONDecodeError

import jwt
import requests
from flask import request, current_app, jsonify, g
from jwt import InvalidSignatureError, InvalidAudienceError, DecodeError
from requests.exceptions import ConnectionError, InvalidURL, HTTPError
from requests.exceptions import SSLError

from api.errors import (
    InvalidArgumentError,
    AuthorizationError,
    APIVoidSSLError
)

NO_AUTH_HEADER = 'Authorization header is missing'
WRONG_AUTH_TYPE = 'Wrong authorization type'
WRONG_PAYLOAD_STRUCTURE = 'Wrong JWT payload structure'
WRONG_JWT_STRUCTURE = 'Wrong JWT structure'
WRONG_AUDIENCE = 'Wrong configuration-token-audience'
KID_NOT_FOUND = 'kid from JWT header not found in API response'
WRONG_KEY = ('Failed to decode JWT with provided key. '
             'Make sure domain in custom_jwks_host '
             'corresponds to your SecureX instance region.')
JWKS_HOST_MISSING = ('jwks_host is missing in JWT payload. Make sure '
                     'custom_jwks_host field is present in module_type')
WRONG_JWKS_HOST = ('Wrong jwks_host in JWT payload. Make sure domain follows '
                   'the visibility.<region>.cisco.com structure')


def set_ctr_entities_limit(payload):
    try:
        ctr_entities_limit = int(payload['CTR_ENTITIES_LIMIT'])
        assert ctr_entities_limit > 0
    except (KeyError, ValueError, AssertionError):
        ctr_entities_limit = current_app.config['CTR_DEFAULT_ENTITIES_LIMIT']
    current_app.config['CTR_ENTITIES_LIMIT'] = ctr_entities_limit


def get_public_key(jwks_host, token):
    """
    Get public key by requesting it from specified jwks host.
    """

    expected_errors = (
        ConnectionError,
        InvalidURL,
        JSONDecodeError,
        HTTPError,
    )

    try:
        response = requests.get(f"https://{jwks_host}/.well-known/jwks")
        response.raise_for_status()
        jwks = response.json()

        public_keys = {}
        for jwk in jwks['keys']:
            kid = jwk['kid']
            public_keys[kid] = jwt.algorithms.RSAAlgorithm.from_jwk(
                json.dumps(jwk)
            )
        kid = jwt.get_unverified_header(token)['kid']
        return public_keys.get(kid)
    except expected_errors:
        raise AuthorizationError(WRONG_JWKS_HOST)


def get_jwt():
    """
    Get authorization token and validate its signature against the public key
    from /.well-known/jwks endpoint. Extract and validate credentials.
    """

    expected_errors = {
        KeyError: WRONG_PAYLOAD_STRUCTURE,
        AssertionError: JWKS_HOST_MISSING,
        InvalidSignatureError: WRONG_KEY,
        DecodeError: WRONG_JWT_STRUCTURE,
        InvalidAudienceError: WRONG_AUDIENCE,
        TypeError: KID_NOT_FOUND
    }

    token = get_auth_token()
    try:
        jwks_payload = jwt.decode(token, options={'verify_signature': False})
        assert 'jwks_host' in jwks_payload
        jwks_host = jwks_payload.get('jwks_host')
        key = get_public_key(jwks_host, token)
        aud = request.url_root
        payload = jwt.decode(
            token, key=key, algorithms=['RS256'], audience=[aud.rstrip('/')]
        )
        set_ctr_entities_limit(payload)

        return payload['key']
    except tuple(expected_errors) as error:
        message = expected_errors[error.__class__]
        raise AuthorizationError(message)


def get_auth_token():
    """
    Parse the incoming request's Authorization header and validate it.
    """

    expected_errors = {
        KeyError: NO_AUTH_HEADER,
        AssertionError: WRONG_AUTH_TYPE
    }
    try:
        scheme, token = request.headers['Authorization'].split()
        assert scheme.lower() == 'bearer'
        return token
    except tuple(expected_errors) as error:
        raise AuthorizationError(expected_errors[error.__class__])


def get_json(schema):
    data = request.get_json(force=True, silent=True, cache=False)

    message = schema.validate(data)

    if message:
        raise InvalidArgumentError(message)

    return data


def jsonify_data(data):
    return jsonify({'data': data})


def format_docs(docs):
    return {'count': len(docs), 'docs': docs}


def jsonify_result():
    result = {'data': {}}

    if g.get('sightings'):
        result['data']['sightings'] = format_docs(g.sightings)
    if g.get('indicators'):
        result['data']['indicators'] = format_docs(g.indicators)
    if g.get('relationships'):
        result['data']['relationships'] = format_docs(g.relationships)

    if g.get('errors'):
        result['errors'] = g.errors
        if not result['data']:
            del result['data']

    return jsonify(result)


def ssl_error_handler(func):
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except SSLError as error:
            raise APIVoidSSLError(error)

    return wrapper
