import os

from version import VERSION


class Config:
    VERSION = VERSION

    SECRET_KEY = os.environ.get('SECRET_KEY', '')

    USER_AGENT = ('Cisco Threat Response Integrations '
                  '<tr-integrations-support@cisco.com>')

    API_URL = 'https://endpoint.apivoid.com/{endpoint}/v1/pay-as-you-go/'

    CTR_DEFAULT_ENTITIES_LIMIT = 100

    try:
        CTR_ENTITIES_LIMIT = int(os.environ['CTR_ENTITIES_LIMIT'])
        assert CTR_ENTITIES_LIMIT > 0
    except (KeyError, ValueError, AssertionError):
        CTR_ENTITIES_LIMIT = CTR_DEFAULT_ENTITIES_LIMIT

    CTIM_DEFAULTS = {
        'schema_version': '1.0.17',
    }
