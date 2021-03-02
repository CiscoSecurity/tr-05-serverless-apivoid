import json
from uuid import NAMESPACE_X500


class Config:
    settings = json.load(open('container_settings.json', 'r'))
    VERSION = settings["VERSION"]

    USER_AGENT = ('SecureX Threat Response Integrations '
                  '<tr-integrations-support@cisco.com>')

    API_URL = 'https://endpoint.apivoid.com/{endpoint}/v1/pay-as-you-go/'

    CTR_DEFAULT_ENTITIES_LIMIT = 100

    CTIM_DEFAULTS = {
        'schema_version': '1.0.22',
    }

    NAMESPACE_BASE = NAMESPACE_X500
