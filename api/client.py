import requests

from flask import current_app

from api.errors import CriticalError, StandardHttpError


NOT_CRITICAL_ERRORS = ("IP address is not valid", "Host is not valid")


class APIVoidClient:
    def __init__(self, token):
        self.api_url = current_app.config['API_URL']
        self.headers = {
            'User-Agent': current_app.config['USER_AGENT']
        }
        self.params = token

    def _get(self, endpoint, params):
        params.update(self.params)  # ToDo
        url = current_app.config['API_URL'].format(endpoint=endpoint)
        response = requests.get(url, headers=self.headers, params=params)

        if not response.ok:
            raise StandardHttpError(response)

        error = response.json().get('error')
        if error not in (NOT_CRITICAL_ERRORS, None):
            raise CriticalError(error)

        return response.json()

    def check_health(self):
        self._get('iprep', {'stats': ''})
