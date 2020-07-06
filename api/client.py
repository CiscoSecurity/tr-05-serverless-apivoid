import requests

from flask import current_app

from api.errors import CriticalError, StandardHttpError


NOT_CRITICAL_ERRORS = ('IP address is not valid', 'Host is not valid')


class APIVoidClient:
    def __init__(self, payload):
        self.api_url = current_app.config['API_URL']
        self.headers = {
            'User-Agent': current_app.config['USER_AGENT']
        }
        self.params = payload

    def _get(self, endpoint, params):
        params.update(self.params)
        url = current_app.config['API_URL'].format(endpoint=endpoint)
        response = requests.get(url, headers=self.headers, params=params)

        if not response.ok:
            raise StandardHttpError(response)

        error = response.json().get('error')
        if error:
            if error in NOT_CRITICAL_ERRORS:
                return {}
            else:
                raise CriticalError(error)

        return response.json()

    def check_health(self):
        _ = self._get('iprep', {'stats': 'true'})

    def get_data(self, observable):
        data = {}
        if observable['type'] == 'ip':
            data = self._get('iprep', {'ip': observable['value']})
        elif observable['type'] == 'domain':
            data = self._get('domainbl', {'host': observable['value']})
        return data
