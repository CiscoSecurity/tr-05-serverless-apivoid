INVALID_ARGUMENT = 'invalid argument'
PERMISSION_DENIED = 'permission denied'
UNKNOWN = 'unknown'
UNAUTHORIZED = 'unauthorized'
AUTH_ERROR = 'authorization error'


class TRFormattedError(Exception):
    def __init__(self, code, message, type_='fatal'):
        self.code = code or 'unknown'
        self.message = message or 'Something went wrong.'
        self.type_ = type_

    @property
    def json(self):
        return {'type': self.type_,
                'code': self.code.lower(),
                'message': self.message}


class CriticalError(TRFormattedError):
    def __init__(self, message):
        api_errors_standardisation = {
            'API key is not valid': UNAUTHORIZED,
            'API key has been disabled or does not exist': UNAUTHORIZED,
        }

        super().__init__(
            api_errors_standardisation.get(message),
            message
        )


class APIVoidSSLError(TRFormattedError):
    def __init__(self, error):
        error = error.args[0].reason.args[0]
        message = getattr(error, 'verify_message', error.args[0]).capitalize()
        super().__init__(
            UNKNOWN,
            f'Unable to verify SSL certificate: {message}'
        )


class AuthorizationError(TRFormattedError):
    def __init__(self, message):
        super().__init__(
            AUTH_ERROR,
            f'Authorization failed: {message}'
        )


class StandardHttpError(TRFormattedError):
    def __init__(self, response):
        super().__init__(
            response.reason,
            'An error occurred on the APIVoid side.'
        )


class InvalidArgumentError(TRFormattedError):
    def __init__(self, message):
        super().__init__(
            INVALID_ARGUMENT,
            f'Invalid JSON payload received. {message}'
        )


class WatchdogError(TRFormattedError):
    def __init__(self):
        super().__init__(
            code='health check failed',
            message='Invalid Health Check'
        )
