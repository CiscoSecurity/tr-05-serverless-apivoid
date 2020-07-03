INVALID_ARGUMENT = 'invalid argument'
PERMISSION_DENIED = 'permission denied'
UNKNOWN = 'unknown'
UNAUTHORIZED = 'unauthorized'


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


class InvalidJWTError(TRFormattedError):
    def __init__(self, message):
        super().__init__(PERMISSION_DENIED, message)


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


class UnsupportedObservableTypeError(InvalidArgumentError):
    def __init__(self, type_):
        super().__init__(
            f'Unsupported observable error: {type_}'
        )
