from __future__ import annotations


class CastlesError(Exception):
    """Base class for expected, sanitized failures."""


class ConfigurationError(CastlesError):
    pass


class SetupError(ConfigurationError):
    """Base class for guided-setup failures."""


class ClientFileNotFoundError(SetupError):
    pass


class ClientUnreadableError(SetupError):
    pass


class ClientOversizedError(SetupError):
    pass


class ClientMalformedError(SetupError):
    pass


class ClientTypeError(SetupError):
    pass


class ClientEndpointError(SetupError):
    pass


class ClientRedirectError(SetupError):
    pass


class ClientPersistenceError(SetupError):
    pass


class NoManagedClientError(SetupError):
    pass


class DownloadsUnavailableError(NoManagedClientError):
    pass


class NoClientCandidateError(NoManagedClientError):
    pass


class MultipleClientCandidatesError(NoManagedClientError):
    pass


class SetupCancelledError(SetupError):
    pass


class AuthorizationError(CastlesError):
    pass


class BrowserOpenError(AuthorizationError):
    pass


class CallbackTimeoutError(AuthorizationError):
    pass


class CallbackStateError(AuthorizationError):
    pass


class StaleCallbackError(CallbackStateError):
    pass


class AuthorizationDeniedError(AuthorizationError):
    pass


class TokenExchangeError(AuthorizationError):
    pass


class MissingScopeError(AuthorizationError):
    pass


class UnexpectedScopeError(AuthorizationError):
    pass


class MalformedCredentialsError(AuthorizationError):
    pass


class TokenPersistenceError(AuthorizationError):
    pass


class ProviderError(CastlesError):
    pass


class StaleCheckpointError(ProviderError):
    pass


class ParsingError(CastlesError):
    pass


class StorageError(CastlesError):
    pass


class CorruptionError(StorageError):
    pass


class LockingError(StorageError):
    pass


class ExportError(CastlesError):
    pass


class InputError(CastlesError):
    pass
