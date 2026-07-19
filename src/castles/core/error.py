from __future__ import annotations


class CastlesError(Exception):
    """Base class for expected, sanitized failures."""


class ConfigurationError(CastlesError):
    pass


class AuthorizationError(CastlesError):
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
