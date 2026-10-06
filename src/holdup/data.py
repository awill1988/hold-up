"""Immutable standard-library values inside the runtime; JSON at its boundaries."""

from collections.abc import Mapping
from functools import wraps
from types import MappingProxyType


def freeze(value):
    if isinstance(value, Mapping):
        return MappingProxyType({key: freeze(item) for key, item in value.items()})
    if isinstance(value, (list, tuple)):
        return tuple(freeze(item) for item in value)
    if isinstance(value, (set, frozenset)):
        return frozenset(freeze(item) for item in value)
    if value is None or isinstance(value, (bool, int, float, str, bytes)):
        return value
    raise TypeError(f"unsupported immutable value: {type(value).__name__}")


def immutable_result(function):
    @wraps(function)
    def wrapped(*args, **kwargs):
        return freeze(function(*args, **kwargs))

    return wrapped


def json_value(value):
    if isinstance(value, Mapping):
        return dict(value)
    raise TypeError(f"unsupported json value: {type(value).__name__}")
