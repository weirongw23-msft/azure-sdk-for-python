# --------------------------------------------------------------------------
#
# Copyright (c) Microsoft Corporation. All rights reserved.
#
# The MIT License (MIT)
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the ""Software""), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
#
# --------------------------------------------------------------------------
"""Provide access to settings for globally used Azure configuration values.
"""
from __future__ import annotations
from collections import namedtuple
from enum import Enum
import logging
import os
from typing import (
    Type,
    Optional,
    Callable,
    Union,
    Dict,
    Any,
    TypeVar,
    Tuple,
    Generic,
    Mapping,
    List,
    TYPE_CHECKING,
)
from ._azure_clouds import AzureClouds

if TYPE_CHECKING:
    from azure.core.tracing import AbstractSpan

ValidInputType = TypeVar("ValidInputType")
ValueType = TypeVar("ValueType")


__all__ = ("settings", "Settings")


# https://www.python.org/dev/peps/pep-0484/#support-for-singleton-types-in-unions
class _Unset(Enum):
    token = 0


_unset = _Unset.token


def convert_bool(value: Union[str, bool]) -> bool:
    """Convert a string to True or False

    If a boolean is passed in, it is returned as-is. Otherwise the function
    maps the following strings, ignoring case:

    * "yes", "1", "on" -> True
    " "no", "0", "off" -> False

    :param value: the value to convert
    :type value: str or bool
    :returns: A boolean value matching the intent of the input
    :rtype: bool
    :raises ValueError: If conversion to bool fails

    """
    if isinstance(value, bool):
        return value
    val = value.lower()
    if val in ["yes", "1", "on", "true", "True"]:
        return True
    if val in ["no", "0", "off", "false", "False"]:
        return False
    raise ValueError("Cannot convert {} to boolean value".format(value))


def convert_tracing_enabled(value: Optional[Union[str, bool]]) -> bool:
    """Convert tracing value to bool with regard to tracing implementation.

    :param value: the value to convert
    :type value: str or bool or None
    :returns: A boolean value matching the intent of the input
    :rtype: bool
    :raises ValueError: If conversion to bool fails
    """
    if value is None:
        # If tracing_enabled was not explicitly set to a boolean, determine tracing enablement
        # based on tracing_implementation being set.
        if settings.tracing_implementation():
            return True
        return False
    return convert_bool(value)


_levels = {
    "CRITICAL": logging.CRITICAL,
    "ERROR": logging.ERROR,
    "WARNING": logging.WARNING,
    "INFO": logging.INFO,
    "DEBUG": logging.DEBUG,
}


def convert_logging(value: Union[str, int]) -> int:
    """Convert a string to a Python logging level

    If a log level is passed in, it is returned as-is. Otherwise the function
    understands the following strings, ignoring case:

    * "critical"
    * "error"
    * "warning"
    * "info"
    * "debug"

    :param value: the value to convert
    :type value: str or int
    :returns: A log level as an int. See the logging module for details.
    :rtype: int
    :raises ValueError: If conversion to log level fails

    """
    if isinstance(value, int):
        # If it's an int, return it. We don't need to check if it's in _levels, as custom int levels are allowed.
        # https://docs.python.org/3/library/logging.html#levels
        return value
    val = value.upper()
    level = _levels.get(val)
    if not level:
        raise ValueError("Cannot convert {} to log level, valid values are: {}".format(value, ", ".join(_levels)))
    return level


def convert_azure_cloud(value: Union[str, AzureClouds]) -> AzureClouds:
    """Convert a string to an Azure Cloud

    :param value: the value to convert
    :type value: string
    :returns: An AzureClouds enum value
    :rtype: AzureClouds
    :raises ValueError: If conversion to AzureClouds fails

    """
    if isinstance(value, AzureClouds):
        return value
    if isinstance(value, str):
        azure_clouds = {cloud.name: cloud for cloud in AzureClouds}
        if value in azure_clouds:
            return azure_clouds[value]
        raise ValueError(
            "Cannot convert {} to Azure Cloud, valid values are: {}".format(value, ", ".join(azure_clouds.keys()))
        )
    raise ValueError("Cannot convert {} to Azure Cloud".format(value))


def _get_opencensus_span() -> Optional[Type[AbstractSpan]]:
    """Returns the OpenCensusSpan if the opencensus tracing plugin is installed else returns None.

    :rtype: type[AbstractSpan] or None
    :returns: OpenCensusSpan type or None
    """
    try:
        from azure.core.tracing.ext.opencensus_span import (
            OpenCensusSpan,
        )

        return OpenCensusSpan
    except ImportError:
        return None


def _get_opentelemetry_span() -> Optional[Type[AbstractSpan]]:
    """Returns the OpenTelemetrySpan if the opentelemetry tracing plugin is installed else returns None.

    :rtype: type[AbstractSpan] or None
    :returns: OpenTelemetrySpan type or None
    """
    try:
        from azure.core.tracing.ext.opentelemetry_span import (
            OpenTelemetrySpan,
        )

        return OpenTelemetrySpan
    except ImportError:
        return None


_tracing_implementation_dict: Dict[str, Callable[[], Optional[Type[AbstractSpan]]]] = {
    "opencensus": _get_opencensus_span,
    "opentelemetry": _get_opentelemetry_span,
}


def convert_tracing_impl(value: Optional[Union[str, Type[AbstractSpan]]]) -> Optional[Type[AbstractSpan]]:
    """Convert a string to AbstractSpan

    If a AbstractSpan is passed in, it is returned as-is. Otherwise the function
    understands the following strings, ignoring case:

    * "opencensus"
    * "opentelemetry"

    :param value: the value to convert
    :type value: string
    :returns: AbstractSpan
    :raises ValueError: If conversion to AbstractSpan fails

    """
    if value is None:
        return None

    if not isinstance(value, str):
        return value

    value = value.lower()
    get_wrapper_class = _tracing_implementation_dict.get(value, lambda: _unset)
    wrapper_class: Optional[Union[_Unset, Type[AbstractSpan]]] = get_wrapper_class()
    if wrapper_class is _unset:
        raise ValueError(
            "Cannot convert {} to AbstractSpan, valid values are: {}".format(
                value, ", ".join(_tracing_implementation_dict)
            )
        )
    return wrapper_class


class PrioritizedSetting(Generic[ValidInputType, ValueType]):
    """Return a value for a global setting according to configuration precedence.

    The following methods are searched in order for the setting:

    4. immediate values
    3. previously user-set value
    2. environment variable
    1. system setting
    0. implicit default

    If a value cannot be determined, a RuntimeError is raised.

    The ``env_var`` argument specifies the name of an environment to check for
    setting values, e.g. ``"AZURE_LOG_LEVEL"``.
    If a ``convert`` function is provided, the result will be converted before being used.

    The optional ``system_hook`` can be used to specify a function that will
    attempt to look up a value for the setting from system-wide configurations.
    If a ``convert`` function is provided, the hook result will be converted before being used.

    The optional ``default`` argument specified an implicit default value for
    the setting that is returned if no other methods provide a value. If a ``convert`` function is provided,
    ``default`` will be converted before being used.

    A ``convert`` argument may be provided to convert values before they are
    returned. For instance to concert log levels in environment variables
    to ``logging`` module values. If a ``convert`` function is provided, it must support
    str as valid input type.

    :param str name: the name of the setting
    :param str env_var: the name of an environment variable to check for the setting
    :param callable system_hook: a function that will attempt to look up a value for the setting
    :param default: an implicit default value for the setting
    :type default: any
    :param callable convert: a function to convert values before they are returned
    """

    def __init__(
        self,
        name: str,
        env_var: Optional[str] = None,
        system_hook: Optional[Callable[[], ValidInputType]] = None,
        default: Union[ValidInputType, _Unset] = _unset,
        convert: Optional[Callable[[Union[ValidInputType, str]], ValueType]] = None,
    ):

        self._name = name
        self._env_var = env_var
        self._system_hook = system_hook
        self._default = default
        noop_convert: Callable[[Any], Any] = lambda x: x
        self._convert: Callable[[Union[ValidInputType, str]], ValueType] = convert if convert else noop_convert
        self._user_value: Union[ValidInputType, _Unset] = _unset

    def __repr__(self) -> str:
        return "PrioritizedSetting(%r)" % self._name

    def __call__(self, value: Optional[ValidInputType] = None) -> ValueType:
        """Return the setting value according to the standard precedence.

        :param value: value
        :type value: str or int or float or None
        :returns: the value of the setting
        :rtype: str or int or float
        :raises RuntimeError: if no value can be determined
        """

        # 4. immediate values
        if value is not None:
            return self._convert(value)

        # 3. previously user-set value
        if not isinstance(self._user_value, _Unset):
            return self._convert(self._user_value)

        # 2. environment variable
        if self._env_var and self._env_var in os.environ:
            return self._convert(os.environ[self._env_var])

        # 1. system setting
        if self._system_hook:
            return self._convert(self._system_hook())

        # 0. implicit default
        if not isinstance(self._default, _Unset):
            return self._convert(self._default)

        raise RuntimeError("No configured value found for setting %r" % self._name)

    def __get__(self, instance: Any, owner: Optional[Any] = None) -> PrioritizedSetting[ValidInputType, ValueType]:
        return self

    def __set__(self, instance: Any, value: ValidInputType) -> None:
        self.set_value(value)

    def set_value(self, value: ValidInputType) -> None:
        """Specify a value for this setting programmatically.

        A value set this way takes precedence over all other methods except
        immediate values.

        :param value: a user-set value for this setting
        :type value: str or int or float
        """
        self._user_value = value

    def unset_value(self) -> None:
        """Unset the previous user value such that the priority is reset."""
        self._user_value = _unset

    @property
    def env_var(self) -> Optional[str]:
        return self._env_var

    @property
    def default(self) -> Union[ValidInputType, _Unset]:
        return self._default


class Settings:
    """Settings for globally used Azure configuration values.

    You probably don't want to create an instance of this class, but call the singleton instance:

    .. code-block:: python

        from azure.core.settings import settings
        settings.log_level = log_level = logging.DEBUG

    The following methods are searched in order for a setting:

    4. immediate values
    3. previously user-set value
    2. environment variable
    1. system setting
    0. implicit default

    An implicit default is (optionally) defined by the setting attribute itself.

    A system setting value can be obtained from registries or other OS configuration
    for settings that support that method.

    An environment variable value is obtained from ``os.environ``

    User-set values many be specified by assigning to the attribute:

    .. code-block:: python

        settings.log_level = log_level = logging.DEBUG

    Immediate values are (optionally) provided when the setting is retrieved:

    .. code-block:: python

        settings.log_level(logging.DEBUG())

    Immediate values are most often useful to provide from optional arguments
    to client functions. If the argument value is not None, it will be returned
    as-is. Otherwise, the setting searches other methods according to the
    precedence rules.

    Immutable configuration snapshots can be created with the following methods:

    * settings.defaults returns the base defaultsvalues , ignoring any environment or system
      or user settings

    * settings.current returns the current computation of settings including prioritization
      of configuration sources, unless defaults_only is set to True (in which case the result
      is identical to settings.defaults)

    * settings.config can be called with specific values to override what settings.current
      would provide

    .. code-block:: python

        # return current settings with log level overridden
        settings.config(log_level=logging.DEBUG)

    :cvar log_level: a log level to use across all Azure client SDKs (AZURE_LOG_LEVEL)
    :type log_level: PrioritizedSetting
    :cvar tracing_enabled: Whether tracing should be enabled across Azure SDKs (AZURE_TRACING_ENABLED)
    :type tracing_enabled: PrioritizedSetting
    :cvar tracing_implementation: The tracing implementation to use (AZURE_SDK_TRACING_IMPLEMENTATION)
    :type tracing_implementation: PrioritizedSetting

    :Example:

    >>> import logging
    >>> from azure.core.settings import settings
    >>> settings.log_level = logging.DEBUG
    >>> settings.log_level()
    10

    >>> settings.log_level(logging.WARN)
    30

    """

    def __init__(self) -> None:
        self._defaults_only: bool = False

    @property
    def defaults_only(self) -> bool:
        """Whether to ignore environment and system settings and return only base default values.

        :rtype: bool
        :returns: Whether to ignore environment and system settings and return only base default values.
        """
        return self._defaults_only

    @defaults_only.setter
    def defaults_only(self, value: bool) -> None:
        self._defaults_only = value

    @property
    def defaults(self) -> Tuple[Any, ...]:
        """Return implicit default values for all settings, ignoring environment and system.

        :rtype: namedtuple
        :returns: The implicit default values for all settings
        """
        props = {k: v.default for (k, v) in self.__class__.__dict__.items() if isinstance(v, PrioritizedSetting)}
        return self._config(props)

    @property
    def current(self) -> Tuple[Any, ...]:
        """Return the current values for all settings.

        :rtype: namedtuple
        :returns: The current values for all settings
        """
        if self.defaults_only:
            return self.defaults
        return self.config()

    def config(self, **kwargs: Any) -> Tuple[Any, ...]:
        """Return the currently computed settings, with values overridden by parameter values.

        :rtype: namedtuple
        :returns: The current values for all settings, with values overridden by parameter values

        Examples:

        .. code-block:: python

           # return current settings with log level overridden
           settings.config(log_level=logging.DEBUG)

        """
        props = {k: v() for (k, v) in self.__class__.__dict__.items() if isinstance(v, PrioritizedSetting)}
        props.update(kwargs)
        return self._config(props)

    def _config(self, props: Mapping[str, Any]) -> Tuple[Any, ...]:
        keys: List[str] = list(props.keys())
        # https://github.com/python/mypy/issues/4414
        Config = namedtuple("Config", keys)  # type: ignore
        return Config(**props)

    log_level: PrioritizedSetting[Union[str, int], int] = PrioritizedSetting(
        "log_level",
        env_var="AZURE_LOG_LEVEL",
        convert=convert_logging,
        default=logging.INFO,
    )

    tracing_enabled: PrioritizedSetting[Optional[Union[str, bool]], bool] = PrioritizedSetting(
        "tracing_enabled",
        env_var="AZURE_TRACING_ENABLED",
        convert=convert_tracing_enabled,
        default=None,
    )

    tracing_implementation: PrioritizedSetting[
        Optional[Union[str, Type[AbstractSpan]]], Optional[Type[AbstractSpan]]
    ] = PrioritizedSetting(
        "tracing_implementation",
        env_var="AZURE_SDK_TRACING_IMPLEMENTATION",
        convert=convert_tracing_impl,
        default=None,
    )

    azure_cloud: PrioritizedSetting[Union[str, AzureClouds], AzureClouds] = PrioritizedSetting(
        "azure_cloud",
        env_var="AZURE_CLOUD",
        convert=convert_azure_cloud,
        default=AzureClouds.AZURE_PUBLIC_CLOUD,
    )


settings: Settings = Settings()
"""The settings unique instance.

:type settings: Settings
"""
