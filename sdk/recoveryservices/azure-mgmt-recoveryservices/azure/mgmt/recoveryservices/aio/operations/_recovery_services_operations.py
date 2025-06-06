# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is regenerated.
# --------------------------------------------------------------------------
from collections.abc import MutableMapping
from io import IOBase
from typing import Any, Callable, Dict, IO, Optional, TypeVar, Union, overload

from azure.core import AsyncPipelineClient
from azure.core.exceptions import (
    ClientAuthenticationError,
    HttpResponseError,
    ResourceExistsError,
    ResourceNotFoundError,
    ResourceNotModifiedError,
    map_error,
)
from azure.core.pipeline import PipelineResponse
from azure.core.rest import AsyncHttpResponse, HttpRequest
from azure.core.tracing.decorator_async import distributed_trace_async
from azure.core.utils import case_insensitive_dict
from azure.mgmt.core.exceptions import ARMErrorFormat

from ... import models as _models
from ..._utils.serialization import Deserializer, Serializer
from ...operations._recovery_services_operations import (
    build_capabilities_request,
    build_check_name_availability_request,
)
from .._configuration import RecoveryServicesClientConfiguration

T = TypeVar("T")
ClsType = Optional[Callable[[PipelineResponse[HttpRequest, AsyncHttpResponse], T, Dict[str, Any]], Any]]


class RecoveryServicesOperations:
    """
    .. warning::
        **DO NOT** instantiate this class directly.

        Instead, you should access the following operations through
        :class:`~azure.mgmt.recoveryservices.aio.RecoveryServicesClient`'s
        :attr:`recovery_services` attribute.
    """

    models = _models

    def __init__(self, *args, **kwargs) -> None:
        input_args = list(args)
        self._client: AsyncPipelineClient = input_args.pop(0) if input_args else kwargs.pop("client")
        self._config: RecoveryServicesClientConfiguration = input_args.pop(0) if input_args else kwargs.pop("config")
        self._serialize: Serializer = input_args.pop(0) if input_args else kwargs.pop("serializer")
        self._deserialize: Deserializer = input_args.pop(0) if input_args else kwargs.pop("deserializer")

    @overload
    async def check_name_availability(
        self,
        resource_group_name: str,
        location: str,
        input: _models.CheckNameAvailabilityParameters,
        *,
        content_type: str = "application/json",
        **kwargs: Any
    ) -> _models.CheckNameAvailabilityResult:
        """API to check for resource name availability.
        A name is available if no other resource exists that has the same SubscriptionId, Resource Name
        and Type
        or if one or more such resources exist, each of these must be GC'd and their time of deletion
        be more than 24 Hours Ago.

        API to check for resource name availability.
        A name is available if no other resource exists that has the same SubscriptionId, Resource Name
        and Type
        or if one or more such resources exist, each of these must be GC'd and their time of deletion
        be more than 24 Hours Ago.

        :param resource_group_name: The name of the resource group. The name is case insensitive.
         Required.
        :type resource_group_name: str
        :param location: Location of the resource. Required.
        :type location: str
        :param input: Contains information about Resource type and Resource name. Required.
        :type input: ~azure.mgmt.recoveryservices.models.CheckNameAvailabilityParameters
        :keyword content_type: Body Parameter content-type. Content type parameter for JSON body.
         Default value is "application/json".
        :paramtype content_type: str
        :return: CheckNameAvailabilityResult or the result of cls(response)
        :rtype: ~azure.mgmt.recoveryservices.models.CheckNameAvailabilityResult
        :raises ~azure.core.exceptions.HttpResponseError:
        """

    @overload
    async def check_name_availability(
        self,
        resource_group_name: str,
        location: str,
        input: IO[bytes],
        *,
        content_type: str = "application/json",
        **kwargs: Any
    ) -> _models.CheckNameAvailabilityResult:
        """API to check for resource name availability.
        A name is available if no other resource exists that has the same SubscriptionId, Resource Name
        and Type
        or if one or more such resources exist, each of these must be GC'd and their time of deletion
        be more than 24 Hours Ago.

        API to check for resource name availability.
        A name is available if no other resource exists that has the same SubscriptionId, Resource Name
        and Type
        or if one or more such resources exist, each of these must be GC'd and their time of deletion
        be more than 24 Hours Ago.

        :param resource_group_name: The name of the resource group. The name is case insensitive.
         Required.
        :type resource_group_name: str
        :param location: Location of the resource. Required.
        :type location: str
        :param input: Contains information about Resource type and Resource name. Required.
        :type input: IO[bytes]
        :keyword content_type: Body Parameter content-type. Content type parameter for binary body.
         Default value is "application/json".
        :paramtype content_type: str
        :return: CheckNameAvailabilityResult or the result of cls(response)
        :rtype: ~azure.mgmt.recoveryservices.models.CheckNameAvailabilityResult
        :raises ~azure.core.exceptions.HttpResponseError:
        """

    @distributed_trace_async
    async def check_name_availability(
        self,
        resource_group_name: str,
        location: str,
        input: Union[_models.CheckNameAvailabilityParameters, IO[bytes]],
        **kwargs: Any
    ) -> _models.CheckNameAvailabilityResult:
        """API to check for resource name availability.
        A name is available if no other resource exists that has the same SubscriptionId, Resource Name
        and Type
        or if one or more such resources exist, each of these must be GC'd and their time of deletion
        be more than 24 Hours Ago.

        API to check for resource name availability.
        A name is available if no other resource exists that has the same SubscriptionId, Resource Name
        and Type
        or if one or more such resources exist, each of these must be GC'd and their time of deletion
        be more than 24 Hours Ago.

        :param resource_group_name: The name of the resource group. The name is case insensitive.
         Required.
        :type resource_group_name: str
        :param location: Location of the resource. Required.
        :type location: str
        :param input: Contains information about Resource type and Resource name. Is either a
         CheckNameAvailabilityParameters type or a IO[bytes] type. Required.
        :type input: ~azure.mgmt.recoveryservices.models.CheckNameAvailabilityParameters or IO[bytes]
        :return: CheckNameAvailabilityResult or the result of cls(response)
        :rtype: ~azure.mgmt.recoveryservices.models.CheckNameAvailabilityResult
        :raises ~azure.core.exceptions.HttpResponseError:
        """
        error_map: MutableMapping = {
            401: ClientAuthenticationError,
            404: ResourceNotFoundError,
            409: ResourceExistsError,
            304: ResourceNotModifiedError,
        }
        error_map.update(kwargs.pop("error_map", {}) or {})

        _headers = case_insensitive_dict(kwargs.pop("headers", {}) or {})
        _params = case_insensitive_dict(kwargs.pop("params", {}) or {})

        api_version: str = kwargs.pop("api_version", _params.pop("api-version", self._config.api_version))
        content_type: Optional[str] = kwargs.pop("content_type", _headers.pop("Content-Type", None))
        cls: ClsType[_models.CheckNameAvailabilityResult] = kwargs.pop("cls", None)

        content_type = content_type or "application/json"
        _json = None
        _content = None
        if isinstance(input, (IOBase, bytes)):
            _content = input
        else:
            _json = self._serialize.body(input, "CheckNameAvailabilityParameters")

        _request = build_check_name_availability_request(
            resource_group_name=resource_group_name,
            location=location,
            subscription_id=self._config.subscription_id,
            api_version=api_version,
            content_type=content_type,
            json=_json,
            content=_content,
            headers=_headers,
            params=_params,
        )
        _request.url = self._client.format_url(_request.url)

        _stream = False
        pipeline_response: PipelineResponse = await self._client._pipeline.run(  # pylint: disable=protected-access
            _request, stream=_stream, **kwargs
        )

        response = pipeline_response.http_response

        if response.status_code not in [200]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            raise HttpResponseError(response=response, error_format=ARMErrorFormat)

        deserialized = self._deserialize("CheckNameAvailabilityResult", pipeline_response.http_response)

        if cls:
            return cls(pipeline_response, deserialized, {})  # type: ignore

        return deserialized  # type: ignore

    @overload
    async def capabilities(
        self,
        location: str,
        input: _models.ResourceCapabilities,
        *,
        content_type: str = "application/json",
        **kwargs: Any
    ) -> _models.CapabilitiesResponse:
        """API to get details about capabilities provided by Microsoft.RecoveryServices RP.

        API to get details about capabilities provided by Microsoft.RecoveryServices RP.

        :param location: Location of the resource. Required.
        :type location: str
        :param input: Contains information about Resource type and properties to get capabilities.
         Required.
        :type input: ~azure.mgmt.recoveryservices.models.ResourceCapabilities
        :keyword content_type: Body Parameter content-type. Content type parameter for JSON body.
         Default value is "application/json".
        :paramtype content_type: str
        :return: CapabilitiesResponse or the result of cls(response)
        :rtype: ~azure.mgmt.recoveryservices.models.CapabilitiesResponse
        :raises ~azure.core.exceptions.HttpResponseError:
        """

    @overload
    async def capabilities(
        self, location: str, input: IO[bytes], *, content_type: str = "application/json", **kwargs: Any
    ) -> _models.CapabilitiesResponse:
        """API to get details about capabilities provided by Microsoft.RecoveryServices RP.

        API to get details about capabilities provided by Microsoft.RecoveryServices RP.

        :param location: Location of the resource. Required.
        :type location: str
        :param input: Contains information about Resource type and properties to get capabilities.
         Required.
        :type input: IO[bytes]
        :keyword content_type: Body Parameter content-type. Content type parameter for binary body.
         Default value is "application/json".
        :paramtype content_type: str
        :return: CapabilitiesResponse or the result of cls(response)
        :rtype: ~azure.mgmt.recoveryservices.models.CapabilitiesResponse
        :raises ~azure.core.exceptions.HttpResponseError:
        """

    @distributed_trace_async
    async def capabilities(
        self, location: str, input: Union[_models.ResourceCapabilities, IO[bytes]], **kwargs: Any
    ) -> _models.CapabilitiesResponse:
        """API to get details about capabilities provided by Microsoft.RecoveryServices RP.

        API to get details about capabilities provided by Microsoft.RecoveryServices RP.

        :param location: Location of the resource. Required.
        :type location: str
        :param input: Contains information about Resource type and properties to get capabilities. Is
         either a ResourceCapabilities type or a IO[bytes] type. Required.
        :type input: ~azure.mgmt.recoveryservices.models.ResourceCapabilities or IO[bytes]
        :return: CapabilitiesResponse or the result of cls(response)
        :rtype: ~azure.mgmt.recoveryservices.models.CapabilitiesResponse
        :raises ~azure.core.exceptions.HttpResponseError:
        """
        error_map: MutableMapping = {
            401: ClientAuthenticationError,
            404: ResourceNotFoundError,
            409: ResourceExistsError,
            304: ResourceNotModifiedError,
        }
        error_map.update(kwargs.pop("error_map", {}) or {})

        _headers = case_insensitive_dict(kwargs.pop("headers", {}) or {})
        _params = case_insensitive_dict(kwargs.pop("params", {}) or {})

        api_version: str = kwargs.pop("api_version", _params.pop("api-version", self._config.api_version))
        content_type: Optional[str] = kwargs.pop("content_type", _headers.pop("Content-Type", None))
        cls: ClsType[_models.CapabilitiesResponse] = kwargs.pop("cls", None)

        content_type = content_type or "application/json"
        _json = None
        _content = None
        if isinstance(input, (IOBase, bytes)):
            _content = input
        else:
            _json = self._serialize.body(input, "ResourceCapabilities")

        _request = build_capabilities_request(
            location=location,
            subscription_id=self._config.subscription_id,
            api_version=api_version,
            content_type=content_type,
            json=_json,
            content=_content,
            headers=_headers,
            params=_params,
        )
        _request.url = self._client.format_url(_request.url)

        _stream = False
        pipeline_response: PipelineResponse = await self._client._pipeline.run(  # pylint: disable=protected-access
            _request, stream=_stream, **kwargs
        )

        response = pipeline_response.http_response

        if response.status_code not in [200]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            raise HttpResponseError(response=response, error_format=ARMErrorFormat)

        deserialized = self._deserialize("CapabilitiesResponse", pipeline_response.http_response)

        if cls:
            return cls(pipeline_response, deserialized, {})  # type: ignore

        return deserialized  # type: ignore
