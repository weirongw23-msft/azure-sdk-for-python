# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# Code generated by Microsoft (R) Python Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is regenerated.
# --------------------------------------------------------------------------

from copy import deepcopy
from typing import Any, Awaitable, Optional, TYPE_CHECKING, cast
from typing_extensions import Self

from azure.core.pipeline import policies
from azure.core.rest import AsyncHttpResponse, HttpRequest
from azure.core.settings import settings
from azure.mgmt.core import AsyncARMPipelineClient
from azure.mgmt.core.policies import AsyncARMAutoResourceProviderRegistrationPolicy
from azure.mgmt.core.tools import get_arm_endpoints

from .._utils.serialization import Deserializer, Serializer
from ._configuration import MongoClusterMgmtClientConfiguration
from .operations import (
    FirewallRulesOperations,
    MongoClustersOperations,
    Operations,
    PrivateEndpointConnectionsOperations,
    PrivateLinksOperations,
    ReplicasOperations,
    UsersOperations,
)

if TYPE_CHECKING:
    from azure.core.credentials_async import AsyncTokenCredential


class MongoClusterMgmtClient:  # pylint: disable=too-many-instance-attributes
    """The Microsoft Azure management API provides create, read, update, and delete functionality for
    Azure Cosmos DB for MongoDB vCore resources including clusters and firewall rules.

    :ivar operations: Operations operations
    :vartype operations: azure.mgmt.mongocluster.aio.operations.Operations
    :ivar mongo_clusters: MongoClustersOperations operations
    :vartype mongo_clusters: azure.mgmt.mongocluster.aio.operations.MongoClustersOperations
    :ivar firewall_rules: FirewallRulesOperations operations
    :vartype firewall_rules: azure.mgmt.mongocluster.aio.operations.FirewallRulesOperations
    :ivar private_endpoint_connections: PrivateEndpointConnectionsOperations operations
    :vartype private_endpoint_connections:
     azure.mgmt.mongocluster.aio.operations.PrivateEndpointConnectionsOperations
    :ivar private_links: PrivateLinksOperations operations
    :vartype private_links: azure.mgmt.mongocluster.aio.operations.PrivateLinksOperations
    :ivar replicas: ReplicasOperations operations
    :vartype replicas: azure.mgmt.mongocluster.aio.operations.ReplicasOperations
    :ivar users: UsersOperations operations
    :vartype users: azure.mgmt.mongocluster.aio.operations.UsersOperations
    :param credential: Credential used to authenticate requests to the service. Required.
    :type credential: ~azure.core.credentials_async.AsyncTokenCredential
    :param subscription_id: The ID of the target subscription. The value must be an UUID. Required.
    :type subscription_id: str
    :param base_url: Service host. Default value is None.
    :type base_url: str
    :keyword api_version: The API version to use for this operation. Default value is
     "2025-07-01-preview". Note that overriding this default value may result in unsupported
     behavior.
    :paramtype api_version: str
    :keyword int polling_interval: Default waiting time between two polls for LRO operations if no
     Retry-After header is present.
    """

    def __init__(
        self, credential: "AsyncTokenCredential", subscription_id: str, base_url: Optional[str] = None, **kwargs: Any
    ) -> None:
        _endpoint = "{endpoint}"
        _cloud = kwargs.pop("cloud_setting", None) or settings.current.azure_cloud  # type: ignore
        _endpoints = get_arm_endpoints(_cloud)
        if not base_url:
            base_url = _endpoints["resource_manager"]
        credential_scopes = kwargs.pop("credential_scopes", _endpoints["credential_scopes"])
        self._config = MongoClusterMgmtClientConfiguration(
            credential=credential,
            subscription_id=subscription_id,
            base_url=cast(str, base_url),
            credential_scopes=credential_scopes,
            **kwargs
        )

        _policies = kwargs.pop("policies", None)
        if _policies is None:
            _policies = [
                policies.RequestIdPolicy(**kwargs),
                self._config.headers_policy,
                self._config.user_agent_policy,
                self._config.proxy_policy,
                policies.ContentDecodePolicy(**kwargs),
                AsyncARMAutoResourceProviderRegistrationPolicy(),
                self._config.redirect_policy,
                self._config.retry_policy,
                self._config.authentication_policy,
                self._config.custom_hook_policy,
                self._config.logging_policy,
                policies.DistributedTracingPolicy(**kwargs),
                policies.SensitiveHeaderCleanupPolicy(**kwargs) if self._config.redirect_policy else None,
                self._config.http_logging_policy,
            ]
        self._client: AsyncARMPipelineClient = AsyncARMPipelineClient(
            base_url=cast(str, _endpoint), policies=_policies, **kwargs
        )

        self._serialize = Serializer()
        self._deserialize = Deserializer()
        self._serialize.client_side_validation = False
        self.operations = Operations(self._client, self._config, self._serialize, self._deserialize)
        self.mongo_clusters = MongoClustersOperations(self._client, self._config, self._serialize, self._deserialize)
        self.firewall_rules = FirewallRulesOperations(self._client, self._config, self._serialize, self._deserialize)
        self.private_endpoint_connections = PrivateEndpointConnectionsOperations(
            self._client, self._config, self._serialize, self._deserialize
        )
        self.private_links = PrivateLinksOperations(self._client, self._config, self._serialize, self._deserialize)
        self.replicas = ReplicasOperations(self._client, self._config, self._serialize, self._deserialize)
        self.users = UsersOperations(self._client, self._config, self._serialize, self._deserialize)

    def send_request(
        self, request: HttpRequest, *, stream: bool = False, **kwargs: Any
    ) -> Awaitable[AsyncHttpResponse]:
        """Runs the network request through the client's chained policies.

        >>> from azure.core.rest import HttpRequest
        >>> request = HttpRequest("GET", "https://www.example.org/")
        <HttpRequest [GET], url: 'https://www.example.org/'>
        >>> response = await client.send_request(request)
        <AsyncHttpResponse: 200 OK>

        For more information on this code flow, see https://aka.ms/azsdk/dpcodegen/python/send_request

        :param request: The network request you want to make. Required.
        :type request: ~azure.core.rest.HttpRequest
        :keyword bool stream: Whether the response payload will be streamed. Defaults to False.
        :return: The response of your network call. Does not do error handling on your response.
        :rtype: ~azure.core.rest.AsyncHttpResponse
        """

        request_copy = deepcopy(request)
        path_format_arguments = {
            "endpoint": self._serialize.url("self._config.base_url", self._config.base_url, "str", skip_quote=True),
        }

        request_copy.url = self._client.format_url(request_copy.url, **path_format_arguments)
        return self._client.send_request(request_copy, stream=stream, **kwargs)  # type: ignore

    async def close(self) -> None:
        await self._client.close()

    async def __aenter__(self) -> Self:
        await self._client.__aenter__()
        return self

    async def __aexit__(self, *exc_details: Any) -> None:
        await self._client.__aexit__(*exc_details)
