# pylint: disable=line-too-long,useless-suppression
# ------------------------------------
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# ------------------------------------

"""Customize generated code here.

Follow our quickstart for examples: https://aka.ms/azsdk/python/dpcodegen/python/customize
"""
from typing import Any, List, IO, Optional, Union, overload
from datetime import datetime, timedelta, tzinfo
import jwt
from azure.core.credentials import AzureKeyCredential
from azure.core.paging import ItemPaged
from azure.core.tracing.decorator import distributed_trace
from azure.core.exceptions import (
    ClientAuthenticationError,
    HttpResponseError,
    ResourceExistsError,
    ResourceNotFoundError,
    ResourceNotModifiedError,
    map_error,
)
from azure.core.utils import case_insensitive_dict
from ._operations import (
    WebPubSubServiceClientOperationsMixin as WebPubSubServiceClientOperationsMixinGenerated,
    JSON,
    build_web_pub_sub_service_send_to_all_request,
    build_web_pub_sub_service_send_to_connection_request,
    build_web_pub_sub_service_send_to_user_request,
    build_web_pub_sub_service_send_to_group_request,
)
from .._models import GroupMember


class _UTC_TZ(tzinfo):
    """from https://docs.python.org/2/library/datetime.html#tzinfo-objects"""

    ZERO = timedelta(0)

    def utcoffset(self, dt):
        return self.__class__.ZERO

    def tzname(self, dt):
        return "UTC"

    def dst(self, dt):
        return self.__class__.ZERO


def get_token_by_key(endpoint: str, path: str, hub: str, key: str, **kwargs: Any) -> str:
    """build token with access key.
    :param endpoint:  HTTPS endpoint for the WebPubSub service instance.
    :type endpoint: str
    :param path:  HTTPS path for the WebPubSub service instance.
    :type endpoint: str
    :param hub: The hub to give access to.
    :type hub: str
    :param key: The access key
    :type hub: str
    :keyword dict[str, any] jwt_headers: Any headers you want to pass to jwt encoding.
    :returns: token
    :rtype: str
    """
    audience = endpoint + path + hub
    user = kwargs.pop("user_id", None)
    ttl = timedelta(minutes=kwargs.pop("minutes_to_expire", 60))
    roles = kwargs.pop("roles", [])
    groups = kwargs.pop("groups", [])

    payload = {
        "aud": audience,
        "iat": datetime.now(tz=_UTC_TZ()),
        "exp": datetime.now(tz=_UTC_TZ()) + ttl,
    }
    if user:
        payload["sub"] = user
    if roles:
        payload["role"] = roles
    if groups:
        payload["webpubsub.group"] = groups
    encoded = jwt.encode(payload, key, algorithm="HS256", headers=kwargs.pop("jwt_headers", {}))
    return encoded


class WebPubSubServiceClientOperationsMixin(WebPubSubServiceClientOperationsMixinGenerated):
    @distributed_trace
    def get_client_access_token(self, *, client_protocol: Optional[str] = "Default", **kwargs: Any) -> JSON:
        """Build an authentication token.

        :keyword user_id: User Id.
        :paramtype user_id: str
        :keyword roles: Roles that the connection with the generated token will have.
        :paramtype roles: list[str]
        :keyword minutes_to_expire: The expire time of the generated token.
        :paramtype minutes_to_expire: int
        :keyword dict[str, any] jwt_headers: Any headers you want to pass to jwt encoding.
        :keyword groups: Groups that the connection will join when it connects. Default value is None.
        :paramtype groups: list[str]
        :keyword client_protocol: The type of client protocol. Case-insensitive. If not set, it's "Default". For Web
         PubSub for Socket.IO, "SocketIO" type is supported. For Web PubSub, the valid values are
         'Default', 'MQTT'. Known values are: "Default", "MQTT" and "SocketIO". Default value is "Default".
        :paramtype client_type: str
        :returns: JSON response containing the web socket endpoint, the token and a url with the generated access token.
        :rtype: JSON

        Example:

            >>> get_client_access_token()
            {
                'baseUrl': 'wss://contoso.com/api/webpubsub/client/hubs/theHub',
                'token': '<access-token>...',
                'url': 'wss://contoso.com/api/webpubsub/client/hubs/theHub?access_token=<access-token>...'
            }
        """
        endpoint = self._config.endpoint.lower()
        if not endpoint.startswith("http://") and not endpoint.startswith("https://"):
            raise ValueError(
                "Invalid endpoint: '{}' has unknown scheme - expected 'http://' or 'https://'".format(endpoint)
            )
        # Ensure endpoint has no trailing slash

        endpoint = endpoint.rstrip("/")

        # Switch from http(s) to ws(s) scheme

        client_endpoint = "ws" + endpoint[4:]
        hub = self._config.hub
        # Example URL for Default Client Type: https://<service-name>.webpubsub.azure.com/client/hubs/<hub>
        #                 MQTT Client Type: https://<service-name>.webpubsub.azure.com/clients/mqtt/hubs/<hub>
        #                 SocketIO Client Type: https://<service-name>.webpubsub.azure.com/clients/socketio/hubs/<hub>
        path = "/client/hubs/"
        if client_protocol.lower() == "mqtt":
            path = "/clients/mqtt/hubs/"
        elif client_protocol.lower() == "socketio":
            path = "/clients/socketio/hubs/"
        client_url = client_endpoint + path + hub
        jwt_headers = kwargs.pop("jwt_headers", {})
        if isinstance(self._config.credential, AzureKeyCredential):
            token = get_token_by_key(
                endpoint, path, hub, self._config.credential.key, jwt_headers=jwt_headers, **kwargs
            )
        else:
            token = super().get_client_access_token(client_protocol=client_protocol, **kwargs).get("token")
        return {
            "baseUrl": client_url,
            "token": token,
            "url": "{}?access_token={}".format(client_url, token),
        }

    get_client_access_token.metadata = {"url": "/api/hubs/{hub}/:generateToken"}  # type: ignore

    @distributed_trace
    def list_connections(
        self,
        *,
        group: str,
        top: Optional[int] = None,
        **kwargs: Any
    ) -> ItemPaged[GroupMember]:
        """List connections in a group.

        List connections in a group.

        :keyword group: Target group name, whose length should be greater than 0 and less than 1025.
         Required.
        :paramtype group: str
        :keyword top: The maximum number of connections to return. If the value is not set, then all
         the connections in a group are returned. Default value is None.
        :paramtype top: int
        :return: An iterator like instance of GroupMember object
        :rtype: ~azure.core.paging.ItemPaged[GroupMember]
        :raises ~azure.core.exceptions.HttpResponseError:

        Example:
            .. code-block:: python

                connections = client.list_connections(
                    group="group_name",
                    top=100
                )

                for member in connections:
                    assert member.connection_id is not None

        """
        # Call the base implementation to get ItemPaged[dict]
        paged_json = super().list_connections(
            group=group,
            top=top,
            **kwargs
        )

        # Wrap the iterator to convert each item to GroupMember
        class GroupMemberPaged(ItemPaged):
            def __iter__(self_inner):
                for item in paged_json:
                    yield GroupMember(
                        connection_id=item.get("connectionId"),
                        user_id=item.get("userId")
                    )

            def by_page(self_inner, continuation_token: Optional[str] = None):
                for page in paged_json.by_page(continuation_token=continuation_token):
                    yield [
                        GroupMember(
                            connection_id=item.get("connectionId"),
                            user_id=item.get("userId")
                        )
                        for item in page
                    ]
        return GroupMemberPaged()

    @overload
    def send_to_all(  # pylint: disable=inconsistent-return-statements
        self,
        message: Union[str, JSON],
        *,
        excluded: Optional[List[str]] = None,
        filter: Optional[str] = None,
        content_type: Optional[str] = "application/json",
        **kwargs: Any
    ) -> None:
        """Broadcast content inside request body to all the connected client connections.

        Broadcast content inside request body to all the connected client connections.

        :param message: The payload body. Required.
        :type message: Union[str, JSON]
        :keyword excluded: Excluded connection Ids. Default value is None.
        :paramtype excluded: list[str]
        :keyword filter: Following OData filter syntax to filter out the subscribers receiving the
         messages. Default value is None.
        :paramtype filter: str
        :keyword content_type: The content type of the payload. Default value is None. Allowed values are 'application/json', 'application/octet-stream' and 'text/plain'
        :paramtype content_type: str
        :return: None
        :rtype: None
        :raises ~azure.core.exceptions.HttpResponseError:
        """

    @overload
    def send_to_all(  # pylint: disable=inconsistent-return-statements
        self,
        message: str,
        *,
        excluded: Optional[List[str]] = None,
        filter: Optional[str] = None,
        content_type: Optional[str] = "text/plain",
        **kwargs: Any
    ) -> None:
        """Broadcast content inside request body to all the connected client connections.

        Broadcast content inside request body to all the connected client connections.

        :param message: The payload body. Required.
        :type message: str
        :keyword excluded: Excluded connection Ids. Default value is None.
        :paramtype excluded: list[str]
        :keyword filter: Following OData filter syntax to filter out the subscribers receiving the
         messages. Default value is None.
        :paramtype filter: str
        :keyword content_type: The content type of the payload. Default value is None. Allowed values are 'application/json', 'application/octet-stream' and 'text/plain'
        :paramtype content_type: str
        :return: None
        :rtype: None
        :raises ~azure.core.exceptions.HttpResponseError:
        """

    @overload
    def send_to_all(  # pylint: disable=inconsistent-return-statements
        self,
        message: IO,
        *,
        excluded: Optional[List[str]] = None,
        filter: Optional[str] = None,
        content_type: Optional[str] = "application/octet-stream",
        **kwargs: Any
    ) -> None:
        """Broadcast content inside request body to all the connected client connections.

        Broadcast content inside request body to all the connected client connections.

        :param message: The payload body. Required.
        :type message: IO
        :keyword excluded: Excluded connection Ids. Default value is None.
        :paramtype excluded: list[str]
        :keyword filter: Following OData filter syntax to filter out the subscribers receiving the
         messages. Default value is None.
        :paramtype filter: str
        :keyword content_type: The content type of the payload. Default value is None. Allowed values are 'application/json', 'application/octet-stream' and 'text/plain'
        :paramtype content_type: str
        :return: None
        :rtype: None
        :raises ~azure.core.exceptions.HttpResponseError:
        """

    @distributed_trace
    def send_to_all(  # pylint: disable=inconsistent-return-statements
        self,
        message: Union[IO, str, JSON],
        *,
        excluded: Optional[List[str]] = None,
        filter: Optional[str] = None,
        content_type: Optional[str] = None,
        **kwargs: Any
    ) -> None:
        """Broadcast content inside request body to all the connected client connections.

        Broadcast content inside request body to all the connected client connections.

        :param message: The payload body. Required.
        :type message: Union[IO, str, JSON]
        :keyword excluded: Excluded connection Ids. Default value is None.
        :paramtype excluded: list[str]
        :keyword filter: Following OData filter syntax to filter out the subscribers receiving the
         messages. Default value is None.
        :paramtype filter: str
        :keyword content_type: The content type of the payload. Default value is None. Allowed values are 'application/json', 'application/octet-stream' and 'text/plain'
        :paramtype content_type: str
        :return: None
        :rtype: None
        :raises ~azure.core.exceptions.HttpResponseError:
        """
        error_map = {
            401: ClientAuthenticationError,
            404: ResourceNotFoundError,
            409: ResourceExistsError,
            304: ResourceNotModifiedError,
        }
        error_map.update(kwargs.pop("error_map", {}) or {})

        _headers = case_insensitive_dict(kwargs.pop("headers", {}) or {})
        _params = kwargs.pop("params", {}) or {}

        content_type = _headers.pop("Content-Type", "application/json") if content_type is None else content_type
        cls = kwargs.pop("cls", None)  # type: ClsType[None]

        _json = None
        _content = None
        content_type = content_type or ""
        if content_type.split(";")[0] in ["application/json"]:
            _json = message
        elif content_type.split(";")[0] in ["application/octet-stream", "text/plain"]:
            _content = message
        else:
            raise ValueError(
                "The content_type '{}' is not one of the allowed values: "
                "['application/json', 'application/octet-stream', 'text/plain']".format(content_type)
            )
        request = build_web_pub_sub_service_send_to_all_request(
            hub=self._config.hub,
            excluded=excluded,
            filter=filter,
            content_type=content_type,
            api_version=self._config.api_version,
            content=_content,
            json=_json,
            headers=_headers,
            params=_params,
        )
        path_format_arguments = {
            "endpoint": self._serialize.url("self._config.endpoint", self._config.endpoint, "str", skip_quote=True),
        }
        request.url = self._client.format_url(request.url, **path_format_arguments)  # type: ignore

        pipeline_response = self._client._pipeline.run(  # type: ignore # pylint: disable=protected-access
            request, stream=False, **kwargs
        )

        response = pipeline_response.http_response

        if response.status_code not in [202]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            raise HttpResponseError(response=response)
        if cls:
            return cls(pipeline_response, None, {})

    @overload
    def send_to_user(  # pylint: disable=inconsistent-return-statements
        self,
        user_id: str,
        message: Union[str, JSON],
        *,
        filter: Optional[str] = None,
        content_type: Optional[str] = "application/json",
        **kwargs: Any
    ) -> None:
        """Send content inside request body to the specific user.

        Send content inside request body to the specific user.

        :param user_id: The user Id. Required.
        :type user_id: str
        :param message: The payload body. Required.
        :type message: Union[str, JSON]
        :keyword filter: Following OData filter syntax to filter out the subscribers receiving the
         messages. Default value is None.
        :paramtype filter: str
        :keyword content_type: The content type of the payload. Default value is None. Allowed values are 'application/json', 'application/octet-stream' and 'text/plain'
        :paramtype content_type: str
        :return: None
        :rtype: None
        :raises ~azure.core.exceptions.HttpResponseError:
        """

    @overload
    def send_to_user(  # pylint: disable=inconsistent-return-statements
        self,
        user_id: str,
        message: str,
        *,
        filter: Optional[str] = None,
        content_type: Optional[str] = "text/plain",
        **kwargs: Any
    ) -> None:
        """Send content inside request body to the specific user.

        Send content inside request body to the specific user.

        :param user_id: The user Id. Required.
        :type user_id: str
        :param message: The payload body. Required.
        :type message: str
        :keyword filter: Following OData filter syntax to filter out the subscribers receiving the
         messages. Default value is None.
        :paramtype filter: str
        :keyword content_type: The content type of the payload. Default value is None. Allowed values are 'application/json', 'application/octet-stream' and 'text/plain'
        :paramtype content_type: str
        :return: None
        :rtype: None
        :raises ~azure.core.exceptions.HttpResponseError:
        """

    @overload
    def send_to_user(  # pylint: disable=inconsistent-return-statements
        self,
        user_id: str,
        message: IO,
        *,
        filter: Optional[str] = None,
        content_type: Optional[str] = "application/octet-stream",
        **kwargs: Any
    ) -> None:
        """Send content inside request body to the specific user.

        Send content inside request body to the specific user.

        :param user_id: The user Id. Required.
        :type user_id: str
        :param message: The payload body. Required.
        :type message: IO
        :keyword filter: Following OData filter syntax to filter out the subscribers receiving the
         messages. Default value is None.
        :paramtype filter: str
        :keyword content_type: The content type of the payload. Default value is None. Allowed values are 'application/json', 'application/octet-stream' and 'text/plain'
        :paramtype content_type: str
        :return: None
        :rtype: None
        :raises ~azure.core.exceptions.HttpResponseError:
        """

    @distributed_trace
    def send_to_user(  # pylint: disable=inconsistent-return-statements
        self,
        user_id: str,
        message: Union[IO, str, JSON],
        *,
        filter: Optional[str] = None,
        content_type: Optional[str] = None,
        **kwargs: Any
    ) -> None:
        """Send content inside request body to the specific user.

        Send content inside request body to the specific user.

        :param user_id: The user Id. Required.
        :type user_id: str
        :param message: The payload body. Required.
        :type message: Union[IO, str, JSON]
        :keyword filter: Following OData filter syntax to filter out the subscribers receiving the
         messages. Default value is None.
        :paramtype filter: str
        :keyword content_type: The content type of the payload. Default value is None. Allowed values are 'application/json', 'application/octet-stream' and 'text/plain'
        :paramtype content_type: str
        :return: None
        :rtype: None
        :raises ~azure.core.exceptions.HttpResponseError:
        """
        error_map = {
            401: ClientAuthenticationError,
            404: ResourceNotFoundError,
            409: ResourceExistsError,
            304: ResourceNotModifiedError,
        }
        error_map.update(kwargs.pop("error_map", {}) or {})

        _headers = case_insensitive_dict(kwargs.pop("headers", {}) or {})
        _params = kwargs.pop("params", {}) or {}

        content_type = _headers.pop("Content-Type", "application/json") if content_type is None else content_type
        cls = kwargs.pop("cls", None)  # type: ClsType[None]

        _json = None
        _content = None
        content_type = content_type or ""
        if content_type.split(";")[0] in ["application/json"]:
            _json = message
        elif content_type.split(";")[0] in ["application/octet-stream", "text/plain"]:
            _content = message
        else:
            raise ValueError(
                "The content_type '{}' is not one of the allowed values: "
                "['application/json', 'application/octet-stream', 'text/plain']".format(content_type)
            )
        request = build_web_pub_sub_service_send_to_user_request(
            user_id=user_id,
            hub=self._config.hub,
            filter=filter,
            content_type=content_type,
            api_version=self._config.api_version,
            content=_content,
            json=_json,
            headers=_headers,
            params=_params,
        )
        path_format_arguments = {
            "endpoint": self._serialize.url("self._config.endpoint", self._config.endpoint, "str", skip_quote=True),
        }
        request.url = self._client.format_url(request.url, **path_format_arguments)  # type: ignore

        pipeline_response = self._client._pipeline.run(  # type: ignore # pylint: disable=protected-access
            request, stream=False, **kwargs
        )

        response = pipeline_response.http_response

        if response.status_code not in [202]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            raise HttpResponseError(response=response)
        if cls:
            return cls(pipeline_response, None, {})

    @overload
    def send_to_group(  # pylint: disable=inconsistent-return-statements
        self,
        group: str,
        message: Union[str, JSON],
        *,
        excluded: Optional[List[str]] = None,
        filter: Optional[str] = None,
        content_type: Optional[str] = "application/json",
        **kwargs: Any
    ) -> None:
        """Send content inside request body to a group of connections.

        Send content inside request body to a group of connections.

        :param group: Target group name, which length should be greater than 0 and less than 1025.
         Required.
        :type group: str
        :param message: The payload body. Required.
        :type message: Union[str, JSON]
        :keyword excluded: Excluded connection Ids. Default value is None.
        :paramtype excluded: list[str]
        :keyword filter: Following OData filter syntax to filter out the subscribers receiving the
         messages. Default value is None.
        :paramtype filter: str
        :keyword content_type: The content type of the payload. Default value is None. Allowed values are 'application/json', 'application/octet-stream' and 'text/plain'
        :paramtype content_type: str
        :return: None
        :rtype: None
        :raises ~azure.core.exceptions.HttpResponseError:
        """

    @overload
    def send_to_group(  # pylint: disable=inconsistent-return-statements
        self,
        group: str,
        message: str,
        *,
        excluded: Optional[List[str]] = None,
        filter: Optional[str] = None,
        content_type: Optional[str] = "text/plain",
        **kwargs: Any
    ) -> None:
        """Send content inside request body to a group of connections.

        Send content inside request body to a group of connections.

        :param group: Target group name, which length should be greater than 0 and less than 1025.
         Required.
        :type group: str
        :param message: The payload body. Required.
        :type message: str
        :keyword excluded: Excluded connection Ids. Default value is None.
        :paramtype excluded: list[str]
        :keyword filter: Following OData filter syntax to filter out the subscribers receiving the
         messages. Default value is None.
        :paramtype filter: str
        :keyword content_type: The content type of the payload. Default value is None. Allowed values are 'application/json', 'application/octet-stream' and 'text/plain'
        :paramtype content_type: str
        :return: None
        :rtype: None
        :raises ~azure.core.exceptions.HttpResponseError:
        """

    @overload
    def send_to_group(  # pylint: disable=inconsistent-return-statements
        self,
        group: str,
        message: IO,
        *,
        excluded: Optional[List[str]] = None,
        filter: Optional[str] = None,
        content_type: Optional[str] = "application/octet-stream",
        **kwargs: Any
    ) -> None:
        """Send content inside request body to a group of connections.

        Send content inside request body to a group of connections.

        :param group: Target group name, which length should be greater than 0 and less than 1025.
         Required.
        :type group: str
        :param message: The payload body. Required.
        :type message: IO
        :keyword excluded: Excluded connection Ids. Default value is None.
        :paramtype excluded: list[str]
        :keyword filter: Following OData filter syntax to filter out the subscribers receiving the
         messages. Default value is None.
        :paramtype filter: str
        :keyword content_type: The content type of the payload. Default value is None. Allowed values are 'application/json', 'application/octet-stream' and 'text/plain'
        :paramtype content_type: str
        :return: None
        :rtype: None
        :raises ~azure.core.exceptions.HttpResponseError:
        """

    @distributed_trace
    def send_to_group(  # pylint: disable=inconsistent-return-statements
        self,
        group: str,
        message: Union[IO, str, JSON],
        *,
        excluded: Optional[List[str]] = None,
        filter: Optional[str] = None,
        content_type: Optional[str] = None,
        **kwargs: Any
    ) -> None:
        """Send content inside request body to a group of connections.

        Send content inside request body to a group of connections.

        :param group: Target group name, which length should be greater than 0 and less than 1025.
         Required.
        :type group: str
        :param message: The payload body. Required.
        :type message: Union[IO, str, JSON]
        :keyword excluded: Excluded connection Ids. Default value is None.
        :paramtype excluded: list[str]
        :keyword filter: Following OData filter syntax to filter out the subscribers receiving the
         messages. Default value is None.
        :paramtype filter: str
        :keyword content_type: The content type of the payload. Default value is None. Allowed values are 'application/json', 'application/octet-stream' and 'text/plain'
        :paramtype content_type: str
        :return: None
        :rtype: None
        :raises ~azure.core.exceptions.HttpResponseError:
        """
        error_map = {
            401: ClientAuthenticationError,
            404: ResourceNotFoundError,
            409: ResourceExistsError,
            304: ResourceNotModifiedError,
        }
        error_map.update(kwargs.pop("error_map", {}) or {})

        _headers = case_insensitive_dict(kwargs.pop("headers", {}) or {})
        _params = kwargs.pop("params", {}) or {}

        content_type = _headers.pop("Content-Type", "application/json") if content_type is None else content_type
        cls = kwargs.pop("cls", None)  # type: ClsType[None]

        _json = None
        _content = None
        content_type = content_type or ""
        if content_type.split(";")[0] in ["application/json"]:
            _json = message
        elif content_type.split(";")[0] in ["application/octet-stream", "text/plain"]:
            _content = message
        else:
            raise ValueError(
                "The content_type '{}' is not one of the allowed values: "
                "['application/json', 'application/octet-stream', 'text/plain']".format(content_type)
            )
        request = build_web_pub_sub_service_send_to_group_request(
            group=group,
            hub=self._config.hub,
            excluded=excluded,
            filter=filter,
            content_type=content_type,
            api_version=self._config.api_version,
            content=_content,
            json=_json,
            headers=_headers,
            params=_params,
        )
        path_format_arguments = {
            "endpoint": self._serialize.url("self._config.endpoint", self._config.endpoint, "str", skip_quote=True),
        }
        request.url = self._client.format_url(request.url, **path_format_arguments)  # type: ignore

        pipeline_response = self._client._pipeline.run(  # type: ignore # pylint: disable=protected-access
            request, stream=False, **kwargs
        )

        response = pipeline_response.http_response

        if response.status_code not in [202]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            raise HttpResponseError(response=response)
        if cls:
            return cls(pipeline_response, None, {})

    @overload
    def send_to_connection(  # pylint: disable=inconsistent-return-statements
        self,
        connection_id: str,
        message: Union[str, JSON],
        *,
        content_type: Optional[str] = "application/json",
        **kwargs: Any
    ) -> None:
        """Send content inside request body to the specific connection.

        Send content inside request body to the specific connection.

        :param connection_id: The connection Id. Required.
        :type connection_id: str
        :param message: The payload body. Required.
        :type message: Union[str, JSON]
        :keyword content_type: The content type of the payload. Default value is None. Allowed values are 'application/json', 'application/octet-stream' and 'text/plain'
        :paramtype content_type: str
        :return: None
        :rtype: None
        :raises ~azure.core.exceptions.HttpResponseError:
        """

    @overload
    def send_to_connection(  # pylint: disable=inconsistent-return-statements
        self, connection_id: str, message: str, *, content_type: Optional[str] = "text/plain", **kwargs: Any
    ) -> None:
        """Send content inside request body to the specific connection.

        Send content inside request body to the specific connection.

        :param connection_id: The connection Id. Required.
        :type connection_id: str
        :param message: The payload body. Required.
        :type message: str
        :keyword content_type: The content type of the payload. Default value is None. Allowed values are 'application/json', 'application/octet-stream' and 'text/plain'
        :paramtype content_type: str
        :return: None
        :rtype: None
        :raises ~azure.core.exceptions.HttpResponseError:
        """

    @overload
    def send_to_connection(  # pylint: disable=inconsistent-return-statements
        self,
        connection_id: str,
        message: IO,
        *,
        content_type: Optional[str] = "application/octet-stream",
        **kwargs: Any
    ) -> None:
        """Send content inside request body to the specific connection.

        Send content inside request body to the specific connection.

        :param connection_id: The connection Id. Required.
        :type connection_id: str
        :param message: The payload body. Required.
        :type message: IO
        :keyword content_type: The content type of the payload. Default value is None. Allowed values are 'application/json', 'application/octet-stream' and 'text/plain'
        :paramtype content_type: str
        :return: None
        :rtype: None
        :raises ~azure.core.exceptions.HttpResponseError:
        """

    @distributed_trace
    def send_to_connection(  # pylint: disable=inconsistent-return-statements
        self, connection_id: str, message: Union[IO, str, JSON], *, content_type: Optional[str] = None, **kwargs: Any
    ) -> None:
        """Send content inside request body to the specific connection.

        Send content inside request body to the specific connection.

        :param connection_id: The connection Id. Required.
        :type connection_id: str
        :param message: The payload body. Required.
        :type message: Union[IO, str, JSON]
        :keyword content_type: The content type of the payload. Default value is None. Allowed values are 'application/json', 'application/octet-stream' and 'text/plain'
        :paramtype content_type: str
        :return: None
        :rtype: None
        :raises ~azure.core.exceptions.HttpResponseError:
        """
        error_map = {
            401: ClientAuthenticationError,
            404: ResourceNotFoundError,
            409: ResourceExistsError,
            304: ResourceNotModifiedError,
        }
        error_map.update(kwargs.pop("error_map", {}) or {})

        _headers = case_insensitive_dict(kwargs.pop("headers", {}) or {})
        _params = kwargs.pop("params", {}) or {}

        content_type = _headers.pop("Content-Type", "application/json") if content_type is None else content_type
        cls = kwargs.pop("cls", None)  # type: ClsType[None]

        _json = None
        _content = None
        content_type = content_type or ""
        if content_type.split(";")[0] in ["application/json"]:
            _json = message
        elif content_type.split(";")[0] in ["application/octet-stream", "text/plain"]:
            _content = message
        else:
            raise ValueError(
                "The content_type '{}' is not one of the allowed values: "
                "['application/json', 'application/octet-stream', 'text/plain']".format(content_type)
            )
        request = build_web_pub_sub_service_send_to_connection_request(
            connection_id=connection_id,
            hub=self._config.hub,
            content_type=content_type,
            api_version=self._config.api_version,
            content=_content,
            json=_json,
            headers=_headers,
            params=_params,
        )
        path_format_arguments = {
            "endpoint": self._serialize.url("self._config.endpoint", self._config.endpoint, "str", skip_quote=True),
        }
        request.url = self._client.format_url(request.url, **path_format_arguments)  # type: ignore

        pipeline_response = self._client._pipeline.run(  # type: ignore # pylint: disable=protected-access
            request, stream=False, **kwargs
        )

        response = pipeline_response.http_response

        if response.status_code not in [202]:
            map_error(status_code=response.status_code, response=response, error_map=error_map)
            raise HttpResponseError(response=response)
        if cls:
            return cls(pipeline_response, None, {})


__all__: List[str] = [
    "WebPubSubServiceClientOperationsMixin"
]  # Add all objects you want publicly available to users at this package level


def patch_sdk():
    """Do not remove from this file.

    `patch_sdk` is a last resort escape hatch that allows you to do customizations
    you can't accomplish using the techniques described in
    https://aka.ms/azsdk/python/dpcodegen/python/customize
    """
