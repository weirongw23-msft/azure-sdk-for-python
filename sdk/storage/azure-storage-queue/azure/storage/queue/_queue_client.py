# -------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for
# license information.
# --------------------------------------------------------------------------

import functools
import warnings
from types import TracebackType
from typing import Any, cast, Dict, List, Optional, Tuple, TYPE_CHECKING, Union
from typing_extensions import Self

from azure.core.exceptions import HttpResponseError
from azure.core.paging import ItemPaged
from azure.core.tracing.decorator import distributed_trace
from ._deserialize import deserialize_queue_creation, deserialize_queue_properties
from ._encryption import modify_user_agent_for_encryption, StorageEncryptionMixin
from ._generated import AzureQueueStorage
from ._generated.models import QueueMessage as GenQueueMessage, SignedIdentifier
from ._message_encoding import NoDecodePolicy, NoEncodePolicy
from ._models import AccessPolicy, MessagesPaged, QueueMessage
from ._queue_client_helpers import _format_url, _from_queue_url, _parse_url
from ._serialize import get_api_version
from ._shared.base_client import parse_connection_str, StorageAccountHostsMixin
from ._shared.request_handlers import add_metadata_headers, serialize_iso
from ._shared.response_handlers import process_storage_error, return_headers_and_deserialized, return_response_headers

if TYPE_CHECKING:
    from azure.core.credentials import AzureNamedKeyCredential, AzureSasCredential, TokenCredential
    from ._message_encoding import (
        BinaryBase64DecodePolicy,
        BinaryBase64EncodePolicy,
        TextBase64DecodePolicy,
        TextBase64EncodePolicy,
    )
    from ._models import QueueProperties


class QueueClient(StorageAccountHostsMixin, StorageEncryptionMixin):
    """A client to interact with a specific Queue.

    For more optional configuration, please click
    `here <https://github.com/Azure/azure-sdk-for-python/tree/main/sdk/storage/azure-storage-queue
    #optional-configuration>`__.

    :param str account_url:
        The URL to the storage account. In order to create a client given the full URI to the queue,
        use the :func:`from_queue_url` classmethod.
    :param queue_name: The name of the queue.
    :type queue_name: str
    :param credential:
        The credentials with which to authenticate. This is optional if the
        account URL already has a SAS token. The value can be a SAS token string,
        an instance of a AzureSasCredential or AzureNamedKeyCredential from azure.core.credentials,
        an account shared access key, or an instance of a TokenCredentials class from azure.identity.
        If the resource URI already contains a SAS token, this will be ignored in favor of an explicit credential
        - except in the case of AzureSasCredential, where the conflicting SAS tokens will raise a ValueError.
        If using an instance of AzureNamedKeyCredential, "name" should be the storage account name, and "key"
        should be the storage account key.
    :type credential:
        ~azure.core.credentials.AzureNamedKeyCredential or
        ~azure.core.credentials.AzureSasCredential or
        ~azure.core.credentials.TokenCredential or
        str or dict[str, str] or None
    :keyword str api_version:
        The Storage API version to use for requests. Default value is the most recent service version that is
        compatible with the current SDK. Setting to an older version may result in reduced feature compatibility.
    :keyword str secondary_hostname:
        The hostname of the secondary endpoint.
    :keyword message_encode_policy: The encoding policy to use on outgoing messages.
        Default is not to encode messages. Other options include ~azure.storage.queue.TextBase64EncodePolicy,
        ~azure.storage.queue.BinaryBase64EncodePolicy or `None`.
    :paramtype message_encode_policy: BinaryBase64EncodePolicy or TextBase64EncodePolicy or None
    :keyword message_decode_policy: The decoding policy to use on incoming messages.
        Default value is not to decode messages. Other options include ~azure.storage.queue.TextBase64DecodePolicy,
        ~azure.storage.queue.BinaryBase64DecodePolicy or `None`.
    :paramtype message_decode_policy: BinaryBase64DecodePolicy or TextBase64DecodePolicy or None
    :keyword str audience: The audience to use when requesting tokens for Azure Active Directory
        authentication. Only has an effect when credential is of type TokenCredential. The value could be
        https://storage.azure.com/ (default) or https://<account>.queue.core.windows.net.

    .. admonition:: Example:

        .. literalinclude:: ../samples/queue_samples_message.py
            :start-after: [START create_queue_client]
            :end-before: [END create_queue_client]
            :language: python
            :dedent: 12
            :caption: Create the queue client with url and credential.
    """

    def __init__(
        self,
        account_url: str,
        queue_name: str,
        credential: Optional[
            Union[str, Dict[str, str], "AzureNamedKeyCredential", "AzureSasCredential", "TokenCredential"]
        ] = None,
        *,
        api_version: Optional[str] = None,
        secondary_hostname: Optional[str] = None,
        message_encode_policy: Optional[Union["BinaryBase64EncodePolicy", "TextBase64EncodePolicy"]] = None,
        message_decode_policy: Optional[Union["BinaryBase64DecodePolicy", "TextBase64DecodePolicy"]] = None,
        audience: Optional[str] = None,
        **kwargs: Any
    ) -> None:
        parsed_url, sas_token = _parse_url(account_url=account_url, queue_name=queue_name, credential=credential)
        self.queue_name = queue_name
        self._query_str, credential = self._format_query_string(sas_token, credential)
        super(QueueClient, self).__init__(
            parsed_url,
            service="queue",
            credential=credential,
            secondary_hostname=secondary_hostname,
            audience=audience,
            **kwargs
        )
        self._message_encode_policy = message_encode_policy or NoEncodePolicy()
        self._message_decode_policy = message_decode_policy or NoDecodePolicy()
        self._client = AzureQueueStorage(self.url, base_url=self.url, pipeline=self._pipeline)
        self._client._config.version = get_api_version(api_version)  # type: ignore [assignment]
        self._configure_encryption(kwargs)

    def __enter__(self) -> Self:
        self._client.__enter__()
        return self

    def __exit__(
        self, typ: Optional[type[BaseException]], exc: Optional[BaseException], tb: Optional[TracebackType]
    ) -> None:
        self._client.__exit__(typ, exc, tb)  # pylint: disable=specify-parameter-names-in-call

    def close(self) -> None:
        """This method is to close the sockets opened by the client.
        It need not be used when using with a context manager.

        :return: None
        :rtype: None
        """
        self._client.close()

    def _format_url(self, hostname: str) -> str:
        """Format the endpoint URL according to the current location
        mode hostname.

        :param str hostname: The current location mode hostname.
        :returns: The formatted endpoint URL according to the specified location mode hostname.
        :rtype: str
        """
        return _format_url(queue_name=self.queue_name, hostname=hostname, scheme=self.scheme, query_str=self._query_str)

    @classmethod
    def from_queue_url(
        cls,
        queue_url: str,
        credential: Optional[
            Union[str, Dict[str, str], "AzureNamedKeyCredential", "AzureSasCredential", "TokenCredential"]
        ] = None,
        *,
        api_version: Optional[str] = None,
        secondary_hostname: Optional[str] = None,
        message_encode_policy: Optional[Union["BinaryBase64EncodePolicy", "TextBase64EncodePolicy"]] = None,
        message_decode_policy: Optional[Union["BinaryBase64DecodePolicy", "TextBase64DecodePolicy"]] = None,
        audience: Optional[str] = None,
        **kwargs: Any
    ) -> Self:
        """A client to interact with a specific Queue.

        :param str queue_url: The full URI to the queue, including SAS token if used.
        :param credential:
            The credentials with which to authenticate. This is optional if the
            account URL already has a SAS token. The value can be a SAS token string,
            an instance of a AzureSasCredential or AzureNamedKeyCredential from azure.core.credentials,
            an account shared access key, or an instance of a TokenCredentials class from azure.identity.
            If the resource URI already contains a SAS token, this will be ignored in favor of an explicit credential
            - except in the case of AzureSasCredential, where the conflicting SAS tokens will raise a ValueError.
            If using an instance of AzureNamedKeyCredential, "name" should be the storage account name, and "key"
            should be the storage account key.
        :type credential:
            ~azure.core.credentials.AzureNamedKeyCredential or
            ~azure.core.credentials.AzureSasCredential or
            ~azure.core.credentials.TokenCredential or
            str or dict[str, str] or None
        :keyword str api_version:
            The Storage API version to use for requests. Default value is the most recent service version that is
            compatible with the current SDK. Setting to an older version may result in reduced feature compatibility.
        :keyword str secondary_hostname:
            The hostname of the secondary endpoint.
        :keyword message_encode_policy: The encoding policy to use on outgoing messages.
            Default is not to encode messages. Other options include ~azure.storage.queue.TextBase64EncodePolicy,
            ~azure.storage.queue.BinaryBase64EncodePolicy or `None`.
        :paramtype message_encode_policy: BinaryBase64EncodePolicy or TextBase64EncodePolicy or None
        :keyword message_decode_policy: The decoding policy to use on incoming messages.
            Default value is not to decode messages. Other options include ~azure.storage.queue.TextBase64DecodePolicy,
            ~azure.storage.queue.BinaryBase64DecodePolicy or `None`.
        :paramtype message_decode_policy: BinaryBase64DecodePolicy or TextBase64DecodePolicy or None
        :keyword str audience: The audience to use when requesting tokens for Azure Active Directory
            authentication. Only has an effect when credential is of type TokenCredential. The value could be
            https://storage.azure.com/ (default) or https://<account>.queue.core.windows.net.
        :returns: A queue client.
        :rtype: ~azure.storage.queue.QueueClient
        """
        account_url, queue_name = _from_queue_url(queue_url=queue_url)
        return cls(
            account_url,
            queue_name=queue_name,
            credential=credential,
            api_version=api_version,
            secondary_hostname=secondary_hostname,
            message_encode_policy=message_encode_policy,
            message_decode_policy=message_decode_policy,
            audience=audience,
            **kwargs
        )

    @classmethod
    def from_connection_string(
        cls,
        conn_str: str,
        queue_name: str,
        credential: Optional[
            Union[str, Dict[str, str], "AzureNamedKeyCredential", "AzureSasCredential", "TokenCredential"]
        ] = None,
        *,
        api_version: Optional[str] = None,
        secondary_hostname: Optional[str] = None,
        message_encode_policy: Optional[Union["BinaryBase64EncodePolicy", "TextBase64EncodePolicy"]] = None,
        message_decode_policy: Optional[Union["BinaryBase64DecodePolicy", "TextBase64DecodePolicy"]] = None,
        audience: Optional[str] = None,
        **kwargs: Any
    ) -> Self:
        """Create QueueClient from a Connection String.

        :param str conn_str:
            A connection string to an Azure Storage account.
        :param queue_name: The queue name.
        :type queue_name: str
        :param credential:
            The credentials with which to authenticate. This is optional if the
            account URL already has a SAS token, or the connection string already has shared
            access key values. The value can be a SAS token string,
            an instance of a AzureSasCredential or AzureNamedKeyCredential from azure.core.credentials,
            an account shared access key, or an instance of a TokenCredentials class from azure.identity.
            Credentials provided here will take precedence over those in the connection string.
            If using an instance of AzureNamedKeyCredential, "name" should be the storage account name, and "key"
            should be the storage account key.
        :type credential:
            ~azure.core.credentials.AzureNamedKeyCredential or
            ~azure.core.credentials.AzureSasCredential or
            ~azure.core.credentials.TokenCredential or
            str or dict[str, str] or None
        :keyword str api_version:
            The Storage API version to use for requests. Default value is the most recent service version that is
            compatible with the current SDK. Setting to an older version may result in reduced feature compatibility.
        :keyword str secondary_hostname:
            The hostname of the secondary endpoint.
        :keyword message_encode_policy: The encoding policy to use on outgoing messages.
            Default is not to encode messages. Other options include ~azure.storage.queue.TextBase64EncodePolicy,
            ~azure.storage.queue.BinaryBase64EncodePolicy or `None`.
        :paramtype message_encode_policy: BinaryBase64EncodePolicy or TextBase64EncodePolicy or None
        :keyword message_decode_policy: The decoding policy to use on incoming messages.
            Default value is not to decode messages. Other options include ~azure.storage.queue.TextBase64DecodePolicy,
            ~azure.storage.queue.BinaryBase64DecodePolicy or `None`.
        :paramtype message_decode_policy: BinaryBase64DecodePolicy or TextBase64DecodePolicy or None
        :keyword str audience: The audience to use when requesting tokens for Azure Active Directory
            authentication. Only has an effect when credential is of type TokenCredential. The value could be
            https://storage.azure.com/ (default) or https://<account>.queue.core.windows.net.
        :returns: A queue client.
        :rtype: ~azure.storage.queue.QueueClient

        .. admonition:: Example:

            .. literalinclude:: ../samples/queue_samples_message.py
                :start-after: [START create_queue_client_from_connection_string]
                :end-before: [END create_queue_client_from_connection_string]
                :language: python
                :dedent: 8
                :caption: Create the queue client from connection string.
        """
        account_url, secondary, credential = parse_connection_str(conn_str, credential, "queue")
        return cls(
            account_url,
            queue_name=queue_name,
            credential=credential,
            api_version=api_version,
            secondary_hostname=secondary_hostname or secondary,
            message_encode_policy=message_encode_policy,
            message_decode_policy=message_decode_policy,
            audience=audience,
            **kwargs
        )

    @distributed_trace
    def create_queue(
        self, *, metadata: Optional[Dict[str, str]] = None, timeout: Optional[int] = None, **kwargs: Any
    ) -> None:
        """Creates a new queue in the storage account.

        If a queue with the same name already exists, the operation fails with
        a `ResourceExistsError`.

        :keyword Dict[str, str] metadata:
            A dict containing name-value pairs to associate with the queue as
            metadata. Note that metadata names preserve the case with which they
            were created, but are case-insensitive when set or read.
        :keyword int timeout:
            Sets the server-side timeout for the operation in seconds. For more details see
            https://learn.microsoft.com/rest/api/storageservices/setting-timeouts-for-queue-service-operations.
            This value is not tracked or validated on the client. To configure client-side network timesouts
            see `here <https://github.com/Azure/azure-sdk-for-python/tree/main/sdk/storage/azure-storage-queue
            #other-client--per-operation-configuration>`__.
        :return: None or the result of cls(response)
        :rtype: None
        :raises: StorageErrorException

        .. admonition:: Example:

            .. literalinclude:: ../samples/queue_samples_hello_world.py
                :start-after: [START create_queue]
                :end-before: [END create_queue]
                :language: python
                :dedent: 8
                :caption: Create a queue.
        """
        headers = kwargs.pop("headers", {})
        headers.update(add_metadata_headers(metadata))
        try:
            return self._client.queue.create(
                metadata=metadata, timeout=timeout, headers=headers, cls=deserialize_queue_creation, **kwargs
            )
        except HttpResponseError as error:
            process_storage_error(error)

    @distributed_trace
    def delete_queue(self, *, timeout: Optional[int] = None, **kwargs: Any) -> None:
        """Deletes the specified queue and any messages it contains.

        When a queue is successfully deleted, it is immediately marked for deletion
        and is no longer accessible to clients. The queue is later removed from
        the Queue service during garbage collection.

        Note that deleting a queue is likely to take at least 40 seconds to complete.
        If an operation is attempted against the queue while it was being deleted,
        an ~azure.core.exceptions.HttpResponseError will be thrown.

        :keyword int timeout:
            Sets the server-side timeout for the operation in seconds. For more details see
            https://learn.microsoft.com/rest/api/storageservices/setting-timeouts-for-queue-service-operations.
            This value is not tracked or validated on the client. To configure client-side network timesouts
            see `here <https://github.com/Azure/azure-sdk-for-python/tree/main/sdk/storage/azure-storage-queue
            #other-client--per-operation-configuration>`__.
        :rtype: None

        .. admonition:: Example:

            .. literalinclude:: ../samples/queue_samples_hello_world.py
                :start-after: [START delete_queue]
                :end-before: [END delete_queue]
                :language: python
                :dedent: 12
                :caption: Delete a queue.
        """
        try:
            self._client.queue.delete(timeout=timeout, **kwargs)
        except HttpResponseError as error:
            process_storage_error(error)

    @distributed_trace
    def get_queue_properties(self, *, timeout: Optional[int] = None, **kwargs: Any) -> "QueueProperties":
        """Returns all user-defined metadata for the specified queue.

        The data returned does not include the queue's list of messages.

        :keyword int timeout:
            The timeout parameter is expressed in seconds.
        :return: User-defined metadata for the queue.
        :rtype: ~azure.storage.queue.QueueProperties

        .. admonition:: Example:

            .. literalinclude:: ../samples/queue_samples_message.py
                :start-after: [START get_queue_properties]
                :end-before: [END get_queue_properties]
                :language: python
                :dedent: 12
                :caption: Get the properties on the queue.
        """
        try:
            response = cast(
                "QueueProperties",
                self._client.queue.get_properties(timeout=timeout, cls=deserialize_queue_properties, **kwargs),
            )
        except HttpResponseError as error:
            process_storage_error(error)
        response.name = self.queue_name
        return response

    @distributed_trace
    def set_queue_metadata(
        self, metadata: Optional[Dict[str, str]] = None, *, timeout: Optional[int] = None, **kwargs: Any
    ) -> Dict[str, Any]:
        """Sets user-defined metadata on the specified queue.

        Metadata is associated with the queue as name-value pairs.

        :param Optional[Dict[str, str]] metadata:
            A dict containing name-value pairs to associate with the
            queue as metadata.
        :keyword int timeout:
            Sets the server-side timeout for the operation in seconds. For more details see
            https://learn.microsoft.com/rest/api/storageservices/setting-timeouts-for-queue-service-operations.
            This value is not tracked or validated on the client. To configure client-side network timesouts
            see `here <https://github.com/Azure/azure-sdk-for-python/tree/main/sdk/storage/azure-storage-queue
            #other-client--per-operation-configuration>`__.
        :return: A dictionary of response headers.
        :rtype: Dict[str, Any]

        .. admonition:: Example:

            .. literalinclude:: ../samples/queue_samples_message.py
                :start-after: [START set_queue_metadata]
                :end-before: [END set_queue_metadata]
                :language: python
                :dedent: 12
                :caption: Set metadata on the queue.
        """
        headers = kwargs.pop("headers", {})
        headers.update(add_metadata_headers(metadata))
        try:
            return self._client.queue.set_metadata(
                timeout=timeout, headers=headers, cls=return_response_headers, **kwargs
            )
        except HttpResponseError as error:
            process_storage_error(error)

    @distributed_trace
    def get_queue_access_policy(self, *, timeout: Optional[int] = None, **kwargs: Any) -> Dict[str, AccessPolicy]:
        """Returns details about any stored access policies specified on the
        queue that may be used with Shared Access Signatures.

        :keyword int timeout:
            Sets the server-side timeout for the operation in seconds. For more details see
            https://learn.microsoft.com/rest/api/storageservices/setting-timeouts-for-queue-service-operations.
            This value is not tracked or validated on the client. To configure client-side network timesouts
            see `here <https://github.com/Azure/azure-sdk-for-python/tree/main/sdk/storage/azure-storage-queue
            #other-client--per-operation-configuration>`__.
        :return: A dictionary of access policies associated with the queue.
        :rtype: Dict[str, ~azure.storage.queue.AccessPolicy]
        """
        try:
            _, identifiers = cast(
                Tuple[Dict, List],
                self._client.queue.get_access_policy(timeout=timeout, cls=return_headers_and_deserialized, **kwargs),
            )
        except HttpResponseError as error:
            process_storage_error(error)
        return {s.id: s.access_policy or AccessPolicy() for s in identifiers}

    @distributed_trace
    def set_queue_access_policy(
        self, signed_identifiers: Dict[str, AccessPolicy], *, timeout: Optional[int] = None, **kwargs: Any
    ) -> None:
        """Sets stored access policies for the queue that may be used with Shared
        Access Signatures.

        When you set permissions for a queue, the existing permissions are replaced.
        To update the queue's permissions, call :func:`~get_queue_access_policy` to fetch
        all access policies associated with the queue, modify the access policy
        that you wish to change, and then call this function with the complete
        set of data to perform the update.

        When you establish a stored access policy on a queue, it may take up to
        30 seconds to take effect. During this interval, a shared access signature
        that is associated with the stored access policy will throw an
        ~azure.core.exceptions.HttpResponseError until the access policy becomes active.

        :param signed_identifiers:
            SignedIdentifier access policies to associate with the queue.
            This may contain up to 5 elements. An empty dict
            will clear the access policies set on the service.
        :type signed_identifiers: Dict[str, ~azure.storage.queue.AccessPolicy]
        :keyword int timeout:
            Sets the server-side timeout for the operation in seconds. For more details see
            https://learn.microsoft.com/rest/api/storageservices/setting-timeouts-for-queue-service-operations.
            This value is not tracked or validated on the client. To configure client-side network timesouts
            see `here <https://github.com/Azure/azure-sdk-for-python/tree/main/sdk/storage/azure-storage-queue
            #other-client--per-operation-configuration>`__.

        .. admonition:: Example:

            .. literalinclude:: ../samples/queue_samples_message.py
                :start-after: [START set_access_policy]
                :end-before: [END set_access_policy]
                :language: python
                :dedent: 12
                :caption: Set an access policy on the queue.
        """
        if len(signed_identifiers) > 15:
            raise ValueError(
                "Too many access policies provided. The server does not support setting "
                "more than 15 access policies on a single resource."
            )
        identifiers = []
        for key, value in signed_identifiers.items():
            if value:
                value.start = serialize_iso(value.start)
                value.expiry = serialize_iso(value.expiry)
            identifiers.append(SignedIdentifier(id=key, access_policy=value))
        try:
            self._client.queue.set_access_policy(queue_acl=identifiers or None, timeout=timeout, **kwargs)
        except HttpResponseError as error:
            process_storage_error(error)

    @distributed_trace
    def send_message(
        self,
        content: Optional[object],
        *,
        visibility_timeout: Optional[int] = None,
        time_to_live: Optional[int] = None,
        timeout: Optional[int] = None,
        **kwargs: Any
    ) -> QueueMessage:
        """Adds a new message to the back of the message queue.

        The visibility timeout specifies the time that the message will be
        invisible. After the timeout expires, the message will become visible.
        If a visibility timeout is not specified, the default value of 0 is used.

        The message time-to-live specifies how long a message will remain in the
        queue. The message will be deleted from the queue when the time-to-live
        period expires.

        If the key-encryption-key field is set on the local service object, this method will
        encrypt the content before uploading.

        :param Optional[object] content:
            Message content. Allowed type is determined by the encode_function
            set on the service. Default is str. The encoded message can be up to
            64KB in size.
        :keyword int visibility_timeout:
            If not specified, the default value is 0. Specifies the
            new visibility timeout value, in seconds, relative to server time.
            The value must be larger than or equal to 0, and cannot be
            larger than 7 days. The visibility timeout of a message cannot be
            set to a value later than the expiry time. visibility_timeout
            should be set to a value smaller than the time-to-live value.
        :keyword int time_to_live:
            Specifies the time-to-live interval for the message, in
            seconds. The time-to-live may be any positive number or -1 for infinity. If this
            parameter is omitted, the default time-to-live is 7 days.
        :keyword int timeout:
            Sets the server-side timeout for the operation in seconds. For more details see
            https://learn.microsoft.com/rest/api/storageservices/setting-timeouts-for-queue-service-operations.
            This value is not tracked or validated on the client. To configure client-side network timesouts
            see `here <https://github.com/Azure/azure-sdk-for-python/tree/main/sdk/storage/azure-storage-queue
            #other-client--per-operation-configuration>`__.
        :return:
            A ~azure.storage.queue.QueueMessage object.
            This object is also populated with the content, although it is not
            returned from the service.
        :rtype: ~azure.storage.queue.QueueMessage

        .. admonition:: Example:

            .. literalinclude:: ../samples/queue_samples_message.py
                :start-after: [START send_messages]
                :end-before: [END send_messages]
                :language: python
                :dedent: 12
                :caption: Send messages.
        """
        if self.key_encryption_key:
            modify_user_agent_for_encryption(
                self._config.user_agent_policy.user_agent, self._sdk_moniker, self.encryption_version, kwargs
            )

        try:
            self._message_encode_policy.configure(
                require_encryption=self.require_encryption,
                key_encryption_key=self.key_encryption_key,
                resolver=self.key_resolver_function,
                encryption_version=self.encryption_version,
            )
        except TypeError:
            warnings.warn(
                "TypeError when calling message_encode_policy.configure. \
                It is likely missing the encryption_version parameter. \
                Consider updating your encryption information/implementation. \
                Retrying without encryption_version."
            )
            self._message_encode_policy.configure(
                require_encryption=self.require_encryption,
                key_encryption_key=self.key_encryption_key,
                resolver=self.key_resolver_function,
            )
        encoded_content = self._message_encode_policy(content)
        new_message = GenQueueMessage(message_text=encoded_content)

        try:
            enqueued = self._client.messages.enqueue(
                queue_message=new_message,
                visibilitytimeout=visibility_timeout,
                message_time_to_live=time_to_live,
                timeout=timeout,
                **kwargs
            )
            queue_message = QueueMessage(
                content=content,
                id=enqueued[0].message_id,
                inserted_on=enqueued[0].insertion_time,
                expires_on=enqueued[0].expiration_time,
                pop_receipt=enqueued[0].pop_receipt,
                next_visible_on=enqueued[0].time_next_visible,
            )
            return queue_message
        except HttpResponseError as error:
            process_storage_error(error)

    @distributed_trace
    def receive_message(
        self, *, visibility_timeout: Optional[int] = None, timeout: Optional[int] = None, **kwargs: Any
    ) -> Optional[QueueMessage]:
        """Removes one message from the front of the queue.

        When the message is retrieved from the queue, the response includes the message
        content and a pop_receipt value, which is required to delete the message.
        The message is not automatically deleted from the queue, but after it has
        been retrieved, it is not visible to other clients for the time interval
        specified by the visibility_timeout parameter.

        If the key-encryption-key or resolver field is set on the local service object, the message will be
        decrypted before being returned.

        :keyword int visibility_timeout:
            If not specified, the default value is 30. Specifies the
            new visibility timeout value, in seconds, relative to server time.
            The value must be larger than or equal to 1, and cannot be
            larger than 7 days. The visibility timeout of a message cannot be
            set to a value later than the expiry time. visibility_timeout
            should be set to a value smaller than the time-to-live value.
        :keyword int timeout:
            Sets the server-side timeout for the operation in seconds. For more details see
            https://learn.microsoft.com/rest/api/storageservices/setting-timeouts-for-queue-service-operations.
            This value is not tracked or validated on the client. To configure client-side network timesouts
            see `here <https://github.com/Azure/azure-sdk-for-python/tree/main/sdk/storage/azure-storage-queue
            #other-client--per-operation-configuration>`__.
        :return:
            Returns a message from the Queue or None if the Queue is empty.
        :rtype: ~azure.storage.queue.QueueMessage or None

        .. admonition:: Example:

            .. literalinclude:: ../samples/queue_samples_message.py
                :start-after: [START receive_one_message]
                :end-before: [END receive_one_message]
                :language: python
                :dedent: 12
                :caption: Receive one message from the queue.
        """
        if self.key_encryption_key or self.key_resolver_function:
            modify_user_agent_for_encryption(
                self._config.user_agent_policy.user_agent, self._sdk_moniker, self.encryption_version, kwargs
            )

        self._message_decode_policy.configure(
            require_encryption=self.require_encryption,
            key_encryption_key=self.key_encryption_key,
            resolver=self.key_resolver_function,
        )
        try:
            message = self._client.messages.dequeue(
                number_of_messages=1,
                visibilitytimeout=visibility_timeout,
                timeout=timeout,
                cls=self._message_decode_policy,
                **kwargs
            )
            wrapped_message = (
                QueueMessage._from_generated(message[0]) if message != [] else None  # pylint: disable=protected-access
            )
            return wrapped_message
        except HttpResponseError as error:
            process_storage_error(error)

    @distributed_trace
    def receive_messages(
        self,
        *,
        messages_per_page: Optional[int] = None,
        visibility_timeout: Optional[int] = None,
        max_messages: Optional[int] = None,
        timeout: Optional[int] = None,
        **kwargs: Any
    ) -> ItemPaged[QueueMessage]:
        """Removes one or more messages from the front of the queue.

        When a message is retrieved from the queue, the response includes the message
        content and a pop_receipt value, which is required to delete the message.
        The message is not automatically deleted from the queue, but after it has
        been retrieved, it is not visible to other clients for the time interval
        specified by the visibility_timeout parameter. The iterator will continuously
        fetch messages until the queue is empty or max_messages is reached (if max_messages
        is set).

        If the key-encryption-key or resolver field is set on the local service object, the messages will be
        decrypted before being returned.

        :keyword int messages_per_page:
            A nonzero integer value that specifies the number of
            messages to retrieve from the queue, up to a maximum of 32. If
            fewer are visible, the visible messages are returned. By default,
            a single message is retrieved from the queue with this operation.
            `by_page()` can be used to provide a page iterator on the AsyncItemPaged if messages_per_page is set.
            `next()` can be used to get the next page.

        .. admonition:: Example:

            .. literalinclude:: ../samples/queue_samples_message.py
                :start-after: [START receive_messages_listing]
                :end-before: [END receive_messages_listing]
                :language: python
                :dedent: 12
                :caption: List pages and corresponding messages from the queue.

        :keyword int visibility_timeout:
            If not specified, the default value is 30. Specifies the
            new visibility timeout value, in seconds, relative to server time.
            The value must be larger than or equal to 1, and cannot be
            larger than 7 days. The visibility timeout of a message cannot be
            set to a value later than the expiry time. visibility_timeout
            should be set to a value smaller than the time-to-live value.
        :keyword int max_messages:
            An integer that specifies the maximum number of messages to retrieve from the queue.
        :keyword int timeout:
            Sets the server-side timeout for the operation in seconds. For more details see
            https://learn.microsoft.com/rest/api/storageservices/setting-timeouts-for-queue-service-operations.
            This value is not tracked or validated on the client. To configure client-side network timesouts
            see `here <https://github.com/Azure/azure-sdk-for-python/tree/main/sdk/storage/azure-storage-queue
            #other-client--per-operation-configuration>`__.
        :return:
            Returns a message iterator of dict-like Message objects.
        :rtype: ~azure.core.paging.ItemPaged[~azure.storage.queue.QueueMessage]

        .. admonition:: Example:

            .. literalinclude:: ../samples/queue_samples_message.py
                :start-after: [START receive_messages]
                :end-before: [END receive_messages]
                :language: python
                :dedent: 12
                :caption: Receive messages from the queue.
        """
        if self.key_encryption_key or self.key_resolver_function:
            modify_user_agent_for_encryption(
                self._config.user_agent_policy.user_agent, self._sdk_moniker, self.encryption_version, kwargs
            )

        self._message_decode_policy.configure(
            require_encryption=self.require_encryption,
            key_encryption_key=self.key_encryption_key,
            resolver=self.key_resolver_function,
        )
        try:
            command = functools.partial(
                self._client.messages.dequeue,
                visibilitytimeout=visibility_timeout,
                timeout=timeout,
                cls=self._message_decode_policy,
                **kwargs
            )
            if max_messages is not None and messages_per_page is not None:
                if max_messages < messages_per_page:
                    raise ValueError("max_messages must be greater or equal to messages_per_page")
            return ItemPaged(
                command,
                results_per_page=messages_per_page,
                page_iterator_class=MessagesPaged,
                max_messages=max_messages,
            )
        except HttpResponseError as error:
            process_storage_error(error)

    @distributed_trace
    def update_message(
        self,
        message: Union[str, QueueMessage],
        pop_receipt: Optional[str] = None,
        content: Optional[object] = None,
        *,
        visibility_timeout: Optional[int] = None,
        timeout: Optional[int] = None,
        **kwargs: Any
    ) -> QueueMessage:
        """Updates the visibility timeout of a message. You can also use this
        operation to update the contents of a message.

        This operation can be used to continually extend the invisibility of a
        queue message. This functionality can be useful if you want a worker role
        to "lease" a queue message. For example, if a worker role calls :func:`~receive_messages()`
        and recognizes that it needs more time to process a message, it can
        continually extend the message's invisibility until it is processed. If
        the worker role were to fail during processing, eventually the message
        would become visible again and another worker role could process it.

        If the key-encryption-key field is set on the local service object, this method will
        encrypt the content before uploading.

        :param message:
            The message object or id identifying the message to update.
        :type message: str or ~azure.storage.queue.QueueMessage
        :param str pop_receipt:
            A valid pop receipt value returned from an earlier call
            to the :func:`~receive_messages` or :func:`~update_message` operation.
        :param Optional[object] content:
            Message content. Allowed type is determined by the encode_function
            set on the service. Default is str.
        :keyword int visibility_timeout:
            Specifies the new visibility timeout value, in seconds,
            relative to server time. The new value must be larger than or equal
            to 0, and cannot be larger than 7 days. The visibility timeout of a
            message cannot be set to a value later than the expiry time. A
            message can be updated until it has been deleted or has expired.
            The message object or message id identifying the message to update.
        :keyword int timeout:
            Sets the server-side timeout for the operation in seconds. For more details see
            https://learn.microsoft.com/rest/api/storageservices/setting-timeouts-for-queue-service-operations.
            This value is not tracked or validated on the client. To configure client-side network timesouts
            see `here <https://github.com/Azure/azure-sdk-for-python/tree/main/sdk/storage/azure-storage-queue
            #other-client--per-operation-configuration>`__.
        :return:
            A ~azure.storage.queue.QueueMessage object. For convenience,
            this object is also populated with the content, although it is not returned by the service.
        :rtype: ~azure.storage.queue.QueueMessage

        .. admonition:: Example:

            .. literalinclude:: ../samples/queue_samples_message.py
                :start-after: [START update_message]
                :end-before: [END update_message]
                :language: python
                :dedent: 12
                :caption: Update a message.
        """
        if self.key_encryption_key or self.key_resolver_function:
            modify_user_agent_for_encryption(
                self._config.user_agent_policy.user_agent, self._sdk_moniker, self.encryption_version, kwargs
            )

        if isinstance(message, QueueMessage):
            message_id = message.id
            message_text = content or message.content
            receipt = pop_receipt or message.pop_receipt
            inserted_on = message.inserted_on
            expires_on = message.expires_on
            dequeue_count = message.dequeue_count
        else:
            message_id = message
            message_text = content
            receipt = pop_receipt
            inserted_on = None
            expires_on = None
            dequeue_count = None

        if receipt is None:
            raise ValueError("pop_receipt must be present")
        if message_text is not None:
            try:
                self._message_encode_policy.configure(
                    self.require_encryption,
                    self.key_encryption_key,
                    self.key_resolver_function,
                    encryption_version=self.encryption_version,
                )
            except TypeError:
                warnings.warn(
                    "TypeError when calling message_encode_policy.configure. \
                    It is likely missing the encryption_version parameter. \
                    Consider updating your encryption information/implementation. \
                    Retrying without encryption_version."
                )
                self._message_encode_policy.configure(
                    self.require_encryption, self.key_encryption_key, self.key_resolver_function
                )
            encoded_message_text = self._message_encode_policy(message_text)
            updated = GenQueueMessage(message_text=encoded_message_text)
        else:
            updated = None
        try:
            response = cast(
                QueueMessage,
                self._client.message_id.update(
                    queue_message=updated,
                    visibilitytimeout=visibility_timeout or 0,
                    timeout=timeout,
                    pop_receipt=receipt,
                    cls=return_response_headers,
                    queue_message_id=message_id,
                    **kwargs
                ),
            )
            new_message = QueueMessage(
                content=message_text,
                id=message_id,
                inserted_on=inserted_on,
                dequeue_count=dequeue_count,
                expires_on=expires_on,
                pop_receipt=response["popreceipt"],
                next_visible_on=response["time_next_visible"],
            )
            return new_message
        except HttpResponseError as error:
            process_storage_error(error)

    @distributed_trace
    def peek_messages(
        self, max_messages: Optional[int] = None, *, timeout: Optional[int] = None, **kwargs: Any
    ) -> List[QueueMessage]:
        """Retrieves one or more messages from the front of the queue, but does
        not alter the visibility of the message.

        Only messages that are visible may be retrieved. When a message is retrieved
        for the first time with a call to :func:`~receive_messages`, its dequeue_count property
        is set to 1. If it is not deleted and is subsequently retrieved again, the
        dequeue_count property is incremented. The client may use this value to
        determine how many times a message has been retrieved. Note that a call
        to peek_messages does not increment the value of dequeue_count, but returns
        this value for the client to read.

        If the key-encryption-key or resolver field is set on the local service object,
        the messages will be decrypted before being returned.

        :param int max_messages:
            A nonzero integer value that specifies the number of
            messages to peek from the queue, up to a maximum of 32. By default,
            a single message is peeked from the queue with this operation.
        :keyword int timeout:
            Sets the server-side timeout for the operation in seconds. For more details see
            https://learn.microsoft.com/rest/api/storageservices/setting-timeouts-for-queue-service-operations.
            This value is not tracked or validated on the client. To configure client-side network timesouts
            see `here <https://github.com/Azure/azure-sdk-for-python/tree/main/sdk/storage/azure-storage-queue
            #other-client--per-operation-configuration>`__.
        :return:
            A list of ~azure.storage.queue.QueueMessage objects. Note that
            next_visible_on and pop_receipt will not be populated as peek does
            not pop the message and can only retrieve already visible messages.
        :rtype: List[~azure.storage.queue.QueueMessage]

        .. admonition:: Example:

            .. literalinclude:: ../samples/queue_samples_message.py
                :start-after: [START peek_message]
                :end-before: [END peek_message]
                :language: python
                :dedent: 12
                :caption: Peek messages.
        """
        if max_messages and not 1 <= max_messages <= 32:
            raise ValueError("Number of messages to peek should be between 1 and 32")

        if self.key_encryption_key or self.key_resolver_function:
            modify_user_agent_for_encryption(
                self._config.user_agent_policy.user_agent, self._sdk_moniker, self.encryption_version, kwargs
            )

        self._message_decode_policy.configure(
            require_encryption=self.require_encryption,
            key_encryption_key=self.key_encryption_key,
            resolver=self.key_resolver_function,
        )
        try:
            messages = self._client.messages.peek(
                number_of_messages=max_messages, timeout=timeout, cls=self._message_decode_policy, **kwargs
            )
            wrapped_messages = []
            for peeked in messages:
                wrapped_messages.append(QueueMessage._from_generated(peeked))  # pylint: disable=protected-access
            return wrapped_messages
        except HttpResponseError as error:
            process_storage_error(error)

    @distributed_trace
    def clear_messages(self, *, timeout: Optional[int] = None, **kwargs: Any) -> None:
        """Deletes all messages from the specified queue.

        :keyword int timeout:
            Sets the server-side timeout for the operation in seconds. For more details see
            https://learn.microsoft.com/rest/api/storageservices/setting-timeouts-for-queue-service-operations.
            This value is not tracked or validated on the client. To configure client-side network timesouts
            see `here <https://github.com/Azure/azure-sdk-for-python/tree/main/sdk/storage/azure-storage-queue
            #other-client--per-operation-configuration>`__.

        .. admonition:: Example:

            .. literalinclude:: ../samples/queue_samples_message.py
                :start-after: [START clear_messages]
                :end-before: [END clear_messages]
                :language: python
                :dedent: 12
                :caption: Clears all messages.
        """
        try:
            self._client.messages.clear(timeout=timeout, **kwargs)
        except HttpResponseError as error:
            process_storage_error(error)

    @distributed_trace
    def delete_message(
        self,
        message: Union[str, QueueMessage],
        pop_receipt: Optional[str] = None,
        *,
        timeout: Optional[int] = None,
        **kwargs: Any
    ) -> None:
        """Deletes the specified message.

        Normally after a client retrieves a message with the receive messages operation,
        the client is expected to process and delete the message. To delete the
        message, you must have the message object itself, or two items of data: id and pop_receipt.
        The id is returned from the previous receive_messages operation. The
        pop_receipt is returned from the most recent :func:`~receive_messages` or
        :func:`~update_message` operation. In order for the delete_message operation
        to succeed, the pop_receipt specified on the request must match the
        pop_receipt returned from the :func:`~receive_messages` or :func:`~update_message`
        operation.

        :param message:
            The message object or id identifying the message to delete.
        :type message: str or ~azure.storage.queue.QueueMessage
        :param str pop_receipt:
            A valid pop receipt value returned from an earlier call
            to the :func:`~receive_messages` or :func:`~update_message`.
        :keyword int timeout:
            Sets the server-side timeout for the operation in seconds. For more details see
            https://learn.microsoft.com/rest/api/storageservices/setting-timeouts-for-queue-service-operations.
            This value is not tracked or validated on the client. To configure client-side network timesouts
            see `here <https://github.com/Azure/azure-sdk-for-python/tree/main/sdk/storage/azure-storage-queue
            #other-client--per-operation-configuration>`__.

        .. admonition:: Example:

            .. literalinclude:: ../samples/queue_samples_message.py
                :start-after: [START delete_message]
                :end-before: [END delete_message]
                :language: python
                :dedent: 12
                :caption: Delete a message.
        """
        receipt: Optional[str]
        if isinstance(message, QueueMessage):
            message_id = message.id
            receipt = pop_receipt or message.pop_receipt
        else:
            message_id = message
            receipt = pop_receipt

        if receipt is None:
            raise ValueError("pop_receipt must be present")
        try:
            self._client.message_id.delete(pop_receipt=receipt, timeout=timeout, queue_message_id=message_id, **kwargs)
        except HttpResponseError as error:
            process_storage_error(error)
