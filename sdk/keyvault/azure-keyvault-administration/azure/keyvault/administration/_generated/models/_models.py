# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# Code generated by Microsoft (R) Python Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is regenerated.
# --------------------------------------------------------------------------
# pylint: disable=useless-super-delegation

import datetime
from typing import Any, List, Mapping, Optional, TYPE_CHECKING, Union, overload

from .._utils.model_base import Model as _Model, rest_field

if TYPE_CHECKING:
    from .. import models as _models


class FullBackupOperation(_Model):
    """Full backup operation.

    :ivar status: Status of the backup operation. Known values are: "InProgress", "Succeeded",
     "Canceled", and "Failed".
    :vartype status: str or ~azure.keyvault.administration._generated.models.OperationStatus
    :ivar status_details: The status details of backup operation.
    :vartype status_details: str
    :ivar error: Error encountered, if any, during the full backup operation.
    :vartype error: ~azure.keyvault.administration._generated.models.FullBackupOperationError
    :ivar start_time: The start time of the backup operation in UTC.
    :vartype start_time: ~datetime.datetime
    :ivar end_time: The end time of the backup operation in UTC.
    :vartype end_time: ~datetime.datetime
    :ivar job_id: Identifier for the full backup operation.
    :vartype job_id: str
    :ivar azure_storage_blob_container_uri: The Azure blob storage container Uri which contains the
     full backup.
    :vartype azure_storage_blob_container_uri: str
    """

    status: Optional[Union[str, "_models.OperationStatus"]] = rest_field(
        visibility=["read", "create", "update", "delete", "query"]
    )
    """Status of the backup operation. Known values are: \"InProgress\", \"Succeeded\", \"Canceled\",
     and \"Failed\"."""
    status_details: Optional[str] = rest_field(
        name="statusDetails", visibility=["read", "create", "update", "delete", "query"]
    )
    """The status details of backup operation."""
    error: Optional["_models.FullBackupOperationError"] = rest_field(
        visibility=["read", "create", "update", "delete", "query"]
    )
    """Error encountered, if any, during the full backup operation."""
    start_time: Optional[datetime.datetime] = rest_field(
        name="startTime", visibility=["read", "create", "update", "delete", "query"], format="unix-timestamp"
    )
    """The start time of the backup operation in UTC."""
    end_time: Optional[datetime.datetime] = rest_field(
        name="endTime", visibility=["read", "create", "update", "delete", "query"], format="unix-timestamp"
    )
    """The end time of the backup operation in UTC."""
    job_id: Optional[str] = rest_field(name="jobId", visibility=["read", "create", "update", "delete", "query"])
    """Identifier for the full backup operation."""
    azure_storage_blob_container_uri: Optional[str] = rest_field(
        name="azureStorageBlobContainerUri", visibility=["read", "create", "update", "delete", "query"]
    )
    """The Azure blob storage container Uri which contains the full backup."""

    @overload
    def __init__(
        self,
        *,
        status: Optional[Union[str, "_models.OperationStatus"]] = None,
        status_details: Optional[str] = None,
        error: Optional["_models.FullBackupOperationError"] = None,
        start_time: Optional[datetime.datetime] = None,
        end_time: Optional[datetime.datetime] = None,
        job_id: Optional[str] = None,
        azure_storage_blob_container_uri: Optional[str] = None,
    ) -> None: ...

    @overload
    def __init__(self, mapping: Mapping[str, Any]) -> None:
        """
        :param mapping: raw JSON to initialize the model.
        :type mapping: Mapping[str, Any]
        """

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)


class FullBackupOperationError(_Model):
    """FullBackupOperationError.

    :ivar code: The error code.
    :vartype code: str
    :ivar message: The error message.
    :vartype message: str
    :ivar inner_error: The key vault server error.
    :vartype inner_error: ~azure.keyvault.administration._generated.models.FullBackupOperationError
    """

    code: Optional[str] = rest_field(visibility=["read"])
    """The error code."""
    message: Optional[str] = rest_field(visibility=["read"])
    """The error message."""
    inner_error: Optional["_models.FullBackupOperationError"] = rest_field(name="innererror", visibility=["read"])
    """The key vault server error."""


class KeyVaultError(_Model):
    """The key vault error exception.

    :ivar error: The key vault server error.
    :vartype error: ~azure.keyvault.administration._generated.models.FullBackupOperationError
    """

    error: Optional["_models.FullBackupOperationError"] = rest_field(visibility=["read"])
    """The key vault server error."""


class Permission(_Model):
    """Role definition permissions.

    :ivar actions: Action permissions that are granted.
    :vartype actions: list[str]
    :ivar not_actions: Action permissions that are excluded but not denied. They may be granted by
     other role definitions assigned to a principal.
    :vartype not_actions: list[str]
    :ivar data_actions: Data action permissions that are granted.
    :vartype data_actions: list[str or ~azure.keyvault.administration._generated.models.DataAction]
    :ivar not_data_actions: Data action permissions that are excluded but not denied. They may be
     granted by other role definitions assigned to a principal.
    :vartype not_data_actions: list[str or
     ~azure.keyvault.administration._generated.models.DataAction]
    """

    actions: Optional[List[str]] = rest_field(visibility=["read", "create", "update", "delete", "query"])
    """Action permissions that are granted."""
    not_actions: Optional[List[str]] = rest_field(
        name="notActions", visibility=["read", "create", "update", "delete", "query"]
    )
    """Action permissions that are excluded but not denied. They may be granted by other role
     definitions assigned to a principal."""
    data_actions: Optional[List[Union[str, "_models.DataAction"]]] = rest_field(
        name="dataActions", visibility=["read", "create", "update", "delete", "query"]
    )
    """Data action permissions that are granted."""
    not_data_actions: Optional[List[Union[str, "_models.DataAction"]]] = rest_field(
        name="notDataActions", visibility=["read", "create", "update", "delete", "query"]
    )
    """Data action permissions that are excluded but not denied. They may be granted by other role
     definitions assigned to a principal."""

    @overload
    def __init__(
        self,
        *,
        actions: Optional[List[str]] = None,
        not_actions: Optional[List[str]] = None,
        data_actions: Optional[List[Union[str, "_models.DataAction"]]] = None,
        not_data_actions: Optional[List[Union[str, "_models.DataAction"]]] = None,
    ) -> None: ...

    @overload
    def __init__(self, mapping: Mapping[str, Any]) -> None:
        """
        :param mapping: raw JSON to initialize the model.
        :type mapping: Mapping[str, Any]
        """

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)


class PreBackupOperationParameters(_Model):
    """The authentication method and location for the backup operation.

    :ivar storage_resource_uri: Azure Blob storage container Uri.
    :vartype storage_resource_uri: str
    :ivar token: The SAS token pointing to an Azure Blob storage container.
    :vartype token: str
    :ivar use_managed_identity: Indicates which authentication method should be used. If set to
     true, Managed HSM will use the configured user-assigned managed identity to authenticate with
     Azure Storage. Otherwise, a SAS token has to be specified.
    :vartype use_managed_identity: bool
    """

    storage_resource_uri: Optional[str] = rest_field(
        name="storageResourceUri", visibility=["read", "create", "update", "delete", "query"]
    )
    """Azure Blob storage container Uri."""
    token: Optional[str] = rest_field(visibility=["read", "create", "update", "delete", "query"])
    """The SAS token pointing to an Azure Blob storage container."""
    use_managed_identity: Optional[bool] = rest_field(
        name="useManagedIdentity", visibility=["read", "create", "update", "delete", "query"]
    )
    """Indicates which authentication method should be used. If set to true, Managed HSM will use the
     configured user-assigned managed identity to authenticate with Azure Storage. Otherwise, a SAS
     token has to be specified."""

    @overload
    def __init__(
        self,
        *,
        storage_resource_uri: Optional[str] = None,
        token: Optional[str] = None,
        use_managed_identity: Optional[bool] = None,
    ) -> None: ...

    @overload
    def __init__(self, mapping: Mapping[str, Any]) -> None:
        """
        :param mapping: raw JSON to initialize the model.
        :type mapping: Mapping[str, Any]
        """

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)


class PreRestoreOperationParameters(_Model):
    """The authentication method and location for the restore operation.

    :ivar sas_token_parameters: A user-provided SAS token to an Azure blob storage container.
    :vartype sas_token_parameters:
     ~azure.keyvault.administration._generated.models.SASTokenParameter
    :ivar folder_to_restore: The Folder name of the blob where the previous successful full backup
     was stored.
    :vartype folder_to_restore: str
    """

    sas_token_parameters: Optional["_models.SASTokenParameter"] = rest_field(
        name="sasTokenParameters", visibility=["read", "create", "update", "delete", "query"]
    )
    """A user-provided SAS token to an Azure blob storage container."""
    folder_to_restore: Optional[str] = rest_field(
        name="folderToRestore", visibility=["read", "create", "update", "delete", "query"]
    )
    """The Folder name of the blob where the previous successful full backup was stored."""

    @overload
    def __init__(
        self,
        *,
        sas_token_parameters: Optional["_models.SASTokenParameter"] = None,
        folder_to_restore: Optional[str] = None,
    ) -> None: ...

    @overload
    def __init__(self, mapping: Mapping[str, Any]) -> None:
        """
        :param mapping: raw JSON to initialize the model.
        :type mapping: Mapping[str, Any]
        """

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)


class RestoreOperation(_Model):
    """Restore operation.

    :ivar status: Status of the restore operation. Known values are: "InProgress", "Succeeded",
     "Canceled", and "Failed".
    :vartype status: str or ~azure.keyvault.administration._generated.models.OperationStatus
    :ivar status_details: The status details of restore operation.
    :vartype status_details: str
    :ivar error: Error encountered, if any, during the restore operation.
    :vartype error: ~azure.keyvault.administration._generated.models.FullBackupOperationError
    :ivar job_id: Identifier for the restore operation.
    :vartype job_id: str
    :ivar start_time: The start time of the restore operation.
    :vartype start_time: ~datetime.datetime
    :ivar end_time: The end time of the restore operation.
    :vartype end_time: ~datetime.datetime
    """

    status: Optional[Union[str, "_models.OperationStatus"]] = rest_field(
        visibility=["read", "create", "update", "delete", "query"]
    )
    """Status of the restore operation. Known values are: \"InProgress\", \"Succeeded\", \"Canceled\",
     and \"Failed\"."""
    status_details: Optional[str] = rest_field(
        name="statusDetails", visibility=["read", "create", "update", "delete", "query"]
    )
    """The status details of restore operation."""
    error: Optional["_models.FullBackupOperationError"] = rest_field(
        visibility=["read", "create", "update", "delete", "query"]
    )
    """Error encountered, if any, during the restore operation."""
    job_id: Optional[str] = rest_field(name="jobId", visibility=["read", "create", "update", "delete", "query"])
    """Identifier for the restore operation."""
    start_time: Optional[datetime.datetime] = rest_field(
        name="startTime", visibility=["read", "create", "update", "delete", "query"], format="unix-timestamp"
    )
    """The start time of the restore operation."""
    end_time: Optional[datetime.datetime] = rest_field(
        name="endTime", visibility=["read", "create", "update", "delete", "query"], format="unix-timestamp"
    )
    """The end time of the restore operation."""

    @overload
    def __init__(
        self,
        *,
        status: Optional[Union[str, "_models.OperationStatus"]] = None,
        status_details: Optional[str] = None,
        error: Optional["_models.FullBackupOperationError"] = None,
        job_id: Optional[str] = None,
        start_time: Optional[datetime.datetime] = None,
        end_time: Optional[datetime.datetime] = None,
    ) -> None: ...

    @overload
    def __init__(self, mapping: Mapping[str, Any]) -> None:
        """
        :param mapping: raw JSON to initialize the model.
        :type mapping: Mapping[str, Any]
        """

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)


class RestoreOperationParameters(_Model):
    """The authentication method and location for the restore operation.

    :ivar sas_token_parameters: A user-provided SAS token to an Azure blob storage container.
     Required.
    :vartype sas_token_parameters:
     ~azure.keyvault.administration._generated.models.SASTokenParameter
    :ivar folder_to_restore: The Folder name of the blob where the previous successful full backup
     was stored. Required.
    :vartype folder_to_restore: str
    """

    sas_token_parameters: "_models.SASTokenParameter" = rest_field(
        name="sasTokenParameters", visibility=["read", "create", "update", "delete", "query"]
    )
    """A user-provided SAS token to an Azure blob storage container. Required."""
    folder_to_restore: str = rest_field(
        name="folderToRestore", visibility=["read", "create", "update", "delete", "query"]
    )
    """The Folder name of the blob where the previous successful full backup was stored. Required."""

    @overload
    def __init__(
        self,
        *,
        sas_token_parameters: "_models.SASTokenParameter",
        folder_to_restore: str,
    ) -> None: ...

    @overload
    def __init__(self, mapping: Mapping[str, Any]) -> None:
        """
        :param mapping: raw JSON to initialize the model.
        :type mapping: Mapping[str, Any]
        """

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)


class RoleAssignment(_Model):
    """Role Assignments.

    :ivar id: The role assignment ID.
    :vartype id: str
    :ivar name: The role assignment name.
    :vartype name: str
    :ivar type: The role assignment type.
    :vartype type: str
    :ivar properties: Role assignment properties.
    :vartype properties:
     ~azure.keyvault.administration._generated.models.RoleAssignmentPropertiesWithScope
    """

    id: Optional[str] = rest_field(visibility=["read"])
    """The role assignment ID."""
    name: Optional[str] = rest_field(visibility=["read"])
    """The role assignment name."""
    type: Optional[str] = rest_field(visibility=["read"])
    """The role assignment type."""
    properties: Optional["_models.RoleAssignmentPropertiesWithScope"] = rest_field(
        visibility=["read", "create", "update", "delete", "query"]
    )
    """Role assignment properties."""

    @overload
    def __init__(
        self,
        *,
        properties: Optional["_models.RoleAssignmentPropertiesWithScope"] = None,
    ) -> None: ...

    @overload
    def __init__(self, mapping: Mapping[str, Any]) -> None:
        """
        :param mapping: raw JSON to initialize the model.
        :type mapping: Mapping[str, Any]
        """

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)


class RoleAssignmentCreateParameters(_Model):
    """Role assignment create parameters.

    :ivar properties: Role assignment properties. Required.
    :vartype properties: ~azure.keyvault.administration._generated.models.RoleAssignmentProperties
    """

    properties: "_models.RoleAssignmentProperties" = rest_field(
        visibility=["read", "create", "update", "delete", "query"]
    )
    """Role assignment properties. Required."""

    @overload
    def __init__(
        self,
        *,
        properties: "_models.RoleAssignmentProperties",
    ) -> None: ...

    @overload
    def __init__(self, mapping: Mapping[str, Any]) -> None:
        """
        :param mapping: raw JSON to initialize the model.
        :type mapping: Mapping[str, Any]
        """

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)


class RoleAssignmentProperties(_Model):
    """Role assignment properties.

    :ivar role_definition_id: The role definition ID used in the role assignment. Required.
    :vartype role_definition_id: str
    :ivar principal_id: The principal ID assigned to the role. This maps to the ID inside the
     Active Directory. It can point to a user, service principal, or security group. Required.
    :vartype principal_id: str
    """

    role_definition_id: str = rest_field(
        name="roleDefinitionId", visibility=["read", "create", "update", "delete", "query"]
    )
    """The role definition ID used in the role assignment. Required."""
    principal_id: str = rest_field(name="principalId", visibility=["read", "create", "update", "delete", "query"])
    """The principal ID assigned to the role. This maps to the ID inside the Active Directory. It can
     point to a user, service principal, or security group. Required."""

    @overload
    def __init__(
        self,
        *,
        role_definition_id: str,
        principal_id: str,
    ) -> None: ...

    @overload
    def __init__(self, mapping: Mapping[str, Any]) -> None:
        """
        :param mapping: raw JSON to initialize the model.
        :type mapping: Mapping[str, Any]
        """

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)


class RoleAssignmentPropertiesWithScope(_Model):
    """Role assignment properties with scope.

    :ivar scope: The role scope. Known values are: "/" and "/keys".
    :vartype scope: str or ~azure.keyvault.administration._generated.models.RoleScope
    :ivar role_definition_id: The role definition ID.
    :vartype role_definition_id: str
    :ivar principal_id: The principal ID.
    :vartype principal_id: str
    """

    scope: Optional[Union[str, "_models.RoleScope"]] = rest_field(
        visibility=["read", "create", "update", "delete", "query"]
    )
    """The role scope. Known values are: \"/\" and \"/keys\"."""
    role_definition_id: Optional[str] = rest_field(
        name="roleDefinitionId", visibility=["read", "create", "update", "delete", "query"]
    )
    """The role definition ID."""
    principal_id: Optional[str] = rest_field(
        name="principalId", visibility=["read", "create", "update", "delete", "query"]
    )
    """The principal ID."""

    @overload
    def __init__(
        self,
        *,
        scope: Optional[Union[str, "_models.RoleScope"]] = None,
        role_definition_id: Optional[str] = None,
        principal_id: Optional[str] = None,
    ) -> None: ...

    @overload
    def __init__(self, mapping: Mapping[str, Any]) -> None:
        """
        :param mapping: raw JSON to initialize the model.
        :type mapping: Mapping[str, Any]
        """

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)


class RoleDefinition(_Model):
    """Role definition.

    :ivar id: The role definition ID.
    :vartype id: str
    :ivar name: The role definition name.
    :vartype name: str
    :ivar type: The role definition type. "Microsoft.Authorization/roleDefinitions"
    :vartype type: str or ~azure.keyvault.administration._generated.models.RoleDefinitionType
    :ivar properties: Role definition properties.
    :vartype properties: ~azure.keyvault.administration._generated.models.RoleDefinitionProperties
    """

    id: Optional[str] = rest_field(visibility=["read"])
    """The role definition ID."""
    name: Optional[str] = rest_field(visibility=["read"])
    """The role definition name."""
    type: Optional[Union[str, "_models.RoleDefinitionType"]] = rest_field(visibility=["read"])
    """The role definition type. \"Microsoft.Authorization/roleDefinitions\""""
    properties: Optional["_models.RoleDefinitionProperties"] = rest_field(
        visibility=["read", "create", "update", "delete", "query"]
    )
    """Role definition properties."""

    __flattened_items = ["role_name", "description", "role_type", "permissions", "assignable_scopes"]

    @overload
    def __init__(
        self,
        *,
        properties: Optional["_models.RoleDefinitionProperties"] = None,
    ) -> None: ...

    @overload
    def __init__(self, mapping: Mapping[str, Any]) -> None:
        """
        :param mapping: raw JSON to initialize the model.
        :type mapping: Mapping[str, Any]
        """

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        _flattened_input = {k: kwargs.pop(k) for k in kwargs.keys() & self.__flattened_items}
        super().__init__(*args, **kwargs)
        for k, v in _flattened_input.items():
            setattr(self, k, v)

    def __getattr__(self, name: str) -> Any:
        if name in self.__flattened_items:
            if self.properties is None:
                return None
            return getattr(self.properties, name)
        raise AttributeError(f"'{self.__class__.__name__}' object has no attribute '{name}'")

    def __setattr__(self, key: str, value: Any) -> None:
        if key in self.__flattened_items:
            if self.properties is None:
                self.properties = self._attr_to_rest_field["properties"]._class_type()
            setattr(self.properties, key, value)
        else:
            super().__setattr__(key, value)


class RoleDefinitionCreateParameters(_Model):
    """Role definition create parameters.

    :ivar properties: Role definition properties. Required.
    :vartype properties: ~azure.keyvault.administration._generated.models.RoleDefinitionProperties
    """

    properties: "_models.RoleDefinitionProperties" = rest_field(
        visibility=["read", "create", "update", "delete", "query"]
    )
    """Role definition properties. Required."""

    @overload
    def __init__(
        self,
        *,
        properties: "_models.RoleDefinitionProperties",
    ) -> None: ...

    @overload
    def __init__(self, mapping: Mapping[str, Any]) -> None:
        """
        :param mapping: raw JSON to initialize the model.
        :type mapping: Mapping[str, Any]
        """

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)


class RoleDefinitionProperties(_Model):
    """Role definition properties.

    :ivar role_name: The role name.
    :vartype role_name: str
    :ivar description: The role definition description.
    :vartype description: str
    :ivar role_type: The role type. Known values are: "AKVBuiltInRole" and "CustomRole".
    :vartype role_type: str or ~azure.keyvault.administration._generated.models.RoleType
    :ivar permissions: Role definition permissions.
    :vartype permissions: list[~azure.keyvault.administration._generated.models.Permission]
    :ivar assignable_scopes: Role definition assignable scopes.
    :vartype assignable_scopes: list[str or
     ~azure.keyvault.administration._generated.models.RoleScope]
    """

    role_name: Optional[str] = rest_field(name="roleName", visibility=["read", "create", "update", "delete", "query"])
    """The role name."""
    description: Optional[str] = rest_field(visibility=["read", "create", "update", "delete", "query"])
    """The role definition description."""
    role_type: Optional[Union[str, "_models.RoleType"]] = rest_field(
        name="type", visibility=["read", "create", "update", "delete", "query"]
    )
    """The role type. Known values are: \"AKVBuiltInRole\" and \"CustomRole\"."""
    permissions: Optional[List["_models.Permission"]] = rest_field(
        visibility=["read", "create", "update", "delete", "query"]
    )
    """Role definition permissions."""
    assignable_scopes: Optional[List[Union[str, "_models.RoleScope"]]] = rest_field(
        name="assignableScopes", visibility=["read", "create", "update", "delete", "query"]
    )
    """Role definition assignable scopes."""

    @overload
    def __init__(
        self,
        *,
        role_name: Optional[str] = None,
        description: Optional[str] = None,
        role_type: Optional[Union[str, "_models.RoleType"]] = None,
        permissions: Optional[List["_models.Permission"]] = None,
        assignable_scopes: Optional[List[Union[str, "_models.RoleScope"]]] = None,
    ) -> None: ...

    @overload
    def __init__(self, mapping: Mapping[str, Any]) -> None:
        """
        :param mapping: raw JSON to initialize the model.
        :type mapping: Mapping[str, Any]
        """

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)


class SASTokenParameter(_Model):
    """An authentication method and location for the operation.

    :ivar storage_resource_uri: Azure Blob storage container Uri. Required.
    :vartype storage_resource_uri: str
    :ivar token: The SAS token pointing to an Azure Blob storage container.
    :vartype token: str
    :ivar use_managed_identity: Indicates which authentication method should be used. If set to
     true, Managed HSM will use the configured user-assigned managed identity to authenticate with
     Azure Storage. Otherwise, a SAS token has to be specified.
    :vartype use_managed_identity: bool
    """

    storage_resource_uri: str = rest_field(
        name="storageResourceUri", visibility=["read", "create", "update", "delete", "query"]
    )
    """Azure Blob storage container Uri. Required."""
    token: Optional[str] = rest_field(visibility=["read", "create", "update", "delete", "query"])
    """The SAS token pointing to an Azure Blob storage container."""
    use_managed_identity: Optional[bool] = rest_field(
        name="useManagedIdentity", visibility=["read", "create", "update", "delete", "query"]
    )
    """Indicates which authentication method should be used. If set to true, Managed HSM will use the
     configured user-assigned managed identity to authenticate with Azure Storage. Otherwise, a SAS
     token has to be specified."""

    @overload
    def __init__(
        self,
        *,
        storage_resource_uri: str,
        token: Optional[str] = None,
        use_managed_identity: Optional[bool] = None,
    ) -> None: ...

    @overload
    def __init__(self, mapping: Mapping[str, Any]) -> None:
        """
        :param mapping: raw JSON to initialize the model.
        :type mapping: Mapping[str, Any]
        """

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)


class SelectiveKeyRestoreOperation(_Model):
    """Selective Key Restore operation.

    :ivar status: Status of the restore operation. Known values are: "InProgress", "Succeeded",
     "Canceled", and "Failed".
    :vartype status: str or ~azure.keyvault.administration._generated.models.OperationStatus
    :ivar status_details: The status details of restore operation.
    :vartype status_details: str
    :ivar error: Error encountered, if any, during the selective key restore operation.
    :vartype error: ~azure.keyvault.administration._generated.models.FullBackupOperationError
    :ivar job_id: Identifier for the selective key restore operation.
    :vartype job_id: str
    :ivar start_time: The start time of the restore operation.
    :vartype start_time: ~datetime.datetime
    :ivar end_time: The end time of the restore operation.
    :vartype end_time: ~datetime.datetime
    """

    status: Optional[Union[str, "_models.OperationStatus"]] = rest_field(
        visibility=["read", "create", "update", "delete", "query"]
    )
    """Status of the restore operation. Known values are: \"InProgress\", \"Succeeded\", \"Canceled\",
     and \"Failed\"."""
    status_details: Optional[str] = rest_field(
        name="statusDetails", visibility=["read", "create", "update", "delete", "query"]
    )
    """The status details of restore operation."""
    error: Optional["_models.FullBackupOperationError"] = rest_field(
        visibility=["read", "create", "update", "delete", "query"]
    )
    """Error encountered, if any, during the selective key restore operation."""
    job_id: Optional[str] = rest_field(name="jobId", visibility=["read", "create", "update", "delete", "query"])
    """Identifier for the selective key restore operation."""
    start_time: Optional[datetime.datetime] = rest_field(
        name="startTime", visibility=["read", "create", "update", "delete", "query"], format="unix-timestamp"
    )
    """The start time of the restore operation."""
    end_time: Optional[datetime.datetime] = rest_field(
        name="endTime", visibility=["read", "create", "update", "delete", "query"], format="unix-timestamp"
    )
    """The end time of the restore operation."""

    @overload
    def __init__(
        self,
        *,
        status: Optional[Union[str, "_models.OperationStatus"]] = None,
        status_details: Optional[str] = None,
        error: Optional["_models.FullBackupOperationError"] = None,
        job_id: Optional[str] = None,
        start_time: Optional[datetime.datetime] = None,
        end_time: Optional[datetime.datetime] = None,
    ) -> None: ...

    @overload
    def __init__(self, mapping: Mapping[str, Any]) -> None:
        """
        :param mapping: raw JSON to initialize the model.
        :type mapping: Mapping[str, Any]
        """

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)


class SelectiveKeyRestoreOperationParameters(_Model):
    """The authentication method and location for the selective key restore operation.

    :ivar sas_token_parameters: A user-provided SAS token to an Azure blob storage container.
     Required.
    :vartype sas_token_parameters:
     ~azure.keyvault.administration._generated.models.SASTokenParameter
    :ivar folder: The Folder name of the blob where the previous successful full backup was stored.
     Required.
    :vartype folder: str
    """

    sas_token_parameters: "_models.SASTokenParameter" = rest_field(
        name="sasTokenParameters", visibility=["read", "create", "update", "delete", "query"]
    )
    """A user-provided SAS token to an Azure blob storage container. Required."""
    folder: str = rest_field(visibility=["read", "create", "update", "delete", "query"])
    """The Folder name of the blob where the previous successful full backup was stored. Required."""

    @overload
    def __init__(
        self,
        *,
        sas_token_parameters: "_models.SASTokenParameter",
        folder: str,
    ) -> None: ...

    @overload
    def __init__(self, mapping: Mapping[str, Any]) -> None:
        """
        :param mapping: raw JSON to initialize the model.
        :type mapping: Mapping[str, Any]
        """

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)


class Setting(_Model):
    """A Key Vault account setting.

    :ivar name: The account setting to be updated. Required.
    :vartype name: str
    :ivar value: The value of the pool setting. Required.
    :vartype value: str
    :ivar type: The type specifier of the value. "boolean"
    :vartype type: str or ~azure.keyvault.administration._generated.models.SettingTypeEnum
    """

    name: str = rest_field(visibility=["read", "create", "update", "delete", "query"])
    """The account setting to be updated. Required."""
    value: str = rest_field(visibility=["read", "create", "update", "delete", "query"])
    """The value of the pool setting. Required."""
    type: Optional[Union[str, "_models.SettingTypeEnum"]] = rest_field(
        visibility=["read", "create", "update", "delete", "query"]
    )
    """The type specifier of the value. \"boolean\""""

    @overload
    def __init__(
        self,
        *,
        name: str,
        value: str,
        type: Optional[Union[str, "_models.SettingTypeEnum"]] = None,
    ) -> None: ...

    @overload
    def __init__(self, mapping: Mapping[str, Any]) -> None:
        """
        :param mapping: raw JSON to initialize the model.
        :type mapping: Mapping[str, Any]
        """

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)


class SettingsListResult(_Model):
    """The settings list result.

    :ivar settings: A response message containing a list of account settings with their associated
     value.
    :vartype settings: list[~azure.keyvault.administration._generated.models.Setting]
    """

    settings: Optional[List["_models.Setting"]] = rest_field(visibility=["read"])
    """A response message containing a list of account settings with their associated value."""


class UpdateSettingRequest(_Model):
    """The update settings request object.

    :ivar value: The value of the pool setting. Required.
    :vartype value: str
    """

    value: str = rest_field(visibility=["read", "create", "update", "delete", "query"])
    """The value of the pool setting. Required."""

    @overload
    def __init__(
        self,
        *,
        value: str,
    ) -> None: ...

    @overload
    def __init__(self, mapping: Mapping[str, Any]) -> None:
        """
        :param mapping: raw JSON to initialize the model.
        :type mapping: Mapping[str, Any]
        """

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
