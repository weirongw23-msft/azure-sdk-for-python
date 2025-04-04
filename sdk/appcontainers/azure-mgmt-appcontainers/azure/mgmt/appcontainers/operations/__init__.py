# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is regenerated.
# --------------------------------------------------------------------------

from ._app_resiliency_operations import AppResiliencyOperations
from ._container_apps_auth_configs_operations import ContainerAppsAuthConfigsOperations
from ._available_workload_profiles_operations import AvailableWorkloadProfilesOperations
from ._billing_meters_operations import BillingMetersOperations
from ._builders_operations import BuildersOperations
from ._builds_by_builder_resource_operations import BuildsByBuilderResourceOperations
from ._builds_operations import BuildsOperations
from ._build_auth_token_operations import BuildAuthTokenOperations
from ._connected_environments_operations import ConnectedEnvironmentsOperations
from ._connected_environments_certificates_operations import ConnectedEnvironmentsCertificatesOperations
from ._connected_environments_dapr_components_operations import ConnectedEnvironmentsDaprComponentsOperations
from ._connected_environments_storages_operations import ConnectedEnvironmentsStoragesOperations
from ._container_apps_operations import ContainerAppsOperations
from ._container_apps_builds_by_container_app_operations import ContainerAppsBuildsByContainerAppOperations
from ._container_apps_builds_operations import ContainerAppsBuildsOperations
from ._container_apps_patches_operations import ContainerAppsPatchesOperations
from ._container_apps_revisions_operations import ContainerAppsRevisionsOperations
from ._container_apps_revision_replicas_operations import ContainerAppsRevisionReplicasOperations
from ._container_apps_diagnostics_operations import ContainerAppsDiagnosticsOperations
from ._managed_environment_diagnostics_operations import ManagedEnvironmentDiagnosticsOperations
from ._managed_environments_diagnostics_operations import ManagedEnvironmentsDiagnosticsOperations
from ._jobs_operations import JobsOperations
from ._dot_net_components_operations import DotNetComponentsOperations
from ._functions_extension_operations import FunctionsExtensionOperations
from ._operations import Operations
from ._java_components_operations import JavaComponentsOperations
from ._jobs_executions_operations import JobsExecutionsOperations
from ._container_apps_api_client_operations import ContainerAppsAPIClientOperationsMixin
from ._logic_apps_operations import LogicAppsOperations
from ._managed_environments_operations import ManagedEnvironmentsOperations
from ._certificates_operations import CertificatesOperations
from ._managed_certificates_operations import ManagedCertificatesOperations
from ._namespaces_operations import NamespacesOperations
from ._managed_environment_private_endpoint_connections_operations import (
    ManagedEnvironmentPrivateEndpointConnectionsOperations,
)
from ._managed_environment_private_link_resources_operations import ManagedEnvironmentPrivateLinkResourcesOperations
from ._dapr_component_resiliency_policies_operations import DaprComponentResiliencyPoliciesOperations
from ._dapr_components_operations import DaprComponentsOperations
from ._dapr_subscriptions_operations import DaprSubscriptionsOperations
from ._managed_environments_storages_operations import ManagedEnvironmentsStoragesOperations
from ._container_apps_session_pools_operations import ContainerAppsSessionPoolsOperations
from ._container_apps_source_controls_operations import ContainerAppsSourceControlsOperations
from ._usages_operations import UsagesOperations
from ._managed_environment_usages_operations import ManagedEnvironmentUsagesOperations

from ._patch import __all__ as _patch_all
from ._patch import *  # pylint: disable=unused-wildcard-import
from ._patch import patch_sdk as _patch_sdk

__all__ = [
    "AppResiliencyOperations",
    "ContainerAppsAuthConfigsOperations",
    "AvailableWorkloadProfilesOperations",
    "BillingMetersOperations",
    "BuildersOperations",
    "BuildsByBuilderResourceOperations",
    "BuildsOperations",
    "BuildAuthTokenOperations",
    "ConnectedEnvironmentsOperations",
    "ConnectedEnvironmentsCertificatesOperations",
    "ConnectedEnvironmentsDaprComponentsOperations",
    "ConnectedEnvironmentsStoragesOperations",
    "ContainerAppsOperations",
    "ContainerAppsBuildsByContainerAppOperations",
    "ContainerAppsBuildsOperations",
    "ContainerAppsPatchesOperations",
    "ContainerAppsRevisionsOperations",
    "ContainerAppsRevisionReplicasOperations",
    "ContainerAppsDiagnosticsOperations",
    "ManagedEnvironmentDiagnosticsOperations",
    "ManagedEnvironmentsDiagnosticsOperations",
    "JobsOperations",
    "DotNetComponentsOperations",
    "FunctionsExtensionOperations",
    "Operations",
    "JavaComponentsOperations",
    "JobsExecutionsOperations",
    "ContainerAppsAPIClientOperationsMixin",
    "LogicAppsOperations",
    "ManagedEnvironmentsOperations",
    "CertificatesOperations",
    "ManagedCertificatesOperations",
    "NamespacesOperations",
    "ManagedEnvironmentPrivateEndpointConnectionsOperations",
    "ManagedEnvironmentPrivateLinkResourcesOperations",
    "DaprComponentResiliencyPoliciesOperations",
    "DaprComponentsOperations",
    "DaprSubscriptionsOperations",
    "ManagedEnvironmentsStoragesOperations",
    "ContainerAppsSessionPoolsOperations",
    "ContainerAppsSourceControlsOperations",
    "UsagesOperations",
    "ManagedEnvironmentUsagesOperations",
]
__all__.extend([p for p in _patch_all if p not in __all__])
_patch_sdk()
