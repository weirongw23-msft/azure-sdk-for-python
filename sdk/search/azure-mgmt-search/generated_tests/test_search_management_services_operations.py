# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is regenerated.
# --------------------------------------------------------------------------
import pytest
from azure.mgmt.search import SearchManagementClient

from devtools_testutils import AzureMgmtRecordedTestCase, RandomNameResourceGroupPreparer, recorded_by_proxy

AZURE_LOCATION = "eastus"


@pytest.mark.skip("you may need to update the auto-generated test case before run it")
class TestSearchManagementServicesOperations(AzureMgmtRecordedTestCase):
    def setup_method(self, method):
        self.client = self.create_mgmt_client(SearchManagementClient)

    @RandomNameResourceGroupPreparer(location=AZURE_LOCATION)
    @recorded_by_proxy
    def test_services_begin_create_or_update(self, resource_group):
        response = self.client.services.begin_create_or_update(
            resource_group_name=resource_group.name,
            search_service_name="str",
            service={
                "location": "str",
                "authOptions": {"aadOrApiKey": {"aadAuthFailureMode": "str"}, "apiKeyOnly": {}},
                "computeType": "str",
                "dataExfiltrationProtections": ["str"],
                "disableLocalAuth": bool,
                "eTag": "str",
                "encryptionWithCmk": {"encryptionComplianceStatus": "str", "enforcement": "str"},
                "endpoint": "str",
                "hostingMode": "default",
                "id": "str",
                "identity": {
                    "type": "str",
                    "principalId": "str",
                    "tenantId": "str",
                    "userAssignedIdentities": {"str": {"clientId": "str", "principalId": "str"}},
                },
                "name": "str",
                "networkRuleSet": {"bypass": "str", "ipRules": [{"value": "str"}]},
                "partitionCount": 1,
                "privateEndpointConnections": [
                    {
                        "id": "str",
                        "name": "str",
                        "properties": {
                            "groupId": "str",
                            "privateEndpoint": {"id": "str"},
                            "privateLinkServiceConnectionState": {
                                "actionsRequired": "None",
                                "description": "str",
                                "status": "str",
                            },
                            "provisioningState": "str",
                        },
                        "systemData": {
                            "createdAt": "2020-02-20 00:00:00",
                            "createdBy": "str",
                            "createdByType": "str",
                            "lastModifiedAt": "2020-02-20 00:00:00",
                            "lastModifiedBy": "str",
                            "lastModifiedByType": "str",
                        },
                        "type": "str",
                    }
                ],
                "provisioningState": "str",
                "publicNetworkAccess": "enabled",
                "replicaCount": 1,
                "semanticSearch": "str",
                "serviceUpgradedAt": "2020-02-20 00:00:00",
                "sharedPrivateLinkResources": [
                    {
                        "id": "str",
                        "name": "str",
                        "properties": {
                            "groupId": "str",
                            "privateLinkResourceId": "str",
                            "provisioningState": "str",
                            "requestMessage": "str",
                            "resourceRegion": "str",
                            "status": "str",
                        },
                        "systemData": {
                            "createdAt": "2020-02-20 00:00:00",
                            "createdBy": "str",
                            "createdByType": "str",
                            "lastModifiedAt": "2020-02-20 00:00:00",
                            "lastModifiedBy": "str",
                            "lastModifiedByType": "str",
                        },
                        "type": "str",
                    }
                ],
                "sku": {"name": "str"},
                "status": "str",
                "statusDetails": "str",
                "systemData": {
                    "createdAt": "2020-02-20 00:00:00",
                    "createdBy": "str",
                    "createdByType": "str",
                    "lastModifiedAt": "2020-02-20 00:00:00",
                    "lastModifiedBy": "str",
                    "lastModifiedByType": "str",
                },
                "tags": {"str": "str"},
                "type": "str",
                "upgradeAvailable": "str",
            },
            api_version="2025-05-01",
        ).result()  # call '.result()' to poll until service return final result

        # please add some check logic here by yourself
        # ...

    @RandomNameResourceGroupPreparer(location=AZURE_LOCATION)
    @recorded_by_proxy
    def test_services_update(self, resource_group):
        response = self.client.services.update(
            resource_group_name=resource_group.name,
            search_service_name="str",
            service={
                "authOptions": {"aadOrApiKey": {"aadAuthFailureMode": "str"}, "apiKeyOnly": {}},
                "computeType": "str",
                "dataExfiltrationProtections": ["str"],
                "disableLocalAuth": bool,
                "eTag": "str",
                "encryptionWithCmk": {"encryptionComplianceStatus": "str", "enforcement": "str"},
                "endpoint": "str",
                "hostingMode": "default",
                "id": "str",
                "identity": {
                    "type": "str",
                    "principalId": "str",
                    "tenantId": "str",
                    "userAssignedIdentities": {"str": {"clientId": "str", "principalId": "str"}},
                },
                "location": "str",
                "name": "str",
                "networkRuleSet": {"bypass": "str", "ipRules": [{"value": "str"}]},
                "partitionCount": 1,
                "privateEndpointConnections": [
                    {
                        "id": "str",
                        "name": "str",
                        "properties": {
                            "groupId": "str",
                            "privateEndpoint": {"id": "str"},
                            "privateLinkServiceConnectionState": {
                                "actionsRequired": "None",
                                "description": "str",
                                "status": "str",
                            },
                            "provisioningState": "str",
                        },
                        "systemData": {
                            "createdAt": "2020-02-20 00:00:00",
                            "createdBy": "str",
                            "createdByType": "str",
                            "lastModifiedAt": "2020-02-20 00:00:00",
                            "lastModifiedBy": "str",
                            "lastModifiedByType": "str",
                        },
                        "type": "str",
                    }
                ],
                "provisioningState": "str",
                "publicNetworkAccess": "enabled",
                "replicaCount": 1,
                "semanticSearch": "str",
                "serviceUpgradedAt": "2020-02-20 00:00:00",
                "sharedPrivateLinkResources": [
                    {
                        "id": "str",
                        "name": "str",
                        "properties": {
                            "groupId": "str",
                            "privateLinkResourceId": "str",
                            "provisioningState": "str",
                            "requestMessage": "str",
                            "resourceRegion": "str",
                            "status": "str",
                        },
                        "systemData": {
                            "createdAt": "2020-02-20 00:00:00",
                            "createdBy": "str",
                            "createdByType": "str",
                            "lastModifiedAt": "2020-02-20 00:00:00",
                            "lastModifiedBy": "str",
                            "lastModifiedByType": "str",
                        },
                        "type": "str",
                    }
                ],
                "sku": {"name": "str"},
                "status": "str",
                "statusDetails": "str",
                "systemData": {
                    "createdAt": "2020-02-20 00:00:00",
                    "createdBy": "str",
                    "createdByType": "str",
                    "lastModifiedAt": "2020-02-20 00:00:00",
                    "lastModifiedBy": "str",
                    "lastModifiedByType": "str",
                },
                "tags": {"str": "str"},
                "type": "str",
                "upgradeAvailable": "str",
            },
            api_version="2025-05-01",
        )

        # please add some check logic here by yourself
        # ...

    @RandomNameResourceGroupPreparer(location=AZURE_LOCATION)
    @recorded_by_proxy
    def test_services_get(self, resource_group):
        response = self.client.services.get(
            resource_group_name=resource_group.name,
            search_service_name="str",
            api_version="2025-05-01",
        )

        # please add some check logic here by yourself
        # ...

    @RandomNameResourceGroupPreparer(location=AZURE_LOCATION)
    @recorded_by_proxy
    def test_services_delete(self, resource_group):
        response = self.client.services.delete(
            resource_group_name=resource_group.name,
            search_service_name="str",
            api_version="2025-05-01",
        )

        # please add some check logic here by yourself
        # ...

    @RandomNameResourceGroupPreparer(location=AZURE_LOCATION)
    @recorded_by_proxy
    def test_services_list_by_resource_group(self, resource_group):
        response = self.client.services.list_by_resource_group(
            resource_group_name=resource_group.name,
            api_version="2025-05-01",
        )
        result = [r for r in response]
        # please add some check logic here by yourself
        # ...

    @RandomNameResourceGroupPreparer(location=AZURE_LOCATION)
    @recorded_by_proxy
    def test_services_list_by_subscription(self, resource_group):
        response = self.client.services.list_by_subscription(
            api_version="2025-05-01",
        )
        result = [r for r in response]
        # please add some check logic here by yourself
        # ...

    @RandomNameResourceGroupPreparer(location=AZURE_LOCATION)
    @recorded_by_proxy
    def test_services_check_name_availability(self, resource_group):
        response = self.client.services.check_name_availability(
            name="str",
            api_version="2025-05-01",
            type="searchServices",
        )

        # please add some check logic here by yourself
        # ...

    @RandomNameResourceGroupPreparer(location=AZURE_LOCATION)
    @recorded_by_proxy
    def test_services_begin_upgrade(self, resource_group):
        response = self.client.services.begin_upgrade(
            resource_group_name=resource_group.name,
            search_service_name="str",
            api_version="2025-05-01",
        ).result()  # call '.result()' to poll until service return final result

        # please add some check logic here by yourself
        # ...
