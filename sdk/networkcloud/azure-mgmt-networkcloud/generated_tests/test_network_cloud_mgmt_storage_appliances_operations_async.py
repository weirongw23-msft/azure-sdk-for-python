# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is regenerated.
# --------------------------------------------------------------------------
import pytest
from azure.mgmt.networkcloud.aio import NetworkCloudMgmtClient

from devtools_testutils import AzureMgmtRecordedTestCase, RandomNameResourceGroupPreparer
from devtools_testutils.aio import recorded_by_proxy_async

AZURE_LOCATION = "eastus"


@pytest.mark.skip("you may need to update the auto-generated test case before run it")
class TestNetworkCloudMgmtStorageAppliancesOperationsAsync(AzureMgmtRecordedTestCase):
    def setup_method(self, method):
        self.client = self.create_mgmt_client(NetworkCloudMgmtClient, is_async=True)

    @RandomNameResourceGroupPreparer(location=AZURE_LOCATION)
    @recorded_by_proxy_async
    async def test_storage_appliances_list_by_subscription(self, resource_group):
        response = self.client.storage_appliances.list_by_subscription(
            api_version="2025-02-01",
        )
        result = [r async for r in response]
        # please add some check logic here by yourself
        # ...

    @RandomNameResourceGroupPreparer(location=AZURE_LOCATION)
    @recorded_by_proxy_async
    async def test_storage_appliances_list_by_resource_group(self, resource_group):
        response = self.client.storage_appliances.list_by_resource_group(
            resource_group_name=resource_group.name,
            api_version="2025-02-01",
        )
        result = [r async for r in response]
        # please add some check logic here by yourself
        # ...

    @RandomNameResourceGroupPreparer(location=AZURE_LOCATION)
    @recorded_by_proxy_async
    async def test_storage_appliances_get(self, resource_group):
        response = await self.client.storage_appliances.get(
            resource_group_name=resource_group.name,
            storage_appliance_name="str",
            api_version="2025-02-01",
        )

        # please add some check logic here by yourself
        # ...

    @RandomNameResourceGroupPreparer(location=AZURE_LOCATION)
    @recorded_by_proxy_async
    async def test_storage_appliances_begin_create_or_update(self, resource_group):
        response = await (
            await self.client.storage_appliances.begin_create_or_update(
                resource_group_name=resource_group.name,
                storage_appliance_name="str",
                storage_appliance_parameters={
                    "administratorCredentials": {"password": "str", "username": "str"},
                    "extendedLocation": {"name": "str", "type": "str"},
                    "location": "str",
                    "rackId": "str",
                    "rackSlot": 0,
                    "serialNumber": "str",
                    "storageApplianceSkuId": "str",
                    "capacity": 0,
                    "capacityUsed": 0,
                    "clusterId": "str",
                    "detailedStatus": "str",
                    "detailedStatusMessage": "str",
                    "etag": "str",
                    "id": "str",
                    "managementIpv4Address": "str",
                    "manufacturer": "str",
                    "model": "str",
                    "name": "str",
                    "provisioningState": "str",
                    "remoteVendorManagementFeature": "str",
                    "remoteVendorManagementStatus": "str",
                    "secretRotationStatus": [
                        {
                            "expirePeriodDays": 0,
                            "lastRotationTime": "2020-02-20 00:00:00",
                            "rotationPeriodDays": 0,
                            "secretArchiveReference": {
                                "keyVaultId": "str",
                                "secretName": "str",
                                "secretVersion": "str",
                            },
                            "secretType": "str",
                        }
                    ],
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
                    "version": "str",
                },
                api_version="2025-02-01",
            )
        ).result()  # call '.result()' to poll until service return final result

        # please add some check logic here by yourself
        # ...

    @RandomNameResourceGroupPreparer(location=AZURE_LOCATION)
    @recorded_by_proxy_async
    async def test_storage_appliances_begin_delete(self, resource_group):
        response = await (
            await self.client.storage_appliances.begin_delete(
                resource_group_name=resource_group.name,
                storage_appliance_name="str",
                api_version="2025-02-01",
            )
        ).result()  # call '.result()' to poll until service return final result

        # please add some check logic here by yourself
        # ...

    @RandomNameResourceGroupPreparer(location=AZURE_LOCATION)
    @recorded_by_proxy_async
    async def test_storage_appliances_begin_update(self, resource_group):
        response = await (
            await self.client.storage_appliances.begin_update(
                resource_group_name=resource_group.name,
                storage_appliance_name="str",
                api_version="2025-02-01",
            )
        ).result()  # call '.result()' to poll until service return final result

        # please add some check logic here by yourself
        # ...

    @RandomNameResourceGroupPreparer(location=AZURE_LOCATION)
    @recorded_by_proxy_async
    async def test_storage_appliances_begin_disable_remote_vendor_management(self, resource_group):
        response = await (
            await self.client.storage_appliances.begin_disable_remote_vendor_management(
                resource_group_name=resource_group.name,
                storage_appliance_name="str",
                api_version="2025-02-01",
            )
        ).result()  # call '.result()' to poll until service return final result

        # please add some check logic here by yourself
        # ...

    @RandomNameResourceGroupPreparer(location=AZURE_LOCATION)
    @recorded_by_proxy_async
    async def test_storage_appliances_begin_enable_remote_vendor_management(self, resource_group):
        response = await (
            await self.client.storage_appliances.begin_enable_remote_vendor_management(
                resource_group_name=resource_group.name,
                storage_appliance_name="str",
                api_version="2025-02-01",
            )
        ).result()  # call '.result()' to poll until service return final result

        # please add some check logic here by yourself
        # ...
