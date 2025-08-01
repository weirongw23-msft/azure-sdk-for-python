# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is regenerated.
# --------------------------------------------------------------------------
import pytest
from azure.mgmt.compute.v2024_11_01.aio import ComputeManagementClient

from devtools_testutils import AzureMgmtRecordedTestCase, RandomNameResourceGroupPreparer
from devtools_testutils.aio import recorded_by_proxy_async

AZURE_LOCATION = "eastus"


@pytest.mark.skip("you may need to update the auto-generated test case before run it")
class TestComputeManagementVirtualMachineScaleSetVMExtensionsOperationsAsync(AzureMgmtRecordedTestCase):
    def setup_method(self, method):
        self.client = self.create_mgmt_client(ComputeManagementClient, is_async=True)

    @RandomNameResourceGroupPreparer(location=AZURE_LOCATION)
    @recorded_by_proxy_async
    async def test_virtual_machine_scale_set_vm_extensions_list(self, resource_group):
        response = await self.client.virtual_machine_scale_set_vm_extensions.list(
            resource_group_name=resource_group.name,
            vm_scale_set_name="str",
            instance_id="str",
            api_version="2024-11-01",
        )

        # please add some check logic here by yourself
        # ...

    @RandomNameResourceGroupPreparer(location=AZURE_LOCATION)
    @recorded_by_proxy_async
    async def test_virtual_machine_scale_set_vm_extensions_get(self, resource_group):
        response = await self.client.virtual_machine_scale_set_vm_extensions.get(
            resource_group_name=resource_group.name,
            vm_scale_set_name="str",
            instance_id="str",
            vm_extension_name="str",
            api_version="2024-11-01",
        )

        # please add some check logic here by yourself
        # ...

    @RandomNameResourceGroupPreparer(location=AZURE_LOCATION)
    @recorded_by_proxy_async
    async def test_virtual_machine_scale_set_vm_extensions_begin_create_or_update(self, resource_group):
        response = await (
            await self.client.virtual_machine_scale_set_vm_extensions.begin_create_or_update(
                resource_group_name=resource_group.name,
                vm_scale_set_name="str",
                instance_id="str",
                vm_extension_name="str",
                extension_parameters={
                    "autoUpgradeMinorVersion": bool,
                    "enableAutomaticUpgrade": bool,
                    "forceUpdateTag": "str",
                    "id": "str",
                    "instanceView": {
                        "name": "str",
                        "statuses": [
                            {
                                "code": "str",
                                "displayStatus": "str",
                                "level": "str",
                                "message": "str",
                                "time": "2020-02-20 00:00:00",
                            }
                        ],
                        "substatuses": [
                            {
                                "code": "str",
                                "displayStatus": "str",
                                "level": "str",
                                "message": "str",
                                "time": "2020-02-20 00:00:00",
                            }
                        ],
                        "type": "str",
                        "typeHandlerVersion": "str",
                    },
                    "location": "str",
                    "name": "str",
                    "protectedSettings": {},
                    "protectedSettingsFromKeyVault": {"secretUrl": "str", "sourceVault": {"id": "str"}},
                    "provisionAfterExtensions": ["str"],
                    "provisioningState": "str",
                    "publisher": "str",
                    "settings": {},
                    "suppressFailures": bool,
                    "type": "str",
                    "typeHandlerVersion": "str",
                },
                api_version="2024-11-01",
            )
        ).result()  # call '.result()' to poll until service return final result

        # please add some check logic here by yourself
        # ...

    @RandomNameResourceGroupPreparer(location=AZURE_LOCATION)
    @recorded_by_proxy_async
    async def test_virtual_machine_scale_set_vm_extensions_begin_update(self, resource_group):
        response = await (
            await self.client.virtual_machine_scale_set_vm_extensions.begin_update(
                resource_group_name=resource_group.name,
                vm_scale_set_name="str",
                instance_id="str",
                vm_extension_name="str",
                extension_parameters={
                    "autoUpgradeMinorVersion": bool,
                    "enableAutomaticUpgrade": bool,
                    "forceUpdateTag": "str",
                    "id": "str",
                    "name": "str",
                    "protectedSettings": {},
                    "protectedSettingsFromKeyVault": {"secretUrl": "str", "sourceVault": {"id": "str"}},
                    "publisher": "str",
                    "settings": {},
                    "suppressFailures": bool,
                    "type": "str",
                    "typeHandlerVersion": "str",
                },
                api_version="2024-11-01",
            )
        ).result()  # call '.result()' to poll until service return final result

        # please add some check logic here by yourself
        # ...

    @RandomNameResourceGroupPreparer(location=AZURE_LOCATION)
    @recorded_by_proxy_async
    async def test_virtual_machine_scale_set_vm_extensions_begin_delete(self, resource_group):
        response = await (
            await self.client.virtual_machine_scale_set_vm_extensions.begin_delete(
                resource_group_name=resource_group.name,
                vm_scale_set_name="str",
                instance_id="str",
                vm_extension_name="str",
                api_version="2024-11-01",
            )
        ).result()  # call '.result()' to poll until service return final result

        # please add some check logic here by yourself
        # ...
