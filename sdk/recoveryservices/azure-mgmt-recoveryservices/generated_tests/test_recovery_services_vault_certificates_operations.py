# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is regenerated.
# --------------------------------------------------------------------------
import pytest
from azure.mgmt.recoveryservices import RecoveryServicesClient

from devtools_testutils import AzureMgmtRecordedTestCase, RandomNameResourceGroupPreparer, recorded_by_proxy

AZURE_LOCATION = "eastus"


@pytest.mark.skip("you may need to update the auto-generated test case before run it")
class TestRecoveryServicesVaultCertificatesOperations(AzureMgmtRecordedTestCase):
    def setup_method(self, method):
        self.client = self.create_mgmt_client(RecoveryServicesClient)

    @RandomNameResourceGroupPreparer(location=AZURE_LOCATION)
    @recorded_by_proxy
    def test_vault_certificates_create(self, resource_group):
        response = self.client.vault_certificates.create(
            resource_group_name=resource_group.name,
            vault_name="str",
            certificate_name="str",
            certificate_request={"properties": {"authType": "str", "certificate": bytes("bytes", encoding="utf-8")}},
            api_version="2025-02-01",
        )

        # please add some check logic here by yourself
        # ...
