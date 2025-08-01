# pylint: disable=line-too-long,useless-suppression
# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is regenerated.
# --------------------------------------------------------------------------

from azure.identity import DefaultAzureCredential

from azure.mgmt.sql import SqlManagementClient

"""
# PREREQUISITES
    pip install azure-identity
    pip install azure-mgmt-sql
# USAGE
    python managed_instance_update_max.py

    Before run the sample, please set the values of the client ID, tenant ID and client secret
    of the AAD application as environment variables: AZURE_CLIENT_ID, AZURE_TENANT_ID,
    AZURE_CLIENT_SECRET. For more info about how to get the value, please see:
    https://docs.microsoft.com/azure/active-directory/develop/howto-create-service-principal-portal
"""


def main():
    client = SqlManagementClient(
        credential=DefaultAzureCredential(),
        subscription_id="00000000-1111-2222-3333-444444444444",
    )

    response = client.managed_instances.begin_update(
        resource_group_name="testrg",
        managed_instance_name="testinstance",
        parameters={
            "properties": {
                "administratorLogin": "dummylogin",
                "administratorLoginPassword": "PLACEHOLDER",
                "authenticationMetadata": "Windows",
                "collation": "SQL_Latin1_General_CP1_CI_AS",
                "databaseFormat": "AlwaysUpToDate",
                "hybridSecondaryUsage": "Passive",
                "licenseType": "BasePrice",
                "maintenanceConfigurationId": "/subscriptions/00000000-1111-2222-3333-444444444444/providers/Microsoft.Maintenance/publicMaintenanceConfigurations/SQL_JapanEast_MI_1",
                "minimalTlsVersion": "1.2",
                "proxyOverride": "Redirect",
                "publicDataEndpointEnabled": False,
                "requestedBackupStorageRedundancy": "Geo",
                "requestedLogicalAvailabilityZone": "1",
                "storageSizeInGB": 448,
                "vCores": 8,
            },
            "sku": {"capacity": 8, "name": "GP_Gen5", "tier": "GeneralPurpose"},
            "tags": {"tagKey1": "TagValue1"},
        },
    ).result()
    print(response)


# x-ms-original-file: specification/sql/resource-manager/Microsoft.Sql/preview/2024-11-01-preview/examples/ManagedInstanceUpdateMax.json
if __name__ == "__main__":
    main()
