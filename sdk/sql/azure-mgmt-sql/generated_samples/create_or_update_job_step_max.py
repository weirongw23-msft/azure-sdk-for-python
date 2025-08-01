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
    python create_or_update_job_step_max.py

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

    response = client.job_steps.create_or_update(
        resource_group_name="group1",
        server_name="server1",
        job_agent_name="agent1",
        job_name="job1",
        step_name="step1",
        parameters={
            "properties": {
                "action": {"source": "Inline", "type": "TSql", "value": "select 2"},
                "credential": "/subscriptions/00000000-1111-2222-3333-444444444444/resourceGroups/group1/providers/Microsoft.Sql/servers/server1/jobAgents/agent1/credentials/cred1",
                "executionOptions": {
                    "initialRetryIntervalSeconds": 11,
                    "maximumRetryIntervalSeconds": 222,
                    "retryAttempts": 42,
                    "retryIntervalBackoffMultiplier": 3,
                    "timeoutSeconds": 1234,
                },
                "output": {
                    "credential": "/subscriptions/00000000-1111-2222-3333-444444444444/resourceGroups/group1/providers/Microsoft.Sql/servers/server1/jobAgents/agent1/credentials/cred0",
                    "databaseName": "database3",
                    "resourceGroupName": "group3",
                    "schemaName": "myschema1234",
                    "serverName": "server3",
                    "subscriptionId": "3501b905-a848-4b5d-96e8-b253f62d735a",
                    "tableName": "mytable5678",
                    "type": "SqlDatabase",
                },
                "stepId": 1,
                "targetGroup": "/subscriptions/00000000-1111-2222-3333-444444444444/resourceGroups/group1/providers/Microsoft.Sql/servers/server1/jobAgents/agent1/targetGroups/targetGroup1",
            }
        },
    )
    print(response)


# x-ms-original-file: specification/sql/resource-manager/Microsoft.Sql/preview/2024-11-01-preview/examples/CreateOrUpdateJobStepMax.json
if __name__ == "__main__":
    main()
