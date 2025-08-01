# pylint: disable=line-too-long,useless-suppression
# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is regenerated.
# --------------------------------------------------------------------------

from azure.identity import DefaultAzureCredential

from azure.mgmt.authorization import AuthorizationManagementClient

"""
# PREREQUISITES
    pip install azure-identity
    pip install azure-mgmt-authorization
# USAGE
    python get_access_review_instance_contacted_reviewers.py

    Before run the sample, please set the values of the client ID, tenant ID and client secret
    of the AAD application as environment variables: AZURE_CLIENT_ID, AZURE_TENANT_ID,
    AZURE_CLIENT_SECRET. For more info about how to get the value, please see:
    https://docs.microsoft.com/azure/active-directory/develop/howto-create-service-principal-portal
"""


def main():
    client = AuthorizationManagementClient(
        credential=DefaultAzureCredential(),
        subscription_id="SUBSCRIPTION_ID",
    )

    response = client.scope_access_review_instance_contacted_reviewers.list(
        scope="subscriptions/fa73e90b-5bf1-45fd-a182-35ce5fc0674d",
        schedule_definition_id="265785a7-a81f-4201-8a18-bb0db95982b7",
        id="f25ed880-9c31-4101-bc57-825d8df3b58c",
    )
    for item in response:
        print(item)


# x-ms-original-file: specification/authorization/resource-manager/Microsoft.Authorization/preview/2021-12-01-preview/examples/GetAccessReviewInstanceContactedReviewers.json
if __name__ == "__main__":
    main()
