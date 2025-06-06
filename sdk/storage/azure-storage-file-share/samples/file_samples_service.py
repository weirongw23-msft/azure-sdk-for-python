# coding: utf-8

# -------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for
# license information.
# --------------------------------------------------------------------------

"""
FILE: file_samples_service.py

DESCRIPTION:
    These samples demonstrate file share service operations like setting and getting
    service properties, listing the shares within the service, and getting a share
    client.

USAGE:
    python file_samples_service.py

    Set the environment variables with your own values before running the sample:
    1) STORAGE_CONNECTION_STRING - the connection string to your storage account
"""

import os
import sys

current_dir = os.path.dirname(os.path.abspath(__file__))
DEST_FILE = os.path.join(current_dir, "SampleDestination.txt")
SOURCE_FILE = os.path.join(current_dir, "SampleSource.txt")


class FileShareServiceSamples(object):

    connection_string = os.getenv('STORAGE_CONNECTION_STRING')

    def file_service_properties(self):
        if self.connection_string is None:
            print("Missing required environment variable: STORAGE_CONNECTION_STRING." + '\n' +
                  "Test: file_service_properties")
            sys.exit(1)

        # Instantiate the ShareServiceClient from a connection string
        from azure.storage.fileshare import ShareServiceClient
        file_service = ShareServiceClient.from_connection_string(self.connection_string)

        # [START set_service_properties]
        # Create service properties
        from azure.storage.fileshare import Metrics, CorsRule, RetentionPolicy

        # Create metrics for requests statistics
        hour_metrics = Metrics(enabled=True, include_apis=True, retention_policy=RetentionPolicy(enabled=True, days=5))
        minute_metrics = Metrics(enabled=True, include_apis=True,
                                 retention_policy=RetentionPolicy(enabled=True, days=5))

        # Create CORS rules
        cors_rule1 = CorsRule(['www.xyz.com'], ['GET'])
        allowed_origins = ['www.xyz.com', "www.ab.com", "www.bc.com"]
        allowed_methods = ['GET', 'PUT']
        max_age_in_seconds = 500
        exposed_headers = ["x-ms-meta-data*", "x-ms-meta-source*", "x-ms-meta-abc", "x-ms-meta-bcd"]
        allowed_headers = ["x-ms-meta-data*", "x-ms-meta-target*", "x-ms-meta-xyz", "x-ms-meta-foo"]
        cors_rule2 = CorsRule(
            allowed_origins,
            allowed_methods,
            max_age_in_seconds=max_age_in_seconds,
            exposed_headers=exposed_headers,
            allowed_headers=allowed_headers)

        cors = [cors_rule1, cors_rule2]

        # Set the service properties
        file_service.set_service_properties(hour_metrics, minute_metrics, cors)
        # [END set_service_properties]

        # [START get_service_properties]
        properties = file_service.get_service_properties()
        # [END get_service_properties]

    def list_shares_in_service(self):
        if self.connection_string is None:
            print("Missing required environment variable: STORAGE_CONNECTION_STRING." + '\n' +
                  "Test: list_shares_in_service")
            sys.exit(1)

        # Instantiate the ShareServiceClient from a connection string
        from azure.storage.fileshare import ShareServiceClient
        file_service = ShareServiceClient.from_connection_string(self.connection_string)

        # [START fsc_create_shares]
        file_service.create_share(share_name="fileshare1")
        # [END fsc_create_shares]
        try:
            # [START fsc_list_shares]
            # List the shares in the file service
            my_shares = list(file_service.list_shares())

            # Print the shares
            for share in my_shares:
                print(share)
            # [END fsc_list_shares]

        finally:
            # [START fsc_delete_shares]
            file_service.delete_share(share_name="fileshare1")
            # [END fsc_delete_shares]

    def get_share_client(self):
        if self.connection_string is None:
            print("Missing required environment variable: STORAGE_CONNECTION_STRING." + '\n' +
                  "Test: get_share_client")
            sys.exit(1)

        # [START get_share_client]
        from azure.storage.fileshare import ShareServiceClient
        file_service = ShareServiceClient.from_connection_string(self.connection_string)

        # Get a share client to interact with a specific share
        share = file_service.get_share_client("fileshare2")
        # [END get_share_client]


if __name__ == '__main__':
    sample = FileShareServiceSamples()
    sample.file_service_properties()
    sample.list_shares_in_service()
    sample.get_share_client()

