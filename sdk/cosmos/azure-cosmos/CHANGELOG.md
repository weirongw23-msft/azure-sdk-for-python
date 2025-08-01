## Release History

### 4.14.0b2 (Unreleased)

#### Features Added
* Added feed range support in `query_items`. See [PR 41722](https://github.com/Azure/azure-sdk-for-python/pull/41722).

#### Breaking Changes

#### Bugs Fixed
* Fixed session container session token logic. The SDK will now only send the relevant partition-local session tokens for read document requests and write requests when multi-region writes are enabled, as opposed to the entire compound session token for the container for every document request. See [PR 41678](https://github.com/Azure/azure-sdk-for-python/pull/41678).
* Write requests for single-write region accounts will no longer send session tokens when using session consistency. See [PR 41678](https://github.com/Azure/azure-sdk-for-python/pull/41678).
* Fixed bug where container cache was not being properly updated resulting in unnecessary extra requests. See [PR 42143](https://github.com/Azure/azure-sdk-for-python/pull/42143).

#### Other Changes
* Changed to include client id in headers for all requests. See [PR 42104](https://github.com/Azure/azure-sdk-for-python/pull/42104).
* Added an option to override AAD audience scope through environment variable. See [PR 42228](https://github.com/Azure/azure-sdk-for-python/pull/42228).

### 4.14.0b1 (2025-07-14)

#### Features Added
* Added option to enable automatic retries for write document operations. See [PR 41272](https://github.com/Azure/azure-sdk-for-python/pull/41272).

#### Breaking Changes
* Adds cross region retries when no preferred locations are set. This is only a breaking change for customers using bounded staleness consistency. See [PR 39714](https://github.com/Azure/azure-sdk-for-python/pull/39714)

#### Bugs Fixed
* Fixed bug where replacing manual throughput using `ThroughputProperties` would not work. See [PR 41564](https://github.com/Azure/azure-sdk-for-python/pull/41564)
* Fixed bug where constantly raising Service Request Error Exceptions would cause the Service Request Retry Policy to indefinitely retry the request during a query or when a request was sent without a request object. See [PR 41804](https://github.com/Azure/azure-sdk-for-python/pull/41804)

### 4.13.0b2 (2025-06-18)

#### Bugs Fixed
- Fixed issue where key error would occur when getting properties from a container using legacy hash v1 as they may not always contain version property in the partition key definition. See [PR 41639](https://github.com/Azure/azure-sdk-for-python/pull/41639)

### 4.13.0b1 (2025-06-05)

#### Features Added
* Added ability to set a user agent suffix at the client level. See [PR 40904](https://github.com/Azure/azure-sdk-for-python/pull/40904)
* Added ability to use request level `excluded_locations` on metadata calls, such as getting container properties. See [PR 40905](https://github.com/Azure/azure-sdk-for-python/pull/40905)
* Per partition circuit breaker support. It can be enabled through the environment variable `AZURE_COSMOS_ENABLE_CIRCUIT_BREAKER`. See [PR 40302](https://github.com/Azure/azure-sdk-for-python/pull/40302).

#### Bugs Fixed
* Fixed how resource tokens are parsed for metadata calls in the lifecycle of a document operation. See [PR 40302](https://github.com/Azure/azure-sdk-for-python/pull/40302).
* Fixed issue where Query Change Feed did not return items if the container uses legacy Hash V1 Partition Keys. This also fixes issues with not being able to change feed query for Specific Partition Key Values for HPK. See [PR 41270](https://github.com/Azure/azure-sdk-for-python/pull/41270/)

#### Other Changes
* Added Client Generated Activity IDs to all Requests. Cosmos Diagnostics Logs will more clearly show the Activity ID for each request and response. [PR 41013](https://github.com/Azure/azure-sdk-for-python/pull/41013)

### 4.12.0b1 (2025-05-19)

#### Features Added
* Added ability to use weighted RRF (Reciprocal Rank Fusion) for Hybrid full text search queries. See [PR 40899](https://github.com/Azure/azure-sdk-for-python/pull/40899/files).

#### Bugs Fixed
* Fixed Diagnostics Error Log Formatting to handle error messages from non-CosmosHttpResponseExceptions. See [PR 40889](https://github.com/Azure/azure-sdk-for-python/pull/40889/files)
* Fixed bug where `multiple_write_locations` option in client was not being honored. See [PR 40999](https://github.com/Azure/azure-sdk-for-python/pull/40999).

### 4.11.0b1 (2025-04-30)

#### Features Added
* Added ability to set `throughput_bucket` header at the client level and for all requests. See [PR 40340](https://github.com/Azure/azure-sdk-for-python/pull/40340).
* Added ability to use Filters from Logging module on Diagnostics Logging based on Http request/response related attributes. See [PR 39897](https://github.com/Azure/azure-sdk-for-python/pull/39897).
* Added ability to use `excluded_locations` on client level and document API request level. See [PR 40298](https://github.com/Azure/azure-sdk-for-python/pull/40298) 

#### Bugs Fixed
* Fixed bug where change feed requests would not respect the partition key filter. See [PR 40677](https://github.com/Azure/azure-sdk-for-python/pull/40677).
* Fixed how the environment variables in the sdk are parsed. See [PR 40303](https://github.com/Azure/azure-sdk-for-python/pull/40303).
* Fixed health check to check the first write region when it is not specified in the preferred regions. See [PR 40588](https://github.com/Azure/azure-sdk-for-python/pull/40588).
* Fixed `response_hook` not getting called for aggregate queries. See [PR 40696](https://github.com/Azure/azure-sdk-for-python/pull/40696).
* Fixed bug where writes were being retried for 5xx status codes for patch and replace. See [PR 40672](https://github.com/Azure/azure-sdk-for-python/pull/40672).

#### Other Changes
* Optimized Diagnostics Logging by reducing time spent on logging. Logged Errors are more readable and formatted. See [PR 39897](https://github.com/Azure/azure-sdk-for-python/pull/39897).
* Health checks are now done concurrently and for all regions for async apis. See [PR 40588](https://github.com/Azure/azure-sdk-for-python/pull/40588).


### 4.10.0b4 (2025-04-01)

#### Bugs Fixed
* Fixed bug introduced in 4.10.0b3 with explicitly setting `etag` keyword argument as `None` causing exceptions. See [PR 40282](https://github.com/Azure/azure-sdk-for-python/pull/40282).

### 4.10.0b3 (2025-03-27)

#### Bugs Fixed
* Fixed too many health checks happening when skipping the recommended client startup. See [PR 40203](https://github.com/Azure/azure-sdk-for-python/pull/40203).

#### Other Changes
* Removed excess keyword arguments from methods that did not use them. See [PR 40008](https://github.com/Azure/azure-sdk-for-python/pull/40008).
* Removed first `response_hook` call for query methods that would utilize wrong response headers. See [PR 40008](https://github.com/Azure/azure-sdk-for-python/pull/40008).

### 4.10.0b2 (2025-03-17)

#### Bugs Fixed
* Fixed bug preventing health check in some scenarios. See [PR 39647](https://github.com/Azure/azure-sdk-for-python/pull/39647).
* Fixed `partition_key` filter for `query_items_change_feed` API. See [PR 39895](https://github.com/Azure/azure-sdk-for-python/pull/39895).

#### Other Changes
* Moved endpoint health check to the background for async APIs. See [PR 39647](https://github.com/Azure/azure-sdk-for-python/pull/39647).

### 4.10.0b1 (2025-02-13)

#### Features Added
* Added ability to replace `computed_properties` through `replace_container` method. See [PR 39543](https://github.com/Azure/azure-sdk-for-python/pull/39543).

#### Other Changes
* Un-marked `computed_properties` keyword as **provisional**. See [PR 39543](https://github.com/Azure/azure-sdk-for-python/pull/39543).

### 4.9.1b4 (2025-02-06)

#### Bugs Fixed
* Improved retry logic for read requests to failover on other regions in case of timeouts and any error codes >= 500. See [PR 39596](https://github.com/Azure/azure-sdk-for-python/pull/39596).
* Fixed a regression where read operations were not retrying on timeouts. See [PR 39596](https://github.com/Azure/azure-sdk-for-python/pull/39596)
* Updated default read timeout for `getDatabaseAccount` calls to 3 seconds. See [PR 39596](https://github.com/Azure/azure-sdk-for-python/pull/39596)

### 4.9.1b3 (2025-02-04)

#### Features Added
* Improved retry logic by retrying alternative endpoint for writes within a region before performing a cross region retry. See [PR 39390](https://github.com/Azure/azure-sdk-for-python/pull/39390).
* Added endpoint health check logic during database account calls. See [PR 39390](https://github.com/Azure/azure-sdk-for-python/pull/39390)

#### Bugs Fixed
* Fixed unnecessary retries on the wrong region for timout retry policy. See [PR 39390](https://github.com/Azure/azure-sdk-for-python/pull/39390).
* All client connection errors from aiohttp will be retried. See [PR 39390](https://github.com/Azure/azure-sdk-for-python/pull/39390).

#### Other Changes
* Changed defaults for retry delays. See [PR 39390](https://github.com/Azure/azure-sdk-for-python/pull/39390).
* Changed default connection timeout to be 5 seconds. See [PR 39390](https://github.com/Azure/azure-sdk-for-python/pull/39390).
* Changed default read timeout to be 65 seconds. See [PR 39390](https://github.com/Azure/azure-sdk-for-python/pull/39390).
* On database account calls send a client id header for load balancing. See [PR 39390](https://github.com/Azure/azure-sdk-for-python/pull/39390).
* Removed aiohttp dependency. See [PR 39390](https://github.com/Azure/azure-sdk-for-python/pull/39390).

### 4.9.1b2 (2025-01-24)

#### Features Added
* Added new cross-regional retry logic for `ServiceRequestError` and `ServiceResponseError` exceptions. See [PR 39396](https://github.com/Azure/azure-sdk-for-python/pull/39396).

#### Bugs Fixed
* Fixed `KeyError` being returned by location cache when most preferred location is not present in cached regions. See [PR 39396](https://github.com/Azure/azure-sdk-for-python/pull/39396).
* Fixed cross-region retries on `CosmosClient` initialization. See [PR 39396](https://github.com/Azure/azure-sdk-for-python/pull/39396).

#### Other Changes
* This release requires aiohttp version 3.10.11 and above. See [PR 39396](https://github.com/Azure/azure-sdk-for-python/pull/39396).

### 4.9.1b1 (2024-12-13)

#### Features Added
* Added change feed mode support in `query_items_change_feed`. See [PR 38105](https://github.com/Azure/azure-sdk-for-python/pull/38105).
* Added a **Preview Feature** for adding Diagnostics Handler to filter what diagnostics get logged. This feature is subject to change significantly. See [PR 38105](https://github.com/Azure/azure-sdk-for-python/pull/38581).

### 4.9.0 (2024-11-18)

#### Features Added
* Added full text policy and full text indexing policy. See [PR 37891](https://github.com/Azure/azure-sdk-for-python/pull/37891).
* Added support for full text search and hybrid search queries. See [PR 38275](https://github.com/Azure/azure-sdk-for-python/pull/38275).

### 4.8.0 (2024-11-12)
This version and all future versions will support Python 3.13.

#### Features Added
* Added response headers directly to SDK item point operation responses. See [PR 35791](https://github.com/Azure/azure-sdk-for-python/pull/35791).
* SDK will now retry all ServiceRequestErrors (failing outgoing requests) before failing. Default number of retries is 3. See [PR 36514](https://github.com/Azure/azure-sdk-for-python/pull/36514).
* Added Retry Policy for Container Recreate in the Python SDK. See [PR 36043](https://github.com/Azure/azure-sdk-for-python/pull/36043).
* Added option to disable write payload on writes. See [PR 37365](https://github.com/Azure/azure-sdk-for-python/pull/37365).
* Added get feed ranges API. See [PR 37687](https://github.com/Azure/azure-sdk-for-python/pull/37687).
* Added feed range support in `query_items_change_feed`. See [PR 37687](https://github.com/Azure/azure-sdk-for-python/pull/37687).
* Added **provisional** helper APIs for managing session tokens. See [PR 36971](https://github.com/Azure/azure-sdk-for-python/pull/36971).
* Added ability to get feed range for a partition key. See [PR 36971](https://github.com/Azure/azure-sdk-for-python/pull/36971).

#### Breaking Changes
* Item-level point operations will now return `CosmosDict` and `CosmosList` response types. 
Responses will still be able to be used directly as previously, but will now have access to their response headers without need for a response hook. See [PR 35791](https://github.com/Azure/azure-sdk-for-python/pull/35791).
For more information on this, see our README section [here](https://github.com/Azure/azure-sdk-for-python/blob/main/sdk/cosmos/azure-cosmos/README.md#using-item-operation-response-headers).

#### Bugs Fixed
* Consolidated Container Properties Cache to be in the Client to cache partition key definition and container rid to avoid unnecessary container reads. See [PR 35731](https://github.com/Azure/azure-sdk-for-python/pull/35731).
* Fixed bug with client hangs when running into WriteForbidden exceptions. See [PR 36514](https://github.com/Azure/azure-sdk-for-python/pull/36514).
* Added retry handling logic for DatabaseAccountNotFound exceptions. See [PR 36514](https://github.com/Azure/azure-sdk-for-python/pull/36514).
* Fixed SDK regex validation that would not allow for item ids to be longer than 255 characters. See [PR 36569](https://github.com/Azure/azure-sdk-for-python/pull/36569).
* Fixed issue where 'NoneType' object has no attribute error was raised when a session retry happened during a query. See [PR 37578](https://github.com/Azure/azure-sdk-for-python/pull/37578).
* Fixed issue where passing subpartition partition key values as a tuple in a query would raise an error. See [PR 38136](https://github.com/Azure/azure-sdk-for-python/pull/38136).
* Batch requests will now be properly considered as Write operation. See [PR 38365](https://github.com/Azure/azure-sdk-for-python/pull/38365).

#### Other Changes
* Getting offer thoughput when it has not been defined in a container will now give a 404/10004 instead of just a 404. See [PR 36043](https://github.com/Azure/azure-sdk-for-python/pull/36043).
* Incomplete Partition Key Extractions in documents for Subpartitioning now gives 400/1001 instead of just a 400. See [PR 36043](https://github.com/Azure/azure-sdk-for-python/pull/36043).
* SDK will now make database account calls every 5 minutes to refresh location cache. See [PR 36514](https://github.com/Azure/azure-sdk-for-python/pull/36514).

### 4.7.0 (2024-05-15)

#### Features Added
* Adds vector embedding policy and vector indexing policy. See [PR 34882](https://github.com/Azure/azure-sdk-for-python/pull/34882).
* Adds support for vector search non-streaming order by queries. See [PR 35468](https://github.com/Azure/azure-sdk-for-python/pull/35468).
* Adds support for using the start time option for change feed query API. See [PR 35090](https://github.com/Azure/azure-sdk-for-python/pull/35090).

#### Bugs Fixed
* Fixed a bug where change feed query in Async client was not returning all pages due to case-sensitive response headers. See [PR 35090](https://github.com/Azure/azure-sdk-for-python/pull/35090).
* Fixed a bug when a retryable exception occurs in the first page of a query execution causing query to return 0 results. See [PR 35090](https://github.com/Azure/azure-sdk-for-python/pull/35090).

### 4.6.1 (2024-05-15)

### 4.6.0 (2024-03-14)

#### Features Added
* GA release of hierarchical partitioning, index metrics and transactional batch.

#### Bugs Fixed
* Keyword arguments were not being passed down for `create_container_if_not_exists()` methods. See [PR 34286](https://github.com/Azure/azure-sdk-for-python/pull/34286).

#### Other Changes
* Made several updates to the type hints used throughout the SDK for greater detail. See [PR 33269](https://github.com/Azure/azure-sdk-for-python/pull/33269), [PR 33341](https://github.com/Azure/azure-sdk-for-python/pull/33341), [PR 33738](https://github.com/Azure/azure-sdk-for-python/pull/33738).

### 4.5.2b5 (2024-03-02)

#### Bugs Fixed
* Fixed bug with async lock not properly releasing on async global endpoint manager. see [PR 34579](https://github.com/Azure/azure-sdk-for-python/pull/34579).

#### Other Changes
* Marked `computed_properties` keyword as provisional, un-marked `continuation_token_limit` as provisional. See [PR 34207](https://github.com/Azure/azure-sdk-for-python/pull/34207).

### 4.5.2b4 (2024-02-02)
This version and all future versions will require Python 3.8+.

#### Features Added
* Added **preview** support for Computed Properties on Python SDK (Must be enabled on the account level before it can be used). See [PR 33626](https://github.com/Azure/azure-sdk-for-python/pull/33626).

#### Bugs Fixed
* Made use of `response_hook` thread-safe in the sync client. See [PR 33790](https://github.com/Azure/azure-sdk-for-python/pull/33790).
* Fixed bug with the session container not being properly maintained. See [33738](https://github.com/Azure/azure-sdk-for-python/pull/33738).

### 4.5.2b3 (2023-11-10)

#### Features Added
* Added support for capturing Index Metrics in query operations. See [PR 33034](https://github.com/Azure/azure-sdk-for-python/pull/33034).

### 4.5.2b2 (2023-10-31)

#### Features Added
* Added support for Transactional Batch. See [PR 32508](https://github.com/Azure/azure-sdk-for-python/pull/32508).
* Added **preview** support for Priority Based Throttling/Priority Based Execution (Must be enabled at the account level before it can be used). See [PR 32441](https://github.com/Azure/azure-sdk-for-python/pull/32441/).

### 4.5.2b1 (2023-10-17)

#### Features Added
* Added support for Hierarchical Partitioning, also known as Subpartitioning. See [PR 31121](https://github.com/Azure/azure-sdk-for-python/pull/31121).

#### Bugs Fixed
* Small fix to the `offer_throughput` option in the async client's `create_database_if_not_exists` method, which was previously misspelled as `offerThroughput`.
See [PR 32076](https://github.com/Azure/azure-sdk-for-python/pull/32076).

#### Other Changes
* Marked the outdated `diagnostics.py` file for deprecation since we now recommend the use of our `CosmosHttpLoggingPolicy` for diagnostics.
For more on the `CosmosHttpLoggingPolicy` see our [README](https://github.com/Azure/azure-sdk-for-python/tree/main/sdk/cosmos/azure-cosmos#logging-diagnostics).

### 4.5.1 (2023-09-12)

#### Bugs Fixed
* Fixed bug when query with DISTINCT + OFFSET/LIMIT operators returns unexpected result. See [PR 31925](https://github.com/Azure/azure-sdk-for-python/pull/31925).

#### Other Changes
* Added additional checks for resource creation using specific characters that cause issues. See [PR 31861](https://github.com/Azure/azure-sdk-for-python/pull/31861).

### 4.5.0 (2023-08-09)

#### Features Added
* Added support for continuation tokens for streamable cross partition queries. See [PR 31189](https://github.com/Azure/azure-sdk-for-python/pull/31189).

#### Bugs Fixed
* Fixed bug with async `create_database_if_not_exists` method not working when passing `offer_throughput` as an option. See [PR 31478](https://github.com/Azure/azure-sdk-for-python/pull/31478).

#### Other Changes
* Renamed `response_continuation_token_limit_in_kb` to `continuation_token_limit` for GA. See [PR 31532](https://github.com/Azure/azure-sdk-for-python/pull/31532).

### 4.4.1b1 (2023-07-25)

#### Features Added
* Added ability to limit continuation token size when querying for items. See [PR 30731](https://github.com/Azure/azure-sdk-for-python/pull/30731)

#### Bugs Fixed
* Fixed bug with async patch_item method. See [PR 30804](https://github.com/Azure/azure-sdk-for-python/pull/30804).

### 4.4.0 (2023-06-09)

#### Features Added
- GA release of Patch API and Delete All Items By Partition Key

### 4.4.0b2 (2023-05-22)

#### Features Added
* Added conditional patching for Patch operations. See [PR 30455](https://github.com/Azure/azure-sdk-for-python/pull/30455).

#### Bugs Fixed
* Fixed bug with non english locales causing an error with the RFC 1123 Date Format. See [PR 30125](https://github.com/Azure/azure-sdk-for-python/pull/30125).

#### Other Changes
* Refactoring of our client `connection_timeout` and `request_timeout` configurations. See [PR 30171](https://github.com/Azure/azure-sdk-for-python/pull/30171).

### 4.4.0b1 (2023-04-11)

#### Features Added
 - Added **preview** delete all items by partition key functionality. See [PR 29186](https://github.com/Azure/azure-sdk-for-python/pull/29186). For more information on Partition Key Delete, please see [Azure Cosmos DB Partition Key Delete](https://learn.microsoft.com/azure/cosmos-db/nosql/how-to-delete-by-partition-key?tabs=python-example).
 - Added **preview** partial document update (Patch API) functionality and container methods for patching items with operations. See [PR 29497](https://github.com/Azure/azure-sdk-for-python/pull/29497). For more information on Patch, please see [Azure Cosmos DB Partial Document Update](https://learn.microsoft.com/azure/cosmos-db/partial-document-update).

#### Bugs Fixed
* Fixed bug in method `create_container_if_not_exists()` of async database client for unexpected kwargs being passed into `read()` method used internally. See [PR 29136](https://github.com/Azure/azure-sdk-for-python/pull/29136).
* Fixed bug with method `query_items()` of our async container class, where partition key and cross partition headers would both be set when using partition keys. See [PR 29366](https://github.com/Azure/azure-sdk-for-python/pull/29366/).
* Fixed bug with client not properly surfacing errors for invalid credentials and identities with insufficient permissions. Users running into 'NoneType has no attribute ConsistencyPolicy' errors when initializing their clients will now see proper authentication exceptions. See [PR 29256](https://github.com/Azure/azure-sdk-for-python/pull/29256).

#### Other Changes
* Removed use of `six` package within the SDK.

### 4.3.1 (2023-02-23)

#### Features Added
 - Added `correlated_activity_id` for query operations.
 - Added cross regional retries for Service Unavailable/Request Timeouts for read/Query Plan operations.
 - GA release of CosmosHttpLoggingPolicy and autoscale feature.

#### Bugs Fixed
- Bug fix to address queries with VALUE MAX (or any other aggregate) that run into an issue if the query is executed on a container with at least one "empty" partition.

### 4.3.1b1 (2022-09-19)

#### Features Added
- GA release of integrated cache functionality. For more information on integrated cache please see [Azure Cosmos DB integrated cache](https://learn.microsoft.com/azure/cosmos-db/integrated-cache).
- Added ability to replace analytical ttl on containers. For more information on analytical ttl please see [Azure Cosmos DB analytical store](https://learn.microsoft.com/azure/cosmos-db/analytical-store-introduction).
- Added `CosmosHttpLoggingPolicy` to replace `HttpLoggingPolicy` for logging HTTP sessions.
- Added the ability to create containers and databases with autoscale properties for the sync and async clients.
- Added the ability to update autoscale throughput properties.

#### Bugs Fixed
- Fixed parsing of args for overloaded `container.read()` method.
- Fixed `validate_cache_staleness_value()` method to allow max_integrated_cache_staleness to be an integer greater than or equal to 0.
- Fixed `__aiter__()` method by removing the async keyword.

### 4.3.0 (2022-05-23)
#### Features Added
- GA release of Async I/O APIs, including all changes from 4.3.0b1 to 4.3.0b4.

#### Breaking Changes
- Method signatures have been updated to use keyword arguments instead of positional arguments for most method options in the async client.
- Bugfix: Automatic Id generation for items was turned on for `upsert_items()` method when no 'id' value was present in document body.
Method call will now require an 'id' field to be present in the document body.

#### Other Changes
- Deprecated offer-named methods in favor of their new throughput-named counterparts (`read_offer` -> `get_throughput`).
- Marked the GetAuthorizationHeader method for deprecation since it will no longer be public in a future release.
- Added samples showing how to configure retry options for both the sync and async clients.
- Deprecated the `connection_retry_policy` and `retry_options` options in the sync client.
- Added user warning to non-query methods trying to use `populate_query_metrics` options.

### 4.3.0b4 (2022-04-07)

#### Features Added
- Added support for AAD authentication for the async client.
- Added support for AAD authentication for the sync client.

#### Other Changes
- Changed `_set_partition_key` return typehint in async client.

### 4.3.0b3 (2022-03-10)

>[WARNING]
>The default `Session` consistency bugfix will impact customers whose database accounts have a `Bounded Staleness` or `Strong`
> consistency level, and were previously not sending `Session` as a consistency_level parameter when initializing
> their clients.
> Default consistency level for the sync and async clients is no longer "Session" and will instead be set to the 
  consistency level of the user's cosmos account setting on initialization if not passed during client initialization. 
> Please see [Consistency Levels in Azure Cosmos DB](https://learn.microsoft.com/azure/cosmos-db/consistency-levels) 
> for more details on consistency levels, or the README section on this change [here](https://github.com/Azure/azure-sdk-for-python/tree/main/sdk/cosmos/azure-cosmos#note-on-client-consistency-levels).

#### Features Added
- Added new **provisional** `max_integrated_cache_staleness_in_ms` parameter to read item and query items APIs in order
  to make use of the **preview** CosmosDB integrated cache functionality [See PR #22946](https://github.com/Azure/azure-sdk-for-python/pull/22946).
  Please see [Azure Cosmos DB integrated cache](https://learn.microsoft.com/azure/cosmos-db/integrated-cache) for more details.
- Added support for split-proof queries for the async client.

### Bugs fixed
- Default consistency level for the sync and async clients is no longer `Session` and will instead be set to the 
  consistency level of the user's cosmos account setting on initialization if not passed during client initialization. 
  This change will impact client application in terms of RUs and latency. Users relying on default `Session` consistency
  will need to pass it explicitly if their account consistency is different than `Session`.
  Please see [Consistency Levels in Azure Cosmos DB](https://learn.microsoft.com/azure/cosmos-db/consistency-levels) for more details.  
- Fixed invalid request body being sent when passing in `serverScript` body parameter to replace operations for trigger, sproc and udf resources.
- Moved `is_system_key` logic in async client.
- Fixed TypeErrors not being thrown when passing in invalid connection retry policies to the client.

### 4.3.0b2 (2022-01-25)

This version and all future versions will require Python 3.6+. Python 2.7 is no longer supported.
We will also be removing support for Python 3.6 and will only support Python 3.7+ starting December 2022.

#### Features Added
- Added support for split-proof queries for the sync client.

#### Other Changes
- Added async user agent for async client.

### 4.3.0b1 (2021-12-14)

#### Features Added
- Added language native async i/o client.

### 4.2.0 (2020-10-08)

**Bug fixes**
- Fixed bug where continuation token is not honored when query_iterable is used to get results by page. Issue #13265.
- Fixed bug where resource tokens not being honored for document reads and deletes. Issue #13634.

**New features**
- Added support for passing partitionKey while querying changefeed. Issue #11689.

### 4.1.0 (2020-08-10)

- Added deprecation warning for "lazy" indexing mode. The backend no longer allows creating containers with this mode and will set them to consistent instead.

**New features**
- Added the ability to set the analytical storage TTL when creating a new container.

**Bug fixes**
- Fixed support for dicts as inputs for get_client APIs.
- Fixed Python 2/3 compatibility in query iterators.
- Fixed type hint error. Issue #12570 - thanks @sl-sandy.
- Fixed bug where options headers were not added to upsert_item function. Issue #11791 - thank you @aalapatirvbd.
- Fixed error raised when a non string ID is used in an item. It now raises TypeError rather than AttributeError. Issue #11793 - thank you @Rabbit994.


### 4.0.0 (2020-05-20)

- Stable release.
- Added HttpLoggingPolicy to pipeline to enable passing in a custom logger for request and response headers.


## 4.0.0b6

- Fixed bug in synchronized_request for media APIs.
- Removed MediaReadMode and MediaRequestTimeout from ConnectionPolicy as media requests are not supported.


## 4.0.0b5

- azure.cosmos.errors module deprecated and replaced by azure.cosmos.exceptions
- The access condition parameters (`access_condition`, `if_match`, `if_none_match`) have been deprecated in favor of separate `match_condition` and `etag` parameters.
- Fixed bug in routing map provider.
- Added query Distinct, Offset and Limit support.
- Default document query execution context now used for
    - ChangeFeed queries
    - single partition queries (partitionkey, partitionKeyRangeId is present in options)
    - Non document queries
- Errors out for aggregates on multiple partitions, with enable cross partition query set to true, but no "value" keyword present
- Hits query plan endpoint for other scenarios to fetch query plan
- Added `__repr__` support for Cosmos entity objects.
- Updated documentation.


## 4.0.0b4

- Added support for a `timeout` keyword argument to all operations to specify an absolute timeout in seconds
  within which the operation must be completed. If the timeout value is exceeded, a `azure.cosmos.errors.CosmosClientTimeoutError` will be raised.
- Added a new `ConnectionRetryPolicy` to manage retry behaviour during HTTP connection errors.
- Added new constructor and per-operation configuration keyword arguments:
    - `retry_total` - Maximum retry attempts.
    - `retry_backoff_max` - Maximum retry wait time in seconds.
    - `retry_fixed_interval` - Fixed retry interval in milliseconds.
    - `retry_read` - Maximum number of socket read retry attempts.
    - `retry_connect` - Maximum number of connection error retry attempts.
    - `retry_status` - Maximum number of retry attempts on error status codes.
    - `retry_on_status_codes` - A list of specific status codes to retry on.
    - `retry_backoff_factor` - Factor to calculate wait time between retry attempts.

## 4.0.0b3

- Added `create_database_if_not_exists()` and `create_container_if_not_exists` functionalities to CosmosClient and Database respectively.

## 4.0.0b2

Version 4.0.0b2 is the second iteration in our efforts to build a more Pythonic client library.

**Breaking changes**

- The client connection has been adapted to consume the HTTP pipeline defined in `azure.core.pipeline`.
- Interactive objects have now been renamed as proxies. This includes:
    - `Database` -> `DatabaseProxy`
    - `User` -> `UserProxy`
    - `Container` -> `ContainerProxy`
    - `Scripts` -> `ScriptsProxy`
- The constructor of `CosmosClient` has been updated:
    - The `auth` parameter has been renamed to `credential` and will now take an authentication type directly. This means the master key value, a dictionary of resource tokens, or a list of permissions can be passed in. However the old dictionary format is still supported.
    - The `connection_policy` parameter has been made a keyword only parameter, and while it is still supported, each of the individual attributes of the policy can now be passed in as explicit keyword arguments:
        - `request_timeout`
        - `media_request_timeout`
        - `connection_mode`
        - `media_read_mode`
        - `proxy_config`
        - `enable_endpoint_discovery`
        - `preferred_locations`
        - `multiple_write_locations`
- A new classmethod constructor has been added to `CosmosClient` to enable creation via a connection string retrieved from the Azure portal.
- Some `read_all` operations have been renamed to `list` operations:
    - `CosmosClient.read_all_databases` -> `CosmosClient.list_databases`
    - `Container.read_all_conflicts` -> `ContainerProxy.list_conflicts`
    - `Database.read_all_containers` -> `DatabaseProxy.list_containers`
    - `Database.read_all_users` -> `DatabaseProxy.list_users`
    - `User.read_all_permissions` -> `UserProxy.list_permissions`
- All operations that take `request_options` or `feed_options` parameters, these have been moved to keyword only parameters. In addition, while these options dictionaries are still supported, each of the individual options within the dictionary are now supported as explicit keyword arguments.
- The error hierarchy is now inherited from `azure.core.AzureError` instead of `CosmosError` which has been removed.
    - `HTTPFailure` has been renamed to `CosmosHttpResponseError`
    - `JSONParseFailure` has been removed and replaced by `azure.core.DecodeError`
    - Added additional errors for specific response codes:
        - `CosmosResourceNotFoundError` for status 404
        - `CosmosResourceExistsError` for status 409
        - `CosmosAccessConditionFailedError` for status 412
- `CosmosClient` can now be run in a context manager to handle closing the client connection.
- Iterable responses (e.g. query responses and list responses) are now of type `azure.core.paging.ItemPaged`. The method `fetch_next_block` has been replaced by a secondary iterator, accessed by the `by_page` method.

## 4.0.0b1

Version 4.0.0b1 is the first preview of our efforts to create a user-friendly and Pythonic client library for Azure Cosmos. For more information about this, and preview releases of other Azure SDK libraries, please visit https://aka.ms/azure-sdk-preview1-python.

**Breaking changes: New API design**

- Operations are now scoped to a particular client:
    - `CosmosClient`: This client handles account-level operations. This includes managing service properties and listing the databases within an account.
    - `Database`: This client handles database-level operations. This includes creating and deleting containers, users and stored procedures. It can be accessed from a `CosmosClient` instance by name.
    - `Container`: This client handles operations for a particular container. This includes querying and inserting items and managing properties.
    - `User`: This client handles operations for a particular user. This includes adding and deleting permissions and managing user properties.
    
    These clients can be accessed by navigating down the client hierarchy using the `get_<child>_client` method. For full details on the new API, please see the [reference documentation](https://aka.ms/azsdk-python-cosmos-ref).
- Clients are accessed by name rather than by Id. No need to concatenate strings to create links.
- No more need to import types and methods from individual modules. The public API surface area is available directly in the `azure.cosmos` package.
- Individual request properties can be provided as keyword arguments rather than constructing a separate `RequestOptions` instance.

## 3.0.2

- Added Support for MultiPolygon Datatype
- Bug Fix in Session Read Retry Policy
- Bug Fix for Incorrect padding issues while decoding base 64 strings

## 3.0.1

- Bug fix in LocationCache
- Bug fix endpoint retry logic
- Fixed documentation

## 3.0.0

- Multi-region write support added
- Naming changes
  - DocumentClient to CosmosClient
  - Collection to Container
  - Document to Item
  - Package name updated to "azure-cosmos"
  - Namespace updated to "azure.cosmos"

## 2.3.3

- Added support for proxy
- Added support for reading change feed
- Added support for collection quota headers
- Bugfix for large session tokens issue
- Bugfix for ReadMedia API
- Bugfix in partition key range cache

## 2.3.2

- Added support for default retries on connection issues.

## 2.3.1

- Updated documentation to reference Azure Cosmos DB instead of Azure DocumentDB.

## 2.3.0

- This SDK version requires the latest version of Azure Cosmos DB Emulator available for download from https://aka.ms/cosmosdb-emulator.

## 2.2.1

- bugfix for aggregate dict
- bugfix for trimming slashes in the resource link
- tests for unicode encoding

## 2.2.0

- Added support for Request Unit per Minute (RU/m) feature.
- Added support for a new consistency level called ConsistentPrefix.

## 2.1.0

- Added support for aggregation queries (COUNT, MIN, MAX, SUM, and AVG).
- Added an option for disabling SSL verification when running against DocumentDB Emulator.
- Removed the restriction of dependent requests module to be exactly 2.10.0.
- Lowered minimum throughput on partitioned collections from 10,100 RU/s to 2500 RU/s.
- Added support for enabling script logging during stored procedure execution.
- REST API version bumped to '2017-01-19' with this release.

## 2.0.1

- Made editorial changes to documentation comments.

## 2.0.0

- Added support for Python 3.5.
- Added support for connection pooling using the requests module.
- Added support for session consistency.
- Added support for TOP/ORDERBY queries for partitioned collections.

## 1.9.0

- Added retry policy support for throttled requests. (Throttled requests receive a request rate too large exception, error code 429.)
  By default, DocumentDB retries nine times for each request when error code 429 is encountered, honoring the retryAfter time in the response header.
  A fixed retry interval time can now be set as part of the RetryOptions property on the ConnectionPolicy object if you want to ignore the retryAfter time returned by server between the retries.
  DocumentDB now waits for a maximum of 30 seconds for each request that is being throttled (irrespective of retry count) and returns the response with error code 429.
  This time can also be overridden in the RetryOptions property on ConnectionPolicy object.

- DocumentDB now returns x-ms-throttle-retry-count and x-ms-throttle-retry-wait-time-ms as the response headers in every request to denote the throttle retry count
  and the cumulative time the request waited between the retries.

- Removed the RetryPolicy class and the corresponding property (retry_policy) exposed on the document_client class and instead introduced a RetryOptions class
  exposing the RetryOptions property on ConnectionPolicy class that can be used to override some of the default retry options.

## 1.8.0

- Added the support for geo-replicated database accounts.
- Test fixes to move the global host and masterKey into the individual test classes.

## 1.7.0

- Added the support for Time To Live(TTL) feature for documents.

## 1.6.1

- Bug fixes related to server side partitioning to allow special characters in partitionkey path.

## 1.6.0

- Added the support for server side partitioned collections feature.

## 1.5.0

- Added Client-side sharding framework to the SDK. Implemented HashPartionResolver and RangePartitionResolver classes.

## 1.4.2

- Implement Upsert. New UpsertXXX methods added to support Upsert feature.
- Implement ID Based Routing. No public API changes, all changes internal.

## 1.3.0

- Release skipped to bring version number in alignment with other SDKs

## 1.2.0

- Supports GeoSpatial index.
- Validates id property for all resources. Ids for resources cannot contain ?, /, #, \\, characters or end with a space.
- Adds new header "index transformation progress" to ResourceResponse.

## 1.1.0

- Implements V2 indexing policy

## 1.0.1

- Supports proxy connection

