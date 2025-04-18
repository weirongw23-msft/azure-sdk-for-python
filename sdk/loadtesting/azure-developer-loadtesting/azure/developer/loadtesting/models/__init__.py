# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# Code generated by Microsoft (R) Python Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is regenerated.
# --------------------------------------------------------------------------
# pylint: disable=wrong-import-position

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ._patch import *  # pylint: disable=unused-wildcard-import


from ._models import (  # type: ignore
    AppComponent,
    ArtifactsContainerInfo,
    AutoStopCriteria,
    CertificateMetadata,
    DimensionFilter,
    DimensionValue,
    ErrorDetails,
    FunctionFlexConsumptionResourceConfiguration,
    FunctionFlexConsumptionTargetResourceConfigurations,
    LoadTestConfiguration,
    MetricAvailability,
    MetricDefinition,
    MetricDefinitionCollection,
    MetricNamespace,
    MetricNamespaceCollection,
    MetricRequestPayload,
    MetricValue,
    NameAndDescription,
    OptionalLoadTestConfiguration,
    PassFailCriteria,
    PassFailMetric,
    PassFailServerMetric,
    RegionalConfiguration,
    ResourceMetric,
    Secret,
    TargetResourceConfigurations,
    Test,
    TestAppComponents,
    TestFileInfo,
    TestInputArtifacts,
    TestProfile,
    TestProfileRun,
    TestProfileRunRecommendation,
    TestRun,
    TestRunAppComponents,
    TestRunArtifacts,
    TestRunDetail,
    TestRunFileInfo,
    TestRunInputArtifacts,
    TestRunOutputArtifacts,
    TestRunServerMetricsConfiguration,
    TestRunStatistics,
    TestServerMetricsConfiguration,
    TimeSeriesElement,
)

from ._enums import (  # type: ignore
    Aggregation,
    CertificateType,
    CreatedByType,
    FileType,
    FileValidationStatus,
    ManagedIdentityType,
    MetricUnit,
    PFMetrics,
    PassFailAction,
    PassFailAggregationFunction,
    PassFailResult,
    PassFailTestResult,
    RecommendationCategory,
    RequestDataLevel,
    ResourceKind,
    SecretType,
    TestKind,
    TestProfileRunStatus,
    TestRunStatus,
    TimeGrain,
)
from ._patch import __all__ as _patch_all
from ._patch import *
from ._patch import patch_sdk as _patch_sdk

__all__ = [
    "AppComponent",
    "ArtifactsContainerInfo",
    "AutoStopCriteria",
    "CertificateMetadata",
    "DimensionFilter",
    "DimensionValue",
    "ErrorDetails",
    "FunctionFlexConsumptionResourceConfiguration",
    "FunctionFlexConsumptionTargetResourceConfigurations",
    "LoadTestConfiguration",
    "MetricAvailability",
    "MetricDefinition",
    "MetricDefinitionCollection",
    "MetricNamespace",
    "MetricNamespaceCollection",
    "MetricRequestPayload",
    "MetricValue",
    "NameAndDescription",
    "OptionalLoadTestConfiguration",
    "PassFailCriteria",
    "PassFailMetric",
    "PassFailServerMetric",
    "RegionalConfiguration",
    "ResourceMetric",
    "Secret",
    "TargetResourceConfigurations",
    "Test",
    "TestAppComponents",
    "TestFileInfo",
    "TestInputArtifacts",
    "TestProfile",
    "TestProfileRun",
    "TestProfileRunRecommendation",
    "TestRun",
    "TestRunAppComponents",
    "TestRunArtifacts",
    "TestRunDetail",
    "TestRunFileInfo",
    "TestRunInputArtifacts",
    "TestRunOutputArtifacts",
    "TestRunServerMetricsConfiguration",
    "TestRunStatistics",
    "TestServerMetricsConfiguration",
    "TimeSeriesElement",
    "Aggregation",
    "CertificateType",
    "CreatedByType",
    "FileType",
    "FileValidationStatus",
    "ManagedIdentityType",
    "MetricUnit",
    "PFMetrics",
    "PassFailAction",
    "PassFailAggregationFunction",
    "PassFailResult",
    "PassFailTestResult",
    "RecommendationCategory",
    "RequestDataLevel",
    "ResourceKind",
    "SecretType",
    "TestKind",
    "TestProfileRunStatus",
    "TestRunStatus",
    "TimeGrain",
]
__all__.extend([p for p in _patch_all if p not in __all__])  # pyright: ignore
_patch_sdk()
