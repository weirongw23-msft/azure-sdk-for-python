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

from ._operations import ConnectionsOperations  # type: ignore
from ._operations import EvaluationsOperations  # type: ignore
from ._operations import DatasetsOperations  # type: ignore
from ._operations import IndexesOperations  # type: ignore
from ._operations import DeploymentsOperations  # type: ignore
from ._operations import RedTeamsOperations  # type: ignore
from ._operations import EvaluationResultsOperations  # type: ignore

from ._patch import __all__ as _patch_all
from ._patch import *
from ._patch import patch_sdk as _patch_sdk

__all__ = [
    "ConnectionsOperations",
    "EvaluationsOperations",
    "DatasetsOperations",
    "IndexesOperations",
    "DeploymentsOperations",
    "RedTeamsOperations",
    "EvaluationResultsOperations",
]
__all__.extend([p for p in _patch_all if p not in __all__])  # pyright: ignore
_patch_sdk()
