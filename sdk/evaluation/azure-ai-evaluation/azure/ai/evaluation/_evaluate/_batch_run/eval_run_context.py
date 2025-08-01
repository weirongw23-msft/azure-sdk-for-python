# ---------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# ---------------------------------------------------------
import os
import types
from typing import Optional, Type, Union

from azure.ai.evaluation._legacy._adapters._constants import PF_FLOW_ENTRY_IN_TMP, PF_FLOW_META_LOAD_IN_SUBPROCESS
from azure.ai.evaluation._legacy._adapters.utils import ClientUserAgentUtil
from azure.ai.evaluation._legacy._adapters.tracing import inject_openai_api, recover_openai_api
from azure.ai.evaluation._legacy._batch_engine._openai_injector import (
    inject_openai_api as ported_inject_openai_api,
    recover_openai_api as ported_recover_openai_api,
)

from azure.ai.evaluation._constants import (
    OTEL_EXPORTER_OTLP_TRACES_TIMEOUT,
    OTEL_EXPORTER_OTLP_TRACES_TIMEOUT_DEFAULT,
    PF_BATCH_TIMEOUT_SEC,
    PF_BATCH_TIMEOUT_SEC_DEFAULT,
    PF_DISABLE_TRACING,
)

from ..._user_agent import UserAgentSingleton
from .._utils import set_event_loop_policy
from .batch_clients import BatchClient
from ._run_submitter_client import RunSubmitterClient
from .code_client import CodeClient
from .proxy_client import ProxyClient


class EvalRunContext:
    """Context manager for eval batch run.

    :param client: The client to run in the context.
    :type client: Union[
        ~azure.ai.evaluation._evaluate._batch_run.code_client.CodeClient,
        ~azure.ai.evaluation._evaluate._batch_run.proxy_client.ProxyClient
    ]
    """

    def __init__(self, client: BatchClient) -> None:
        self.client = client
        self._is_batch_timeout_set_by_system = False
        self._is_otel_timeout_set_by_system = False
        self._original_cwd = os.getcwd()

    def __enter__(self) -> None:
        # Preserve current working directory, as PF may change it without restoring it afterward
        self._original_cwd = os.getcwd()

        if isinstance(self.client, CodeClient):
            ClientUserAgentUtil.append_user_agent(UserAgentSingleton().value)
            inject_openai_api()

        if isinstance(self.client, ProxyClient):
            os.environ[PF_FLOW_ENTRY_IN_TMP] = "true"
            os.environ[PF_FLOW_META_LOAD_IN_SUBPROCESS] = "false"
            os.environ[PF_DISABLE_TRACING] = "true"

            if os.environ.get(PF_BATCH_TIMEOUT_SEC) is None:
                os.environ[PF_BATCH_TIMEOUT_SEC] = str(PF_BATCH_TIMEOUT_SEC_DEFAULT)
                self._is_batch_timeout_set_by_system = True

            # For dealing with the timeout issue of OpenTelemetry exporter when multiple evaluators are running
            if os.environ.get(OTEL_EXPORTER_OTLP_TRACES_TIMEOUT) is None:
                os.environ[OTEL_EXPORTER_OTLP_TRACES_TIMEOUT] = str(OTEL_EXPORTER_OTLP_TRACES_TIMEOUT_DEFAULT)
                self._is_otel_timeout_set_by_system = True

            # For addressing the issue of asyncio event loop closed on Windows
            set_event_loop_policy()

        if isinstance(self.client, RunSubmitterClient):
            set_event_loop_policy()
            ported_inject_openai_api()

    def __exit__(
        self,
        exc_type: Optional[Type[BaseException]],
        exc_value: Optional[BaseException],
        exc_tb: Optional[types.TracebackType],
    ) -> None:
        os.chdir(self._original_cwd)

        if isinstance(self.client, CodeClient):
            recover_openai_api()

        if isinstance(self.client, ProxyClient):
            os.environ.pop(PF_FLOW_ENTRY_IN_TMP, None)
            os.environ.pop(PF_FLOW_META_LOAD_IN_SUBPROCESS, None)
            os.environ.pop(PF_DISABLE_TRACING, None)

            if self._is_batch_timeout_set_by_system:
                os.environ.pop(PF_BATCH_TIMEOUT_SEC, None)
                self._is_batch_timeout_set_by_system = False

            if self._is_otel_timeout_set_by_system:
                os.environ.pop(OTEL_EXPORTER_OTLP_TRACES_TIMEOUT, None)
                self._is_otel_timeout_set_by_system = False

        if isinstance(self.client, RunSubmitterClient):
            ported_recover_openai_api()
