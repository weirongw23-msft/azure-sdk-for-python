# ------------------------------------
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# ------------------------------------
import base64
import logging
import subprocess
import sys
from typing import Any, List, Tuple, Optional

from azure.core.credentials import AccessToken, AccessTokenInfo, TokenRequestOptions
from azure.core.exceptions import ClientAuthenticationError

from .azure_cli import get_safe_working_dir
from .. import CredentialUnavailableError
from .._internal import _scopes_to_resource, resolve_tenant, within_dac, validate_tenant_id, validate_scope
from .._internal.decorators import log_get_token


_LOGGER = logging.getLogger(__name__)

AZ_ACCOUNT_NOT_INSTALLED = "Az.Account module >= 2.2.0 is not installed"
BLOCKED_BY_EXECUTION_POLICY = "Execution policy prevented invoking Azure PowerShell"
NO_AZ_ACCOUNT_MODULE = "NO_AZ_ACCOUNT_MODULE"
POWERSHELL_NOT_INSTALLED = "PowerShell is not installed"
RUN_CONNECT_AZ_ACCOUNT = 'Please run "Connect-AzAccount" to set up account'
SCRIPT = """$ErrorActionPreference = 'Stop'
[version]$minimumVersion = '2.2.0'

$m = Import-Module Az.Accounts -MinimumVersion $minimumVersion -PassThru -ErrorAction SilentlyContinue

if (! $m) {{
    Write-Output {}
    exit
}}

$params = @{{ 'ResourceUrl' = '{}'; 'WarningAction' = 'Ignore' }}

$tenantId = '{}'
if ($tenantId.Length -gt 0) {{
    $params['TenantId'] = $tenantId
}}

if ($m.Version -ge [version]'2.17.0' -and $m.Version -lt [version]'5.0.0') {{
    $params['AsSecureString'] = $true
}}

$token = Get-AzAccessToken @params
$tokenValue = $token.Token
if ($tokenValue -is [System.Security.SecureString]) {{
    if ($PSVersionTable.PSVersion.Major -lt 7) {{
        $ssPtr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($tokenValue)
        try {{
            $tokenValue = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($ssPtr)
        }}
        finally {{
            [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ssPtr)
        }}
    }}
    else {{
        $tokenValue = $tokenValue | ConvertFrom-SecureString -AsPlainText
    }}
}}
Write-Output "`nazsdk%$($tokenValue)%$($token.ExpiresOn.ToUnixTimeSeconds())`n"
"""


class AzurePowerShellCredential:
    """Authenticates by requesting a token from Azure PowerShell.

    This requires previously logging in to Azure via "Connect-AzAccount", and will use the currently logged in identity.

    :keyword str tenant_id: Optional tenant to include in the token request.
    :keyword List[str] additionally_allowed_tenants: Specifies tenants in addition to the specified "tenant_id"
        for which the credential may acquire tokens. Add the wildcard value "*" to allow the credential to
        acquire tokens for any tenant the application can access.
    :keyword int process_timeout: Seconds to wait for the Azure PowerShell process to respond. Defaults to 10 seconds.

    .. admonition:: Example:

        .. literalinclude:: ../samples/credential_creation_code_snippets.py
            :start-after: [START create_azure_power_shell_credential]
            :end-before: [END create_azure_power_shell_credential]
            :language: python
            :dedent: 4
            :caption: Create an AzurePowerShellCredential.
    """

    def __init__(
        self,
        *,
        tenant_id: str = "",
        additionally_allowed_tenants: Optional[List[str]] = None,
        process_timeout: int = 10,
    ) -> None:
        if tenant_id:
            validate_tenant_id(tenant_id)
        self.tenant_id = tenant_id
        self._additionally_allowed_tenants = additionally_allowed_tenants or []
        self._process_timeout = process_timeout

    def __enter__(self) -> "AzurePowerShellCredential":
        return self

    def __exit__(self, *args: Any) -> None:
        pass

    def close(self) -> None:
        """Calling this method is unnecessary."""

    @log_get_token
    def get_token(
        self,
        *scopes: str,
        claims: Optional[str] = None,  # pylint:disable=unused-argument
        tenant_id: Optional[str] = None,
        **kwargs: Any,
    ) -> AccessToken:
        """Request an access token for `scopes`.

        This method is called automatically by Azure SDK clients. Applications calling this method directly must
        also handle token caching because this credential doesn't cache the tokens it acquires.

        :param str scopes: desired scope for the access token. This credential allows only one scope per request.
            For more information about scopes, see
            https://learn.microsoft.com/entra/identity-platform/scopes-oidc.
        :keyword str claims: not used by this credential; any value provided will be ignored.
        :keyword str tenant_id: optional tenant to include in the token request.

        :return: An access token with the desired scopes.
        :rtype: ~azure.core.credentials.AccessToken

        :raises ~azure.identity.CredentialUnavailableError: the credential was unable to invoke Azure PowerShell, or
          no account is authenticated
        :raises ~azure.core.exceptions.ClientAuthenticationError: the credential invoked Azure PowerShell but didn't
          receive an access token
        """

        options: TokenRequestOptions = {}
        if tenant_id:
            options["tenant_id"] = tenant_id

        token_info = self._get_token_base(*scopes, options=options, **kwargs)
        return AccessToken(token_info.token, token_info.expires_on)

    @log_get_token
    def get_token_info(self, *scopes: str, options: Optional[TokenRequestOptions] = None) -> AccessTokenInfo:
        """Request an access token for `scopes`.

        This is an alternative to `get_token` to enable certain scenarios that require additional properties
        on the token. This method is called automatically by Azure SDK clients. Applications calling this method
        directly must also handle token caching because this credential doesn't cache the tokens it acquires.

        :param str scopes: desired scopes for the access token. TThis credential allows only one scope per request.
            For more information about scopes, see https://learn.microsoft.com/entra/identity-platform/scopes-oidc.
        :keyword options: A dictionary of options for the token request. Unknown options will be ignored. Optional.
        :paramtype options: ~azure.core.credentials.TokenRequestOptions

        :rtype: ~azure.core.credentials.AccessTokenInfo
        :return: An AccessTokenInfo instance containing information about the token.

        :raises ~azure.identity.CredentialUnavailableError: the credential was unable to invoke Azure PowerShell, or
          no account is authenticated
        :raises ~azure.core.exceptions.ClientAuthenticationError: the credential invoked Azure PowerShell but didn't
          receive an access token
        """
        return self._get_token_base(*scopes, options=options)

    def _get_token_base(
        self, *scopes: str, options: Optional[TokenRequestOptions] = None, **kwargs: Any
    ) -> AccessTokenInfo:

        tenant_id = options.get("tenant_id") if options else None
        if tenant_id:
            validate_tenant_id(tenant_id)
        for scope in scopes:
            validate_scope(scope)

        tenant_id = resolve_tenant(
            default_tenant=self.tenant_id,
            tenant_id=tenant_id,
            additionally_allowed_tenants=self._additionally_allowed_tenants,
            **kwargs,
        )
        command_line = get_command_line(scopes, tenant_id)
        output = run_command_line(command_line, self._process_timeout)
        token = parse_token(output)
        return token


def run_command_line(command_line: List[str], timeout: int) -> str:
    stdout = stderr = ""
    proc = None
    kwargs = {"timeout": timeout}

    try:
        proc = start_process(command_line)
        stdout, stderr = proc.communicate(**kwargs)
        if sys.platform.startswith("win") and ("' is not recognized" in stderr or proc.returncode == 9009):
            # pwsh.exe isn't on the path; try powershell.exe
            command_line[-1] = command_line[-1].replace("pwsh", "powershell", 1)
            proc = start_process(command_line)
            stdout, stderr = proc.communicate(**kwargs)

    except Exception as ex:
        # failed to execute "cmd" or "/bin/sh", or timed out; PowerShell and Az.Account may or may not be installed
        # (handling Exception here because subprocess.SubprocessError and .TimeoutExpired were added in 3.3)
        if proc and not proc.returncode:
            proc.kill()
        error = CredentialUnavailableError(
            message="Failed to invoke PowerShell.\n"
            "To mitigate this issue, please refer to the troubleshooting guidelines here at "
            "https://aka.ms/azsdk/python/identity/powershellcredential/troubleshoot."
        )
        raise error from ex

    raise_for_error(proc.returncode, stdout, stderr)
    return stdout


def start_process(args: List[str]) -> "subprocess.Popen":
    working_directory = get_safe_working_dir()
    proc = subprocess.Popen(  # pylint:disable=consider-using-with
        args,
        cwd=working_directory,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        stdin=subprocess.DEVNULL,
        universal_newlines=True,
    )
    return proc


def parse_token(output: str) -> AccessTokenInfo:
    for line in output.split():
        if line.startswith("azsdk%"):
            _, token, expires_on = line.split("%")
            return AccessTokenInfo(token, int(expires_on))

    if within_dac.get():
        raise CredentialUnavailableError(message='Unexpected output from Get-AzAccessToken: "{}"'.format(output))
    raise ClientAuthenticationError(message='Unexpected output from Get-AzAccessToken: "{}"'.format(output))


def get_command_line(scopes: Tuple[str, ...], tenant_id: str) -> List[str]:
    tenant_argument = tenant_id if tenant_id else ""
    resource = _scopes_to_resource(*scopes)
    script = SCRIPT.format(NO_AZ_ACCOUNT_MODULE, resource, tenant_argument)
    encoded_script = base64.b64encode(script.encode("utf-16-le")).decode()

    command = "pwsh -NoProfile -NonInteractive -EncodedCommand " + encoded_script
    if sys.platform.startswith("win"):
        return ["cmd", "/c", command + " & exit"]
    return ["/bin/sh", "-c", command]


def raise_for_error(return_code: int, stdout: str, stderr: str) -> None:
    if return_code == 0:
        if NO_AZ_ACCOUNT_MODULE in stdout:
            raise CredentialUnavailableError(AZ_ACCOUNT_NOT_INSTALLED)
        return

    if return_code == 127 or "' is not recognized" in stderr:
        raise CredentialUnavailableError(message=POWERSHELL_NOT_INSTALLED)
    if "Run Connect-AzAccount to login" in stderr:
        raise CredentialUnavailableError(message=RUN_CONNECT_AZ_ACCOUNT)
    if "AuthorizationManager check failed" in stderr:
        raise CredentialUnavailableError(message=BLOCKED_BY_EXECUTION_POLICY)

    if stderr:
        # stderr is too noisy to include with an exception but may be useful for debugging
        _LOGGER.debug('%s received an error from Azure PowerShell: "%s"', AzurePowerShellCredential.__name__, stderr)
    raise CredentialUnavailableError(
        message="Failed to invoke PowerShell. Enable debug logging for additional information."
    )
