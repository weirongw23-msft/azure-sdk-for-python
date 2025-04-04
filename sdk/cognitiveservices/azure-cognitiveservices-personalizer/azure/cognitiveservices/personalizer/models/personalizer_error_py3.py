# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for
# license information.
#
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.
# --------------------------------------------------------------------------

from msrest.serialization import Model


class PersonalizerError(Model):
    """The error object.

    All required parameters must be populated in order to send to Azure.

    :param code: Required. High level error code. Possible values include:
     'BadRequest', 'ResourceNotFound', 'InternalServerError'
    :type code: str or ~azure.cognitiveservices.personalizer.models.ErrorCode
    :param message: Required. A message explaining the error reported by the
     service.
    :type message: str
    :param target: Error source element.
    :type target: str
    :param details: An array of details about specific errors that led to this
     reported error.
    :type details:
     list[~azure.cognitiveservices.personalizer.models.PersonalizerError]
    :param inner_error: Finer error details.
    :type inner_error:
     ~azure.cognitiveservices.personalizer.models.InternalError
    """

    _validation = {
        "code": {"required": True},
        "message": {"required": True},
    }

    _attribute_map = {
        "code": {"key": "code", "type": "str"},
        "message": {"key": "message", "type": "str"},
        "target": {"key": "target", "type": "str"},
        "details": {"key": "details", "type": "[PersonalizerError]"},
        "inner_error": {"key": "innerError", "type": "InternalError"},
    }

    def __init__(self, *, code, message: str, target: str = None, details=None, inner_error=None, **kwargs) -> None:
        super(PersonalizerError, self).__init__(**kwargs)
        self.code = code
        self.message = message
        self.target = target
        self.details = details
        self.inner_error = inner_error
