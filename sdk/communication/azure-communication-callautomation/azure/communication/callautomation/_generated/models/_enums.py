# coding=utf-8
# --------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is regenerated.
# --------------------------------------------------------------------------

from enum import Enum
from azure.core import CaseInsensitiveEnumMeta


class AudioFormat(str, Enum, metaclass=CaseInsensitiveEnumMeta):
    """Specifies the audio format used for encoding, including sample rate and channel type."""

    PCM16_K_MONO = "Pcm16KMono"
    """Pcm16KMono"""
    PCM24_K_MONO = "Pcm24KMono"
    """Pcm24KMono"""


class CallConnectionState(str, Enum, metaclass=CaseInsensitiveEnumMeta):
    """The state of the call connection."""

    UNKNOWN = "unknown"
    CONNECTING = "connecting"
    CONNECTED = "connected"
    TRANSFERRING = "transferring"
    TRANSFER_ACCEPTED = "transferAccepted"
    DISCONNECTING = "disconnecting"
    DISCONNECTED = "disconnected"


class CallLocatorKind(str, Enum, metaclass=CaseInsensitiveEnumMeta):
    """The call locator kind."""

    GROUP_CALL_LOCATOR = "groupCallLocator"
    SERVER_CALL_LOCATOR = "serverCallLocator"
    ROOM_CALL_LOCATOR = "roomCallLocator"


class CallRejectReason(str, Enum, metaclass=CaseInsensitiveEnumMeta):
    """The rejection reason."""

    NONE = "none"
    BUSY = "busy"
    FORBIDDEN = "forbidden"


class CallSessionEndReason(str, Enum, metaclass=CaseInsensitiveEnumMeta):
    """CallSessionEndReason."""

    SESSION_STILL_ONGOING = "sessionStillOngoing"
    CALL_ENDED = "callEnded"
    INITIATOR_LEFT = "initiatorLeft"
    HANDED_OVER_OR_TRANSFERED = "handedOverOrTransfered"
    MAXIMUM_SESSION_TIME_REACHED = "maximumSessionTimeReached"
    CALL_START_TIMEOUT = "callStartTimeout"
    MEDIA_TIMEOUT = "mediaTimeout"
    AUDIO_STREAM_FAILURE = "audioStreamFailure"
    ALL_INSTANCES_BUSY = "allInstancesBusy"
    TEAMS_TOKEN_CONVERSION_FAILED = "teamsTokenConversionFailed"
    REPORT_CALL_STATE_FAILED = "reportCallStateFailed"
    REPORT_CALL_STATE_FAILED_AND_SESSION_MUST_BE_DISCARDED = "reportCallStateFailedAndSessionMustBeDiscarded"
    COULD_NOT_REJOIN_CALL = "couldNotRejoinCall"
    INVALID_BOT_DATA = "invalidBotData"
    COULD_NOT_START = "couldNotStart"
    APP_HOSTED_MEDIA_FAILURE_OUTCOME_WITH_ERROR = "appHostedMediaFailureOutcomeWithError"
    APP_HOSTED_MEDIA_FAILURE_OUTCOME_GRACEFULLY = "appHostedMediaFailureOutcomeGracefully"
    HANDED_OVER_DUE_TO_MEDIA_TIMEOUT = "handedOverDueToMediaTimeout"
    HANDED_OVER_DUE_TO_AUDIO_STREAM_FAILURE = "handedOverDueToAudioStreamFailure"
    SPEECH_RECOGNITION_SESSION_NON_RETRIABLE_ERROR = "speechRecognitionSessionNonRetriableError"
    SPEECH_RECOGNITION_SESSION_RETRIABLE_ERROR_MAX_RETRY_COUNT_REACHED = (
        "speechRecognitionSessionRetriableErrorMaxRetryCountReached"
    )
    HANDED_OVER_DUE_TO_CHUNK_CREATION_FAILURE = "handedOverDueToChunkCreationFailure"
    CHUNK_CREATION_FAILED = "chunkCreationFailed"
    HANDED_OVER_DUE_TO_PROCESSING_TIMEOUT = "handedOverDueToProcessingTimeout"
    PROCESSING_TIMEOUT = "processingTimeout"
    TRANSCRIPT_OBJECT_CREATION_FAILED = "transcriptObjectCreationFailed"


class ChunkEndReason(str, Enum, metaclass=CaseInsensitiveEnumMeta):
    """Reason this chunk ended."""

    CHUNK_IS_BEING_RECORDED = "chunkIsBeingRecorded"
    SESSION_ENDED = "sessionEnded"
    CHUNK_MAXIMUM_SIZE_EXCEEDED = "chunkMaximumSizeExceeded"
    CHUNK_MAXIMUM_TIME_EXCEEDED = "chunkMaximumTimeExceeded"
    CHUNK_UPLOAD_FAILURE = "chunkUploadFailure"


class CommunicationCloudEnvironmentModel(str, Enum, metaclass=CaseInsensitiveEnumMeta):
    """The cloud that the identifier belongs to."""

    PUBLIC = "public"
    DOD = "dod"
    GCCH = "gcch"


class CommunicationIdentifierModelKind(str, Enum, metaclass=CaseInsensitiveEnumMeta):
    """The identifier kind, for example 'communicationUser' or 'phoneNumber'."""

    UNKNOWN = "unknown"
    COMMUNICATION_USER = "communicationUser"
    PHONE_NUMBER = "phoneNumber"
    MICROSOFT_TEAMS_USER = "microsoftTeamsUser"
    MICROSOFT_TEAMS_APP = "microsoftTeamsApp"
    TEAMS_EXTENSION_USER = "teamsExtensionUser"


class DialogInputType(str, Enum, metaclass=CaseInsensitiveEnumMeta):
    """Determines the type of the dialog."""

    POWER_VIRTUAL_AGENTS = "powerVirtualAgents"
    AZURE_OPEN_AI = "azureOpenAI"


class DtmfTone(str, Enum, metaclass=CaseInsensitiveEnumMeta):
    """DtmfTone."""

    ZERO = "zero"
    ONE = "one"
    TWO = "two"
    THREE = "three"
    FOUR = "four"
    FIVE = "five"
    SIX = "six"
    SEVEN = "seven"
    EIGHT = "eight"
    NINE = "nine"
    A = "a"
    B = "b"
    C = "c"
    D = "d"
    POUND = "pound"
    ASTERISK = "asterisk"


class MediaStreamingAudioChannelType(str, Enum, metaclass=CaseInsensitiveEnumMeta):
    """Audio channel type to stream, eg. unmixed audio, mixed audio."""

    MIXED = "mixed"
    UNMIXED = "unmixed"


class MediaStreamingContentType(str, Enum, metaclass=CaseInsensitiveEnumMeta):
    """Content type to stream, eg. audio."""

    AUDIO = "audio"


class MediaStreamingStatus(str, Enum, metaclass=CaseInsensitiveEnumMeta):
    """MediaStreamingStatus."""

    MEDIA_STREAMING_STARTED = "mediaStreamingStarted"
    MEDIA_STREAMING_FAILED = "mediaStreamingFailed"
    MEDIA_STREAMING_STOPPED = "mediaStreamingStopped"
    UNSPECIFIED_ERROR = "unspecifiedError"


class MediaStreamingStatusDetails(str, Enum, metaclass=CaseInsensitiveEnumMeta):
    """MediaStreamingStatusDetails."""

    SUBSCRIPTION_STARTED = "subscriptionStarted"
    STREAM_CONNECTION_REESTABLISHED = "streamConnectionReestablished"
    STREAM_CONNECTION_UNSUCCESSFUL = "streamConnectionUnsuccessful"
    STREAM_URL_MISSING = "streamUrlMissing"
    SERVICE_SHUTDOWN = "serviceShutdown"
    STREAM_CONNECTION_INTERRUPTED = "streamConnectionInterrupted"
    SPEECH_SERVICES_CONNECTION_ERROR = "speechServicesConnectionError"
    SUBSCRIPTION_STOPPED = "subscriptionStopped"
    UNSPECIFIED_ERROR = "unspecifiedError"
    AUTHENTICATION_FAILURE = "authenticationFailure"
    BAD_REQUEST = "badRequest"
    TOO_MANY_REQUESTS = "tooManyRequests"
    FORBIDDEN = "forbidden"
    SERVICE_TIMEOUT = "serviceTimeout"
    INITIAL_WEB_SOCKET_CONNECTION_FAILED = "initialWebSocketConnectionFailed"


class MediaStreamingSubscriptionState(str, Enum, metaclass=CaseInsensitiveEnumMeta):
    """Media streaming subscription state."""

    DISABLED = "disabled"
    INACTIVE = "inactive"
    ACTIVE = "active"


class MediaStreamingTransportType(str, Enum, metaclass=CaseInsensitiveEnumMeta):
    """The type of transport to be used for media streaming, eg. Websocket."""

    WEBSOCKET = "websocket"


class PlaySourceType(str, Enum, metaclass=CaseInsensitiveEnumMeta):
    """Defines the type of the play source."""

    FILE = "file"
    TEXT = "text"
    SSML = "ssml"


class RecognitionType(str, Enum, metaclass=CaseInsensitiveEnumMeta):
    """Determines the sub-type of the recognize operation.
    In case of cancel operation the this field is not set and is returned empty.
    """

    DTMF = "dtmf"
    SPEECH = "speech"
    CHOICES = "choices"


class RecognizeInputType(str, Enum, metaclass=CaseInsensitiveEnumMeta):
    """Determines the type of the recognition."""

    DTMF = "dtmf"
    SPEECH = "speech"
    SPEECH_OR_DTMF = "speechOrDtmf"
    CHOICES = "choices"


class RecordingChannel(str, Enum, metaclass=CaseInsensitiveEnumMeta):
    """The channel type of call recording."""

    MIXED = "mixed"
    UNMIXED = "unmixed"


class RecordingContent(str, Enum, metaclass=CaseInsensitiveEnumMeta):
    """The content type of call recording."""

    AUDIO = "audio"
    AUDIO_VIDEO = "audioVideo"


class RecordingFormat(str, Enum, metaclass=CaseInsensitiveEnumMeta):
    """The format type of call recording."""

    WAV = "wav"
    MP3 = "mp3"
    MP4 = "mp4"


class RecordingKind(str, Enum, metaclass=CaseInsensitiveEnumMeta):
    """RecordingKind."""

    AZURE_COMMUNICATION_SERVICES = "AzureCommunicationServices"
    """Recording initiated by Azure Communication Services"""
    TEAMS = "Teams"
    """Recording initiated by Teams user"""
    TEAMS_COMPLIANCE = "TeamsCompliance"
    """Recording initiated by Teams compliance policy"""


class RecordingState(str, Enum, metaclass=CaseInsensitiveEnumMeta):
    """RecordingState."""

    ACTIVE = "active"
    INACTIVE = "inactive"


class RecordingStorageKind(str, Enum, metaclass=CaseInsensitiveEnumMeta):
    """Defines the kind of external storage."""

    AZURE_COMMUNICATION_SERVICES = "AzureCommunicationServices"
    """Storage managed by Azure Communication Services"""
    AZURE_BLOB_STORAGE = "AzureBlobStorage"
    """Storage managed by provided Azure blob"""


class TranscriptionResultType(str, Enum, metaclass=CaseInsensitiveEnumMeta):
    """TranscriptionResultType."""

    FINAL = "final"
    INTERMEDIATE = "intermediate"


class TranscriptionStatus(str, Enum, metaclass=CaseInsensitiveEnumMeta):
    """TranscriptionStatus."""

    TRANSCRIPTION_STARTED = "transcriptionStarted"
    TRANSCRIPTION_FAILED = "transcriptionFailed"
    TRANSCRIPTION_RESUMED = "transcriptionResumed"
    TRANSCRIPTION_UPDATED = "transcriptionUpdated"
    TRANSCRIPTION_STOPPED = "transcriptionStopped"
    UNSPECIFIED_ERROR = "unspecifiedError"


class TranscriptionStatusDetails(str, Enum, metaclass=CaseInsensitiveEnumMeta):
    """TranscriptionStatusDetails."""

    SUBSCRIPTION_STARTED = "subscriptionStarted"
    STREAM_CONNECTION_REESTABLISHED = "streamConnectionReestablished"
    STREAM_CONNECTION_UNSUCCESSFUL = "streamConnectionUnsuccessful"
    STREAM_URL_MISSING = "streamUrlMissing"
    SERVICE_SHUTDOWN = "serviceShutdown"
    STREAM_CONNECTION_INTERRUPTED = "streamConnectionInterrupted"
    SPEECH_SERVICES_CONNECTION_ERROR = "speechServicesConnectionError"
    SUBSCRIPTION_STOPPED = "subscriptionStopped"
    UNSPECIFIED_ERROR = "unspecifiedError"
    AUTHENTICATION_FAILURE = "authenticationFailure"
    BAD_REQUEST = "badRequest"
    TOO_MANY_REQUESTS = "tooManyRequests"
    FORBIDDEN = "forbidden"
    SERVICE_TIMEOUT = "serviceTimeout"
    TRANSCRIPTION_LOCALE_UPDATED = "transcriptionLocaleUpdated"


class TranscriptionSubscriptionState(str, Enum, metaclass=CaseInsensitiveEnumMeta):
    """Transcription subscription state."""

    DISABLED = "disabled"
    INACTIVE = "inactive"
    ACTIVE = "active"


class TranscriptionTransportType(str, Enum, metaclass=CaseInsensitiveEnumMeta):
    """The type of transport to be used for live transcription, eg. Websocket."""

    WEBSOCKET = "websocket"


class VoiceKind(str, Enum, metaclass=CaseInsensitiveEnumMeta):
    """Voice kind type."""

    MALE = "male"
    FEMALE = "female"
