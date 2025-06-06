# pylint: disable=too-many-lines
# --------------------------------------------------------------------------
#
# Copyright (c) Microsoft Corporation. All rights reserved.
#
# The MIT License (MIT)
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the ""Software""), to
# deal in the Software without restriction, including without limitation the
# rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
# sell copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
# IN THE SOFTWARE.
#
# --------------------------------------------------------------------------

# pylint: skip-file
# pyright: reportUnnecessaryTypeIgnoreComment=false

from base64 import b64decode, b64encode
import calendar
import datetime
import decimal
import email
from enum import Enum
import json
import logging
import re
import sys
import codecs
from typing import (
    Dict,
    Any,
    cast,
    Optional,
    Union,
    AnyStr,
    IO,
    Mapping,
    Callable,
    TypeVar,
    MutableMapping,
    Type,
    List,
    Mapping,
)

try:
    from urllib import quote  # type: ignore
except ImportError:
    from urllib.parse import quote
import xml.etree.ElementTree as ET

import isodate  # type: ignore

from azure.core.exceptions import (
    DeserializationError,
    SerializationError,
    raise_with_traceback,
)
from azure.core.serialization import NULL as AzureCoreNull

_BOM = codecs.BOM_UTF8.decode(encoding="utf-8")

ModelType = TypeVar("ModelType", bound="Model")
JSON = MutableMapping[str, Any]


class RawDeserializer:
    # Accept "text" because we're open minded people...
    JSON_REGEXP = re.compile(r"^(application|text)/([a-z+.]+\+)?json$")

    # Name used in context
    CONTEXT_NAME = "deserialized_data"

    @classmethod
    def deserialize_from_text(cls, data: Optional[Union[AnyStr, IO]], content_type: Optional[str] = None) -> Any:
        """Decode data according to content-type.

        Accept a stream of data as well, but will be load at once in memory for now.

        If no content-type, will return the string version (not bytes, not stream)

        :param data: Input, could be bytes or stream (will be decoded with UTF8) or text
        :type data: str or bytes or IO
        :param str content_type: The content type.
        """
        if hasattr(data, "read"):
            # Assume a stream
            data = cast(IO, data).read()

        if isinstance(data, bytes):
            data_as_str = data.decode(encoding="utf-8-sig")
        else:
            # Explain to mypy the correct type.
            data_as_str = cast(str, data)

            # Remove Byte Order Mark if present in string
            data_as_str = data_as_str.lstrip(_BOM)

        if content_type is None:
            return data

        if cls.JSON_REGEXP.match(content_type):
            try:
                return json.loads(data_as_str)
            except ValueError as err:
                raise DeserializationError("JSON is invalid: {}".format(err), err)
        elif "xml" in (content_type or []):
            try:
                try:
                    if isinstance(data, unicode):  # type: ignore
                        # If I'm Python 2.7 and unicode XML will scream if I try a "fromstring" on unicode string
                        data_as_str = data_as_str.encode(encoding="utf-8")  # type: ignore
                except NameError:
                    pass

                return ET.fromstring(data_as_str)  # nosec
            except ET.ParseError:
                # It might be because the server has an issue, and returned JSON with
                # content-type XML....
                # So let's try a JSON load, and if it's still broken
                # let's flow the initial exception
                def _json_attemp(data):
                    try:
                        return True, json.loads(data)
                    except ValueError:
                        return False, None  # Don't care about this one

                success, json_result = _json_attemp(data)
                if success:
                    return json_result
                # If i'm here, it's not JSON, it's not XML, let's scream
                # and raise the last context in this block (the XML exception)
                # The function hack is because Py2.7 messes up with exception
                # context otherwise.
                _LOGGER.critical("Wasn't XML not JSON, failing")
                raise_with_traceback(DeserializationError, "XML is invalid")
        raise DeserializationError("Cannot deserialize content-type: {}".format(content_type))

    @classmethod
    def deserialize_from_http_generics(cls, body_bytes: Optional[Union[AnyStr, IO]], headers: Mapping) -> Any:
        """Deserialize from HTTP response.

        Use bytes and headers to NOT use any requests/aiohttp or whatever
        specific implementation.
        Headers will tested for "content-type"
        """
        # Try to use content-type from headers if available
        content_type = None
        if "content-type" in headers:
            content_type = headers["content-type"].split(";")[0].strip().lower()
        # Ouch, this server did not declare what it sent...
        # Let's guess it's JSON...
        # Also, since Autorest was considering that an empty body was a valid JSON,
        # need that test as well....
        else:
            content_type = "application/json"

        if body_bytes:
            return cls.deserialize_from_text(body_bytes, content_type)
        return None


try:
    basestring  # type: ignore
    unicode_str = unicode  # type: ignore
except NameError:
    basestring = str
    unicode_str = str

_LOGGER = logging.getLogger(__name__)

try:
    _long_type = long  # type: ignore
except NameError:
    _long_type = int


class UTC(datetime.tzinfo):
    """Time Zone info for handling UTC"""

    def utcoffset(self, dt):
        """UTF offset for UTC is 0."""
        return datetime.timedelta(0)

    def tzname(self, dt):
        """Timestamp representation."""
        return "Z"

    def dst(self, dt):
        """No daylight saving for UTC."""
        return datetime.timedelta(hours=1)


try:
    from datetime import timezone as _FixedOffset  # type: ignore
except ImportError:  # Python 2.7

    class _FixedOffset(datetime.tzinfo):  # type: ignore
        """Fixed offset in minutes east from UTC.
        Copy/pasted from Python doc
        :param datetime.timedelta offset: offset in timedelta format
        """

        def __init__(self, offset):
            self.__offset = offset

        def utcoffset(self, dt):
            return self.__offset

        def tzname(self, dt):
            return str(self.__offset.total_seconds() / 3600)

        def __repr__(self):
            return "<FixedOffset {}>".format(self.tzname(None))

        def dst(self, dt):
            return datetime.timedelta(0)

        def __getinitargs__(self):
            return (self.__offset,)


try:
    from datetime import timezone

    TZ_UTC = timezone.utc
except ImportError:
    TZ_UTC = UTC()  # type: ignore

_FLATTEN = re.compile(r"(?<!\\)\.")


def attribute_transformer(key, attr_desc, value):
    """A key transformer that returns the Python attribute.

    :param str key: The attribute name
    :param dict attr_desc: The attribute metadata
    :param object value: The value
    :returns: A key using attribute name
    """
    return (key, value)


def full_restapi_key_transformer(key, attr_desc, value):
    """A key transformer that returns the full RestAPI key path.

    :param str _: The attribute name
    :param dict attr_desc: The attribute metadata
    :param object value: The value
    :returns: A list of keys using RestAPI syntax.
    """
    keys = _FLATTEN.split(attr_desc["key"])
    return ([_decode_attribute_map_key(k) for k in keys], value)


def last_restapi_key_transformer(key, attr_desc, value):
    """A key transformer that returns the last RestAPI key.

    :param str key: The attribute name
    :param dict attr_desc: The attribute metadata
    :param object value: The value
    :returns: The last RestAPI key.
    """
    key, value = full_restapi_key_transformer(key, attr_desc, value)
    return (key[-1], value)


def _create_xml_node(tag, prefix=None, ns=None):
    """Create a XML node."""
    if prefix and ns:
        ET.register_namespace(prefix, ns)
    if ns:
        return ET.Element("{" + ns + "}" + tag)
    else:
        return ET.Element(tag)


class Model(object):
    """Mixin for all client request body/response body models to support
    serialization and deserialization.
    """

    _subtype_map: Dict[str, Dict[str, Any]] = {}
    _attribute_map: Dict[str, Dict[str, Any]] = {}
    _validation: Dict[str, Dict[str, Any]] = {}

    def __init__(self, **kwargs: Any) -> None:
        self.additional_properties: Dict[str, Any] = {}
        for k in kwargs:
            if k not in self._attribute_map:
                _LOGGER.warning(
                    "%s is not a known attribute of class %s and will be ignored",
                    k,
                    self.__class__,
                )
            elif k in self._validation and self._validation[k].get("readonly", False):
                _LOGGER.warning(
                    "Readonly attribute %s will be ignored in class %s",
                    k,
                    self.__class__,
                )
            else:
                setattr(self, k, kwargs[k])

    def __eq__(self, other: Any) -> bool:
        """Compare objects by comparing all attributes."""
        if isinstance(other, self.__class__):
            return self.__dict__ == other.__dict__
        return False

    def __ne__(self, other: Any) -> bool:
        """Compare objects by comparing all attributes."""
        return not self.__eq__(other)

    def __str__(self) -> str:
        return str(self.__dict__)

    @classmethod
    def enable_additional_properties_sending(cls) -> None:
        cls._attribute_map["additional_properties"] = {"key": "", "type": "{object}"}

    @classmethod
    def is_xml_model(cls) -> bool:
        try:
            cls._xml_map  # type: ignore
        except AttributeError:
            return False
        return True

    @classmethod
    def _create_xml_node(cls):
        """Create XML node."""
        try:
            xml_map = cls._xml_map  # type: ignore
        except AttributeError:
            xml_map = {}

        return _create_xml_node(
            xml_map.get("name", cls.__name__),
            xml_map.get("prefix", None),
            xml_map.get("ns", None),
        )

    def serialize(self, keep_readonly: bool = False, **kwargs: Any) -> JSON:
        """Return the JSON that would be sent to azure from this model.

        This is an alias to `as_dict(full_restapi_key_transformer, keep_readonly=False)`.

        If you want XML serialization, you can pass the kwargs is_xml=True.

        :param bool keep_readonly: If you want to serialize the readonly attributes
        :returns: A dict JSON compatible object
        :rtype: dict
        """
        serializer = Serializer(self._infer_class_models())
        return serializer._serialize(self, keep_readonly=keep_readonly, **kwargs)

    def as_dict(
        self,
        keep_readonly: bool = True,
        key_transformer: Callable[[str, Dict[str, Any], Any], Any] = attribute_transformer,
        **kwargs: Any
    ) -> JSON:
        """Return a dict that can be serialized using json.dump.

        Advanced usage might optionally use a callback as parameter:

        .. code::python

            def my_key_transformer(key, attr_desc, value):
                return key

        Key is the attribute name used in Python. Attr_desc
        is a dict of metadata. Currently contains 'type' with the
        msrest type and 'key' with the RestAPI encoded key.
        Value is the current value in this object.

        The string returned will be used to serialize the key.
        If the return type is a list, this is considered hierarchical
        result dict.

        See the three examples in this file:

        - attribute_transformer
        - full_restapi_key_transformer
        - last_restapi_key_transformer

        If you want XML serialization, you can pass the kwargs is_xml=True.

        :param function key_transformer: A key transformer function.
        :returns: A dict JSON compatible object
        :rtype: dict
        """
        serializer = Serializer(self._infer_class_models())
        return serializer._serialize(self, key_transformer=key_transformer, keep_readonly=keep_readonly, **kwargs)

    @classmethod
    def _infer_class_models(cls):
        try:
            str_models = cls.__module__.rsplit(".", 1)[0]
            models = sys.modules[str_models]
            client_models = {k: v for k, v in models.__dict__.items() if isinstance(v, type)}
            if cls.__name__ not in client_models:
                raise ValueError("Not Autorest generated code")
        except Exception:
            # Assume it's not Autorest generated (tests?). Add ourselves as dependencies.
            client_models = {cls.__name__: cls}
        return client_models

    @classmethod
    def deserialize(cls: Type[ModelType], data: Any, content_type: Optional[str] = None) -> ModelType:
        """Parse a str using the RestAPI syntax and return a model.

        :param str data: A str using RestAPI structure. JSON by default.
        :param str content_type: JSON by default, set application/xml if XML.
        :returns: An instance of this model
        :raises: DeserializationError if something went wrong
        """
        deserializer = Deserializer(cls._infer_class_models())
        return deserializer(cls.__name__, data, content_type=content_type)

    @classmethod
    def from_dict(
        cls: Type[ModelType],
        data: Any,
        key_extractors: Optional[Callable[[str, Dict[str, Any], Any], Any]] = None,
        content_type: Optional[str] = None,
    ) -> ModelType:
        """Parse a dict using given key extractor return a model.

        By default consider key
        extractors (rest_key_case_insensitive_extractor, attribute_key_case_insensitive_extractor
        and last_rest_key_case_insensitive_extractor)

        :param dict data: A dict using RestAPI structure
        :param str content_type: JSON by default, set application/xml if XML.
        :returns: An instance of this model
        :raises: DeserializationError if something went wrong
        """
        deserializer = Deserializer(cls._infer_class_models())
        deserializer.key_extractors = (  # type: ignore
            [  # type: ignore
                attribute_key_case_insensitive_extractor,
                rest_key_case_insensitive_extractor,
                last_rest_key_case_insensitive_extractor,
            ]
            if key_extractors is None
            else key_extractors
        )
        return deserializer(cls.__name__, data, content_type=content_type)

    @classmethod
    def _flatten_subtype(cls, key, objects):
        if "_subtype_map" not in cls.__dict__:
            return {}
        result = dict(cls._subtype_map[key])
        for valuetype in cls._subtype_map[key].values():
            result.update(objects[valuetype]._flatten_subtype(key, objects))
        return result

    @classmethod
    def _classify(cls, response, objects):
        """Check the class _subtype_map for any child classes.
        We want to ignore any inherited _subtype_maps.
        Remove the polymorphic key from the initial data.
        """
        for subtype_key in cls.__dict__.get("_subtype_map", {}).keys():
            subtype_value = None

            if not isinstance(response, ET.Element):
                rest_api_response_key = cls._get_rest_key_parts(subtype_key)[-1]
                subtype_value = response.pop(rest_api_response_key, None) or response.pop(subtype_key, None)
            else:
                subtype_value = xml_key_extractor(subtype_key, cls._attribute_map[subtype_key], response)
            if subtype_value:
                # Try to match base class. Can be class name only
                # (bug to fix in Autorest to support x-ms-discriminator-name)
                if cls.__name__ == subtype_value:
                    return cls
                flatten_mapping_type = cls._flatten_subtype(subtype_key, objects)
                try:
                    return objects[flatten_mapping_type[subtype_value]]  # type: ignore
                except KeyError:
                    _LOGGER.warning(
                        "Subtype value %s has no mapping, use base class %s.",
                        subtype_value,
                        cls.__name__,
                    )
                    break
            else:
                _LOGGER.warning(
                    "Discriminator %s is absent or null, use base class %s.",
                    subtype_key,
                    cls.__name__,
                )
                break
        return cls

    @classmethod
    def _get_rest_key_parts(cls, attr_key):
        """Get the RestAPI key of this attr, split it and decode part
        :param str attr_key: Attribute key must be in attribute_map.
        :returns: A list of RestAPI part
        :rtype: list
        """
        rest_split_key = _FLATTEN.split(cls._attribute_map[attr_key]["key"])
        return [_decode_attribute_map_key(key_part) for key_part in rest_split_key]


def _decode_attribute_map_key(key):
    """This decode a key in an _attribute_map to the actual key we want to look at
    inside the received data.

    :param str key: A key string from the generated code
    """
    return key.replace("\\.", ".")


class Serializer(object):
    """Request object model serializer."""

    basic_types = {str: "str", int: "int", bool: "bool", float: "float"}

    _xml_basic_types_serializers = {"bool": lambda x: str(x).lower()}
    days = {0: "Mon", 1: "Tue", 2: "Wed", 3: "Thu", 4: "Fri", 5: "Sat", 6: "Sun"}
    months = {
        1: "Jan",
        2: "Feb",
        3: "Mar",
        4: "Apr",
        5: "May",
        6: "Jun",
        7: "Jul",
        8: "Aug",
        9: "Sep",
        10: "Oct",
        11: "Nov",
        12: "Dec",
    }
    validation = {
        "min_length": lambda x, y: len(x) < y,
        "max_length": lambda x, y: len(x) > y,
        "minimum": lambda x, y: x < y,
        "maximum": lambda x, y: x > y,
        "minimum_ex": lambda x, y: x <= y,
        "maximum_ex": lambda x, y: x >= y,
        "min_items": lambda x, y: len(x) < y,
        "max_items": lambda x, y: len(x) > y,
        "pattern": lambda x, y: not re.match(y, x, re.UNICODE),
        "unique": lambda x, y: len(x) != len(set(x)),
        "multiple": lambda x, y: x % y != 0,
    }

    def __init__(self, classes: Optional[Mapping[str, Type[ModelType]]] = None):
        self.serialize_type = {
            "iso-8601": Serializer.serialize_iso,
            "rfc-1123": Serializer.serialize_rfc,
            "unix-time": Serializer.serialize_unix,
            "duration": Serializer.serialize_duration,
            "date": Serializer.serialize_date,
            "time": Serializer.serialize_time,
            "decimal": Serializer.serialize_decimal,
            "long": Serializer.serialize_long,
            "bytearray": Serializer.serialize_bytearray,
            "base64": Serializer.serialize_base64,
            "object": self.serialize_object,
            "[]": self.serialize_iter,
            "{}": self.serialize_dict,
        }
        self.dependencies: Dict[str, Type[ModelType]] = dict(classes) if classes else {}
        self.key_transformer = full_restapi_key_transformer
        self.client_side_validation = True

    def _serialize(self, target_obj, data_type=None, **kwargs):
        """Serialize data into a string according to type.

        :param target_obj: The data to be serialized.
        :param str data_type: The type to be serialized from.
        :rtype: str, dict
        :raises: SerializationError if serialization fails.
        """
        key_transformer = kwargs.get("key_transformer", self.key_transformer)
        keep_readonly = kwargs.get("keep_readonly", False)
        if target_obj is None:
            return None

        attr_name = None
        class_name = target_obj.__class__.__name__

        if data_type:
            return self.serialize_data(target_obj, data_type, **kwargs)

        if not hasattr(target_obj, "_attribute_map"):
            data_type = type(target_obj).__name__
            if data_type in self.basic_types.values():
                return self.serialize_data(target_obj, data_type, **kwargs)

        # Force "is_xml" kwargs if we detect a XML model
        try:
            is_xml_model_serialization = kwargs["is_xml"]
        except KeyError:
            is_xml_model_serialization = kwargs.setdefault("is_xml", target_obj.is_xml_model())

        serialized = {}
        if is_xml_model_serialization:
            serialized = target_obj._create_xml_node()
        try:
            attributes = target_obj._attribute_map
            for attr, attr_desc in attributes.items():
                attr_name = attr
                if not keep_readonly and target_obj._validation.get(attr_name, {}).get("readonly", False):
                    continue

                if attr_name == "additional_properties" and attr_desc["key"] == "":
                    if target_obj.additional_properties is not None:
                        serialized.update(target_obj.additional_properties)
                    continue
                try:
                    orig_attr = getattr(target_obj, attr)
                    if is_xml_model_serialization:
                        pass  # Don't provide "transformer" for XML for now. Keep "orig_attr"
                    else:  # JSON
                        keys, orig_attr = key_transformer(attr, attr_desc.copy(), orig_attr)
                        keys = keys if isinstance(keys, list) else [keys]

                    kwargs["serialization_ctxt"] = attr_desc
                    new_attr = self.serialize_data(orig_attr, attr_desc["type"], **kwargs)

                    if is_xml_model_serialization:
                        xml_desc = attr_desc.get("xml", {})
                        xml_name = xml_desc.get("name", attr_desc["key"])
                        xml_prefix = xml_desc.get("prefix", None)
                        xml_ns = xml_desc.get("ns", None)
                        if xml_desc.get("attr", False):
                            if xml_ns:
                                ET.register_namespace(xml_prefix, xml_ns)
                                xml_name = "{{{}}}{}".format(xml_ns, xml_name)
                            serialized.set(xml_name, new_attr)  # type: ignore
                            continue
                        if xml_desc.get("text", False):
                            serialized.text = new_attr  # type: ignore
                            continue
                        if isinstance(new_attr, list):
                            serialized.extend(new_attr)  # type: ignore
                        elif isinstance(new_attr, ET.Element):
                            # If the down XML has no XML/Name, we MUST replace the tag with the local tag. But keeping the namespaces.
                            if "name" not in getattr(orig_attr, "_xml_map", {}):
                                splitted_tag = new_attr.tag.split("}")
                                if len(splitted_tag) == 2:  # Namespace
                                    new_attr.tag = "}".join([splitted_tag[0], xml_name])
                                else:
                                    new_attr.tag = xml_name
                            serialized.append(new_attr)  # type: ignore
                        else:  # That's a basic type
                            # Integrate namespace if necessary
                            local_node = _create_xml_node(xml_name, xml_prefix, xml_ns)
                            local_node.text = unicode_str(new_attr)
                            serialized.append(local_node)  # type: ignore
                    else:  # JSON
                        for k in reversed(keys):  # type: ignore
                            new_attr = {k: new_attr}

                        _new_attr = new_attr
                        _serialized = serialized
                        for k in keys:  # type: ignore
                            if k not in _serialized:
                                _serialized.update(_new_attr)  # type: ignore
                            _new_attr = _new_attr[k]  # type: ignore
                            _serialized = _serialized[k]
                except ValueError:
                    continue

        except (AttributeError, KeyError, TypeError) as err:
            msg = "Attribute {} in object {} cannot be serialized.\n{}".format(attr_name, class_name, str(target_obj))
            raise_with_traceback(SerializationError, msg, err)
        else:
            return serialized

    def body(self, data, data_type, **kwargs):
        """Serialize data intended for a request body.

        :param data: The data to be serialized.
        :param str data_type: The type to be serialized from.
        :rtype: dict
        :raises: SerializationError if serialization fails.
        :raises: ValueError if data is None
        """

        # Just in case this is a dict
        internal_data_type_str = data_type.strip("[]{}")
        internal_data_type = self.dependencies.get(internal_data_type_str, None)
        try:
            is_xml_model_serialization = kwargs["is_xml"]
        except KeyError:
            if internal_data_type and issubclass(internal_data_type, Model):
                is_xml_model_serialization = kwargs.setdefault("is_xml", internal_data_type.is_xml_model())
            else:
                is_xml_model_serialization = False
        if internal_data_type and not isinstance(internal_data_type, Enum):
            try:
                deserializer = Deserializer(self.dependencies)
                # Since it's on serialization, it's almost sure that format is not JSON REST
                # We're not able to deal with additional properties for now.
                deserializer.additional_properties_detection = False
                if is_xml_model_serialization:
                    deserializer.key_extractors = [  # type: ignore
                        attribute_key_case_insensitive_extractor,
                    ]
                else:
                    deserializer.key_extractors = [
                        rest_key_case_insensitive_extractor,
                        attribute_key_case_insensitive_extractor,
                        last_rest_key_case_insensitive_extractor,
                    ]
                data = deserializer._deserialize(data_type, data)
            except DeserializationError as err:
                raise_with_traceback(SerializationError, "Unable to build a model: " + str(err), err)

        return self._serialize(data, data_type, **kwargs)

    def url(self, name, data, data_type, **kwargs):
        """Serialize data intended for a URL path.

        :param data: The data to be serialized.
        :param str data_type: The type to be serialized from.
        :rtype: str
        :raises: TypeError if serialization fails.
        :raises: ValueError if data is None
        """
        try:
            output = self.serialize_data(data, data_type, **kwargs)
            if data_type == "bool":
                output = json.dumps(output)

            if kwargs.get("skip_quote") is True:
                output = str(output)
            else:
                output = quote(str(output), safe="")
        except SerializationError:
            raise TypeError("{} must be type {}.".format(name, data_type))
        else:
            return output

    def query(self, name, data, data_type, **kwargs):
        """Serialize data intended for a URL query.

        :param data: The data to be serialized.
        :param str data_type: The type to be serialized from.
        :rtype: str
        :raises: TypeError if serialization fails.
        :raises: ValueError if data is None
        """
        try:
            # Treat the list aside, since we don't want to encode the div separator
            if data_type.startswith("["):
                internal_data_type = data_type[1:-1]
                data = [self.serialize_data(d, internal_data_type, **kwargs) if d is not None else "" for d in data]
                if not kwargs.get("skip_quote", False):
                    data = [quote(str(d), safe="") for d in data]
                return str(self.serialize_iter(data, internal_data_type, **kwargs))

            # Not a list, regular serialization
            output = self.serialize_data(data, data_type, **kwargs)
            if data_type == "bool":
                output = json.dumps(output)
            if kwargs.get("skip_quote") is True:
                output = str(output)
            else:
                output = quote(str(output), safe="")
        except SerializationError:
            raise TypeError("{} must be type {}.".format(name, data_type))
        else:
            return str(output)

    def header(self, name, data, data_type, **kwargs):
        """Serialize data intended for a request header.

        :param data: The data to be serialized.
        :param str data_type: The type to be serialized from.
        :rtype: str
        :raises: TypeError if serialization fails.
        :raises: ValueError if data is None
        """
        try:
            if data_type in ["[str]"]:
                data = ["" if d is None else d for d in data]

            output = self.serialize_data(data, data_type, **kwargs)
            if data_type == "bool":
                output = json.dumps(output)
        except SerializationError:
            raise TypeError("{} must be type {}.".format(name, data_type))
        else:
            return str(output)

    def serialize_data(self, data, data_type, **kwargs):
        """Serialize generic data according to supplied data type.

        :param data: The data to be serialized.
        :param str data_type: The type to be serialized from.
        :param bool required: Whether it's essential that the data not be
         empty or None
        :raises: AttributeError if required data is None.
        :raises: ValueError if data is None
        :raises: SerializationError if serialization fails.
        """
        if data is None:
            raise ValueError("No value for given attribute")

        try:
            if data is AzureCoreNull:
                return None
            if data_type in self.basic_types.values():
                return self.serialize_basic(data, data_type, **kwargs)

            elif data_type in self.serialize_type:
                return self.serialize_type[data_type](data, **kwargs)

            # If dependencies is empty, try with current data class
            # It has to be a subclass of Enum anyway
            enum_type = self.dependencies.get(data_type, data.__class__)
            if issubclass(enum_type, Enum):
                return Serializer.serialize_enum(data, enum_obj=enum_type)

            iter_type = data_type[0] + data_type[-1]
            if iter_type in self.serialize_type:
                return self.serialize_type[iter_type](data, data_type[1:-1], **kwargs)

        except (ValueError, TypeError) as err:
            msg = "Unable to serialize value: {!r} as type: {!r}."
            raise_with_traceback(SerializationError, msg.format(data, data_type), err)
        else:
            return self._serialize(data, **kwargs)

    @classmethod
    def _get_custom_serializers(cls, data_type, **kwargs):
        custom_serializer = kwargs.get("basic_types_serializers", {}).get(data_type)
        if custom_serializer:
            return custom_serializer
        if kwargs.get("is_xml", False):
            return cls._xml_basic_types_serializers.get(data_type)

    @classmethod
    def serialize_basic(cls, data, data_type, **kwargs):
        """Serialize basic builting data type.
        Serializes objects to str, int, float or bool.

        Possible kwargs:
        - basic_types_serializers dict[str, callable] : If set, use the callable as serializer
        - is_xml bool : If set, use xml_basic_types_serializers

        :param data: Object to be serialized.
        :param str data_type: Type of object in the iterable.
        """
        custom_serializer = cls._get_custom_serializers(data_type, **kwargs)
        if custom_serializer:
            return custom_serializer(data)
        if data_type == "str":
            return cls.serialize_unicode(data)
        return eval(data_type)(data)  # nosec

    @classmethod
    def serialize_unicode(cls, data):
        """Special handling for serializing unicode strings in Py2.
        Encode to UTF-8 if unicode, otherwise handle as a str.

        :param data: Object to be serialized.
        :rtype: str
        """
        try:  # If I received an enum, return its value
            return data.value
        except AttributeError:
            pass

        try:
            if isinstance(data, unicode):  # type: ignore
                # Don't change it, JSON and XML ElementTree are totally able
                # to serialize correctly u'' strings
                return data
        except NameError:
            return str(data)
        else:
            return str(data)

    def serialize_iter(self, data, iter_type, div=None, **kwargs):
        """Serialize iterable.

        Supported kwargs:
        - serialization_ctxt dict : The current entry of _attribute_map, or same format.
          serialization_ctxt['type'] should be same as data_type.
        - is_xml bool : If set, serialize as XML

        :param list attr: Object to be serialized.
        :param str iter_type: Type of object in the iterable.
        :param bool required: Whether the objects in the iterable must
         not be None or empty.
        :param str div: If set, this str will be used to combine the elements
         in the iterable into a combined string. Default is 'None'.
        :rtype: list, str
        """
        if isinstance(data, str):
            raise SerializationError("Refuse str type as a valid iter type.")

        serialization_ctxt = kwargs.get("serialization_ctxt", {})
        is_xml = kwargs.get("is_xml", False)

        serialized = []
        for d in data:
            try:
                serialized.append(self.serialize_data(d, iter_type, **kwargs))
            except ValueError:
                serialized.append(None)

        if div:
            serialized = ["" if s is None else str(s) for s in serialized]
            serialized = div.join(serialized)

        if "xml" in serialization_ctxt or is_xml:
            # XML serialization is more complicated
            xml_desc = serialization_ctxt.get("xml", {})
            xml_name = xml_desc.get("name")
            if not xml_name:
                xml_name = serialization_ctxt["key"]

            # Create a wrap node if necessary (use the fact that Element and list have "append")
            is_wrapped = xml_desc.get("wrapped", False)
            node_name = xml_desc.get("itemsName", xml_name)
            if is_wrapped:
                final_result = _create_xml_node(xml_name, xml_desc.get("prefix", None), xml_desc.get("ns", None))
            else:
                final_result = []
            # All list elements to "local_node"
            for el in serialized:
                if isinstance(el, ET.Element):
                    el_node = el
                else:
                    el_node = _create_xml_node(
                        node_name,
                        xml_desc.get("prefix", None),
                        xml_desc.get("ns", None),
                    )
                    if el is not None:  # Otherwise it writes "None" :-p
                        el_node.text = str(el)
                final_result.append(el_node)
            return final_result
        return serialized

    def serialize_dict(self, attr, dict_type, **kwargs):
        """Serialize a dictionary of objects.

        :param dict attr: Object to be serialized.
        :param str dict_type: Type of object in the dictionary.
        :param bool required: Whether the objects in the dictionary must
         not be None or empty.
        :rtype: dict
        """
        serialization_ctxt = kwargs.get("serialization_ctxt", {})
        serialized = {}
        for key, value in attr.items():
            try:
                serialized[self.serialize_unicode(key)] = self.serialize_data(value, dict_type, **kwargs)
            except ValueError:
                serialized[self.serialize_unicode(key)] = None

        if "xml" in serialization_ctxt:
            # XML serialization is more complicated
            xml_desc = serialization_ctxt["xml"]
            xml_name = xml_desc["name"]

            final_result = _create_xml_node(xml_name, xml_desc.get("prefix", None), xml_desc.get("ns", None))
            for key, value in serialized.items():
                ET.SubElement(final_result, key).text = value
            return final_result

        return serialized

    def serialize_object(self, attr, **kwargs):
        """Serialize a generic object.
        This will be handled as a dictionary. If object passed in is not
        a basic type (str, int, float, dict, list) it will simply be
        cast to str.

        :param dict attr: Object to be serialized.
        :rtype: dict or str
        """
        if attr is None:
            return None
        if isinstance(attr, ET.Element):
            return attr
        obj_type = type(attr)
        if obj_type in self.basic_types:
            return self.serialize_basic(attr, self.basic_types[obj_type], **kwargs)
        if obj_type is _long_type:
            return self.serialize_long(attr)
        if obj_type is unicode_str:
            return self.serialize_unicode(attr)
        if obj_type is datetime.datetime:
            return self.serialize_iso(attr)
        if obj_type is datetime.date:
            return self.serialize_date(attr)
        if obj_type is datetime.time:
            return self.serialize_time(attr)
        if obj_type is datetime.timedelta:
            return self.serialize_duration(attr)
        if obj_type is decimal.Decimal:
            return self.serialize_decimal(attr)

        # If it's a model or I know this dependency, serialize as a Model
        elif obj_type in self.dependencies.values() or isinstance(attr, Model):
            return self._serialize(attr)

        if obj_type == dict:
            serialized = {}
            for key, value in attr.items():
                try:
                    serialized[self.serialize_unicode(key)] = self.serialize_object(value, **kwargs)
                except ValueError:
                    serialized[self.serialize_unicode(key)] = None
            return serialized

        if obj_type == list:
            serialized = []
            for obj in attr:
                try:
                    serialized.append(self.serialize_object(obj, **kwargs))
                except ValueError:
                    pass
            return serialized
        return str(attr)

    @staticmethod
    def serialize_enum(attr, enum_obj=None):
        try:
            result = attr.value
        except AttributeError:
            result = attr
        try:
            enum_obj(result)  # type: ignore
            return result
        except ValueError:
            for enum_value in enum_obj:  # type: ignore
                if enum_value.value.lower() == str(attr).lower():
                    return enum_value.value
            error = "{!r} is not valid value for enum {!r}"
            raise SerializationError(error.format(attr, enum_obj))

    @staticmethod
    def serialize_bytearray(attr, **kwargs):
        """Serialize bytearray into base-64 string.

        :param attr: Object to be serialized.
        :rtype: str
        """
        return b64encode(attr).decode()

    @staticmethod
    def serialize_base64(attr, **kwargs):
        """Serialize str into base-64 string.

        :param attr: Object to be serialized.
        :rtype: str
        """
        encoded = b64encode(attr).decode("ascii")
        return encoded.strip("=").replace("+", "-").replace("/", "_")

    @staticmethod
    def serialize_decimal(attr, **kwargs):
        """Serialize Decimal object to float.

        :param attr: Object to be serialized.
        :rtype: float
        """
        return float(attr)

    @staticmethod
    def serialize_long(attr, **kwargs):
        """Serialize long (Py2) or int (Py3).

        :param attr: Object to be serialized.
        :rtype: int/long
        """
        return _long_type(attr)

    @staticmethod
    def serialize_date(attr, **kwargs):
        """Serialize Date object into ISO-8601 formatted string.

        :param Date attr: Object to be serialized.
        :rtype: str
        """
        if isinstance(attr, str):
            attr = isodate.parse_date(attr)
        t = "{:04}-{:02}-{:02}".format(attr.year, attr.month, attr.day)
        return t

    @staticmethod
    def serialize_time(attr, **kwargs):
        """Serialize Time object into ISO-8601 formatted string.

        :param datetime.time attr: Object to be serialized.
        :rtype: str
        """
        if isinstance(attr, str):
            attr = isodate.parse_time(attr)
        t = "{:02}:{:02}:{:02}".format(attr.hour, attr.minute, attr.second)
        if attr.microsecond:
            t += ".{:02}".format(attr.microsecond)
        return t

    @staticmethod
    def serialize_duration(attr, **kwargs):
        """Serialize TimeDelta object into ISO-8601 formatted string.

        :param TimeDelta attr: Object to be serialized.
        :rtype: str
        """
        if isinstance(attr, str):
            attr = isodate.parse_duration(attr)
        return isodate.duration_isoformat(attr)

    @staticmethod
    def serialize_rfc(attr, **kwargs):
        """Serialize Datetime object into RFC-1123 formatted string.

        :param Datetime attr: Object to be serialized.
        :rtype: str
        :raises: TypeError if format invalid.
        """
        try:
            if not attr.tzinfo:
                _LOGGER.warning("Datetime with no tzinfo will be considered UTC.")
            utc = attr.utctimetuple()
        except AttributeError:
            raise TypeError("RFC1123 object must be valid Datetime object.")

        return "{}, {:02} {} {:04} {:02}:{:02}:{:02} GMT".format(
            Serializer.days[utc.tm_wday],
            utc.tm_mday,
            Serializer.months[utc.tm_mon],
            utc.tm_year,
            utc.tm_hour,
            utc.tm_min,
            utc.tm_sec,
        )

    @staticmethod
    def serialize_iso(attr, **kwargs):
        """Serialize Datetime object into ISO-8601 formatted string.

        :param Datetime attr: Object to be serialized.
        :rtype: str
        :raises: SerializationError if format invalid.
        """
        if isinstance(attr, str):
            attr = isodate.parse_datetime(attr)
        try:
            if not attr.tzinfo:
                _LOGGER.warning("Datetime with no tzinfo will be considered UTC.")
            utc = attr.utctimetuple()
            if utc.tm_year > 9999 or utc.tm_year < 1:
                raise OverflowError("Hit max or min date")

            microseconds = str(attr.microsecond).rjust(6, "0").rstrip("0").ljust(3, "0")
            if microseconds:
                microseconds = "." + microseconds
            date = "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}".format(
                utc.tm_year,
                utc.tm_mon,
                utc.tm_mday,
                utc.tm_hour,
                utc.tm_min,
                utc.tm_sec,
            )
            return date + microseconds + "Z"
        except (ValueError, OverflowError) as err:
            msg = "Unable to serialize datetime object."
            raise_with_traceback(SerializationError, msg, err)
        except AttributeError as err:
            msg = "ISO-8601 object must be valid Datetime object."
            raise_with_traceback(TypeError, msg, err)

    @staticmethod
    def serialize_unix(attr, **kwargs):
        """Serialize Datetime object into IntTime format.
        This is represented as seconds.

        :param Datetime attr: Object to be serialized.
        :rtype: int
        :raises: SerializationError if format invalid
        """
        if isinstance(attr, int):
            return attr
        try:
            if not attr.tzinfo:
                _LOGGER.warning("Datetime with no tzinfo will be considered UTC.")
            return int(calendar.timegm(attr.utctimetuple()))
        except AttributeError:
            raise TypeError("Unix time object must be valid Datetime object.")


def rest_key_extractor(attr, attr_desc, data):
    key = attr_desc["key"]
    working_data = data

    while "." in key:
        # Need the cast, as for some reasons "split" is typed as list[str | Any]
        dict_keys = cast(List[str], _FLATTEN.split(key))
        if len(dict_keys) == 1:
            key = _decode_attribute_map_key(dict_keys[0])
            break
        working_key = _decode_attribute_map_key(dict_keys[0])
        working_data = working_data.get(working_key, data)
        if working_data is None:
            # If at any point while following flatten JSON path see None, it means
            # that all properties under are None as well
            # https://github.com/Azure/msrest-for-python/issues/197
            return None
        key = ".".join(dict_keys[1:])

    return working_data.get(key)


def rest_key_case_insensitive_extractor(attr, attr_desc, data):
    key = attr_desc["key"]
    working_data = data

    while "." in key:
        dict_keys = _FLATTEN.split(key)
        if len(dict_keys) == 1:
            key = _decode_attribute_map_key(dict_keys[0])
            break
        working_key = _decode_attribute_map_key(dict_keys[0])
        working_data = attribute_key_case_insensitive_extractor(working_key, None, working_data)
        if working_data is None:
            # If at any point while following flatten JSON path see None, it means
            # that all properties under are None as well
            # https://github.com/Azure/msrest-for-python/issues/197
            return None
        key = ".".join(dict_keys[1:])

    if working_data:
        return attribute_key_case_insensitive_extractor(key, None, working_data)


def last_rest_key_extractor(attr, attr_desc, data):
    """Extract the attribute in "data" based on the last part of the JSON path key."""
    key = attr_desc["key"]
    dict_keys = _FLATTEN.split(key)
    return attribute_key_extractor(dict_keys[-1], None, data)


def last_rest_key_case_insensitive_extractor(attr, attr_desc, data):
    """Extract the attribute in "data" based on the last part of the JSON path key.

    This is the case insensitive version of "last_rest_key_extractor"
    """
    key = attr_desc["key"]
    dict_keys = _FLATTEN.split(key)
    return attribute_key_case_insensitive_extractor(dict_keys[-1], None, data)


def attribute_key_extractor(attr, _, data):
    return data.get(attr)


def attribute_key_case_insensitive_extractor(attr, _, data):
    found_key = None
    lower_attr = attr.lower()
    for key in data:
        if lower_attr == key.lower():
            found_key = key
            break

    return data.get(found_key)


def _extract_name_from_internal_type(internal_type):
    """Given an internal type XML description, extract correct XML name with namespace.

    :param dict internal_type: An model type
    :rtype: tuple
    :returns: A tuple XML name + namespace dict
    """
    internal_type_xml_map = getattr(internal_type, "_xml_map", {})
    xml_name = internal_type_xml_map.get("name", internal_type.__name__)
    xml_ns = internal_type_xml_map.get("ns", None)
    if xml_ns:
        xml_name = "{{{}}}{}".format(xml_ns, xml_name)
    return xml_name


def xml_key_extractor(attr, attr_desc, data):
    if isinstance(data, dict):
        return None

    # Test if this model is XML ready first
    if not isinstance(data, ET.Element):
        return None

    xml_desc = attr_desc.get("xml", {})
    xml_name = xml_desc.get("name", attr_desc["key"])

    # Look for a children
    is_iter_type = attr_desc["type"].startswith("[")
    is_wrapped = xml_desc.get("wrapped", False)
    internal_type = attr_desc.get("internalType", None)
    internal_type_xml_map = getattr(internal_type, "_xml_map", {})

    # Integrate namespace if necessary
    xml_ns = xml_desc.get("ns", internal_type_xml_map.get("ns", None))
    if xml_ns:
        xml_name = "{{{}}}{}".format(xml_ns, xml_name)

    # If it's an attribute, that's simple
    if xml_desc.get("attr", False):
        return data.get(xml_name)

    # If it's x-ms-text, that's simple too
    if xml_desc.get("text", False):
        return data.text

    # Scenario where I take the local name:
    # - Wrapped node
    # - Internal type is an enum (considered basic types)
    # - Internal type has no XML/Name node
    if is_wrapped or (internal_type and (issubclass(internal_type, Enum) or "name" not in internal_type_xml_map)):
        children = data.findall(xml_name)
    # If internal type has a local name and it's not a list, I use that name
    elif not is_iter_type and internal_type and "name" in internal_type_xml_map:
        xml_name = _extract_name_from_internal_type(internal_type)
        children = data.findall(xml_name)
    # That's an array
    else:
        if internal_type:  # Complex type, ignore itemsName and use the complex type name
            items_name = _extract_name_from_internal_type(internal_type)
        else:
            items_name = xml_desc.get("itemsName", xml_name)
        children = data.findall(items_name)

    if len(children) == 0:
        if is_iter_type:
            if is_wrapped:
                return None  # is_wrapped no node, we want None
            else:
                return []  # not wrapped, assume empty list
        return None  # Assume it's not there, maybe an optional node.

    # If is_iter_type and not wrapped, return all found children
    if is_iter_type:
        if not is_wrapped:
            return children
        else:  # Iter and wrapped, should have found one node only (the wrap one)
            if len(children) != 1:
                raise DeserializationError(
                    "Tried to deserialize an array not wrapped, and found several nodes '{}'. Maybe you should declare this array as wrapped?".format(
                        xml_name
                    )
                )
            return list(children[0])  # Might be empty list and that's ok.

    # Here it's not a itertype, we should have found one element only or empty
    if len(children) > 1:
        raise DeserializationError("Find several XML '{}' where it was not expected".format(xml_name))
    return children[0]


class Deserializer(object):
    """Response object model deserializer.

    :param dict classes: Class type dictionary for deserializing complex types.
    :ivar list key_extractors: Ordered list of extractors to be used by this deserializer.
    """

    basic_types = {str: "str", int: "int", bool: "bool", float: "float"}

    valid_date = re.compile(r"\d{4}[-]\d{2}[-]\d{2}T\d{2}:\d{2}:\d{2}" r"\.?\d*Z?[-+]?[\d{2}]?:?[\d{2}]?")

    def __init__(self, classes: Optional[Mapping[str, Type[ModelType]]] = None):
        self.deserialize_type = {
            "iso-8601": Deserializer.deserialize_iso,
            "rfc-1123": Deserializer.deserialize_rfc,
            "unix-time": Deserializer.deserialize_unix,
            "duration": Deserializer.deserialize_duration,
            "date": Deserializer.deserialize_date,
            "time": Deserializer.deserialize_time,
            "decimal": Deserializer.deserialize_decimal,
            "long": Deserializer.deserialize_long,
            "bytearray": Deserializer.deserialize_bytearray,
            "base64": Deserializer.deserialize_base64,
            "object": self.deserialize_object,
            "[]": self.deserialize_iter,
            "{}": self.deserialize_dict,
        }
        self.deserialize_expected_types = {
            "duration": (isodate.Duration, datetime.timedelta),
            "iso-8601": (datetime.datetime),
        }
        self.dependencies: Dict[str, Type[ModelType]] = dict(classes) if classes else {}
        self.key_extractors = [rest_key_extractor, xml_key_extractor]
        # Additional properties only works if the "rest_key_extractor" is used to
        # extract the keys. Making it to work whatever the key extractor is too much
        # complicated, with no real scenario for now.
        # So adding a flag to disable additional properties detection. This flag should be
        # used if your expect the deserialization to NOT come from a JSON REST syntax.
        # Otherwise, result are unexpected
        self.additional_properties_detection = True

    def __call__(self, target_obj, response_data, content_type=None):
        """Call the deserializer to process a REST response.

        :param str target_obj: Target data type to deserialize to.
        :param requests.Response response_data: REST response object.
        :param str content_type: Swagger "produces" if available.
        :raises: DeserializationError if deserialization fails.
        :return: Deserialized object.
        """
        data = self._unpack_content(response_data, content_type)
        return self._deserialize(target_obj, data)

    def _deserialize(self, target_obj, data):
        """Call the deserializer on a model.

        Data needs to be already deserialized as JSON or XML ElementTree

        :param str target_obj: Target data type to deserialize to.
        :param object data: Object to deserialize.
        :raises: DeserializationError if deserialization fails.
        :return: Deserialized object.
        """
        # This is already a model, go recursive just in case
        if hasattr(data, "_attribute_map"):
            constants = [name for name, config in getattr(data, "_validation", {}).items() if config.get("constant")]
            try:
                for attr, mapconfig in data._attribute_map.items():
                    if attr in constants:
                        continue
                    value = getattr(data, attr)
                    if value is None:
                        continue
                    local_type = mapconfig["type"]
                    internal_data_type = local_type.strip("[]{}")
                    if internal_data_type not in self.dependencies or isinstance(internal_data_type, Enum):
                        continue
                    setattr(data, attr, self._deserialize(local_type, value))
                return data
            except AttributeError:
                return

        response, class_name = self._classify_target(target_obj, data)

        if isinstance(response, basestring):
            return self.deserialize_data(data, response)
        elif isinstance(response, type) and issubclass(response, Enum):
            return self.deserialize_enum(data, response)

        if data is None:
            return data
        try:
            attributes = response._attribute_map  # type: ignore
            d_attrs = {}
            for attr, attr_desc in attributes.items():
                # Check empty string. If it's not empty, someone has a real "additionalProperties"...
                if attr == "additional_properties" and attr_desc["key"] == "":
                    continue
                raw_value = None
                # Enhance attr_desc with some dynamic data
                attr_desc = attr_desc.copy()  # Do a copy, do not change the real one
                internal_data_type = attr_desc["type"].strip("[]{}")
                if internal_data_type in self.dependencies:
                    attr_desc["internalType"] = self.dependencies[internal_data_type]

                for key_extractor in self.key_extractors:
                    found_value = key_extractor(attr, attr_desc, data)
                    if found_value is not None:
                        if raw_value is not None and raw_value != found_value:
                            msg = (
                                "Ignoring extracted value '%s' from %s for key '%s'"
                                " (duplicate extraction, follow extractors order)"
                            )
                            _LOGGER.warning(msg, found_value, key_extractor, attr)
                            continue
                        raw_value = found_value

                value = self.deserialize_data(raw_value, attr_desc["type"])
                d_attrs[attr] = value
        except (AttributeError, TypeError, KeyError) as err:
            msg = "Unable to deserialize to object: " + class_name  # type: ignore
            raise_with_traceback(DeserializationError, msg, err)
        else:
            additional_properties = self._build_additional_properties(attributes, data)
            return self._instantiate_model(response, d_attrs, additional_properties)

    def _build_additional_properties(self, attribute_map, data):
        if not self.additional_properties_detection:
            return None
        if "additional_properties" in attribute_map and attribute_map.get("additional_properties", {}).get("key") != "":
            # Check empty string. If it's not empty, someone has a real "additionalProperties"
            return None
        if isinstance(data, ET.Element):
            data = {el.tag: el.text for el in data}

        known_keys = {
            _decode_attribute_map_key(_FLATTEN.split(desc["key"])[0])
            for desc in attribute_map.values()
            if desc["key"] != ""
        }
        present_keys = set(data.keys())
        missing_keys = present_keys - known_keys
        return {key: data[key] for key in missing_keys}

    def _classify_target(self, target, data):
        """Check to see whether the deserialization target object can
        be classified into a subclass.
        Once classification has been determined, initialize object.

        :param str target: The target object type to deserialize to.
        :param str/dict data: The response data to deserialize.
        """
        if target is None:
            return None, None

        if isinstance(target, basestring):
            try:
                target = self.dependencies[target]
            except KeyError:
                return target, target

        try:
            target = target._classify(data, self.dependencies)
        except AttributeError:
            pass  # Target is not a Model, no classify
        return target, target.__class__.__name__  # type: ignore

    def failsafe_deserialize(self, target_obj, data, content_type=None):
        """Ignores any errors encountered in deserialization,
        and falls back to not deserializing the object. Recommended
        for use in error deserialization, as we want to return the
        HttpResponseError to users, and not have them deal with
        a deserialization error.

        :param str target_obj: The target object type to deserialize to.
        :param str/dict data: The response data to deserialize.
        :param str content_type: Swagger "produces" if available.
        """
        try:
            return self(target_obj, data, content_type=content_type)
        except:
            _LOGGER.debug(
                "Ran into a deserialization error. Ignoring since this is failsafe deserialization",
                exc_info=True,
            )
            return None

    @staticmethod
    def _unpack_content(raw_data, content_type=None):
        """Extract the correct structure for deserialization.

        If raw_data is a PipelineResponse, try to extract the result of RawDeserializer.
        if we can't, raise. Your Pipeline should have a RawDeserializer.

        If not a pipeline response and raw_data is bytes or string, use content-type
        to decode it. If no content-type, try JSON.

        If raw_data is something else, bypass all logic and return it directly.

        :param raw_data: Data to be processed.
        :param content_type: How to parse if raw_data is a string/bytes.
        :raises JSONDecodeError: If JSON is requested and parsing is impossible.
        :raises UnicodeDecodeError: If bytes is not UTF8
        """
        # Assume this is enough to detect a Pipeline Response without importing it
        context = getattr(raw_data, "context", {})
        if context:
            if RawDeserializer.CONTEXT_NAME in context:
                return context[RawDeserializer.CONTEXT_NAME]
            raise ValueError("This pipeline didn't have the RawDeserializer policy; can't deserialize")

        # Assume this is enough to recognize universal_http.ClientResponse without importing it
        if hasattr(raw_data, "body"):
            return RawDeserializer.deserialize_from_http_generics(raw_data.text(), raw_data.headers)

        # Assume this enough to recognize requests.Response without importing it.
        if hasattr(raw_data, "_content_consumed"):
            return RawDeserializer.deserialize_from_http_generics(raw_data.text, raw_data.headers)

        if isinstance(raw_data, (basestring, bytes)) or hasattr(raw_data, "read"):
            return RawDeserializer.deserialize_from_text(raw_data, content_type)  # type: ignore
        return raw_data

    def _instantiate_model(self, response, attrs, additional_properties=None):
        """Instantiate a response model passing in deserialized args.

        :param response: The response model class.
        :param d_attrs: The deserialized response attributes.
        """
        if callable(response):
            subtype = getattr(response, "_subtype_map", {})
            try:
                readonly = [k for k, v in response._validation.items() if v.get("readonly")]
                const = [k for k, v in response._validation.items() if v.get("constant")]
                kwargs = {k: v for k, v in attrs.items() if k not in subtype and k not in readonly + const}
                response_obj = response(**kwargs)
                for attr in readonly:
                    setattr(response_obj, attr, attrs.get(attr))
                if additional_properties:
                    response_obj.additional_properties = additional_properties
                return response_obj
            except TypeError as err:
                msg = "Unable to deserialize {} into model {}. ".format(kwargs, response)  # type: ignore
                raise DeserializationError(msg + str(err))
        else:
            try:
                for attr, value in attrs.items():
                    setattr(response, attr, value)
                return response
            except Exception as exp:
                msg = "Unable to populate response model. "
                msg += "Type: {}, Error: {}".format(type(response), exp)
                raise DeserializationError(msg)

    def deserialize_data(self, data, data_type):
        """Process data for deserialization according to data type.

        :param str data: The response string to be deserialized.
        :param str data_type: The type to deserialize to.
        :raises: DeserializationError if deserialization fails.
        :return: Deserialized object.
        """
        if data is None:
            return data

        try:
            if not data_type:
                return data
            if data_type in self.basic_types.values():
                return self.deserialize_basic(data, data_type)
            if data_type in self.deserialize_type:
                if isinstance(data, self.deserialize_expected_types.get(data_type, tuple())):
                    return data

                is_a_text_parsing_type = lambda x: x not in ["object", "[]", r"{}"]
                if isinstance(data, ET.Element) and is_a_text_parsing_type(data_type) and not data.text:
                    return None
                data_val = self.deserialize_type[data_type](data)
                return data_val

            iter_type = data_type[0] + data_type[-1]
            if iter_type in self.deserialize_type:
                return self.deserialize_type[iter_type](data, data_type[1:-1])

            obj_type = self.dependencies[data_type]
            if issubclass(obj_type, Enum):
                if isinstance(data, ET.Element):
                    data = data.text
                return self.deserialize_enum(data, obj_type)

        except (ValueError, TypeError, AttributeError) as err:
            msg = "Unable to deserialize response data."
            msg += " Data: {}, {}".format(data, data_type)
            raise_with_traceback(DeserializationError, msg, err)
        else:
            return self._deserialize(obj_type, data)

    def deserialize_iter(self, attr, iter_type):
        """Deserialize an iterable.

        :param list attr: Iterable to be deserialized.
        :param str iter_type: The type of object in the iterable.
        :rtype: list
        """
        if attr is None:
            return None
        if isinstance(attr, ET.Element):  # If I receive an element here, get the children
            attr = list(attr)
        if not isinstance(attr, (list, set)):
            raise DeserializationError("Cannot deserialize as [{}] an object of type {}".format(iter_type, type(attr)))
        return [self.deserialize_data(a, iter_type) for a in attr]

    def deserialize_dict(self, attr, dict_type):
        """Deserialize a dictionary.

        :param dict/list attr: Dictionary to be deserialized. Also accepts
         a list of key, value pairs.
        :param str dict_type: The object type of the items in the dictionary.
        :rtype: dict
        """
        if isinstance(attr, list):
            return {x["key"]: self.deserialize_data(x["value"], dict_type) for x in attr}

        if isinstance(attr, ET.Element):
            # Transform <Key>value</Key> into {"Key": "value"}
            attr = {el.tag: el.text for el in attr}
        return {k: self.deserialize_data(v, dict_type) for k, v in attr.items()}

    def deserialize_object(self, attr, **kwargs):
        """Deserialize a generic object.
        This will be handled as a dictionary.

        :param dict attr: Dictionary to be deserialized.
        :rtype: dict
        :raises: TypeError if non-builtin datatype encountered.
        """
        if attr is None:
            return None
        if isinstance(attr, ET.Element):
            # Do no recurse on XML, just return the tree as-is
            return attr
        if isinstance(attr, basestring):
            return self.deserialize_basic(attr, "str")
        obj_type = type(attr)
        if obj_type in self.basic_types:
            return self.deserialize_basic(attr, self.basic_types[obj_type])
        if obj_type is _long_type:
            return self.deserialize_long(attr)

        if obj_type == dict:
            deserialized = {}
            for key, value in attr.items():
                try:
                    deserialized[key] = self.deserialize_object(value, **kwargs)
                except ValueError:
                    deserialized[key] = None
            return deserialized

        if obj_type == list:
            deserialized = []
            for obj in attr:
                try:
                    deserialized.append(self.deserialize_object(obj, **kwargs))
                except ValueError:
                    pass
            return deserialized

        else:
            error = "Cannot deserialize generic object with type: "
            raise TypeError(error + str(obj_type))

    def deserialize_basic(self, attr, data_type):
        """Deserialize basic builtin data type from string.
        Will attempt to convert to str, int, float and bool.
        This function will also accept '1', '0', 'true' and 'false' as
        valid bool values.

        :param str attr: response string to be deserialized.
        :param str data_type: deserialization data type.
        :rtype: str, int, float or bool
        :raises: TypeError if string format is not valid.
        """
        # If we're here, data is supposed to be a basic type.
        # If it's still an XML node, take the text
        if isinstance(attr, ET.Element):
            attr = attr.text
            if not attr:
                if data_type == "str":
                    # None or '', node <a/> is empty string.
                    return ""
                else:
                    # None or '', node <a/> with a strong type is None.
                    # Don't try to model "empty bool" or "empty int"
                    return None

        if data_type == "bool":
            if attr in [True, False, 1, 0]:
                return bool(attr)
            elif isinstance(attr, basestring):
                if attr.lower() in ["true", "1"]:
                    return True
                elif attr.lower() in ["false", "0"]:
                    return False
            raise TypeError("Invalid boolean value: {}".format(attr))

        if data_type == "str":
            return self.deserialize_unicode(attr)
        return eval(data_type)(attr)  # nosec

    @staticmethod
    def deserialize_unicode(data):
        """Preserve unicode objects in Python 2, otherwise return data
        as a string.

        :param str data: response string to be deserialized.
        :rtype: str or unicode
        """
        # We might be here because we have an enum modeled as string,
        # and we try to deserialize a partial dict with enum inside
        if isinstance(data, Enum):
            return data

        # Consider this is real string
        try:
            if isinstance(data, unicode):  # type: ignore
                return data
        except NameError:
            return str(data)
        else:
            return str(data)

    @staticmethod
    def deserialize_enum(data, enum_obj):
        """Deserialize string into enum object.

        If the string is not a valid enum value it will be returned as-is
        and a warning will be logged.

        :param str data: Response string to be deserialized. If this value is
         None or invalid it will be returned as-is.
        :param Enum enum_obj: Enum object to deserialize to.
        :rtype: Enum
        """
        if isinstance(data, enum_obj) or data is None:
            return data
        if isinstance(data, Enum):
            data = data.value
        if isinstance(data, int):
            # Workaround. We might consider remove it in the future.
            # https://github.com/Azure/azure-rest-api-specs/issues/141
            try:
                return list(enum_obj.__members__.values())[data]
            except IndexError:
                error = "{!r} is not a valid index for enum {!r}"
                raise DeserializationError(error.format(data, enum_obj))
        try:
            return enum_obj(str(data))
        except ValueError:
            for enum_value in enum_obj:
                if enum_value.value.lower() == str(data).lower():
                    return enum_value
            # We don't fail anymore for unknown value, we deserialize as a string
            _LOGGER.warning(
                "Deserializer is not able to find %s as valid enum in %s",
                data,
                enum_obj,
            )
            return Deserializer.deserialize_unicode(data)

    @staticmethod
    def deserialize_bytearray(attr):
        """Deserialize string into bytearray.

        :param str attr: response string to be deserialized.
        :rtype: bytearray
        :raises: TypeError if string format invalid.
        """
        if isinstance(attr, ET.Element):
            attr = attr.text
        return bytearray(b64decode(attr))  # type: ignore

    @staticmethod
    def deserialize_base64(attr):
        """Deserialize base64 encoded string into string.

        :param str attr: response string to be deserialized.
        :rtype: bytearray
        :raises: TypeError if string format invalid.
        """
        if isinstance(attr, ET.Element):
            attr = attr.text
        padding = "=" * (3 - (len(attr) + 3) % 4)  # type: ignore
        attr = attr + padding  # type: ignore
        encoded = attr.replace("-", "+").replace("_", "/")
        return b64decode(encoded)

    @staticmethod
    def deserialize_decimal(attr):
        """Deserialize string into Decimal object.

        :param str attr: response string to be deserialized.
        :rtype: Decimal
        :raises: DeserializationError if string format invalid.
        """
        if isinstance(attr, ET.Element):
            attr = attr.text
        try:
            return decimal.Decimal(attr)  # type: ignore
        except decimal.DecimalException as err:
            msg = "Invalid decimal {}".format(attr)
            raise_with_traceback(DeserializationError, msg, err)

    @staticmethod
    def deserialize_long(attr):
        """Deserialize string into long (Py2) or int (Py3).

        :param str attr: response string to be deserialized.
        :rtype: long or int
        :raises: ValueError if string format invalid.
        """
        if isinstance(attr, ET.Element):
            attr = attr.text
        return _long_type(attr)  # type: ignore

    @staticmethod
    def deserialize_duration(attr):
        """Deserialize ISO-8601 formatted string into TimeDelta object.

        :param str attr: response string to be deserialized.
        :rtype: TimeDelta
        :raises: DeserializationError if string format invalid.
        """
        if isinstance(attr, ET.Element):
            attr = attr.text
        try:
            duration = isodate.parse_duration(attr)
        except (ValueError, OverflowError, AttributeError) as err:
            msg = "Cannot deserialize duration object."
            raise_with_traceback(DeserializationError, msg, err)
        else:
            return duration

    @staticmethod
    def deserialize_date(attr):
        """Deserialize ISO-8601 formatted string into Date object.

        :param str attr: response string to be deserialized.
        :rtype: Date
        :raises: DeserializationError if string format invalid.
        """
        if isinstance(attr, ET.Element):
            attr = attr.text
        if re.search(r"[^\W\d_]", attr, re.I + re.U):  # type: ignore
            raise DeserializationError("Date must have only digits and -. Received: %s" % attr)
        # This must NOT use defaultmonth/defaultday. Using None ensure this raises an exception.
        return isodate.parse_date(attr, defaultmonth=None, defaultday=None)

    @staticmethod
    def deserialize_time(attr):
        """Deserialize ISO-8601 formatted string into time object.

        :param str attr: response string to be deserialized.
        :rtype: datetime.time
        :raises: DeserializationError if string format invalid.
        """
        if isinstance(attr, ET.Element):
            attr = attr.text
        if re.search(r"[^\W\d_]", attr, re.I + re.U):  # type: ignore
            raise DeserializationError("Date must have only digits and -. Received: %s" % attr)
        return isodate.parse_time(attr)

    @staticmethod
    def deserialize_rfc(attr):
        """Deserialize RFC-1123 formatted string into Datetime object.

        :param str attr: response string to be deserialized.
        :rtype: Datetime
        :raises: DeserializationError if string format invalid.
        """
        if isinstance(attr, ET.Element):
            attr = attr.text
        try:
            parsed_date = email.utils.parsedate_tz(attr)  # type: ignore
            date_obj = datetime.datetime(
                *parsed_date[:6], tzinfo=_FixedOffset(datetime.timedelta(minutes=(parsed_date[9] or 0) / 60))
            )
            if not date_obj.tzinfo:
                date_obj = date_obj.astimezone(tz=TZ_UTC)
        except ValueError as err:
            msg = "Cannot deserialize to rfc datetime object."
            raise_with_traceback(DeserializationError, msg, err)
        else:
            return date_obj

    @staticmethod
    def deserialize_iso(attr):
        """Deserialize ISO-8601 formatted string into Datetime object.

        :param str attr: response string to be deserialized.
        :rtype: Datetime
        :raises: DeserializationError if string format invalid.
        """
        if isinstance(attr, ET.Element):
            attr = attr.text
        try:
            attr = attr.upper()  # type: ignore
            match = Deserializer.valid_date.match(attr)
            if not match:
                raise ValueError("Invalid datetime string: " + attr)

            check_decimal = attr.split(".")
            if len(check_decimal) > 1:
                decimal_str = ""
                for digit in check_decimal[1]:
                    if digit.isdigit():
                        decimal_str += digit
                    else:
                        break
                if len(decimal_str) > 6:
                    attr = attr.replace(decimal_str, decimal_str[0:6])

            date_obj = isodate.parse_datetime(attr)
            test_utc = date_obj.utctimetuple()
            if test_utc.tm_year > 9999 or test_utc.tm_year < 1:
                raise OverflowError("Hit max or min date")
        except (ValueError, OverflowError, AttributeError) as err:
            msg = "Cannot deserialize datetime object."
            raise_with_traceback(DeserializationError, msg, err)
        else:
            return date_obj

    @staticmethod
    def deserialize_unix(attr):
        """Serialize Datetime object into IntTime format.
        This is represented as seconds.

        :param int attr: Object to be serialized.
        :rtype: Datetime
        :raises: DeserializationError if format invalid
        """
        if isinstance(attr, ET.Element):
            attr = int(attr.text)  # type: ignore
        try:
            date_obj = datetime.datetime.fromtimestamp(attr, TZ_UTC)
        except ValueError as err:
            msg = "Cannot deserialize to unix datetime object."
            raise_with_traceback(DeserializationError, msg, err)
        else:
            return date_obj
