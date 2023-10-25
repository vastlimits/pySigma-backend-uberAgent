from dataclasses import dataclass
from typing import List, Optional, Union

from sigma.exceptions import SigmaTransformationError
from sigma.pipelines.common import logsource_windows_process_creation, logsource_windows_image_load, \
    logsource_windows_dns_query, logsource_windows_network_connection, logsource_windows_create_remote_thread, \
    logsource_windows_registry_add, logsource_windows_registry_set, \
    logsource_windows_registry_delete, logsource_windows_registry_event, logsource_windows_driver_load, \
    logsource_windows_file_rename, logsource_windows_file_delete, logsource_windows_file_change, \
    logsource_windows_file_event, logsource_windows_file_access
from sigma.processing.conditions import IncludeFieldCondition, RuleProcessingCondition, \
    LogsourceCondition, RuleProcessingItemAppliedCondition
from sigma.processing.pipeline import ProcessingPipeline, ProcessingItem
from sigma.processing.transformations import FieldMappingTransformation, \
    DetectionItemTransformation, ChangeLogsourceTransformation, SetStateTransformation, RuleFailureTransformation
from sigma.rule import SigmaDetectionItem

from sigma.pipelines.uberagent.category import Category
from sigma.pipelines.uberagent.field import Field
from sigma.pipelines.uberagent.version import UA_VERSION_6_0, UA_VERSION_6_1, UA_VERSION_6_2, UA_VERSION_7_0, \
    UA_VERSION_7_1, UA_VERSION_DEVELOP, UA_VERSION_CURRENT_RELEASE, Version


# TODO: import tests for all implemented pipelines and contained transformations
# Wrapped from DetectionItemFailureTransformation to output the field name.
@dataclass
class FieldDetectionItemFailureTransformation(DetectionItemTransformation):
    message: str

    def apply_detection_item(self, detection_item: SigmaDetectionItem) -> None:
        raise SigmaTransformationError(self.message.format(detection_item.field))


# Maps all known Sigma fields to uberAgent Process Event Properties
# Note: The process properties are re-usable for all event types as all events are linked to a process.
#
# Documentation:
# https://uberagent.com/docs/uberagent/latest/esa-features-configuration/threat-detection-engine/event-properties/common-event-properties/
ua_process_creation_mapping: dict[str, Field] = {

    # Common fields.
    # The fields here are usable in all other event types if supported by Sigma.
    "image"                 : Field(UA_VERSION_6_0, "Process.Path"),
    "childimage"            : Field(UA_VERSION_6_0, "Process.Path"),
    "originalfilename"      : Field(UA_VERSION_6_0, "Process.Name"),
    "commandline"           : Field(UA_VERSION_6_0, "Process.CommandLine"),
    "parentimage"           : Field(UA_VERSION_6_0, "Parent.Path"),
    "parentcommandline"     : Field(UA_VERSION_6_0, "Parent.CommandLine"),
    "company"               : Field(UA_VERSION_6_0, "Process.Company"),
    "user"                  : Field(UA_VERSION_6_0, "Process.User"),
    "username"              : Field(UA_VERSION_6_0, "Process.User"),
    "md5"                   : Field(UA_VERSION_6_1, "Process.Hash.MD5"),
    "sha1"                  : Field(UA_VERSION_6_1, "Process.Hash.SHA1"),
    "sha256"                : Field(UA_VERSION_6_1, "Process.Hash.SHA256"),
    "imphash"               : Field(UA_VERSION_6_1, "Process.Hash.IMP"),
    "signed"                : Field(UA_VERSION_6_1, "Process.IsSigned"),
    "signature"             : Field(UA_VERSION_6_1, "Process.Signature"),
    "signaturestatus"       : Field(UA_VERSION_6_1, "Process.SignatureStatus"),
    # ""                    : Field(UA_VERSION_6_1, "Parent.Hash.MD5")
    # ""                    : Field(UA_VERSION_6_1, "Parent.Hash.SHA1")
    # ""                    : Field(UA_VERSION_6_1, "Parent.Hash.SHA256")
    # ""                    : Field(UA_VERSION_6_1, "Parent.Hash.IMP")
    # ""                    : Field(UA_VERSION_6_1, "Parent.IsSigned")
    # ""                    : Field(UA_VERSION_6_1, "Parent.Signature")
    # ""                    : Field(UA_VERSION_6_1, "Parent.SignatureStatus")
    # ""                    : Field(UA_VERSION_6_2, "Parent.Hashes")
    "hashes"                : Field(UA_VERSION_6_2, "Process.Hashes")
}

# Maps all known Sigma fields to uberAgent Image Load (or Driver) Event Properties
#
# Documentation:
# https://uberagent.com/docs/uberagent/latest/esa-features-configuration/threat-detection-engine/event-properties/image-load-event-properties/
ua_image_load_mapping: dict[str, Field] = {

    # Common
    "image"                 : Field(UA_VERSION_6_0, "Process.Path"),
    "childimage"            : Field(UA_VERSION_6_0, "Image.Path"),
    "imageloaded"           : Field(UA_VERSION_6_0, "Image.Path"),
    "originalfilename"      : Field(UA_VERSION_6_0, "Process.Name"),
    "commandline"           : Field(UA_VERSION_6_0, "Process.CommandLine"),

    # Image/Driver Load Event
    "md5"                   : Field(UA_VERSION_6_1, "Image.Hash.MD5"),
    "sha1"                  : Field(UA_VERSION_6_1, "Image.Hash.SHA1"),
    "sha256"                : Field(UA_VERSION_6_1, "Image.Hash.SHA256"),
    "imphash"               : Field(UA_VERSION_6_1, "Image.Hash.IMP"),
    "signed"                : Field(UA_VERSION_6_1, "Image.IsSigned"),
    "signature"             : Field(UA_VERSION_6_1, "Image.Signature"),
    "signaturestatus"       : Field(UA_VERSION_6_1, "Image.SignatureStatus"),
    "hashes"                : Field(UA_VERSION_6_2, "Image.Hashes")
}

# Maps all known Sigma fields to uberAgent DNS Query Event Properties
#
# Documentation:
# https://uberagent.com/docs/uberagent/latest/esa-features-configuration/threat-detection-engine/event-properties/dns-query-event-properties/
ua_dns_query_mapping: dict[str, Field] = {

    # Common
    "image"                 : Field(UA_VERSION_6_0, "Process.Path"),
    "originalfilename"      : Field(UA_VERSION_6_0, "Process.Name"),
    "commandline"           : Field(UA_VERSION_6_0, "Process.CommandLine"),

    # DNS Query Event
    "query"                 : Field(UA_VERSION_6_1, "Dns.QueryRequest"),
    "queryname"             : Field(UA_VERSION_6_1, "Dns.QueryRequest"),
    "answer"                : Field(UA_VERSION_6_1, "Dns.QueryResponse")
}

# Maps all known Sigma fields to uberAgent Network Event Properties
#
# Documentation:
# https://uberagent.com/docs/uberagent/latest/esa-features-configuration/threat-detection-engine/event-properties/network-event-properties/
ua_network_connection_mapping: dict[str, Field] = {

    # Common
    "image"                 : Field(UA_VERSION_6_0, "Process.Path"),
    "originalfilename"      : Field(UA_VERSION_6_0, "Process.Name"),
    "commandline"           : Field(UA_VERSION_6_0, "Process.CommandLine"),

    # Network Event
    "destinationip"         : Field(UA_VERSION_6_0, "Net.Target.Ip"),
    "destinationhostname"   : Field(UA_VERSION_6_0, "Net.Target.Name"),
    "destinationport"       : Field(UA_VERSION_6_0, "Net.Target.Port"),
    # ""                    : Field(UA_VERSION_6_2, "Net.Target.PortName")
    # ""                    : Field(UA_VERSION_6_0, "Net.Target.Protocol")
    "destinationisipv6"     : Field(UA_VERSION_6_2, "Net.Target.IpIsV6"),
    # ""                    : Field(UA_VERSION_6_2, "Net.Source.Ip")
    # ""                    : Field(UA_VERSION_6_2, "Net.Source.Name")
    "sourceport"            : Field(UA_VERSION_6_2, "Net.Source.Port")
    # ""                    : Field(UA_VERSION_6_2, "Net.Source.PortName")
    # ""                    : Field(UA_VERSION_6_2, "Net.Source.IpIsV6")
}

# Maps all known Sigma fields to uberAgent Remote Thread Event Properties
#
# Documentation:
# https://uberagent.com/docs/uberagent/latest/esa-features-configuration/threat-detection-engine/event-properties/remote-thread-event-properties/
ua_create_remote_thread_mapping: dict[str, Field] = {

    # Common
    "targetimage"           : Field(UA_VERSION_6_0, "Process.Path"),

    # Thread Event
    "startmodule"           : Field(UA_VERSION_6_2, "Thread.StartModule"),
    "startfunction"         : Field(UA_VERSION_6_2, "Thread.StartFunctionName"),
    # ""                    : Field(UA_VERSION_6_2, "Thread.Process.Id")
    # ""                    : Field(UA_VERSION_6_2, "Thread.Parent.Id")
    # ""                    : Field(UA_VERSION_6_2, "Thread.StartAddress")
    # ""                    : Field(UA_VERSION_6_2, "Thread.Timestamp")
}

# Maps all known Sigma fields to uberAgent Registry Event Properties
#
# Documentation:
# https://uberagent.com/docs/uberagent/latest/esa-features-configuration/threat-detection-engine/event-properties/registry-event-properties/
ua_registry_event_mapping: dict[str, Field] = {

    # Common
    "image": Field(UA_VERSION_6_0, "Process.Path"),
    "originalfilename": Field(UA_VERSION_6_0, "Process.Name"),
    "commandline": Field(UA_VERSION_6_0, "Process.CommandLine"),

    # Registry Event
    # ""                    : Field(UA_VERSION_6_0, "Reg.Key.Path")
    # ""                    : Field(UA_VERSION_6_0, "Reg.Key.Name")
    # ""                    : Field(UA_VERSION_6_0, "Reg.Parent.Key.Path")
    # ""                    : Field(UA_VERSION_6_0, "Reg.Parent.Key.Path")
    "newname": Field(UA_VERSION_6_0, "Reg.Key.Path.New"),
    # ""                    : Field(UA_VERSION_6_0, "Reg.Key.Path.Old"),
    # ""                    : Field(UA_VERSION_6_0, "Reg.Value.Name"),
    # ""                    : Field(UA_VERSION_6_0, "Reg.File.Name"),
    # ""                    : Field(UA_VERSION_6_0, "Reg.Key.Sddl"),
    # ""                    : Field(UA_VERSION_6_0, "Reg.Key.Hive"),
    "targetobject": Field(UA_VERSION_6_2, "Reg.Key.Target"),
    "details": Field(UA_VERSION_7_1, "Reg.Value.Data")
    # ""                    : Field(UA_VERSION_7_1, "Reg.Value.Type")
}

# Maps all known Sigma fields to uberAgent File System Event Properties
#
# Documentation:
# https://uberagent.com/docs/uberagent/latest/esa-features-configuration/threat-detection-engine/event-properties/file-system-activity-event-properties/
ua_file_event_mapping: dict[str, Field] = {

    # Common
    "image"                 : Field(UA_VERSION_6_0, "Process.Path"),
    "originalfilename"      : Field(UA_VERSION_6_0, "Process.Name"),
    "commandline"           : Field(UA_VERSION_6_0, "Process.CommandLine"),
    "parentimage"           : Field(UA_VERSION_6_0, "Parent.Path"),
    "parentcommandline"     : Field(UA_VERSION_6_0, "Parent.CommandLine"),
    "user"                  : Field(UA_VERSION_6_0, "Process.User"),

    # File System Event
    # TODO: <creationutctime> Requires UTC String formatting from uberAgent
    # ""                    : Field(UA_VERSION_7_1, "File.CreationDate"),
    # TODO: This field is only available on macOS
    # ""                    : Field(UA_VERSION_7_1, "File.HasExecPermissions"),
    # ""                    : Field(UA_VERSION_7_1, "File.IsExecutable"),
    # ""                    : Field(UA_VERSION_7_1, "File.Name"),
    # TODO: <previouscreationutctime> Requires UTC String formatting from uberAgent
    # TODO: This field is only available on Windows
    # ""                    : Field(UA_VERSION_7_1, "File.PreviousCreationDate"),
    # ""                    : Field(UA_VERSION_7_1, "File.PreviousName"),
    # ""                    : Field(UA_VERSION_7_1, "File.PreviousPath"),
    "targetfilename"        : Field(UA_VERSION_7_1, "File.Path"),
    "filename"              : Field(UA_VERSION_7_1, "File.Path"),
    "sourcefilename"        : Field(UA_VERSION_7_1, "File.PreviousPath")
}


# No built-in function available. Used a custom condition.
# Only one rule was applicable at the time of creation.
def logsource_windows_process_tampering():
    return LogsourceCondition(category="process_tampering", product="windows")


#
# Lists all Threat Detection Engine event types of uberAgent and maps them to Sigma log sources.
# Some event types of uberAgent are not used in Sigma but if so, uncomment the matching event types and
# add particular log sources.
#
# A full list of available event types is documented here:
# https://uberagent.com/docs/uberagent/latest/esa-features-configuration/threat-detection-engine/event-types/
#
ua_categories: list[Category] = [
    #
    # Process & Image Events
    #
    # Not yet used/mappable: Category(UA_VERSION_6_0, "Process.Stop"),

    Category(UA_VERSION_6_0, "Process.Start",
             conditions=[logsource_windows_process_creation()],
             fields=ua_process_creation_mapping),

    Category(UA_VERSION_6_2, "Process.CreateRemoteThread",
             conditions=[logsource_windows_create_remote_thread()],
             fields=ua_create_remote_thread_mapping),

    Category(UA_VERSION_6_2, "Process.TamperingEvent",
             conditions=[logsource_windows_process_tampering()],
             fields=ua_process_creation_mapping),

    Category(UA_VERSION_6_0, "Image.Load",
             conditions=[logsource_windows_image_load()],
             fields=ua_image_load_mapping),

    Category(UA_VERSION_7_1, "Driver.Load",
             conditions=[logsource_windows_driver_load()],
             fields=ua_image_load_mapping),

    #
    # Network Events
    #
    # Not yet used/mappable: Category(UA_VERSION_6_0, "Net.Send"),
    # Not yet used/mappable: Category(UA_VERSION_6_0, "Net.Receive"),
    # Not yet used/mappable: Category(UA_VERSION_6_0, "Net.Connect"),
    # Not yet used/mappable: Category(UA_VERSION_6_0, "Net.Reconnect"),
    # Not yet used/mappable: Category(UA_VERSION_6_0, "Net.Retransmit"),

    # TODO: Update this missing event type in vlDocs
    Category(UA_VERSION_6_2, "Net.Any",
             conditions=[logsource_windows_network_connection()],
             fields=ua_network_connection_mapping),

    #
    # Registry Events
    #
    # Not yet used/mappable: Category(UA_VERSION_6_0, "Reg.Key.Create"),
    # Not yet used/mappable: Category(UA_VERSION_6_0, "Reg.Value.Write"),
    # Not yet used/mappable: Category(UA_VERSION_6_0, "Reg.Delete"),
    # Not yet used/mappable: Category(UA_VERSION_6_0, "Reg.Key.Delete"),
    # Not yet used/mappable: Category(UA_VERSION_6_0, "Reg.Value.Delete"),
    # Not yet used/mappable: Category(UA_VERSION_6_0, "Reg.Key.SecurityChange"),
    # Not yet used/mappable: Category(UA_VERSION_6_0, "Reg.Key.Rename"),
    # Not yet used/mappable: Category(UA_VERSION_6_0, "Reg.Key.SetInformation"),
    # Not yet used/mappable: Category(UA_VERSION_6_0, "Reg.Key.Load"),
    # Not yet used/mappable: Category(UA_VERSION_6_0, "Reg.Key.Unload"),
    # Not yet used/mappable: Category(UA_VERSION_6_0, "Reg.Key.Save"),
    # Not yet used/mappable: Category(UA_VERSION_6_0, "Reg.Key.Restore"),
    # Not yet used/mappable: Category(UA_VERSION_6_0, "Reg.Key.Replace"),

    Category(UA_VERSION_6_0, "Reg.Any",
             conditions=[
                 logsource_windows_registry_event(),
                 logsource_windows_registry_add(),
                 logsource_windows_registry_delete(),
                 logsource_windows_registry_set()
             ],
             fields=ua_registry_event_mapping),

    #
    # DNS Query Events
    #
    Category(UA_VERSION_6_1, "Dns.Query",
             conditions=[logsource_windows_dns_query()],
             fields=ua_dns_query_mapping),

    #
    # File System Events
    #
    # Not yet used/mappable: Category(UA_VERSION_7_1, "File.ChangeCreationTime"),
    # Not yet used/mappable: Category(UA_VERSION_7_1, "File.CreateStream"),
    # Not yet used/mappable: Category(UA_VERSION_7_1, "File.PipeCreate"),
    # Not yet used/mappable: Category(UA_VERSION_7_1, "File.PipeConnected"),
    # Not yet used/mappable: Category(UA_VERSION_7_1, "File.RawAccessRead"),

    Category(UA_VERSION_7_1, "File.Create",
             conditions=[logsource_windows_file_event()],
             fields=ua_file_event_mapping),

    Category(UA_VERSION_7_1, "File.Delete",
             conditions=[logsource_windows_file_delete()],
             fields=ua_file_event_mapping),

    Category(UA_VERSION_7_1, "File.Rename",
             conditions=[logsource_windows_file_rename()],
             fields=ua_file_event_mapping),

    Category(UA_VERSION_7_1, "File.Write",
             conditions=[logsource_windows_file_change()],
             fields=ua_file_event_mapping),

    Category(UA_VERSION_7_1, "File.Read",
             conditions=[logsource_windows_file_access()],
             fields=ua_file_event_mapping)
]


@dataclass
class uaIncludeFieldCondition(IncludeFieldCondition):
    """Matches on field name if it is contained in fields list."""

    def match_field_name(
            self,
            pipeline: "sigma.processing.pipeline.ProcessingPipeline",
            field: Optional[str],
    ) -> bool:
        if field is None:
            return False
        return field.lower() in [f.lower() for f in self.fields]


@dataclass
class uaExcludeFieldCondition(uaIncludeFieldCondition):
    """Matches on field name if it is not contained in fields list."""

    def match_field_name(
            self,
            pipeline: "sigma.processing.pipeline.ProcessingPipeline",
            field: Optional[str],
    ) -> bool:
        return not super().match_field_name(pipeline, field)


@dataclass
class uaFieldMappingTransformation(FieldMappingTransformation):
    def get_mapping(self, field: str) -> Union[None, str, List[str]]:
        return super().get_mapping(field.lower())


def ua_create_mapping(uaVersion: Version, category: Category):
    # Now get a pair of sigma keys that are actually supported in the given version.
    keys: list[str] = uaVersion.reduce_mapping(category.fields)

    items: list[ProcessingItem] = [
        ProcessingItem(
            identifier=f"ua_{category.name}_unsupported",
            transformation=FieldDetectionItemFailureTransformation("Cannot transform field <{0}>."),
            rule_conditions=category.conditions,
            rule_condition_linking=any,
            field_name_conditions=[uaExcludeFieldCondition(fields=keys)]
        )
    ]
    # items: list[ProcessingItem] = []

    # Build field transformation. Does not combine multiple fields.
    # Builds each field transformation separately to support state transformation per field.
    for field in keys:
        transformed_field = str(category.fields[field])
        fm: dict[str] = {field: transformed_field}

        # Field Transformation: Transform rule field to TDE field name.
        items.append(
            ProcessingItem(
                identifier=f"ua_{category.name}_field_{field}",
                transformation=uaFieldMappingTransformation(fm),
                rule_conditions=category.conditions,
                field_name_conditions=[
                    uaIncludeFieldCondition(fields=[field])
                ]
            )
        )
        # State Transformation: Set the transformed field to pipeline state so that the backend can
        #                       query the actual used fields. Having this information a list of generic properties
        #                       can be filled at runtime.
        items.append(
            ProcessingItem(
                identifier=f"ua_{category.name}_state{field}",
                transformation=SetStateTransformation(field, True),
                rule_conditions=category.conditions,
                field_name_conditions=[
                    uaIncludeFieldCondition(fields=[field])
                ]
            )
        )

    # Build log source transformation
    # TODO: Remove the hard-coded "Windows" platform.
    items.append(
        ProcessingItem(
            identifier=f"ls_{category.name}",
            transformation=ChangeLogsourceTransformation(category.name, "Windows", None),
            rule_conditions=category.conditions
        )
    )

    return items


def make_pipeline(uaVersion: Version):
    # Hold a list of converted log sources that were converted
    converted_conditions: list[RuleProcessingItemAppliedCondition] = []

    # Hold all processing items for the versioned pipeline
    items: list[ProcessingItem] = []
    for category in ua_categories:
        if not uaVersion.is_event_type_supported(category.name):
            continue

        # Create mapping for log source and its fields.
        for item in ua_create_mapping(uaVersion, category):
            items.append(item)

        converted_conditions.append(RuleProcessingItemAppliedCondition(f"ls_{category.name}"))

    # Create a final transformation to fail out any log source that is not yet supported.
    items.append(ProcessingItem(
        identifier="ua_log_source_not_supported",
        rule_condition_linking=any,
        transformation=RuleFailureTransformation("Rule type not yet supported."),
        rule_condition_negation=True,
        rule_conditions=converted_conditions
    ))

    return ProcessingPipeline(
        name=f"uberagent {uaVersion}",
        allowed_backends={"uberagent"},
        priority=20,
        items=items
    )


def uberagent():
    return make_pipeline(Version(UA_VERSION_CURRENT_RELEASE))


def uberagent600():
    return make_pipeline(Version(UA_VERSION_6_0))


def uberagent610():
    return make_pipeline(Version(UA_VERSION_6_1))


def uberagent620():
    return make_pipeline(Version(UA_VERSION_6_2))


def uberagent700():
    return make_pipeline(Version(UA_VERSION_7_0))


def uberagent710():
    return make_pipeline(Version(UA_VERSION_7_1))


def uberagent_develop():
    return make_pipeline(Version(UA_VERSION_DEVELOP))
