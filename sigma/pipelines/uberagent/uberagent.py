from dataclasses import dataclass
from typing import List, Optional, Union

from sigma.exceptions import SigmaTransformationError
from sigma.pipelines.base import Pipeline
from sigma.pipelines.common import logsource_windows_process_creation, logsource_windows_image_load, \
    logsource_windows_dns_query, logsource_windows_network_connection, logsource_windows_create_remote_thread, \
    logsource_windows_registry_add, logsource_windows_registry_set, \
    logsource_windows_registry_delete, logsource_windows_registry_event, logsource_windows_driver_load, \
    logsource_windows_file_rename, logsource_windows_file_delete, logsource_windows_file_change, \
    logsource_windows_file_event, logsource_windows_file_access
from sigma.processing.conditions import ExcludeFieldCondition, IncludeFieldCondition, RuleProcessingCondition, \
    LogsourceCondition, RuleProcessingItemAppliedCondition
from sigma.processing.pipeline import ProcessingPipeline, ProcessingItem
from sigma.processing.transformations import FieldMappingTransformation, \
    DetectionItemTransformation, ChangeLogsourceTransformation, SetStateTransformation, RuleFailureTransformation
from sigma.rule import SigmaDetectionItem

from sigma.pipelines.uberagent.version import UA_VERSION_6_0, UA_VERSION_6_1, UA_VERSION_6_2, UA_VERSION_7_0, \
    UA_VERSION_7_1, UA_VERSION_DEVELOP, UA_VERSION_CURRENT_RELEASE, Version


# TODO: import tests for all implemented pipelines and contained transformations
# Wrapped from DetectionItemFailureTransformation to output the field name.
@dataclass
class FieldDetectionItemFailureTransformation(DetectionItemTransformation):
    message: str

    def apply_detection_item(self, detection_item: SigmaDetectionItem) -> None:
        raise SigmaTransformationError(self.message.format(detection_item.field))


#
# Field Mappings
#

ua_process_creation_mapping: dict[str] = {
    "image": "Process.Path",
    "originalfilename": "Process.Name",
    "commandline": "Process.CommandLine",
    "parentimage": "Parent.Path",
    "parentcommandline": "Parent.CommandLine",
    "company": "Process.Company",
    "user": "Process.User",
    "username": "Process.User",
    "md5": "Process.Hash.MD5",
    "sha1": "Process.Hash.SHA1",
    "sha256": "Process.Hash.SHA256",
    "imphash": "Process.Hash.IMP",
    "childimage": "Process.Path",
    "signed": "Process.IsSigned",
    "hashes": "Process.Hashes",
    "signaturestatus": "Process.SignatureStatus",
    "signature": "Process.Signature"
}

ua_image_load_mapping: dict[str] = {
    "image": "Process.Path",
    "originalfilename": "Process.Name",
    "commandline": "Process.CommandLine",

    "md5": "Image.Hash.MD5",
    "sha1": "Image.Hash.SHA1",
    "sha256": "Image.Hash.SHA256",
    "imphash": "Image.Hash.IMP",
    "childimage": "Image.Path",
    "imageloaded": "Image.Path",
    "signed": "Image.IsSigned",
    "hashes": "Image.Hashes",
    "signaturestatus": "Image.SignatureStatus",
    "signature": "Image.Signature"
}

ua_dns_query_mapping: dict[str] = {
    "image": "Process.Path",
    "originalfilename": "Process.Name",
    "commandline": "Process.CommandLine",

    "query": "Dns.QueryRequest",
    "queryname": "Dns.QueryRequest",
    "answer": "Dns.QueryResponse"
}

ua_network_connection_mapping: dict[str] = {
    "image": "Process.Path",
    "originalfilename": "Process.Name",
    "commandline": "Process.CommandLine",

    "destinationport": "Net.Target.Port",
    "destinationip": "Net.Target.Ip",
    "destinationhostname": "Net.Target.Name",
    "destinationisipv6": "Net.Target.IpIsV6",
    "sourceport": "Net.Source.Port"
}

# StartAddress = Thread.StartAddress = e.g '*0B80'
# SourceImage = Source.Path
# SourceParentImage = Source.Parent.Path
#
ua_create_remote_thread_mapping: dict[str] = {
    "targetimage": "Process.Path",
    "startmodule": "Thread.StartModule",
    "startfunction": "Thread.StartFunctionName"
}

ua_registry_event_mapping: dict[str] = {
    "image": "Process.Path",
    "originalfilename": "Process.Name",
    "commandline": "Process.CommandLine",

    "targetobject": "Reg.Key.Target",
    "newname": "Reg.Key.Path.New",
    "details": "Reg.Value.Data"
}

ua_file_event_mapping: dict[str] = {
    "image": "Process.Path",
    "originalfilename": "Process.Name",
    "commandline": "Process.CommandLine",
    "parentimage": "Parent.Path",
    "parentcommandline": "Parent.CommandLine",
    "user": "Process.User",

    "targetfilename": "File.Path",
    "filename": "File.Path",
    "sourcefilename": "File.PreviousPath"

    # TODO: File.CreationDate, File.PreviousCreationDate time format does not match.
    # "creationutctime": "File.CreationDate",
    # "previouscreationutctime": "File.PreviousCreationDate"
}


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


def ua_create_mapping(uaVersion: Version, event_type: str, mapping: dict[str],
                      rule_conditions: List[RuleProcessingCondition]):
    # First, confirm that the given event type is supported.
    if not uaVersion.is_event_type_supported(event_type):
        return []

    # Now get a pair of sigma keys that are actually supported in the given version.
    keys: list[str] = uaVersion.reduce_mapping(mapping)

    items: list[ProcessingItem] = [
        ProcessingItem(
            identifier=f"ua_{event_type}_unsupported",
            transformation=FieldDetectionItemFailureTransformation("Cannot transform field <{0}>."),
            rule_conditions=rule_conditions,
            rule_condition_linking=any,
            field_name_conditions=[uaExcludeFieldCondition(fields=keys)]
        )
    ]
    # items: list[ProcessingItem] = []

    # Build field transformation. Does not combine multiple fields.
    # Builds each field transformation separately to support state transformation per field.
    for field in keys:
        transformed_field = mapping[field]
        fm: dict[str] = {field: transformed_field}

        # Field Transformation: Transform rule field to TDE field name.
        items.append(
            ProcessingItem(
                identifier=f"ua_{event_type}_field_{field}",
                transformation=uaFieldMappingTransformation(fm),
                rule_conditions=rule_conditions,
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
                identifier=f"ua_{event_type}_state{field}",
                transformation=SetStateTransformation(field, True),
                rule_conditions=rule_conditions,
                field_name_conditions=[
                    uaIncludeFieldCondition(fields=[field])
                ]
            )
        )

    # Build log source transformation
    # TODO: Remove the hard-coded "Windows" platform.
    items.append(
        ProcessingItem(
            identifier=f"ls_{event_type}",
            transformation=ChangeLogsourceTransformation(event_type, "Windows", None),
            rule_conditions=rule_conditions
        )
    )

    return items


def make_versioned_log_source_conditions(uaVersion: Version, event_types: list[str]):
    result: List[RuleProcessingItemAppliedCondition] = []
    for event_type in event_types:
        if uaVersion.is_event_type_supported(event_type):
            result.append(RuleProcessingItemAppliedCondition(f"ls_{event_type}"))
    return result


def make_pipeline(uaVersion: Version):
    return ProcessingPipeline(
        name=f"uberagent {uaVersion}",
        allowed_backends={"uberagent"},
        priority=20,
        items=[

            *ua_create_mapping(uaVersion, "Process.Start", ua_process_creation_mapping,
                               [logsource_windows_process_creation()]),

            *ua_create_mapping(uaVersion, "Image.Load", ua_image_load_mapping,
                               [logsource_windows_image_load()]),

            *ua_create_mapping(uaVersion, "Driver.Load", ua_image_load_mapping,
                               [logsource_windows_driver_load()]),

            *ua_create_mapping(uaVersion, "Dns.Query", ua_dns_query_mapping,
                               [logsource_windows_dns_query()]),

            *ua_create_mapping(uaVersion, "Net.Any", ua_network_connection_mapping,
                               [logsource_windows_network_connection()]),

            *ua_create_mapping(uaVersion, "Process.CreateRemoteThread", ua_create_remote_thread_mapping,
                               [logsource_windows_create_remote_thread()]),

            # TODO: sigma-cli crashes on reading the only process_tampering rule.
            *ua_create_mapping(uaVersion, "Process.TamperingEvent", ua_process_creation_mapping,
                               [LogsourceCondition(category="process_tampering", product="windows")]),

            *ua_create_mapping(uaVersion, "Reg.Any", ua_registry_event_mapping,
                               [
                                   logsource_windows_registry_event(),
                                   logsource_windows_registry_add(),
                                   logsource_windows_registry_delete(),
                                   logsource_windows_registry_set()
                               ]),

            *ua_create_mapping(uaVersion, "File.Create", ua_file_event_mapping, [logsource_windows_file_event()]),
            *ua_create_mapping(uaVersion, "File.Delete", ua_file_event_mapping, [logsource_windows_file_delete()]),
            *ua_create_mapping(uaVersion, "File.Rename", ua_file_event_mapping, [logsource_windows_file_rename()]),
            *ua_create_mapping(uaVersion, "File.Write", ua_file_event_mapping, [logsource_windows_file_change()]),
            *ua_create_mapping(uaVersion, "File.Read", ua_file_event_mapping, [logsource_windows_file_access()]),

            ProcessingItem(
                identifier="ua_log_source_not_supported",
                rule_condition_linking=any,
                transformation=RuleFailureTransformation("Rule type not yet supported."),
                rule_condition_negation=True,
                rule_conditions=make_versioned_log_source_conditions(uaVersion, [
                    "Process.Start",
                    "Image.Load",
                    "Driver.Load",
                    "Dns.Query",
                    "Net.Any",
                    "Process.CreateRemoteThread",
                    "Process.TamperingEvent",
                    "Reg.Any",
                    "File.Created",
                    "File.Delete",
                    "File.Rename",
                    "File.Write",
                    "File.Read"
                ])
            )

            # Note: Not directly covered in Sigma; may be available in future.
            # *ua_create_mapping("File.ChangeCreationTime", ua_file_event_mapping, []),
            # *ua_create_mapping("File.RawAccessRead", ua_file_event_mapping, []),
            # *ua_create_mapping("File.CreateStream", ua_file_event_mapping, []),
            # *ua_create_mapping("File.PipeCreate", ua_file_event_mapping, []),
            # *ua_create_mapping("File.PipeConnected", ua_file_event_mapping, []),

        ]
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
