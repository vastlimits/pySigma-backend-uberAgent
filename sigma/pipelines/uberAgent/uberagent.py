from dataclasses import dataclass
from typing import List

from sigma.exceptions import SigmaTransformationError
from sigma.pipelines.base import Pipeline
from sigma.pipelines.common import logsource_windows_process_creation, logsource_windows_image_load, \
    logsource_windows_dns_query, logsource_windows_network_connection, logsource_windows_create_remote_thread, \
    logsource_windows_registry_add, logsource_windows_registry_set, \
    logsource_windows_registry_delete, logsource_windows_registry_event
from sigma.processing.conditions import ExcludeFieldCondition, IncludeFieldCondition, RuleProcessingCondition
from sigma.processing.pipeline import ProcessingPipeline, ProcessingItem
from sigma.processing.transformations import FieldMappingTransformation, \
    DetectionItemTransformation, ChangeLogsourceTransformation, SetStateTransformation
from sigma.rule import SigmaDetectionItem


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
    "Image": "Process.Path",
    "OriginalFileName": "Process.Name",
    "CommandLine": "Process.CommandLine",
    "ParentImage": "Parent.Path",
    "ParentCommandLine": "Parent.CommandLine",
    "Company": "Process.Company",
    "User": "Process.User",
    "Username": "Process.User",
    "SHA1": "Process.Hash.SHA1",
    "ImpHash": "Process.Hash.IMP",
    "ChildImage": "Process.Path",
    "Signed": "Process.IsSigned",
    "Hashes": "Process.Hashes",
}

ua_image_load_mapping: dict[str] = {
    "SHA1": "Image.Hash.SHA1",
    "ImpHash": "Image.Hash.IMP",
    "ChildImage": "Image.Path",
    "Signed": "Image.IsSigned",
    "Hashes": "Image.Hashes"
}

ua_dns_query_mapping: dict[str] = {
    "Query": "Dns.QueryRequest",
    "QueryName": "Dns.QueryRequest",
    "Answer": "Dns.QueryResponse"
}

ua_network_connection_mapping: dict[str] = {
    "DestinationPort": "Net.Target.Port",
    "DestinationIp": "Net.Target.Ip",
    "DestinationHostName": "Net.Target.Name",
    "DestinationIsIpv6": "Net.Target.IpIsV6",
    "SourcePort": "Net.Source.Port"
}

ua_create_remote_thread_mapping: dict[str] = {
    "TargetImage": "Process.Path",
    "StartModule": "Thread.StartModule",
    "StartFunction": "Thread.StartFunctionName"
}

ua_registry_event_mapping: dict[str] = {
    "TargetObject": "Reg.Key.Target",
    "NewName": "Reg.Key.Path.New"
}


def ua_create_mapping(event_type: str, mapping: dict[str], rule_conditions: List[RuleProcessingCondition]):
    keys = mapping.keys()
    items: list[ProcessingItem] = [
        ProcessingItem(
            identifier=f"ua_{event_type}_unsupported",
            transformation=FieldDetectionItemFailureTransformation(
                "Cannot transform field <{0}>. The uberAgent "
                "backend supports only the following "
                f"fields for {event_type} log source: "
                + ", ".join(keys)),
            rule_conditions=rule_conditions,
            rule_condition_linking=any,
            field_name_conditions=[ExcludeFieldCondition(fields=keys)]
        )
    ]

    # Build field transformation. Does not combine multiple fields.
    # Builds each field transformation separately to support state transformation per field.
    for field in keys:
        transformed_field = mapping[field]
        fm: dict[str] = {field: transformed_field}

        # Field Transformation: Transform rule field to TDE field name.
        items.append(
            ProcessingItem(
                identifier=f"ua_{event_type}_field_{field}",
                transformation=FieldMappingTransformation(fm),
                rule_conditions=rule_conditions,
                field_name_conditions=[
                    IncludeFieldCondition(fields=[field])
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
                    IncludeFieldCondition(fields=[field])
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


@Pipeline
def uberAgentPipeline():
    return ProcessingPipeline(
        name="uberAgent Mapping",
        allowed_backends={"uberagent"},
        priority=20,
        items=[

            *ua_create_mapping("Process.Start", ua_process_creation_mapping,
                               [logsource_windows_process_creation()]),

            *ua_create_mapping("Image.Load", ua_image_load_mapping,
                               [logsource_windows_image_load()]),

            *ua_create_mapping("Dns.Query", ua_dns_query_mapping,
                               [logsource_windows_dns_query()]),

            *ua_create_mapping("Net.Any", ua_network_connection_mapping,
                               [logsource_windows_network_connection()]),

            *ua_create_mapping("Process.CreateRemoteThread", ua_create_remote_thread_mapping,
                               [logsource_windows_create_remote_thread()]),

            *ua_create_mapping("Reg.Any", ua_registry_event_mapping,
                               [
                                   logsource_windows_registry_event(),
                                   logsource_windows_registry_add(),
                                   logsource_windows_registry_delete(),
                                   logsource_windows_registry_set()
                               ])
            # TODO: Process.TamperingEvent
            # TODO: File.ChangeCreationTime
            # TODO: File.RawAccessRead
            # TODO: File.Create
            # TODO: File.CreateStream
            # TODO: File.PipeCreate
            # TODO: File.PipeConnected
            # TODO: File.Delete
            # TODO: File.Rename
            # TODO: File.Write
            # TODO: File.Read
            # TODO: Driver.Load
        ]
    )
