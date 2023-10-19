UA_VERSION_6_0 = "6.0.0"
UA_VERSION_6_1 = "6.1.0"
UA_VERSION_6_2 = "6.2.0"
UA_VERSION_7_0 = "7.0.0"
UA_VERSION_7_1 = "7.1.0"

# Next upcoming version (version number not yet assigned)
UA_VERSION_DEVELOP = "develop"
UA_VERSION_CURRENT_RELEASE = UA_VERSION_7_1


class Version:
    def __init__(self, version: str):
        # It is possible to initialize version with Major.Minor, e.g: 6.0, 7.0
        # However, internally we need build number. Simply append it.
        if version.count('.') == 1:
            version += ".0"
        elif version == "main":
            version = UA_VERSION_CURRENT_RELEASE
        elif version == "develop":
            version = UA_VERSION_DEVELOP

        self._outputVersion = version

    def is_version_6_1_or_newer(self) -> bool:
        return self.is_version_develop() or self._version() >= self._version_tuple(UA_VERSION_6_1)

    def is_version_6_2_or_newer(self) -> bool:
        return self.is_version_develop() or self._version() >= self._version_tuple(UA_VERSION_6_2)

    def is_version_7_0_or_newer(self) -> bool:
        return self.is_version_develop() or self._version() >= self._version_tuple(UA_VERSION_7_0)

    def is_version_7_1_or_newer(self) -> bool:
        return self.is_version_develop() or self._version() >= self._version_tuple(UA_VERSION_7_1)

    def is_version_develop(self) -> bool:
        return self._outputVersion == UA_VERSION_DEVELOP

    def is_sigma_platform_supported(self, platform) -> bool:
        platform_per_version = {
            UA_VERSION_6_0: ["common", "windows"],
            UA_VERSION_DEVELOP: ["common", "windows", "macos"]
        }

        if platform in platform_per_version[UA_VERSION_6_0]:
            return True

        if (self.is_version_develop() or self.is_version_7_1_or_newer) and platform in platform_per_version[UA_VERSION_DEVELOP]:
            return True

    def reduce_mapping(self, mapping: dict[str]):
        result: list[str] = []
        for k in mapping.keys():
            v = mapping[k]
            if self.is_field_supported(v):
                result.append(k)
        return result

    def is_field_supported(self, field) -> bool:
        fields_per_version = {
            UA_VERSION_6_0: [
                "Process.Name",
                "Parent.Name",
                "Process.User",
                "Parent.User",
                "Process.Path",
                "Parent.Path",
                "Process.CommandLine",
                "Parent.CommandLine",
                "Process.AppName",
                "Parent.AppName",
                "Process.AppVersion",
                "Parent.AppVersion",
                "Process.Company",
                "Parent.Company",
                "Process.IsElevated",
                "Parent.IsElevated",
                "Process.IsProtected",
                "Parent.IsProtected",
                "Process.SessionId",
                "Parent.SessionId",
                "Process.DirectorySdSddl",
                "Process.DirectoryUserWritable",
                "Process.Hash",
                "Parent.Hash",
                "Net.Target.Ip",
                "Net.Target.Name",
                "Net.Target.Port",
                "Net.Target.Protocol",
                "Reg.Key.Path",
                "Reg.Key.Name",
                "Reg.Parent.Key.Path",
                "Reg.Key.Path.New",
                "Reg.Key.Path.Old",
                "Reg.Value.Name",
                "Reg.File.Name",
                "Reg.Key.Sddl",
                "Reg.Key.Hive",
                "Image.Name",
                "Image.Path",
                "Image.Hash"
            ],
            UA_VERSION_6_1: [
                "Process.Hash.MD5",
                "Process.Hash.SHA1",
                "Process.Hash.SHA256",
                "Process.Hash.IMP",
                "Process.IsSigned",
                "Process.Signature",
                "Process.SignatureStatus",
                "Parent.Hash.MD5",
                "Parent.Hash.SHA1",
                "Parent.Hash.SHA256",
                "Parent.Hash.IMP",
                "Parent.IsSigned",
                "Parent.Signature",
                "Parent.SignatureStatus",
                "Image.Hash.MD5",
                "Image.Hash.SHA1",
                "Image.Hash.SHA256",
                "Image.Hash.IMP",
                "Image.IsSigned",
                "Image.Signature",
                "Image.SignatureStatus"
            ],
            UA_VERSION_6_2: [
                "Net.Target.IpIsV6",
                "Net.Target.PortName",
                "Net.Source.Ip",
                "Net.Source.IpIsV6",
                "Net.Source.Name",
                "Net.Source.Port",
                "Net.Source.PortName",
                "Thread.Id",
                "Thread.Timestamp",
                "Thread.Process.Id",
                "Thread.Parent.Id",
                "Thread.StartAddress",
                "Thread.StartModule",
                "Thread.StartFunctionName",
                "Reg.Key.Target",
                "Process.Hashes",
                "Parent.Hashes",
                "Image.Hashes"
            ],
            UA_VERSION_7_0: [
                "Image.IsSignedByOSVendor",
                "Process.IsSignedByOSVendor",
                "Parent.IsSignedByOSVendor"
            ],
            UA_VERSION_7_1: [
                "File.Name",
                "File.Path",
                "File.PreviousName",
                "File.PreviousPath",
                "File.CreationDate",
                "File.IsExecutable",
                "File.PreviousCreationDate",
                "File.HasExecPermissions",
                "Reg.Value.Data"
            ],
            UA_VERSION_DEVELOP: []
        }

        if self.is_version_6_1_or_newer():
            # The fields here were removed in version 6.1.0 and replaced with more specific fields.
            # Remove them if we are generating for a newer version, so we don't generate invalid rules.
            fields_per_version[UA_VERSION_6_0].remove("Process.Hash")
            fields_per_version[UA_VERSION_6_0].remove("Parent.Hash")
            fields_per_version[UA_VERSION_6_0].remove("Image.Hash")

        if field in fields_per_version[UA_VERSION_6_0]:
            return True

        if self.is_version_6_1_or_newer() and field in fields_per_version[UA_VERSION_6_1]:
            return True

        if self.is_version_6_2_or_newer() and field in fields_per_version[UA_VERSION_6_2]:
            return True

        if self.is_version_7_0_or_newer() and field in fields_per_version[UA_VERSION_7_0]:
            return True

        if self.is_version_7_1_or_newer() and field in fields_per_version[UA_VERSION_7_1]:
            return True

        if self.is_version_develop() and field in fields_per_version[UA_VERSION_DEVELOP]:
            return True

        return False

    def is_event_type_supported(self, event_type) -> bool:
        """Returns whether uberagent ESA knows the given sigma category or not."""
        event_types_per_version = {
            UA_VERSION_6_0: [
                "Process.Start",
                "Process.Stop",
                "Image.Load",
                "Net.Send",
                "Net.Receive",
                "Net.Connect",
                "Net.Reconnect",
                "Net.Retransmit",
                "Reg.Key.Create",
                "Reg.Value.Write",
                "Reg.Delete",
                "Reg.Key.Delete",
                "Reg.Value.Delete",
                "Reg.Key.SecurityChange",
                "Reg.Key.Rename",
                "Reg.Key.SetInformation",
                "Reg.Key.Load",
                "Reg.Key.Unload",
                "Reg.Key.Save",
                "Reg.Key.Restore",
                "Reg.Key.Replace",
                "Reg.Any"
            ],
            UA_VERSION_6_1: [
                "DNS.Event"
            ],
            UA_VERSION_6_2: [
                "Net.Any",
                "Process.CreateRemoteThread",
                "Process.TamperingEvent"
            ],
            UA_VERSION_7_0: [
            ],
            UA_VERSION_7_1: [
                "Driver.Load",
                "File.Create",
                "File.CreateStream",
                "File.PipeCreate",
                "File.PipeConnected",
                "File.Delete",
                "File.Rename",
                "File.Write",
                "File.Read"
            ],
            UA_VERSION_DEVELOP: []
        }

        if event_type in event_types_per_version[UA_VERSION_6_0]:
            return True

        if self.is_version_6_1_or_newer() and event_type in event_types_per_version[UA_VERSION_6_1]:
            return True

        if self.is_version_6_2_or_newer() and event_type in event_types_per_version[UA_VERSION_6_2]:
            return True

        if self.is_version_7_0_or_newer() and event_type in event_types_per_version[UA_VERSION_7_0]:
            return True

        if self.is_version_7_1_or_newer() and event_type in event_types_per_version[UA_VERSION_7_1]:
            return True

        if self.is_version_develop() and event_type in event_types_per_version[UA_VERSION_DEVELOP]:
            return True

    def _version(self):
        return self._version_tuple(self._outputVersion)

    # Builds a version tuple which works fine as long as we specify the version in Major.Minor.Build.
    # A more efficient and robust way to solve this is using packaging.version but since we dont want to add
    # more dependencies to sigmac were using this method.
    # Because we specify versions in the same format, this is going to be fine.
    @staticmethod
    def _version_tuple(v):
        return tuple(map(int, (v.split("."))))

    def __str__(self):
        return self._outputVersion

    def get_filename(self, rule) -> str:

        # File name since develop (upcoming version)
        if self.is_version_develop() or self.is_version_7_1_or_newer():
            return "uberagent-ESA-am-sigma-" + rule.sigma_level + "-" + rule.platform + ".conf"

        # File name since 6.2
        if self.is_version_6_2_or_newer():
            return "uberagent-ESA-am-sigma-" + rule.sigma_level + ".conf"

        # File name since initial version 6.0
        return "uberagent-ESA-am-sigma-proc-creation-" + rule.sigma_level + ".conf"
