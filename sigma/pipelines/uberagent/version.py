from sigma.pipelines.uberagent.field import Field

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

    def reduce_mapping(self, mapping: dict[str, Field]):
        result: list[str] = []
        for k in mapping.keys():
            v: Field = mapping[k]
            if self.is_field_supported(v):
                result.append(k)
        return result

    def is_field_supported(self, field: Field) -> bool:
        if field.version == UA_VERSION_6_0:
            return True

        if self.is_version_6_1_or_newer() and field.version == UA_VERSION_6_1:
            return True

        if self.is_version_6_2_or_newer() and field.version == UA_VERSION_6_2:
            return True

        if self.is_version_7_0_or_newer() and field.version == UA_VERSION_7_0:
            return True

        if self.is_version_7_1_or_newer() and field.version == UA_VERSION_7_1:
            return True

        if self.is_version_develop() and field.version == UA_VERSION_DEVELOP:
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
