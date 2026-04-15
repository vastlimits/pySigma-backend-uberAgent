import pytest

from sigma.pipelines.uberagent.field import Field
from sigma.pipelines.uberagent.logsource import Logsource
from sigma.pipelines.uberagent.version import (
    UA_VERSION_6_0,
    UA_VERSION_6_1,
    UA_VERSION_6_2,
    UA_VERSION_7_0,
    UA_VERSION_7_1,
    UA_VERSION_7_2,
    UA_VERSION_7_3,
    UA_VERSION_7_4,
    UA_VERSION_7_5,
    UA_VERSION_8_0,
    UA_VERSION_CURRENT_RELEASE,
    UA_VERSION_DEVELOP,
    Version,
)


RELEASE_VERSIONS = [
    UA_VERSION_6_0,
    UA_VERSION_6_1,
    UA_VERSION_6_2,
    UA_VERSION_7_0,
    UA_VERSION_7_1,
    UA_VERSION_7_2,
    UA_VERSION_7_3,
    UA_VERSION_7_4,
    UA_VERSION_7_5,
    UA_VERSION_8_0,
]
ALL_VERSIONS = RELEASE_VERSIONS + [UA_VERSION_DEVELOP]


def is_version_at_least(version: str, minimum_version: str) -> bool:
    if version == UA_VERSION_DEVELOP:
        return True

    if minimum_version == UA_VERSION_DEVELOP:
        return version == UA_VERSION_DEVELOP

    return RELEASE_VERSIONS.index(version) >= RELEASE_VERSIONS.index(minimum_version)


@pytest.mark.parametrize(
    "version,expected",
    [(version, is_version_at_least(version, UA_VERSION_6_1)) for version in ALL_VERSIONS],
)
def test_version_6_1(version, expected):
    assert Version(version).is_version_6_1_or_newer() == expected


@pytest.mark.parametrize(
    "version,expected",
    [(version, is_version_at_least(version, UA_VERSION_6_2)) for version in ALL_VERSIONS],
)
def test_version_6_2(version, expected):
    assert Version(version).is_version_6_2_or_newer() == expected


@pytest.mark.parametrize(
    "version,expected",
    [(version, is_version_at_least(version, UA_VERSION_7_0)) for version in ALL_VERSIONS],
)
def test_version_7_0(version, expected):
    assert Version(version).is_version_7_0_or_newer() == expected


@pytest.mark.parametrize(
    "version,expected",
    [(version, is_version_at_least(version, UA_VERSION_7_1)) for version in ALL_VERSIONS],
)
def test_version_7_1(version, expected):
    assert Version(version).is_version_7_1_or_newer() == expected


@pytest.mark.parametrize(
    "version,expected",
    [(version, is_version_at_least(version, UA_VERSION_7_2)) for version in ALL_VERSIONS],
)
def test_version_7_2(version, expected):
    assert Version(version).is_version_7_2_or_newer() == expected


@pytest.mark.parametrize(
    "version,expected",
    [(version, is_version_at_least(version, UA_VERSION_7_3)) for version in ALL_VERSIONS],
)
def test_version_7_3(version, expected):
    assert Version(version).is_version_7_3_or_newer() == expected


@pytest.mark.parametrize(
    "version,expected",
    [(version, is_version_at_least(version, UA_VERSION_7_4)) for version in ALL_VERSIONS],
)
def test_version_7_4(version, expected):
    assert Version(version).is_version_7_4_or_newer() == expected


@pytest.mark.parametrize(
    "version,expected",
    [(version, is_version_at_least(version, UA_VERSION_7_5)) for version in ALL_VERSIONS],
)
def test_version_7_5(version, expected):
    assert Version(version).is_version_7_5_or_newer() == expected


@pytest.mark.parametrize(
    "version,expected",
    [(version, is_version_at_least(version, UA_VERSION_8_0)) for version in ALL_VERSIONS],
)
def test_version_8_0(version, expected):
    assert Version(version).is_version_8_0_or_newer() == expected


@pytest.mark.parametrize(
    "version,expected",
    [(version, version == UA_VERSION_DEVELOP) for version in ALL_VERSIONS],
)
def test_version_develop(version, expected):
    assert Version(version).is_version_develop() == expected


@pytest.mark.parametrize(
    "platform,version,expected",
    [
        (platform, version, is_version_at_least(version, minimum_version))
        for platform, minimum_version in {
            "windows": UA_VERSION_6_0,
            "common": UA_VERSION_6_0,
            "macos": UA_VERSION_7_1,
        }.items()
        for version in ALL_VERSIONS
    ],
)
def test_platform_supported(platform, version, expected):
    assert Version(version).is_platform_supported(platform) == expected


@pytest.mark.parametrize(
    "logsource_version,version,expected",
    [
        (logsource_version, version, is_version_at_least(version, logsource_version))
        for logsource_version in RELEASE_VERSIONS
        for version in ALL_VERSIONS
    ],
)
def test_logsource_supported(logsource_version, version, expected):
    field = Field(logsource_version, "TestField")
    version_object = Version(version)
    assert version_object.is_logsource_supported(Logsource(logsource_version, "Test")) == expected
    assert version_object.is_field_supported(field) == expected


def test_current_release():
    assert UA_VERSION_CURRENT_RELEASE == UA_VERSION_8_0
