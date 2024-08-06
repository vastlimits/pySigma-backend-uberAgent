import pytest

from sigma.pipelines.uberagent.version import Version, UA_VERSION_6_0, UA_VERSION_6_1, UA_VERSION_6_2, UA_VERSION_7_0, UA_VERSION_7_1, UA_VERSION_7_2, UA_VERSION_7_3, UA_VERSION_CURRENT_RELEASE, UA_VERSION_DEVELOP
from sigma.pipelines.uberagent.logsource import Logsource
from sigma.pipelines.uberagent.field import Field


@pytest.mark.parametrize("version,expected", [
   (UA_VERSION_6_0, False),
   (UA_VERSION_6_1, True),
   (UA_VERSION_6_2, True),
   (UA_VERSION_7_0, True),
   (UA_VERSION_7_1, True),
   (UA_VERSION_7_2, True),
   (UA_VERSION_7_3, True),
   (UA_VERSION_DEVELOP, True),
])
def test_version_6_1(version, expected):
   assert Version(version).is_version_6_1_or_newer() == expected


@pytest.mark.parametrize("version,expected", [
   (UA_VERSION_6_0, False),
   (UA_VERSION_6_1, False),
   (UA_VERSION_6_2, True),
   (UA_VERSION_7_0, True),
   (UA_VERSION_7_1, True),
   (UA_VERSION_7_2, True),
   (UA_VERSION_7_3, True),
   (UA_VERSION_DEVELOP, True),
])
def test_version_6_2(version, expected):
   assert Version(version).is_version_6_2_or_newer() == expected


@pytest.mark.parametrize("version,expected", [
   (UA_VERSION_6_0, False),
   (UA_VERSION_6_1, False),
   (UA_VERSION_6_2, False),
   (UA_VERSION_7_0, True),
   (UA_VERSION_7_1, True),
   (UA_VERSION_7_2, True),
   (UA_VERSION_7_3, True),
   (UA_VERSION_DEVELOP, True),
])
def test_version_7_0(version, expected):
   assert Version(version).is_version_7_0_or_newer() == expected


@pytest.mark.parametrize("version,expected", [
   (UA_VERSION_6_0, False),
   (UA_VERSION_6_1, False),
   (UA_VERSION_6_2, False),
   (UA_VERSION_7_0, False),
   (UA_VERSION_7_1, True),
   (UA_VERSION_7_2, True),
   (UA_VERSION_7_3, True),
   (UA_VERSION_DEVELOP, True),
])
def test_version_7_1(version, expected):
   assert Version(version).is_version_7_1_or_newer() == expected


@pytest.mark.parametrize("version,expected", [
   (UA_VERSION_6_0, False),
   (UA_VERSION_6_1, False),
   (UA_VERSION_6_2, False),
   (UA_VERSION_7_0, False),
   (UA_VERSION_7_1, False),
   (UA_VERSION_7_2, True),
   (UA_VERSION_7_3, True),
   (UA_VERSION_DEVELOP, True),
])
def test_version_7_2(version, expected):
   assert Version(version).is_version_7_2_or_newer() == expected


@pytest.mark.parametrize("version,expected", [
   (UA_VERSION_6_0, False),
   (UA_VERSION_6_1, False),
   (UA_VERSION_6_2, False),
   (UA_VERSION_7_0, False),
   (UA_VERSION_7_1, False),
   (UA_VERSION_7_2, False),
   (UA_VERSION_7_3, True),
   (UA_VERSION_DEVELOP, True),
])
def test_version_7_3(version, expected):
   assert Version(version).is_version_7_3_or_newer() == expected


@pytest.mark.parametrize("version,expected", [
   (UA_VERSION_6_0, False),
   (UA_VERSION_6_1, False),
   (UA_VERSION_6_2, False),
   (UA_VERSION_7_0, False),
   (UA_VERSION_7_1, False),
   (UA_VERSION_7_2, False),
   (UA_VERSION_7_3, False),
   (UA_VERSION_DEVELOP, True),
])
def test_version_develop(version, expected):
   assert Version(version).is_version_develop() == expected


@pytest.mark.parametrize("platform,version,expected", [
   ("windows", UA_VERSION_6_0, True),
   ("windows", UA_VERSION_6_1, True),
   ("windows", UA_VERSION_6_2, True),
   ("windows", UA_VERSION_7_0, True),
   ("windows", UA_VERSION_7_1, True),
   ("windows", UA_VERSION_7_2, True),
   ("windows", UA_VERSION_7_3, True),
   ("windows", UA_VERSION_DEVELOP, True),
   ("common", UA_VERSION_6_0, True),
   ("common", UA_VERSION_6_1, True),
   ("common", UA_VERSION_6_2, True),
   ("common", UA_VERSION_7_0, True),
   ("common", UA_VERSION_7_1, True),
   ("common", UA_VERSION_7_2, True),
   ("common", UA_VERSION_7_3, True),
   ("common", UA_VERSION_DEVELOP, True),
   ("macos", UA_VERSION_6_0, False),
   ("macos", UA_VERSION_6_1, False),
   ("macos", UA_VERSION_6_2, False),
   ("macos", UA_VERSION_7_0, False),
   ("macos", UA_VERSION_7_1, True),
   ("macos", UA_VERSION_7_2, True),
   ("macos", UA_VERSION_7_3, True),
   ("macos", UA_VERSION_DEVELOP, True),
])
def test_version_develop(platform,version, expected):
   assert Version(version).is_platform_supported(platform) == expected


@pytest.mark.parametrize("logsource_version,version,expected", [
   (UA_VERSION_6_0, UA_VERSION_6_0, True),
   (UA_VERSION_6_0, UA_VERSION_6_1, True),
   (UA_VERSION_6_0, UA_VERSION_7_0, True),
   (UA_VERSION_6_0, UA_VERSION_7_1, True),
   (UA_VERSION_6_0, UA_VERSION_7_2, True),
   (UA_VERSION_6_0, UA_VERSION_7_3, True),
   (UA_VERSION_6_0, UA_VERSION_DEVELOP, True),

   (UA_VERSION_6_1, UA_VERSION_6_0, False),
   (UA_VERSION_6_1, UA_VERSION_6_1, True),
   (UA_VERSION_6_1, UA_VERSION_7_0, True),
   (UA_VERSION_6_1, UA_VERSION_7_1, True),
   (UA_VERSION_6_1, UA_VERSION_7_2, True),
   (UA_VERSION_6_1, UA_VERSION_7_3, True),
   (UA_VERSION_6_1, UA_VERSION_DEVELOP, True),

   (UA_VERSION_7_0, UA_VERSION_6_0, False),
   (UA_VERSION_7_0, UA_VERSION_6_1, False),
   (UA_VERSION_7_0, UA_VERSION_7_0, True),
   (UA_VERSION_7_0, UA_VERSION_7_1, True),
   (UA_VERSION_7_0, UA_VERSION_7_2, True),
   (UA_VERSION_7_0, UA_VERSION_7_3, True),
   (UA_VERSION_7_0, UA_VERSION_DEVELOP, True),

   (UA_VERSION_7_1, UA_VERSION_6_0, False),
   (UA_VERSION_7_1, UA_VERSION_6_1, False),
   (UA_VERSION_7_1, UA_VERSION_7_0, False),
   (UA_VERSION_7_1, UA_VERSION_7_1, True),
   (UA_VERSION_7_1, UA_VERSION_7_2, True),
   (UA_VERSION_7_1, UA_VERSION_7_3, True),
   (UA_VERSION_7_1, UA_VERSION_DEVELOP, True),

   (UA_VERSION_7_2, UA_VERSION_6_0, False),
   (UA_VERSION_7_2, UA_VERSION_6_1, False),
   (UA_VERSION_7_2, UA_VERSION_7_0, False),
   (UA_VERSION_7_2, UA_VERSION_7_1, False),
   (UA_VERSION_7_2, UA_VERSION_7_2, True),
   (UA_VERSION_7_2, UA_VERSION_7_3, True),
   (UA_VERSION_7_2, UA_VERSION_DEVELOP, True),

   (UA_VERSION_7_3, UA_VERSION_6_0, False),
   (UA_VERSION_7_3, UA_VERSION_6_1, False),
   (UA_VERSION_7_3, UA_VERSION_7_0, False),
   (UA_VERSION_7_3, UA_VERSION_7_1, False),
   (UA_VERSION_7_3, UA_VERSION_7_2, False),
   (UA_VERSION_7_3, UA_VERSION_7_3, True),
   (UA_VERSION_7_3, UA_VERSION_DEVELOP, True),

   (UA_VERSION_DEVELOP, UA_VERSION_6_0, False),
   (UA_VERSION_DEVELOP, UA_VERSION_6_1, False),
   (UA_VERSION_DEVELOP, UA_VERSION_7_0, False),
   (UA_VERSION_DEVELOP, UA_VERSION_7_1, False),
   (UA_VERSION_DEVELOP, UA_VERSION_7_2, False),
   (UA_VERSION_DEVELOP, UA_VERSION_7_3, False),
   (UA_VERSION_DEVELOP, UA_VERSION_DEVELOP, True),
])
def test_logsource_supported(logsource_version, version, expected):
   field: Field = Field(logsource_version, "TestField")
   version_object: Version = Version(version)
   assert version_object.is_logsource_supported(Logsource(logsource_version, "Test")) == expected and version_object.is_field_supported(field) == expected


def test_current_release():
   assert UA_VERSION_CURRENT_RELEASE == UA_VERSION_7_3


def test_version_str():
   assert str(Version("7.0")) == UA_VERSION_7_0