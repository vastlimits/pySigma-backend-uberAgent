import pytest

from sigma.backends.uberagent.rule import MalformedRuleException, Rule
from sigma.pipelines.uberagent.version import Version

WITH_FIELD_RULE_ID = True
WITH_FIELD_ANNOTATION = True
WITHOUT_FIELD_RULE_ID = False
WITHOUT_FIELD_ANNOTATION = False
WITH_HIVE = True
WITHOUT_HIVE = False

def test_rule_minimum_fields():
    expected = \
        '[ActivityMonitoringRule]\n' \
        'RuleId = Test\n' \
        'RuleName = Test\n' \
        'EventType = Test\n' \
        'Tag = Test\n' \
        'Query = true\n'

    rule = Rule(Version("develop"))
    rule.set_id("Test")
    rule.set_event_type("Test")
    rule.set_tag("Test")
    rule.set_name("Test")
    rule.set_query("true")
    assert str(rule) == expected

@pytest.mark.parametrize("version,method_values,expected_exception", [
    ("develop", {"set_id": "Test", "set_event_type": "Test", "set_tag": "Test", "set_name": "Test", "set_query": "true"}, None),
    ("develop", {"set_id": "Test", "set_event_type": "Test", "set_tag": "Test", "set_name": "Test", "set_query": ""}    , MalformedRuleException), # Query must be not empty.
    ("develop", {"set_id": "Test", "set_event_type": "Test", "set_tag": "Test", "set_name": "Test", "set_query": None}  , MalformedRuleException), # Query must be not None.
    ("develop", {"set_id": "Test", "set_event_type": "Test", "set_tag": "Test", "set_name": "", "set_query": "true"}    , MalformedRuleException), # Name must be not empty.
    ("develop", {"set_id": "Test", "set_event_type": "Test", "set_tag": "Test", "set_name": None, "set_query": "true"}  , MalformedRuleException), # Name must be not None.
    ("develop", {"set_id": "Test", "set_event_type": "Test", "set_tag": "", "set_name": "Test", "set_query": "true"}    , MalformedRuleException), # Tag must be not empty.
    ("develop", {"set_id": "Test", "set_event_type": "Test", "set_tag": None, "set_name": "Test", "set_query": "true"}  , MalformedRuleException), # Tag must be not None.
    ("develop", {"set_id": "Test", "set_event_type": "", "set_tag": "Test", "set_name": "Test", "set_query": "true"}    , MalformedRuleException), # Event Type must be not empty.
    ("develop", {"set_id": "Test", "set_event_type": None, "set_tag": "Test", "set_name": "Test", "set_query": "true"}  , MalformedRuleException), # Event Type must be not None.
    ("develop", {"set_id": "Test", "set_event_type": "", "set_tag": "Test", "set_name": "Test", "set_query": "true"}    , MalformedRuleException), # Event Type must be not empty.
    ("develop", {"set_id": "", "set_event_type": "Test", "set_tag": "Test", "set_name": "Test", "set_query": "true"}    , MalformedRuleException), # RuleId must be not None.
    ("develop", {"set_id": None, "set_event_type": "Test", "set_tag": "Test", "set_name": "Test", "set_query": "true"}  , MalformedRuleException), # RuleId must be not None.
])
def test_rule_creation(version, method_values, expected_exception):
    rule = Rule(Version(version))
    for method_name, value in method_values.items():
        getattr(rule, method_name)(value)

    if expected_exception:
        with pytest.raises(expected_exception):
            str(rule)
    else:
        str(rule)  # Should not raise any exception


@pytest.mark.parametrize("version,with_id", [
    ("6.0.0", WITHOUT_FIELD_RULE_ID),
    ("6.1.0", WITHOUT_FIELD_RULE_ID),
    ("6.2.0", WITHOUT_FIELD_RULE_ID),
    ("7.0.0", WITH_FIELD_RULE_ID),
    ("7.1.0", WITH_FIELD_RULE_ID),
    ("develop", WITH_FIELD_RULE_ID),
    ("main", WITH_FIELD_RULE_ID)
])
def test_rule_id(version, with_id):
    expected_with_id = \
        '[ActivityMonitoringRule]\n' \
        'RuleId = Test\n' \
        'RuleName = Test\n' \
        'EventType = Test\n' \
        'Tag = Test\n' \
        'Query = true\n'

    expected_without_id = \
        '[ActivityMonitoringRule]\n' \
        'RuleName = Test\n' \
        'EventType = Test\n' \
        'Tag = Test\n' \
        'Query = true\n'

    rule = Rule(Version(version))
    rule.set_id("Test")
    rule.set_event_type("Test")
    rule.set_tag("Test")
    rule.set_name("Test")
    rule.set_query("true")
    if with_id:
        assert str(rule) == expected_with_id
    else:
        assert str(rule) == expected_without_id


@pytest.mark.parametrize("version,with_id,with_annotation", [
    ("6.0.0", WITHOUT_FIELD_RULE_ID, WITHOUT_FIELD_ANNOTATION),
    ("6.1.0", WITHOUT_FIELD_RULE_ID, WITHOUT_FIELD_ANNOTATION),
    ("6.2.0", WITHOUT_FIELD_RULE_ID, WITHOUT_FIELD_ANNOTATION),
    ("7.0.0", WITH_FIELD_RULE_ID, WITH_FIELD_ANNOTATION),
    ("7.1.0", WITH_FIELD_RULE_ID, WITH_FIELD_ANNOTATION),
    ("develop", WITH_FIELD_RULE_ID, WITH_FIELD_ANNOTATION),
    ("main", WITH_FIELD_RULE_ID, WITH_FIELD_ANNOTATION)
])
def test_rule_annotation(version, with_id, with_annotation):
    expected_with = \
        '[ActivityMonitoringRule]\n' \
        'RuleId = Test\n' \
        'RuleName = Test\n' \
        'EventType = Test\n' \
        'Tag = Test\n' \
        'Annotation = Test\n' \
        'Query = true\n'

    expected_without = \
        '[ActivityMonitoringRule]\n' \
        'RuleName = Test\n' \
        'EventType = Test\n' \
        'Tag = Test\n' \
        'Query = true\n'

    rule = Rule(Version(version))
    rule.set_annotation("Test")
    rule.set_id("Test")
    rule.set_event_type("Test")
    rule.set_tag("Test")
    rule.set_name("Test")
    rule.set_query("true")
    if with_id and with_annotation:
        assert str(rule) == expected_with
    else:
        assert str(rule) == expected_without

@pytest.mark.parametrize("version,event_type,with_hive", [
    ("6.0.0", "Reg.Any", WITH_HIVE),
    ("6.1.0", "Reg.Any", WITH_HIVE),
    ("6.2.0", "Reg.Any", WITH_HIVE),
    ("7.0.0", "Reg.Any", WITH_HIVE),
    ("7.1.0", "Reg.Any", WITH_HIVE),
    ("develop", "Reg.Any", WITH_HIVE),
    ("main", "Reg.Any", WITH_HIVE),
    ("6.0.0", "Process.Start", WITHOUT_HIVE),
    ("6.1.0", "Process.Start", WITHOUT_HIVE),
    ("6.2.0", "Process.Start", WITHOUT_HIVE),
    ("7.0.0", "Process.Start", WITHOUT_HIVE),
    ("7.1.0", "Process.Start", WITHOUT_HIVE),
    ("develop", "Process.Start", WITHOUT_HIVE),
    ("main", "Process.Start", WITHOUT_HIVE)
])
def test_rule_reg_hive(version, event_type, with_hive):
    rule = Rule(Version(version))
    rule.set_id("Test")
    rule.set_event_type(event_type)
    rule.set_tag("Test")
    rule.set_name("Test")
    rule.set_query("true")
    if with_hive:
        assert "Hive = HKLM,HKU" in str(rule)
    else:
        assert "Hive = HKLM,HKU" not in str(rule)

def test_rule_platform_windows():
    expected = \
        '[ActivityMonitoringRule platform=Windows]\n' \
        'RuleId = Test\n' \
        'RuleName = Test\n' \
        'EventType = Test\n' \
        'Tag = Test\n' \
        'Query = true\n'

    rule = Rule(Version("develop"))
    rule.set_platform("windows")
    rule.set_id("Test")
    rule.set_event_type("Test")
    rule.set_tag("Test")
    rule.set_name("Test")
    rule.set_query("true")
    assert str(rule) == expected


def test_rule_platform_macos():
    expected = \
        '[ActivityMonitoringRule platform=MacOS]\n' \
        'RuleId = Test\n' \
        'RuleName = Test\n' \
        'EventType = Test\n' \
        'Tag = Test\n' \
        'Query = true\n'

    rule = Rule(Version("develop"))
    rule.set_platform("macos")
    rule.set_id("Test")
    rule.set_event_type("Test")
    rule.set_tag("Test")
    rule.set_name("Test")
    rule.set_query("true")
    assert str(rule) == expected


def test_rule_author_description():
    expected = \
        '[ActivityMonitoringRule platform=MacOS]\n' \
        '# Test Description\n' \
        '# Author: Test\n' \
        'RuleId = Test\n' \
        'RuleName = Test\n' \
        'EventType = Test\n' \
        'Tag = Test\n' \
        'Query = true\n'

    rule = Rule(Version("develop"))
    rule.set_platform("macos")
    rule.set_id("Test")
    rule.set_event_type("Test")
    rule.set_tag("Test")
    rule.set_name("Test")
    rule.set_query("true")
    rule.set_author("Test")
    rule.set_description("Test Description")
    assert str(rule) == expected

def test_rule_generic_properties():
    expected = \
        '[ActivityMonitoringRule]\n' \
        'RuleId = Test\n' \
        'RuleName = Test\n' \
        'EventType = Test\n' \
        'Tag = Test\n' \
        'Query = true\n' \
        'GenericProperty1 = Field1\n' \
        'GenericProperty2 = Field2\n' \
        'GenericProperty3 = Field3\n' \
        'GenericProperty4 = Field4\n' \
        'GenericProperty5 = Field5\n' \
        'GenericProperty6 = Field6\n' \
        'GenericProperty7 = Field7\n' \
        'GenericProperty8 = Field8\n' \
        'GenericProperty9 = Field9\n' \
        'GenericProperty10 = Field10\n'

    rule = Rule(Version("develop"))
    rule.set_id("Test")
    rule.set_event_type("Test")
    rule.set_tag("Test")
    rule.set_name("Test")
    rule.set_query("true")
    rule.set_generic_properties(["Field1", "Field2", "Field3", "Field4", "Field5", "Field6", "Field7", "Field8", "Field9", "Field10", "Field11"])
    assert str(rule) == expected