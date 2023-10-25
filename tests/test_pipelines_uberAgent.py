import pytest
from sigma.collection import SigmaCollection

from sigma.backends.uberagent import uberagent
from sigma.backends.uberagent.exceptions import MissingPropertyException
from sigma.pipelines.uberagent import uberagent as uberagent_pipeline


def test_ua_windows():
    assert uberagent(processing_pipeline=uberagent_pipeline()).convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                product: windows
                category: process_creation
            detection:
                sel:
                    Image: test
                    CommandLine: test
                condition: sel
        """)
    ) == ['Process.Path == "test" and Process.CommandLine == "test"']


def test_rule_process_creation():
    expected = \
        '[ActivityMonitoringRule]\n' \
        'RuleId = 0750fe99-1296-4b84-a60a-6af33e74bb37\n' \
        'RuleName = Test\n' \
        'EventType = Process.Start\n' \
        'Tag = proc-start-test\n' \
        'RiskScore = 75\n' \
        'Query = Process.Path == "test" and Process.CommandLine == "test" and Process.Hash.IMP == "test"\n' \
        'GenericProperty1 = Process.Hash.IMP\n'

    assert uberagent(processing_pipeline=uberagent_pipeline()).convert(
        SigmaCollection.from_yaml("""
            title: Test
            id: 0750fe99-1296-4b84-a60a-6af33e74bb37
            status: test
            level: high
            logsource:
                product: windows
                category: process_creation
            detection:
                sel:
                    Image: test
                    CommandLine: test
                    Imphash: test
                condition: sel
        """), "conf"
    ) == [expected]


def test_rule_requires_id():
    with pytest.raises(MissingPropertyException):
        uberagent(processing_pipeline=uberagent_pipeline()).convert(
            SigmaCollection.from_yaml("""
                title: Test
                status: test
                logsource:
                    product: windows
                    category: process_creation
                detection:
                    sel:
                        Image: test
                    condition: sel
            """), "conf")


def test_rule_requires_title():
    with pytest.raises(MissingPropertyException):
        uberagent(processing_pipeline=uberagent_pipeline()).convert(
            SigmaCollection.from_yaml("""
                id: 0750fe99-1296-4b84-a60a-6af33e74bb37
                status: test
                logsource:
                    product: windows
                    category: process_creation
                detection:
                    sel:
                        Image: test
                    condition: sel
            """), "conf")


def test_rule_description():
    expected = \
        '[ActivityMonitoringRule]\n' \
        '# This is a test rule.\n' \
        'RuleId = 0750fe99-1296-4b84-a60a-6af33e74bb37\n' \
        'RuleName = Test\n' \
        'EventType = Process.Start\n' \
        'Tag = proc-start-test\n' \
        'Query = Process.Path == "test" and Process.CommandLine == "test"\n'

    assert uberagent(processing_pipeline=uberagent_pipeline()).convert(
        SigmaCollection.from_yaml("""
            id: 0750fe99-1296-4b84-a60a-6af33e74bb37
            title: Test
            description: This is a test rule.
            status: test
            logsource:
                product: windows
                category: process_creation
            detection:
                sel:
                    Image: test
                    CommandLine: test
                condition: sel
        """), "conf") == [expected]


def test_rule_annotation():
    expected = \
        '[ActivityMonitoringRule]\n' \
        '# This is a test rule.\n' \
        'RuleId = 0750fe99-1296-4b84-a60a-6af33e74bb37\n' \
        'RuleName = Test\n' \
        'EventType = Process.Start\n' \
        'Tag = proc-start-test\n' \
        'Annotation = {"mitre_attack": ["T0001", "T0002"]}\n' \
        'Query = Process.Path == "test" and Process.CommandLine == "test"\n'

    assert uberagent(processing_pipeline=uberagent_pipeline()).convert(
        SigmaCollection.from_yaml("""
            id: 0750fe99-1296-4b84-a60a-6af33e74bb37
            title: Test
            description: This is a test rule.
            status: test
            tags:
                - attack.t0001
                - attack.t0002
                - attack.defense_evasion
            logsource:
                product: windows
                category: process_creation
            detection:
                sel:
                    Image: test
                    CommandLine: test
                condition: sel
        """), "conf") == [expected]
