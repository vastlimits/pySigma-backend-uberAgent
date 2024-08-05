import pytest
from sigma.collection import SigmaCollection
from sigma.exceptions import SigmaLevelError, SigmaTransformationError, SigmaTitleError

from sigma.backends.uberagent import uberagent
from sigma.backends.uberagent.exceptions import MissingPropertyException, MissingFunctionException
from sigma.pipelines.uberagent import uberagent as uberagent_pipeline, uberagent600, uberagent610, uberagent620, uberagent700, uberagent710, uberagent720, uberagent730, uberagent_develop


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

def test_ua_macos():
    assert uberagent(processing_pipeline=uberagent_pipeline()).convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                product: macos
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
        '[ThreatDetectionRule platform=Windows]\n' \
        'RuleId = 01234567-1234-5678-1234-567890123456\n' \
        'RuleName = Test\n' \
        'EventType = Process.Start\n' \
        'Tag = proc-start-test\n' \
        'RiskScore = 75\n' \
        'Query = Process.Path == "test" and Process.CommandLine == "test" and Process.Hash.IMP == "test"\n' \
        'GenericProperty1 = Process.Hash.IMP\n'

    assert uberagent(processing_pipeline=uberagent_pipeline()).convert(
        SigmaCollection.from_yaml("""
            title: Test
            id: 01234567-1234-5678-1234-567890123456
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
    with pytest.raises(SigmaTitleError):
        uberagent(processing_pipeline=uberagent_pipeline()).convert(
            SigmaCollection.from_yaml("""
                id: 01234567-1234-5678-1234-567890123456
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
        '[ThreatDetectionRule platform=Windows]\n' \
        '# This is a test rule.\n' \
        'RuleId = 01234567-1234-5678-1234-567890123456\n' \
        'RuleName = Test\n' \
        'EventType = Process.Start\n' \
        'Tag = proc-start-test\n' \
        'Query = Process.Path == "test" and Process.CommandLine == "test"\n'

    assert uberagent(processing_pipeline=uberagent_pipeline()).convert(
        SigmaCollection.from_yaml("""
            id: 01234567-1234-5678-1234-567890123456
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
        '[ThreatDetectionRule platform=Windows]\n' \
        '# This is a test rule.\n' \
        'RuleId = 01234567-1234-5678-1234-567890123456\n' \
        'RuleName = Test\n' \
        'EventType = Process.Start\n' \
        'Tag = proc-start-test\n' \
        'Annotation = {"mitre_attack": ["T0001", "T0002"]}\n' \
        'Query = Process.Path == "test" and Process.CommandLine == "test"\n'

    assert uberagent(processing_pipeline=uberagent_pipeline()).convert(
        SigmaCollection.from_yaml("""
            id: 01234567-1234-5678-1234-567890123456
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


def test_rule_annotation_with_author():
    expected = \
        '[ThreatDetectionRule platform=Windows]\n' \
        '# This is a test rule.\n' \
        '# Author: Unit Test\n' \
        'RuleId = 01234567-1234-5678-1234-567890123456\n' \
        'RuleName = Test\n' \
        'EventType = Process.Start\n' \
        'Tag = proc-start-test\n' \
        'Annotation = {"mitre_attack": ["T0001", "T0002"], "author": "Unit Test"}\n' \
        'Query = Process.Path == "test" and Process.CommandLine == "test"\n'

    assert uberagent(processing_pipeline=uberagent720()).convert(
        SigmaCollection.from_yaml("""
            id: 01234567-1234-5678-1234-567890123456
            title: Test
            description: This is a test rule.
            status: test
            author: Unit Test
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


def test_rule_annotation_with_author_without_mitre_tags():
    expected = \
        '[ThreatDetectionRule platform=Windows]\n' \
        '# This is a test rule.\n' \
        '# Author: Unit Test\n' \
        'RuleId = 01234567-1234-5678-1234-567890123456\n' \
        'RuleName = Test\n' \
        'EventType = Process.Start\n' \
        'Tag = proc-start-test\n' \
        'Annotation = {"author": "Unit Test"}\n' \
        'Query = Process.Path == "test" and Process.CommandLine == "test"\n'

    assert uberagent(processing_pipeline=uberagent720()).convert(
        SigmaCollection.from_yaml("""
            id: 01234567-1234-5678-1234-567890123456
            title: Test
            description: This is a test rule.
            status: test
            author: Unit Test
            logsource:
                product: windows
                category: process_creation
            detection:
                sel:
                    Image: test
                    CommandLine: test
                condition: sel
        """), "conf") == [expected]


# Test "common" rule without specific product.
def test_rule_network_any_common():
    expected = \
        '[ThreatDetectionRule]\n' \
        'RuleId = 01234567-1234-5678-1234-567890123456\n' \
        'RuleName = Test\n' \
        'EventType = Net.Any\n' \
        'Tag = test\n' \
        'RiskScore = 75\n' \
        'Query = Net.Target.Ip in ["1.1.1.1", "2.2.2.2"]\n' \
        'GenericProperty1 = Net.Target.Ip\n'

    assert uberagent(processing_pipeline=uberagent_pipeline()).convert(
        SigmaCollection.from_yaml("""
            title: Test
            id: 01234567-1234-5678-1234-567890123456
            status: test
            level: high
            logsource:
                category: firewall
            detection:
                select_outgoing:
                    dst_ip:
                        - '1.1.1.1'
                        - '2.2.2.2'
                condition: 1 of select*
        """), "conf"
    ) == [expected]


def test_rule_unknown_risk_score():
    with pytest.raises(SigmaLevelError):
        assert uberagent(processing_pipeline=uberagent_pipeline()).convert(
            SigmaCollection.from_yaml("""
                title: Test
                id: 01234567-1234-5678-1234-567890123456
                status: test
                level: undefined
                logsource:
                    category: firewall
                detection:
                    select_outgoing:
                        dst_ip:
                            - '1.1.1.1'
                            - '2.2.2.2'
                    condition: 1 of select*
            """), "conf"
        )


def test_rule_not_supported():
    with pytest.raises(Exception):
        assert uberagent(processing_pipeline=uberagent600()).convert(
            SigmaCollection.from_yaml("""
                title: Test
                id: 01234567-1234-5678-1234-567890123456
                status: test
                level: high
                logsource:
                    product: macos
                    category: process_creation
                detection:
                    sel:
                        Image: test
                        CommandLine: test
                    condition: sel
            """), "conf"
        )


def test_uberagent600():
    assert uberagent(processing_pipeline=uberagent600()).convert(
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


def test_uberagent610():
    assert uberagent(processing_pipeline=uberagent610()).convert(
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


def test_uberagent620():
    assert uberagent(processing_pipeline=uberagent620()).convert(
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


def test_uberagent700():
    assert uberagent(processing_pipeline=uberagent700()).convert(
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


def test_uberagent710():
    assert uberagent(processing_pipeline=uberagent710()).convert(
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


def test_uberagent720():
    assert uberagent(processing_pipeline=uberagent720()).convert(
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


def test_uberagent730():
    assert uberagent(processing_pipeline=uberagent730()).convert(
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


def test_uberagent_develop():
    assert uberagent(processing_pipeline=uberagent_develop()).convert(
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


def test_uberagent_620_isnull():
    with pytest.raises(MissingFunctionException):
        uberagent(processing_pipeline=uberagent620()).convert(
            SigmaCollection.from_yaml("""
                title: Test
                status: test
                logsource:
                    product: windows
                    category: process_creation
                detection:
                    sel:
                        Image: null
                    condition: sel
            """), "conf")


def test_uberagent_registry_createkey():
    assert uberagent(processing_pipeline=uberagent720()).convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                product: windows
                category: registry_set
            detection:
                sel:
                    EventType: CreateKey
                condition: sel
        """)) == ['Reg.EventType == "CreateKey"']


def test_uberagent_registry_deletekey():
    assert uberagent(processing_pipeline=uberagent720()).convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                product: windows
                category: registry_set
            detection:
                sel:
                    EventType: DeleteKey
                condition: sel
        """)) == ['Reg.EventType == "DeleteKey"']


def test_uberagent_registry_renamekey():
    assert uberagent(processing_pipeline=uberagent720()).convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                product: windows
                category: registry_set
            detection:
                sel:
                    EventType: RenameKey
                condition: sel
        """)) == ['Reg.EventType == "RenameKey"']


def test_uberagent_registry_deletevalue():
    assert uberagent(processing_pipeline=uberagent720()).convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                product: windows
                category: registry_set
            detection:
                sel:
                    EventType: DeleteValue
                condition: sel
        """)) == ['Reg.EventType == "DeleteValue"']


def test_uberagent_registry_setvalue():
    assert uberagent(processing_pipeline=uberagent720()).convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                product: windows
                category: registry_set
            detection:
                sel:
                    EventType: SetValue
                condition: sel
        """)) == ['Reg.EventType == "SetValue"']


def test_uberagent_registry_unsupported_createvalue():
    with pytest.raises(SigmaTransformationError):
        uberagent(processing_pipeline=uberagent720()).convert(
            SigmaCollection.from_yaml("""
                title: Test
                status: test
                logsource:
                    product: windows
                    category: registry_set
                detection:
                    sel:
                        EventType: CreateValue
                    condition: sel
            """))


def test_uberagent_registry_unsupported_renamevalue():
    with pytest.raises(SigmaTransformationError):
        uberagent(processing_pipeline=uberagent720()).convert(
            SigmaCollection.from_yaml("""
                title: Test
                status: test
                logsource:
                    product: windows
                    category: registry_set
                detection:
                    sel:
                        EventType: RenameValue
                    condition: sel
            """))
