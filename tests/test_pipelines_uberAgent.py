import pytest
from sigma.collection import SigmaCollection

from sigma.backends.uberAgent import uberAgentBackend
from sigma.pipelines.uberAgent import uberAgentPipeline


def test_ua_windows():
    assert uberAgentBackend(processing_pipeline=uberAgentPipeline()).convert(
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


def test_ua_windows_conf():
    assert uberAgentBackend(processing_pipeline=uberAgentPipeline()).convert(
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
        """), "conf"
    ) == ['Process.Path == "test" and Process.CommandLine == "test"']
