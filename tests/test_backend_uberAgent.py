import pytest
from sigma.collection import SigmaCollection
from sigma.backends.uberAgent import uberAgentBackend


@pytest.fixture
def uberAgent_backend():
    return uberAgentBackend()


# TODO: implement tests for some basic queries and their expected results.
def test_uberAgent_and_expression(uberAgent_backend: uberAgentBackend):
    assert uberAgent_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA: valueA
                    fieldB: valueB
                condition: sel
        """)
    ) == ['fieldA == "valueA" and fieldB == "valueB"']


def test_uberAgent_or_expression(uberAgent_backend: uberAgentBackend):
    assert uberAgent_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel1:
                    fieldA: valueA
                sel2:
                    fieldB: valueB
                condition: 1 of sel*
        """)
    ) == ['fieldA == "valueA" or fieldB == "valueB"']


# This 'and' 'or' is simplified to an in expression which is correct.
def test_uberAgent_and_or_expression(uberAgent_backend: uberAgentBackend):
    assert uberAgent_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA:
                        - valueA1
                        - valueA2
                    fieldB:
                        - valueB1
                        - valueB2
                condition: sel
        """)
    ) == ['(fieldA in ["valueA1", "valueA2"]) and (fieldB in ["valueB1", "valueB2"])']


def test_uberAgent_or_and_expression(uberAgent_backend: uberAgentBackend):
    assert uberAgent_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel1:
                    fieldA: valueA1
                    fieldB: valueB1
                sel2:
                    fieldA: valueA2
                    fieldB: valueB2
                condition: 1 of sel*
        """)
    ) == ['fieldA == "valueA1" and fieldB == "valueB1" or fieldA == "valueA2" and fieldB == "valueB2"']


# This 'in' expression cannot be simplified in uAQL as it does not support wildcards using 'in' clause.
def test_uberAgent_in_expression(uberAgent_backend: uberAgentBackend):
    assert uberAgent_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA:
                        - valueA
                        - valueB
                        - valueC*
                condition: sel
        """)
    ) == ['fieldA == "valueA" or fieldA == "valueB" or istartswith(fieldA, "valueC")']


def test_uberAgent_regex_query(uberAgent_backend: uberAgentBackend):
    assert uberAgent_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA|re: foo.*bar
                    fieldB: foo
                condition: sel
        """)
    ) == ['<insert expected result here>']


def test_uberAgent_cidr_query(uberAgent_backend: uberAgentBackend):
    assert uberAgent_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    field|cidr: 192.168.0.0/16
                condition: sel
        """)
    ) == ['istartswith(field, "192.168.")']


# TODO: implement tests for all backend features that don't belong to the base class defaults, e.g. features that were
