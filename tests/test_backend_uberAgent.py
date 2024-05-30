import pytest
from sigma.collection import SigmaCollection
from sigma.backends.uberagent import uberagent


@pytest.fixture
def uberAgent_backend():
    return uberagent()


def test_uberAgent_and_expression(uberAgent_backend: uberagent):
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


def test_uberAgent_or_expression(uberAgent_backend: uberagent):
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
def test_uberAgent_and_or_expression(uberAgent_backend: uberagent):
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


def test_uberAgent_or_and_expression(uberAgent_backend: uberagent):
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
def test_uberAgent_in_expression(uberAgent_backend: uberagent):
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
    ) == ['fieldA == "valueA" or fieldA == "valueB" or fieldA like r"valueC%"']


def test_uberAgent_cidr_query(uberAgent_backend: uberagent):
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
    ) == ['field like r"192.168.%"']


def test_uberAgent_null_query(uberAgent_backend: uberagent):
    assert uberAgent_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    field: null
                condition: sel
        """)
    ) == ['isnull(field)']


def test_uberAgent_not_null_query(uberAgent_backend: uberagent):
    assert uberAgent_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    field: null
                condition: not sel
        """)
    ) == ['not isnull(field)']


def test_uberAgent_regex_query1(uberAgent_backend: uberagent):
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
    ) == ['fieldA regex "foo.*bar" and fieldB == "foo"']


def test_uberAgent_regex_query2(uberAgent_backend: uberagent):
    assert uberAgent_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    field|re: '[A-Z]'
                condition: not sel
        """)
    ) == ['not field regex "[A-Z]"']


def test_uberAgent_regex_query3(uberAgent_backend: uberagent):
    assert uberAgent_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    field|re: '"([^"]*)"'
                condition: not sel
        """)
    ) == ['not field regex "\\"([^\\"]*)\\""']


def test_uberAgent_wildcard_match_expression(uberAgent_backend: uberagent):
    assert uberAgent_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    field|endswith:
                      - 'Test*Field'
                condition: sel
        """)
    ) == ['field like r"%Test%Field"']
