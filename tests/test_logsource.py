import pytest

from sigma.pipelines.uberagent.logsource import Logsource

def test_logsource_str():
   assert str(Logsource("1.0.0", "Test.Event", conditions=[], fields={})) == "Test.Event"

