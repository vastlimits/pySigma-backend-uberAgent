from typing import List

from sigma.processing.conditions import LogsourceCondition

from sigma.pipelines.uberagent.field import Field


class Category:
    def __init__(self, version: str, name: str, conditions: List[LogsourceCondition] = [], fields: dict[str, Field] = {}):
        self.version = version
        self.name = name
        self.conditions = conditions
        self.fields = fields

    def __str__(self):
        return self.name
