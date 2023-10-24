from typing import List

from sigma.processing.conditions import LogsourceCondition


class Category:
    def __init__(self, version: str, name: str, conditions: List[LogsourceCondition] = []):
        self.version = version
        self.name = name
        self.conditions = conditions

    def __str__(self):
        return self.name
