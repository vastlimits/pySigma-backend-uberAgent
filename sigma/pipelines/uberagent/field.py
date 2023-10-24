class Field:
    def __init__(self, version: str, name: str):
        self.version = version
        self.name = name

    def __str__(self):
        return self.name

