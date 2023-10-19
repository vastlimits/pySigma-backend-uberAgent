
class MissingPropertyException(Exception):
    def __init__(self, prop):
        super().__init__("The '{}' property is required!".format(prop))
