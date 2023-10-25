from dataclasses import dataclass
from typing import Union, List

from sigma.processing.transformations import FieldMappingTransformation


@dataclass
class FieldMappingTransformationLowercase(FieldMappingTransformation):
    """
    Represents a transformation that maps fields using case-insensitive comparison.

    This class extends the basic `FieldMappingTransformation` by allowing field mapping
    to be performed in a case-insensitive manner.

    Methods:
    - get_mapping(field): Fetches the mapped value(s) for a given field considering lowercase
                          comparison of field names.
    """

    def get_mapping(self, field: str) -> Union[None, str, List[str]]:
        """
        Retrieve the mapping for the provided field using case-insensitive comparison.

        The field name is transformed to lowercase before attempting to fetch its mapping.
        This ensures that the field mapping is case-insensitive.

        Parameters:
        - field (str): The field name for which the mapping should be fetched.

        Returns:
        - Union[None, str, List[str]]: Returns the mapped value(s) for the field. It could be None
                                       (if no mapping exists), a string (single mapping), or a list
                                       of strings (multiple mappings).
        """
        return super().get_mapping(field.lower())
