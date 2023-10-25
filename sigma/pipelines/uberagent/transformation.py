from dataclasses import dataclass
from typing import Union, List

from sigma.exceptions import SigmaTransformationError
from sigma.processing.transformations import FieldMappingTransformation, DetectionItemTransformation
from sigma.rule import SigmaDetectionItem


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


@dataclass
class FieldDetectionItemFailureTransformation(DetectionItemTransformation):
    """
    A transformation that raises an error for a specific Sigma detection item.

    When the transformation is applied, it raises a `SigmaTransformationError` with
    a specified error message. This class is intended for situations where a detection
    item is known to be unsupported or problematic and needs to be flagged during
    processing.

    Attributes:
    - message (str): The error message template that will be formatted with the
                     detection item's field and raised as a `SigmaTransformationError`.

    Methods:
    - apply_detection_item: Applies the transformation to a given Sigma detection item.
    """
    message: str

    def apply_detection_item(self, detection_item: SigmaDetectionItem) -> None:
        """
        Applies the transformation to the provided detection item.

        This method raises a `SigmaTransformationError` using the `message` attribute
        formatted with the detection item's field.

        Parameters:
        - detection_item (SigmaDetectionItem): The Sigma detection item to be transformed.

        Raises:
        - SigmaTransformationError: Raised with the formatted message.
        """
        raise SigmaTransformationError(self.message.format(detection_item.field))
