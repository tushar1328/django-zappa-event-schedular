import json

from django.core.exceptions import ValidationError


def validate_args(value):
    try:
        json.loads(value)
    except:
        raise ValidationError("Invalid Array or list format")


def validate_kwargs(value):
    try:
        json.loads(value)
    except:
        raise ValidationError("Invalid dict format")
