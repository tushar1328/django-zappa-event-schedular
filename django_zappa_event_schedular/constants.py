from django.db import models


class AWSRateChoices(models.TextChoices):
    MINUTE = "minute"
    MINUTES = "minutes"
    HOUR = "hour"
    HOURS = "hours"
    DAY = "day"
    DAYS = "days"
