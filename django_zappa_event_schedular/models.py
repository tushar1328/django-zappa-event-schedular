import json

from django.db import models
from django.db.models.signals import post_save
from django.utils.safestring import mark_safe

from django_zappa_event_schedular import validators
from django_zappa_event_schedular.constants import AWSRateChoices
from django_zappa_event_schedular.utils import schedule_events


class AbstractSchedular(models.Model):
    function = models.CharField(max_length=255, null=False, blank=False)
    args = models.TextField(default="[]", validators=[validators.validate_args])
    kwargs = models.TextField(default="{}", validators=[validators.validate_kwargs])
    rate_value = models.IntegerField(default=1)
    rate_unit = models.CharField(max_length=20, null=False, default=AWSRateChoices.HOUR, choices=AWSRateChoices.choices)
    is_active = models.BooleanField(default=True)

    def __str__(self):
        return f'{self.pk}-{self.function}'

    class Meta:
        abstract = True


class Schedular(AbstractSchedular):
    pass

    @property
    def rate(self):
        return f"rate({self.rate_value} {self.rate_unit})"

    @property
    def resulting_config(self) -> str:
        try:
            config_as_str = json.dumps(self.get_event_config, indent=4)
        except Exception as e:
            config_as_str = f'Could not render config: {e}'
        return mark_safe(config_as_str.replace("\n", "<br>").replace("    ", "&nbsp;&nbsp;&nbsp;&nbsp;"))

    @property
    def get_event_config(self):
        config = {
            'function': f"{self.pk}-{self.function}",
            'kwargs': json.loads(str(self.kwargs)),
            'expression': f"{self.rate}"
        }
        return config


post_save.connect(schedule_events, sender=Schedular)
