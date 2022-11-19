from django.contrib import admin

from django_zappa_event_schedular.models import Schedular


class SchedularAdmin(admin.ModelAdmin):
    list_display = ("function","pk","rate",)
    readonly_fields = ("resulting_config",)


admin.site.register(Schedular, SchedularAdmin)
