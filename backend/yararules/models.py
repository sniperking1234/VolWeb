# yararule/models.py
from django.db import models
from yararulesets.models import YaraRuleSet

RULE_SOURCES = (
    ("custom", "manual"),
    ("github", "github"),
)


class YaraRule(models.Model):
    """
    YaraRule Model
    Holds the important metadata about the YARA rule.
    """

    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=250)
    etag = models.CharField(max_length=256, unique=True)
    rule_content = models.TextField()
    description = models.TextField(null=True, blank=True)
    linked_yararuleset = models.ForeignKey(YaraRuleSet, on_delete=models.CASCADE, null=True)
    status = models.IntegerField(default=0)
    url = models.TextField(null=True)
    source = models.CharField(max_length=10, choices=RULE_SOURCES, null=True)
    is_active = models.BooleanField(default=True)

    def __str__(self):
        return str(self.name)