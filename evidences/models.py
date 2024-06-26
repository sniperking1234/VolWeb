from django.db import models
from cases.models import Case

OS = (
    ("Windows", "Windows"),
    ("Linux", "Linux"),
    #   ('MacOs', 'MacOs'), <- not implemented yet
)

SOURCES = (
    ("AWS","AWS"),
    ("MINIO","MINIO"),
)

class Evidence(models.Model):
    """
    Evidence Model
    Holds the important metadata about the memory image.
    """
    dump_id = models.AutoField(primary_key=True)
    dump_name = models.CharField(max_length=250)
    dump_etag = models.CharField(max_length=256)
    dump_os = models.CharField(max_length=10, choices=OS)
    dump_linked_case = models.ForeignKey(Case, on_delete=models.CASCADE, null=False)
    dump_status = models.IntegerField(default=0)
    dump_logs = models.JSONField(null=True)
    dump_access_key_id = models.TextField(null=True)
    dump_access_key = models.TextField(null=True)
    dump_url  = models.TextField(null=True)
    dump_region = models.TextField(null=True)
    dump_endpoint = models.TextField(null=True)
    dump_source = models.CharField(max_length=10,choices=SOURCES, null=True)
    def __str__(self):
        return str(self.dump_name)
