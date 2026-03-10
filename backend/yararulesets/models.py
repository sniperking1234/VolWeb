# yararuleset/models.py
from django.db import models
import uuid

class YaraRuleSet(models.Model):
    """Model for YARA rule sets/collections"""
    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=200, unique=True)
    description = models.TextField(blank=True, null=True)
    is_default = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    compiled_rules = models.BinaryField(null=True, blank=True)
    status = models.IntegerField(default=0)

    
    def __str__(self):
        return self.name
    
    class Meta:
        ordering = ['-created_at']
        
class UploadSession(models.Model):
    upload_id = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    filename = models.CharField(max_length=255)
    description = models.TextField(blank=True, null=True)
    yararuleset = models.ForeignKey(YaraRuleSet, on_delete=models.CASCADE, null=True, blank=True)
    source = models.CharField(max_length=255, null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return str(self.upload_id)