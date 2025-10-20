# yararuleset/serializers.py
from rest_framework import serializers
from .models import YaraRuleSet

class YaraRuleSetSerializer(serializers.ModelSerializer):
    class Meta:
        model = YaraRuleSet
        fields = '__all__'
        read_only_fields = ('created_at', 'updated_at')
        
        
class InitiateUploadSerializer(serializers.Serializer):
    filename = serializers.CharField(max_length=255)
    description = serializers.CharField(max_length=255,required=False, allow_blank=True, default="")
    yara_ruleset_id = serializers.IntegerField(required=False, allow_null=True, default=None)
    source = serializers.CharField(max_length=255)

class UploadChunkSerializer(serializers.Serializer):
    upload_id = serializers.UUIDField()
    part_number = serializers.IntegerField()
    chunk = serializers.FileField()


class CompleteUploadSerializer(serializers.Serializer):
    upload_id = serializers.UUIDField()
