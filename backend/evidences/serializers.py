from rest_framework import serializers
from .models import Evidence
from cases.serializers import CaseSerializer

class EvidenceSerializer(serializers.ModelSerializer):
    linked_case_details = CaseSerializer(source='linked_case', read_only=True)
    
    class Meta:
        model = Evidence
        fields = "__all__"
        
    def to_representation(self, instance):
        data = super().to_representation(instance)
        
        request = self.context.get('request')
        if request and request.query_params.get('include_case_details'):
            data['linked_case_details'] = CaseSerializer(instance.linked_case).data
        else:
            data['linked_case_name'] = instance.linked_case.name if instance.linked_case else None
            
        return data


class BindEvidenceSerializer(serializers.ModelSerializer):
    class Meta:
        model = Evidence
        fields = "__all__"
        extra_kwargs = {
            "access_key_id": {"write_only": True},
            "access_key": {"write_only": True},
            "etag": {"read_only": True},
            "name": {"read_only": True},
        }
