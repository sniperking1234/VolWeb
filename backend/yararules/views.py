from rest_framework import viewsets, status
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from django.http import HttpResponse
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework.decorators import action
from .models import YaraRule
from .serializers import YaraRuleSerializer
import yara
import logging

logger = logging.getLogger(__name__)


class YaraRuleViewSet(viewsets.ModelViewSet):
    permission_classes = (IsAuthenticated,)
    queryset = YaraRule.objects.all()
    serializer_class = YaraRuleSerializer
    filter_backends = [DjangoFilterBackend]
    filterset_fields = ['linked_yararuleset', 'is_active', 'status', 'source']
    
    def get_queryset(self):
        """
        Optionally filter rules by linked_yararuleset.
        This allows filtering rules that belong to a specific ruleset.
        """

        queryset = super().get_queryset()
        
        # Check if linked_yararuleset parameter is in the request
        linked_yararuleset = self.request.query_params.get('linked_yararuleset', None)
        
        if linked_yararuleset is not None:
            # Filter for rules with the specified ruleset
            queryset = queryset.filter(linked_yararuleset=linked_yararuleset)
            
        return queryset
    
    @action(detail=False, methods=['post'])
    def validate(self, request):
        """
        Validate YARA rule content without saving.
        Expected payload: { "rule_content": "rule test { condition: true }" }
        """
        rule_content = request.data.get('rule_content', '')
        
        if not rule_content or not rule_content.strip():
            return Response(
                {'valid': False, 'error': 'Rule content cannot be empty'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        try:
            # Try to compile the rule
            yara.compile(source=rule_content)
            return Response({'valid': True})
        
        except yara.SyntaxError as e:
            logger.warning(f"YARA syntax error during validation: {e}")
            error_msg = str(e)
            # Extract line number if available
            if 'line' in error_msg.lower():
                return Response({
                    'valid': False,
                    'error': f"Syntax error: {error_msg}",
                    'type': 'syntax'
                })
            return Response({
                'valid': False,
                'error': f"Syntax error in YARA rule: {error_msg}",
                'type': 'syntax'
            })
        
        except yara.Error as e:
            logger.warning(f"YARA compilation error during validation: {e}")
            return Response({
                'valid': False,
                'error': f"Compilation error: {str(e)}",
                'type': 'compilation'
            })
        
        except Exception as e:
            logger.error(f"Unexpected error during YARA validation: {e}")
            return Response({
                'valid': False,
                'error': 'Unexpected error during validation',
                'type': 'unknown'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    @action(detail=True, methods=['post'])
    def recompile(self, request, pk=None):
        """
        Trigger recompilation of a YARA rule.
        """
        try:
            rule = self.get_object()
            
            # Reset status to trigger recompilation
            rule.status = 0
            rule.save()
            
            # Trigger validation through Celery task
            from volatility_engine.tasks import start_yararule_validation
            start_yararule_validation.delay(rule.id)
            
            # Also trigger ruleset recompilation if linked
            if rule.linked_yararuleset:
                rule.linked_yararuleset.status = 0
                rule.linked_yararuleset.save()
                
                from volatility_engine.tasks import start_ruleset_validation
                start_ruleset_validation.delay(rule.linked_yararuleset.id)
            
            return Response({
                'message': 'Recompilation started successfully',
                'rule_id': rule.id,
                'ruleset_id': rule.linked_yararuleset.id if rule.linked_yararuleset else None
            })
            
        except Exception as e:
            logger.error(f"Error triggering recompilation: {e}")
            return Response(
                {'error': f'Failed to start recompilation: {str(e)}'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    @action(detail=True, methods=['get'])
    def download(self, request, pk=None):
        """
        Download a single YARA rule as .yar file
        """
        try:
            rule = self.get_object()
            
            # Create the response with the rule content
            response = HttpResponse(rule.rule_content, content_type='text/plain')
            response['Content-Disposition'] = f'attachment; filename="{rule.name}.yar"'
            
            return response
            
        except Exception as e:
            return Response(
                {'error': f'Failed to download rule: {str(e)}'}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )