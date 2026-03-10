from rest_framework import viewsets, status
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.pagination import PageNumberPagination
from rest_framework.filters import SearchFilter, OrderingFilter
from django.http import HttpResponse
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework.decorators import action
from .models import YaraRule
from .serializers import YaraRuleSerializer, YaraRuleListSerializer
import yara
import logging

from yararules.utils import batch_upload_context, trigger_delayed_ruleset_validation

logger = logging.getLogger(__name__)


class YaraRulePagination(PageNumberPagination):
    page_size = 50
    page_size_query_param = "page_size"
    max_page_size = 200


class YaraRuleViewSet(viewsets.ModelViewSet):
    permission_classes = (IsAuthenticated,)
    queryset = YaraRule.objects.select_related("linked_yararuleset").order_by("name")
    serializer_class = YaraRuleSerializer
    filter_backends = [DjangoFilterBackend, SearchFilter, OrderingFilter]
    filterset_fields = ['linked_yararuleset', 'is_active', 'status', 'source']
    search_fields = ['name', 'description']
    ordering_fields = ['name', 'status']
    pagination_class = YaraRulePagination

    def get_serializer_class(self):
        if self.action == "list":
            return YaraRuleListSerializer
        return YaraRuleSerializer

    def get_queryset(self):
        qs = super().get_queryset()
        if self.action == "list":
            qs = qs.defer("rule_content")
        return qs

    @action(detail=False, methods=["post"])
    def bulk_delete(self, request):
        """
        Delete multiple YARA rules in a single request and trigger a single
        ruleset validation per affected ruleset after deletion.
        Expected payload: { "ids": [1,2,3] }
        """
        ids = request.data.get("ids", [])
        if not isinstance(ids, list) or not ids:
            return Response({"error": "No ids provided"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            # Determine affected ruleset ids
            affected_ruleset_ids = list(
                YaraRule.objects.filter(id__in=ids).values_list("linked_yararuleset_id", flat=True)
            )
            # Filter out None and duplicates
            affected_ruleset_ids = list({r for r in affected_ruleset_ids if r})

            # Perform bulk delete inside batch context to suppress per-delete revalidation
            with batch_upload_context():
                deleted_count, _ = YaraRule.objects.filter(id__in=ids).delete()

            # Trigger a delayed validation for each affected ruleset
            for rs_id in affected_ruleset_ids:
                trigger_delayed_ruleset_validation(rs_id, delay=3, skip_rule_validation=True)

            return Response({"deleted": deleted_count}, status=status.HTTP_200_OK)

        except Exception as e:
            logging.exception("Failed to bulk delete yara rules")
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
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