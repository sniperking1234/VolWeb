from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .models import VolatilityPlugin, EnrichedProcess
from evidences.models import Evidence
from yararules.models import YaraRule
from yararulesets.models import YaraRuleSet
from .serializers import (
    VolatilityPluginDetailSerializer,
    VolatilityPluginNameSerializer,
    EnrichedProcessSerializer,
    TasksSerializer,
)
from rest_framework.permissions import IsAuthenticated
from .tasks import (
    dump_file,
    dump_process,
    start_timeliner,
    dump_windows_handles,
    dump_maps,
    start_extraction,
    start_yarascan,
    start_yararule_validation,
    start_ruleset_validation,
)
from dateutil.parser import parse as parse_date
from django_celery_results.models import TaskResult
import ast
from django.db.models import Count, Q




class EvidencePluginsView(APIView):
    permission_classes = (IsAuthenticated,)

    def get(self, request, evidence_id):
        try:
            evidence = Evidence.objects.get(id=evidence_id)
            plugins = VolatilityPlugin.objects.filter(evidence=evidence)
            serializer = VolatilityPluginNameSerializer(plugins, many=True)

            return Response(serializer.data, status=status.HTTP_200_OK)

        except Evidence.DoesNotExist:
            return Response(
                {"error": "Evidence not found"}, status=status.HTTP_404_NOT_FOUND
            )


class EnrichedProcessView(APIView):
    permission_classes = (IsAuthenticated,)

    def get(self, request, evidence_id, pid):
        try:
            evidence = Evidence.objects.get(id=evidence_id)
            enriched = EnrichedProcess.objects.get(evidence=evidence, pid=pid)
            serializer = EnrichedProcessSerializer(enriched, many=False)
            return Response(serializer.data, status=status.HTTP_200_OK)

        except Evidence.DoesNotExist:
            return Response(
                {"error": "Evidence not found"}, status=status.HTTP_404_NOT_FOUND
            )

        except EnrichedProcess.DoesNotExist:
            return Response(
                {"error": "Enriched process not found"},
                status=status.HTTP_404_NOT_FOUND,
            )


class TimelinerArtefactsView(APIView):
    permission_classes = (IsAuthenticated,)

    def get(self, request, evidence_id, plugin_name):
        try:
            evidence = Evidence.objects.get(id=evidence_id)
            plugin = VolatilityPlugin.objects.get(evidence=evidence, name=plugin_name)
            serializer = VolatilityPluginDetailSerializer(plugin)

            return Response(serializer.data, status=status.HTTP_200_OK)

        except Evidence.DoesNotExist:
            return Response(
                {"error": "Evidence not found"}, status=status.HTTP_404_NOT_FOUND
            )
        except VolatilityPlugin.DoesNotExist:
            return Response(
                {"error": "Plugin not found"}, status=status.HTTP_404_NOT_FOUND
            )


class PluginArtefactsView(APIView):
    permission_classes = (IsAuthenticated,)

    def get(self, request, evidence_id, plugin_name):
        try:
            evidence = Evidence.objects.get(id=evidence_id)
            
            # Special handling for YARA scan results to avoid duplicates
            if plugin_name == "volatility3.plugins.yarascan.latest":
                # Get the most recent one if there are duplicates
                plugin = VolatilityPlugin.objects.filter(
                    evidence=evidence, 
                    name=plugin_name
                ).order_by('-id').first()
                
                if not plugin:
                    return Response(
                        {"error": "Plugin not found"}, 
                        status=status.HTTP_404_NOT_FOUND
                    )
            else:
                plugin = VolatilityPlugin.objects.get(evidence=evidence, name=plugin_name)
                 
            artefacts = plugin.artefacts or []

            # Get start and end timestamps from query parameters
            start_timestamp = request.query_params.get("start")
            end_timestamp = request.query_params.get("end")

            # Parse and filter artefacts by the created date range
            if start_timestamp and end_timestamp:
                start_date = parse_date(start_timestamp)
                end_date = parse_date(end_timestamp)

                filtered_artefacts = [
                    artefact
                    for artefact in artefacts
                    if artefact.get("Created Date")
                    and start_date <= parse_date(artefact["Created Date"]) <= end_date
                ]
            else:
                filtered_artefacts = artefacts

            serializer = VolatilityPluginDetailSerializer(
                {"name": plugin.name, "artefacts": filtered_artefacts}
            )

            return Response(serializer.data, status=status.HTTP_200_OK)

        except Evidence.DoesNotExist:
            return Response(
                {"error": "Evidence not found"}, status=status.HTTP_404_NOT_FOUND
            )
        except VolatilityPlugin.DoesNotExist:
            return Response(
                {"error": "Plugin not found"}, status=status.HTTP_404_NOT_FOUND
            )
        except ValueError as e:
            # Handle parsing errors from dates
            return Response(
                {"error": f"Invalid date format: {str(e)}"},
                status=status.HTTP_400_BAD_REQUEST,
            )

class RestartAnalysisTask(APIView):
    permission_classes = (IsAuthenticated,)

    def post(self, request):
        try:
            evidence_id = request.data.get("id")
            evidence = Evidence.objects.get(id=evidence_id)
            start_extraction.apply_async(args=[evidence.id])
            return Response(status=status.HTTP_200_OK)
        except Evidence.DoesNotExist:
            return Response(
                {"error": "Evidence not found"}, status=status.HTTP_404_NOT_FOUND
            )


class TimelinerTask(APIView):
    permission_classes = (IsAuthenticated,)

    def post(self, request):
        try:
            evidence_id = request.data.get("id")
            evidence = Evidence.objects.get(id=evidence_id)
            start_timeliner.apply_async(args=[evidence.id])
            return Response(status=status.HTTP_200_OK)
        except Evidence.DoesNotExist:
            return Response(
                {"error": "Evidence not found"}, status=status.HTTP_404_NOT_FOUND
            )


class HandlesTask(APIView):
    permission_classes = (IsAuthenticated,)

    def post(self, request):
        try:
            evidence_id = request.data.get("evidenceId")
            pid = request.data.get("pid")
            evidence = Evidence.objects.get(id=evidence_id)
            dump_windows_handles.apply_async(args=[evidence.id, pid])
            return Response(status=status.HTTP_200_OK)
        except Evidence.DoesNotExist:
            return Response(
                {"error": "Evidence not found"}, status=status.HTTP_404_NOT_FOUND
            )


class ProcessDumpPslistTask(APIView):
    permission_classes = (IsAuthenticated,)

    def post(self, request):
        try:
            evidence_id = request.data.get("evidenceId")
            pid = request.data.get("pid")
            evidence = Evidence.objects.get(id=evidence_id)
            dump_process.apply_async(args=[evidence.id, pid])
            return Response(status=status.HTTP_200_OK)
        except Evidence.DoesNotExist:
            return Response(
                {"error": "Evidence not found"}, status=status.HTTP_404_NOT_FOUND
            )


class ProcessDumpMapsTask(APIView):
    permission_classes = (IsAuthenticated,)

    def post(self, request):
        try:
            evidence_id = request.data.get("evidenceId")
            pid = request.data.get("pid")
            evidence = Evidence.objects.get(id=evidence_id)
            dump_maps.apply_async(args=[evidence.id, pid])
            return Response(status=status.HTTP_200_OK)
        except Evidence.DoesNotExist:
            return Response(
                {"error": "Evidence not found"}, status=status.HTTP_404_NOT_FOUND
            )


class FileDumpTask(APIView):
    permission_classes = (IsAuthenticated,)

    def post(self, request):
        try:
            evidence_id = request.data.get("evidenceId")
            offset = request.data.get("offset")
            evidence = Evidence.objects.get(id=evidence_id)
            dump_file.apply_async(args=[evidence.id, offset])
            return Response(status=status.HTTP_200_OK)
        except Evidence.DoesNotExist:
            return Response(
                {"error": "Evidence not found"}, status=status.HTTP_404_NOT_FOUND
            )


class TasksApiView(APIView):
    permission_classes = (IsAuthenticated,)

    def get(self, request, evidence_id, *args, **kwargs):
        """
        Return the requested tasks if existing.
        """
        tasks = TaskResult.objects.filter(Q(status="STARTED") | Q(status="PENDING"))
        try:
            if tasks:
                filtered_tasks = [
                    task
                    for task in tasks
                    if ast.literal_eval(ast.literal_eval(task.task_args))[0]
                    == evidence_id
                ]
                serializer = TasksSerializer(filtered_tasks, many=True)
                return Response(serializer.data, status=status.HTTP_200_OK)
        except:
            return Response(status=status.HTTP_404_NOT_FOUND)
        else:
            return Response(status=status.HTTP_404_NOT_FOUND)

class RestartRuleCompilationTask(APIView):
    permission_classes = (IsAuthenticated,)

    def post(self, request):
        try:
            yararule_id = request.data.get("id")
            yararule = YaraRule.objects.get(id=yararule_id)
            start_yararule_validation.apply_async(args=[yararule.id])
    
            return Response(status=status.HTTP_200_OK)
        except YaraRule.DoesNotExist:
            return Response(
                {"error": "YaraRule not found"}, status=status.HTTP_404_NOT_FOUND
            )
            
class RestartRulesetCompilationTask(APIView):
    permission_classes = (IsAuthenticated,)

    def post(self, request):
        try:
            yararuleset_id = request.data.get("id")
            yararuleset = YaraRuleSet.objects.get(id=yararuleset_id)
            start_ruleset_validation.apply_async(args=[yararuleset.id])
            return Response(status=status.HTTP_200_OK)
        except Evidence.DoesNotExist:
            return Response(
                {"error": "Evidence not found"}, status=status.HTTP_404_NOT_FOUND
            )
            
class YaraScanTask(APIView):
    permission_classes = (IsAuthenticated,)

    def post(self, request):
        try:
            evidence_id = request.data.get("id")
            rulesets = request.data.get("rulesets", [])
            rules = request.data.get("rules", [])
            
            if not evidence_id:
                return Response(
                    {"error": "Evidence ID is required"}, 
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Verify evidence exists
            evidence = Evidence.objects.get(id=evidence_id)
            
            # Start the YARA scan task
            start_yarascan.apply_async(
                args=[evidence.id],
                kwargs={"rulesets": rulesets, "rules": rules}
            )
            
            return Response(
                {"message": "YARA scan task started successfully"},
                status=status.HTTP_200_OK
            )
            
        except Evidence.DoesNotExist:
            return Response(
                {"error": "Evidence not found"}, 
                status=status.HTTP_404_NOT_FOUND
            )
        except Exception as e:
            return Response(
                {"error": f"Failed to start YARA scan: {str(e)}"}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

class YaraScanHistoryView(APIView):
    permission_classes = (IsAuthenticated,)

    def get(self, request, evidence_id):
        """
        Get the most recent YARA scan for an evidence.

        Returns only the latest YARA scan result for the specified evidence.
        """
        try:
            # Get the latest YARA scan plugin for this evidence
            scans = VolatilityPlugin.objects.filter(
                evidence_id=evidence_id,
                name="volatility3.plugins.yarascan.latest"
            ).order_by('-id')[:1]
            
            serializer = VolatilityPluginDetailSerializer(scans, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)
            
        except Exception as e:
            return Response(
                {"error": f"Failed to fetch scan history: {str(e)}"}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    def delete(self, request, evidence_id):
        """
        Delete all YARA scans for an evidence
        """
        try:
            # Delete the YARA scan plugin for this evidence
            deleted_count = VolatilityPlugin.objects.filter(
                evidence_id=evidence_id,
                name="volatility3.plugins.yarascan.latest"
            ).delete()[0]
            
            return Response(
                {"message": f"Successfully deleted YARA scan" if deleted_count > 0 else "No YARA scan found"}, 
                status=status.HTTP_200_OK
            )
            
        except Exception as e:
            return Response(
                {"error": f"Failed to delete scan history: {str(e)}"}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class YaraScanDetailView(APIView):
    permission_classes = (IsAuthenticated,)

    def delete(self, request, evidence_id, plugin_name):
        """
        Delete a specific YARA scan
        """
        try:
            # Special handling for latest YARA scan to handle duplicates
            if plugin_name == "volatility3.plugins.yarascan.latest":
                deleted_count = VolatilityPlugin.objects.filter(
                    evidence_id=evidence_id,
                    name=plugin_name
                ).delete()[0]
            else:
                deleted_count = VolatilityPlugin.objects.filter(
                    evidence_id=evidence_id,
                    name=plugin_name
                ).delete()[0]
            
            if deleted_count == 0:
                return Response(
                    {"error": "YARA scan not found"}, 
                    status=status.HTTP_404_NOT_FOUND
                )
            
            return Response(
                {"message": f"YARA scan deleted successfully (removed {deleted_count} entries)"}, 
                status=status.HTTP_200_OK
            )
            
        except Exception as e:
            return Response(
                {"error": f"Failed to delete YARA scan: {str(e)}"}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )