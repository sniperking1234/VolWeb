from celery import shared_task
from evidences.models import Evidence
from windows_engine.models import *
from VolWeb.voltools import build_timeline, generate_network_graph
from celery.result import allow_join_result
from celery import group
import os, time

@shared_task
def start_analysis(dump_id):
    instance = Evidence.objects.get(dump_id=dump_id)
    output_path = f"media/{instance.dump_id}/"
    if not os.path.exists(os.path.dirname(output_path)):
        os.makedirs(os.path.dirname(output_path))
    evidence_data = {
        'bucket': f"s3://{str(instance.dump_linked_case.case_bucket_id)}/{instance.dump_name}",
        'output_path': output_path,
    }
    if instance.dump_os == "Windows":
        volweb_plugins = [
            PsScan(evidence=instance),
            PsTree(evidence=instance),
            DeviceTree(evidence=instance),
            CmdLine(evidence=instance),
            Privs(evidence=instance),
            Sessions(evidence=instance),
            GetSIDs(evidence=instance),
            LdrModules(evidence=instance),
            Modules(evidence=instance),
            SvcScan(evidence=instance),
            Envars(evidence=instance),
            NetScan(evidence=instance),
            NetStat(evidence=instance),
            Hashdump(evidence=instance),
            Lsadump(evidence=instance),
            Cachedump(evidence=instance),
            HiveList(evidence=instance),
            Timeliner(evidence=instance),
            SkeletonKeyCheck(evidence=instance),
            Malfind(evidence=instance),
            UserAssist(evidence=instance),
            FileScan(evidence=instance),
            DllList(evidence=instance),
            DriverModule(evidence=instance),
            VadWalk(evidence=instance),
            SSDT(evidence=instance)
        ]
        
        task_group = group(
            plugin.run.s(evidence_data) for plugin in volweb_plugins
        )
        group_result = task_group.apply_async()

        while not group_result.ready():
            completed_tasks = len([r for r in group_result.results if r.ready()])
            total_tasks = len(group_result.results)
            instance.dump_status = (completed_tasks*100)/total_tasks
            instance.save()
            time.sleep(1)

        with allow_join_result():
            result = group_result.get()
            for i in range(0, len(result)):
                volweb_plugins[i].artefacts = result[i]
                volweb_plugins[i].save()

            # We need to take care of some specific models
            if result[17]:
                TimeLineChart(evidence=instance, artefacts=build_timeline(result[17])).save()
            if result[11] and result[12]:
                NetGraph(evidence=instance, artefacts=generate_network_graph(result[11]+result[12])).save()
            else:
                if result[11]:
                    NetGraph(evidence=instance, artefacts=generate_network_graph(result[11])).save()
                if result[12]:
                    NetGraph(evidence=instance, artefacts=generate_network_graph(result[12])).save()
            instance.dump_status = 100
            instance.save() 

        