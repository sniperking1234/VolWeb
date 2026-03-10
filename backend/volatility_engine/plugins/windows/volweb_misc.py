import json
import logging
import importlib
import signal
import time
from typing import Dict, Any, List, Tuple, Optional
from volatility3.framework import interfaces
from volatility3.framework.interfaces import plugins
from volatility3.framework.configuration import requirements
from volatility3.framework.renderers import TreeGrid
from volatility_engine.utils import DjangoRenderer
from volatility_engine.models import VolatilityPlugin
from volatility3.plugins import yarascan
from evidences.models import Evidence

vollog = logging.getLogger(__name__)


class VolWebMisc(plugins.PluginInterface):
    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)

    def load_plugin_info(self, json_file_path):
        with open(json_file_path, "r") as file:
            return json.load(file).get("plugins", {}).get("windows", [])

    @classmethod
    def get_requirements(cls):
        return [
            requirements.TranslationLayerRequirement(
                name="primary",
                description="Memory layer for the kernel",
                architectures=["Intel32", "Intel64"],
            )
        ]

    def dynamic_import(self, module_name):
        module_path, class_name = module_name.rsplit(".", 1)
        module = importlib.import_module(module_path)
        return getattr(module, class_name)

    def run_all(self):
        volweb_plugins = self.load_plugin_info("volatility_engine/volweb_misc.json")

        # Filter to selected plugins if specified via context config
        selected_json = self.context.config.get("VolWeb.SelectedPlugins", None)
        if selected_json:
            selected = json.loads(selected_json)
            volweb_plugins = {
                name: details for name, details in volweb_plugins.items()
                if name in selected
            }

        instances = {}
        for plugin, details in volweb_plugins.items():
            try:
                plugin_class = self.dynamic_import(plugin)
                instances[plugin] = {
                    "class": plugin_class(self.context, self.config_path),
                    "details": details,
                }
                instances[plugin]["details"]["name"] = plugin
            except ImportError as e:
                vollog.error(f"Could not import {plugin}: {e}")

        evidence_id = self.context.config["VolWeb.Evidence"]
        evidence = Evidence.objects.get(id=evidence_id)

        # Read optional per-plugin timeout (in seconds)
        plugin_timeout = self.context.config.get("VolWeb.PluginTimeout", None)

        for name, plugin in instances.items():
            # Pause/Stop check
            evidence.refresh_from_db()
            while evidence.extraction_control == "paused":
                time.sleep(3)
                evidence.refresh_from_db()
                if evidence.extraction_control == "stop_requested":
                    break
            if evidence.extraction_control == "stop_requested":
                vollog.info(f"Stop requested — halting extraction for evidence {evidence_id}")
                break

            try:
                vollog.info(f"RUNNING: {name}")
                if plugin_timeout:
                    def _timeout_handler(signum, frame):
                        raise TimeoutError(f"Plugin timed out after {plugin_timeout} seconds")
                    old_handler = signal.signal(signal.SIGALRM, _timeout_handler)
                    signal.alarm(int(plugin_timeout))
                    try:
                        self._grid = plugin["class"].run()
                        renderer = DjangoRenderer(
                            evidence_id=evidence_id,
                            plugin=plugin["details"],
                        )
                        renderer.render(self._grid)
                    finally:
                        signal.alarm(0)
                        signal.signal(signal.SIGALRM, old_handler)
                else:
                    self._grid = plugin["class"].run()
                    renderer = DjangoRenderer(
                        evidence_id=evidence_id,
                        plugin=plugin["details"],
                    )
                    renderer.render(self._grid)
            except Exception as e:
                vollog.error(f"FAILED: {name}: {e}")
                VolatilityPlugin.objects.update_or_create(
                    name=name,
                    evidence=evidence,
                    defaults={
                        "icon": plugin["details"].get("icon", "None"),
                        "description": plugin["details"].get("description", ""),
                        "artefacts": None,
                        "category": plugin["details"].get("category", "Other"),
                        "display": plugin["details"].get("display", "True"),
                        "results": False,
                        "error_message": str(e),
                    },
                )

    def _generator(self):
        yield (0, ("Success",))

    def run(self):
        self.run_all()
        return TreeGrid(
            [("Status", str)],
            self._generator(),
        )
