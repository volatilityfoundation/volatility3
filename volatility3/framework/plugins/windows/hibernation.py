# This file is Copyright 2022 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

from typing import List
import logging
from volatility3.framework.renderers import conversion
from volatility3.framework.configuration import requirements
from volatility3.framework import interfaces, renderers
from volatility3.framework.interfaces import plugins
from volatility3.plugins import layerwriter


vollog = logging.getLogger(__name__)

class Info(plugins.PluginInterface):
    """Plugin to parse an hiberfil.sys to make sure it is safe to be converted to a raw file and not corrupted"""

    _required_framework_version = (2, 0, 0)
    _version = (2, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.TranslationLayerRequirement(name="base_layer", optional=False),
        ]

    def _generator(self):
        base_layer = self.context.layers["base_layer"]
        header = base_layer.read(0, 4)
        yield (0, ("Signature", str(header)))
        if header == b'HIBR':
            # The hibernation file seems exploitable. Next step is to extract important information for the examiner
            PageSize = int.from_bytes(base_layer.read(0x18, 4), "little")
            yield (0, ("PageSize", str(PageSize)))
            if PageSize == 4096:
                yield (0, ("Comment", "The hibernation file header signature is correct."))
                system_time = int.from_bytes(base_layer.read(0x020, 8), "little")
                systemTime = conversion.wintime_to_datetime(system_time)
                yield (0, ("System Time", str(systemTime)))
                FirstBootRestorePage = int.from_bytes(base_layer.read(0x068, 8), "little") 
                yield (0, ("FirstBootRestorePage", str(hex(FirstBootRestorePage))))
                NumPagesForLoader = int.from_bytes(base_layer.read(0x058, 8), "little")
                yield (0, ("NumPagesForLoader", str(NumPagesForLoader)))
            elif PageSize == 2048:
                yield (0, ("Comment", "The hibernation file header signature is correct but x32 compatibility is not available yet."))
            else:
                yield (0, ("Comment : ", "The file is corrupted."))
        elif header == b'RSTR':
            # The hibernation file was extracted when Windows was in a resuming state which makes it not exploitable
            yield (0, ("Comment : ", "The hibernation file header signature is 'RSTR', the file cannot be exploited."))
        else:
            yield (0, ("Comment : ", "The file is not an hibernation file or is corrupted."))
    def run(self):
        return renderers.TreeGrid([("Variable", str), ("Value", str)], self._generator())
    

class Dump(plugins.PluginInterface):
    """Plugin to parse an hiberfil.sys to make sure it is safe to be converted to a raw file and not corrupted"""
    _required_framework_version = (2, 0, 0)
    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.PluginRequirement(
                name="hibernation", plugin=Info, version=(2, 0, 0)
            ),
            requirements.PluginRequirement(
                name="layerwriter", plugin=layerwriter.LayerWriter, version=(2, 0, 0)
            ),
            requirements.IntRequirement(
                name="version",
                description="The Windows version of the hibernation file : 0=>[Windows 10 1703 to Windows 11 23H2] 1=>[Windows 8/8.1] 2=>[Windows 10 1507 to 1511] 3=>[Windows 10 1607]",
                optional=False,
            ),
            requirements.TranslationLayerRequirement(name="memory_layer", optional=False)
        ]

    def _generator(self):
        base_layer = self.context.layers["base_layer"]
        header = base_layer.read(0, 4)
        if header == b'HIBR':
            # Choose the most recently added layer that isn't virtual
            self.config["layers"] = []
            for name in self.context.layers:
                if not self.context.layers[name].metadata.get("mapped", False):
                    self.config["layers"] = [name]
            for name in self.config["layers"]:
                # Check the layer exists and validate the output file
                if name not in self.context.layers:
                    yield 0, (f"Layer Name {name} does not exist",)
                else:
                    output_name = self.config.get("output", ".".join([name, "raw"]))
                    try:
                        file_handle = layerwriter.LayerWriter.write_layer(
                            self.context,
                            name,
                            output_name,
                            self.open,
                            self.config.get("block_size", layerwriter.LayerWriter.default_block_size),
                            progress_callback=self._progress_callback,
                        )
                        file_handle.close()
                    except IOError as excp:
                        yield 0, (
                            f"Layer cannot be written to {self.config['output_name']}: {excp}",
                        )

                    yield 0, (f"The hibernation file was converted to {output_name}",)
        elif header == b'RSTR':
            yield (0, ("The hibernation file header signature is 'RSTR', the file cannot be exploited."))
        else:
            yield (0, ("The file is not an hibernation file or is corrupted."))

    def run(self):
        return renderers.TreeGrid([("Status", str)], self._generator())