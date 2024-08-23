# This file is Copyright 2024 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

from typing import List
import logging, os
from volatility3.framework import constants
from volatility3.framework.renderers import conversion
from volatility3.framework.configuration import requirements
from volatility3.framework.symbols import intermed
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

    @classmethod
    def parse_hibernation_header(cls, hibernation_header):
        if hibernation_header.PageSize == 4096:
            system_time = hibernation_header.SystemTime
            wintime = (system_time.High1Time << 32) | system_time.LowPart
            system_time = conversion.wintime_to_datetime(wintime)

            comment = "The hibernation file header signature is correct."
            return (
                ("Comment", comment),
                ("PageSize", str(hibernation_header.PageSize)),
                ("SystemTime", str(system_time)),
                ("FirstBootRestorePage", str(hibernation_header.FirstBootRestorePage)),
                ("NumPageForLoader", str(hibernation_header.NumPagesForLoader)),
            )
        elif hibernation_header.PageSize == 2048:
            comment = "The hibernation file is correct but x32 extraction isn't available yet."
        else:
            comment = "The hibernation file seems corrupted."
        return (
            ("Comment", comment),
            ("PageSize", str(hibernation_header.PageSize)),
        )

    def _generator(self):
        base_layer = self.context.layers["base_layer"]
        symbol_table = intermed.IntermediateSymbolTable.create(
            self.context,
            self.config_path,
            os.path.join("windows", "hibernation"),
            filename="header",
        )
        hibernation_header_object = (
            symbol_table + constants.BANG + "PO_MEMORY_IMAGE_HEADER"
        )
        hibernation_header = self.context.object(
            hibernation_header_object, offset=0, layer_name=base_layer.name
        )
        signature = hibernation_header.Signature.cast(
            "string", max_length=4, encoding="latin-1"
        )
        yield (0, ("Signature", signature))
        if signature == "HIBR":
            for field in self.parse_hibernation_header(hibernation_header):
                yield (0, field)
        elif signature == "RSTR":
            yield (
                0,
                (
                    "Comment : ",
                    "RSTR : The hibernation file was extracted when Windows was in a resuming state which makes it not exploitable.",
                ),
            )
        else:
            yield (
                0,
                ("Comment : ", "The file is not an hibernation file or is corrupted."),
            )

    def run(self):
        return renderers.TreeGrid(
            [("Variable", str), ("Value", str)], self._generator()
        )


class Dump(plugins.PluginInterface):
    """Plugin to convert an hiberfil.sys to a raw file"""

    _required_framework_version = (2, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.PluginRequirement(
                name="layerwriter", plugin=layerwriter.LayerWriter, version=(2, 0, 0)
            ),
            requirements.IntRequirement(
                name="version",
                description="The Windows version of the hibernation file : 0=>[Windows 10 1703 to Windows 11 23H2] 1=>[Windows 8/8.1] 2=>[Windows 10 1507 to 1511] 3=>[Windows 10 1607]",
                optional=False,
            ),
            requirements.TranslationLayerRequirement(
                name="memory_layer", optional=False
            ),
        ]

    def _generator(self):
        """
        Check if the memory_layer is indeed the HibernationLayer, then perform the conversion using layerwritter.
        """
        if self.context.layers["memory_layer"].__class__.__name__ == "HibernationLayer":
            output_name = self.config.get("output", ".".join(["memory_layer", "raw"]))
            try:
                file_handle = layerwriter.LayerWriter.write_layer(
                    self.context,
                    "memory_layer",
                    output_name,
                    self.open,
                    self.config.get(
                        "block_size", layerwriter.LayerWriter.default_block_size
                    ),
                    progress_callback=self._progress_callback,
                )
                file_handle.close()
            except IOError as excp:
                yield 0, (
                    f"Layer cannot be written to {self.config['output_name']}: {excp}",
                )
            yield 0, (f"The hibernation file was converted to {output_name}",)
        else:
            yield (
                0,
                (
                    """Your hibernation file could not be converted, this can be the case for multiple reasons:
                    - The hibernation file you are trying to dump is corrupted.
                    - The version you provided is not expected (see --help).
                    - The file you are trying to dump is not an hibernation file.
                    - Missing requirements: Make sure all the requirements are installed (requirements.txt).
                    """,
                ),
            )

    def run(self):
        return renderers.TreeGrid([("Status", str)], self._generator())
