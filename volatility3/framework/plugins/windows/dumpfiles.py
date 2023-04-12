# This file is Copyright 2020 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import logging
import ntpath
from typing import List, Tuple, Type, Optional, Generator

from volatility3.framework import interfaces, renderers, exceptions, constants
from volatility3.framework.configuration import requirements
from volatility3.framework.renderers import format_hints
from volatility3.plugins.windows import handles
from volatility3.plugins.windows import pslist

vollog = logging.getLogger(__name__)

FILE_DEVICE_DISK = 0x7
FILE_DEVICE_NETWORK_FILE_SYSTEM = 0x14
EXTENSION_CACHE_MAP = {
    "dat": "DataSectionObject",
    "img": "ImageSectionObject",
    "vacb": "SharedCacheMap",
}


class DumpFiles(interfaces.plugins.PluginInterface):
    """Dumps cached file contents from Windows memory samples."""

    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        # Since we're calling the plugin, make sure we have the plugin's requirements
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Windows kernel",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.IntRequirement(
                name="pid",
                description="Process ID to include (all other processes are excluded)",
                optional=True,
            ),
            requirements.IntRequirement(
                name="virtaddr",
                description="Dump a single _FILE_OBJECT at this virtual address",
                optional=True,
            ),
            requirements.IntRequirement(
                name="physaddr",
                description="Dump a single _FILE_OBJECT at this physical address",
                optional=True,
            ),
            requirements.VersionRequirement(
                name="pslist", component=pslist.PsList, version=(2, 0, 0)
            ),
            requirements.VersionRequirement(
                name="handles", component=handles.Handles, version=(1, 0, 0)
            ),
        ]

    @classmethod
    def dump_file_producer(
        cls,
        file_object: interfaces.objects.ObjectInterface,
        memory_object: interfaces.objects.ObjectInterface,
        open_method: Type[interfaces.plugins.FileHandlerInterface],
        layer: interfaces.layers.DataLayerInterface,
        desired_file_name: str,
    ) -> Optional[interfaces.plugins.FileHandlerInterface]:
        """Produce a file from the memory object's get_available_pages() interface.

        :param file_object: the parent _FILE_OBJECT
        :param memory_object: the _CONTROL_AREA or _SHARED_CACHE_MAP
        :param open_method: class for constructing output files
        :param layer: the memory layer to read from
        :param desired_file_name: name of the output file
        :return: result status
        """
        filedata = open_method(desired_file_name)
        # Description of these variables:
        #   memoffset: offset in the specified layer where the page begins
        #   fileoffset: write to this offset in the destination file
        #   datasize: size of the page

        # track number of bytes written so we don't write empty files to disk
        bytes_written = 0
        try:
            for memoffset, fileoffset, datasize in memory_object.get_available_pages():
                data = layer.read(memoffset, datasize, pad=True)
                bytes_written += len(data)
                filedata.seek(fileoffset)
                filedata.write(data)
        except exceptions.InvalidAddressException:
            vollog.debug(f"Unable to dump file at {file_object.vol.offset:#x}")
            return None
        if not bytes_written:
            vollog.debug(
                f"No data is cached for the file at {file_object.vol.offset:#x}"
            )
            return None

        vollog.debug(f"Stored {filedata.preferred_filename}")
        return filedata

    @classmethod
    def process_file_object(
        cls,
        context: interfaces.context.ContextInterface,
        primary_layer_name: str,
        open_method: Type[interfaces.plugins.FileHandlerInterface],
        file_obj: interfaces.objects.ObjectInterface,
    ) -> Generator[Tuple, None, None]:
        """Given a FILE_OBJECT, dump data to separate files for each of the three file caches.

        :param context: the context to operate upon
        :param primary_layer_name: primary/virtual layer to operate on
        :param open_method: class for constructing output files
        :param file_obj: the FILE_OBJECT
        """
        # Filtering by these types of devices prevents us from processing other types of devices that
        # use the "File" object type, such as \Device\Tcp and \Device\NamedPipe.
        if file_obj.DeviceObject.DeviceType not in [
            FILE_DEVICE_DISK,
            FILE_DEVICE_NETWORK_FILE_SYSTEM,
        ]:
            vollog.log(
                constants.LOGLEVEL_VVV,
                f"The file object at {file_obj.vol.offset:#x} is not a file on disk",
            )
            return

        # Depending on the type of object (DataSection, ImageSection, SharedCacheMap) we may need to
        # read from the memory layer or the primary layer.
        memory_layer_name = context.layers[primary_layer_name].config["memory_layer"]
        memory_layer = context.layers[memory_layer_name]
        primary_layer = context.layers[primary_layer_name]

        obj_name = file_obj.file_name_with_device()

        # This stores a list of tuples, describing what to dump and how to dump it.
        # Ex: (
        #     memory_object with get_available_pages() API (either CONTROL_AREA or SHARED_CACHE_MAP),
        #     layer to read from,
        #     file extension to apply,
        #     )
        dump_parameters = list()

        # The DataSectionObject and ImageSectionObject caches are handled in basically the same way.
        # We carve these "pages" from the memory_layer.
        for member_name, extension in [
            ("DataSectionObject", "dat"),
            ("ImageSectionObject", "img"),
        ]:
            try:
                section_obj = getattr(file_obj.SectionObjectPointer, member_name)
                control_area = section_obj.dereference().cast("_CONTROL_AREA")
                if control_area.is_valid():
                    dump_parameters.append((control_area, memory_layer, extension))
            except exceptions.InvalidAddressException:
                vollog.log(
                    constants.LOGLEVEL_VVV,
                    f"{member_name} is unavailable for file {file_obj.vol.offset:#x}",
                )

        # The SharedCacheMap is handled differently than the caches above.
        # We carve these "pages" from the primary_layer.
        try:
            scm_pointer = file_obj.SectionObjectPointer.SharedCacheMap
            shared_cache_map = scm_pointer.dereference().cast("_SHARED_CACHE_MAP")
            if shared_cache_map.is_valid():
                dump_parameters.append((shared_cache_map, primary_layer, "vacb"))
        except exceptions.InvalidAddressException:
            vollog.log(
                constants.LOGLEVEL_VVV,
                f"SharedCacheMap is unavailable for file {file_obj.vol.offset:#x}",
            )

        for memory_object, layer, extension in dump_parameters:
            cache_name = EXTENSION_CACHE_MAP[extension]
            desired_file_name = "file.{0:#x}.{1:#x}.{2}.{3}.{4}".format(
                file_obj.vol.offset,
                memory_object.vol.offset,
                cache_name,
                ntpath.basename(obj_name),
                extension,
            )

            file_handle = cls.dump_file_producer(
                file_obj, memory_object, open_method, layer, desired_file_name
            )

            file_output = "Error dumping file"
            if file_handle:
                file_handle.close()
                file_output = file_handle.preferred_filename

            yield (
                cache_name,
                format_hints.Hex(file_obj.vol.offset),
                ntpath.basename(
                    obj_name
                ),  # temporary, so its easier to visualize output
                file_output,
            )

    def _generator(self, procs: List, offsets: List):
        kernel = self.context.modules[self.config["kernel"]]

        if procs:
            # The handles plugin doesn't expose any staticmethod/classmethod, and it also requires stashing
            # private variables, so we need an instance (for now, anyway). We _could_ call Handles._generator()
            # to do some of the other work that is duplicated here, but then we'd need to parse the TreeGrid
            # results instead of just dealing with them as direct objects here.
            handles_plugin = handles.Handles(
                context=self.context, config_path=self._config_path
            )
            type_map = handles_plugin.get_type_map(
                context=self.context,
                layer_name=kernel.layer_name,
                symbol_table=kernel.symbol_table_name,
            )
            cookie = handles_plugin.find_cookie(
                context=self.context,
                layer_name=kernel.layer_name,
                symbol_table=kernel.symbol_table_name,
            )

            for proc in procs:
                try:
                    object_table = proc.ObjectTable
                except exceptions.InvalidAddressException:
                    vollog.log(
                        constants.LOGLEVEL_VVV,
                        f"Cannot access _EPROCESS.ObjectTable at {proc.vol.offset:#x}",
                    )
                    continue

                for entry in handles_plugin.handles(object_table):
                    try:
                        obj_type = entry.get_object_type(type_map, cookie)
                        if obj_type == "File":
                            file_obj = entry.Body.cast("_FILE_OBJECT")
                            for result in self.process_file_object(
                                self.context, kernel.layer_name, self.open, file_obj
                            ):
                                yield (0, result)
                    except exceptions.InvalidAddressException:
                        vollog.log(
                            constants.LOGLEVEL_VVV,
                            f"Cannot extract file from _OBJECT_HEADER at {entry.vol.offset:#x}",
                        )

                # Pull file objects from the VADs. This will produce DLLs and EXEs that are
                # mapped into the process as images, but that the process doesn't have an
                # explicit handle remaining open to those files on disk.
                for vad in proc.get_vad_root().traverse():
                    try:
                        if vad.has_member("ControlArea"):
                            # Windows xp and 2003
                            file_obj = vad.ControlArea.FilePointer.dereference()
                        elif vad.has_member("Subsection"):
                            # Vista and beyond
                            file_obj = vad.Subsection.ControlArea.FilePointer.dereference().cast(
                                "_FILE_OBJECT"
                            )
                        else:
                            continue

                        if not file_obj.is_valid():
                            continue

                        for result in self.process_file_object(
                            self.context, kernel.layer_name, self.open, file_obj
                        ):
                            yield (0, result)
                    except exceptions.InvalidAddressException:
                        vollog.log(
                            constants.LOGLEVEL_VVV,
                            f"Cannot extract file from VAD at {vad.vol.offset:#x}",
                        )

        elif offsets:
            # Now process any offsets explicitly requested by the user.
            for offset, is_virtual in offsets:
                try:
                    layer_name = kernel.layer_name
                    # switch to a memory layer if the user provided --physaddr instead of --virtaddr
                    if not is_virtual:
                        layer_name = self.context.layers[layer_name].config[
                            "memory_layer"
                        ]

                    file_obj = self.context.object(
                        kernel.symbol_table_name + constants.BANG + "_FILE_OBJECT",
                        layer_name=layer_name,
                        native_layer_name=kernel.layer_name,
                        offset=offset,
                    )
                    for result in self.process_file_object(
                        self.context, kernel.layer_name, self.open, file_obj
                    ):
                        yield (0, result)
                except exceptions.InvalidAddressException:
                    vollog.log(
                        constants.LOGLEVEL_VVV, f"Cannot extract file at {offset:#x}"
                    )

    def run(self):
        # a list of tuples (<int>, <bool>) where <int> is the address and <bool> is True for virtual.
        offsets = list()
        # a list of processes matching the pid filter. all files for these process(es) will be dumped.
        procs = list()
        kernel = self.context.modules[self.config["kernel"]]

        if self.config.get("virtaddr", None) is not None:
            offsets.append((self.config["virtaddr"], True))
        elif self.config.get("physaddr", None) is not None:
            offsets.append((self.config["physaddr"], False))
        else:
            filter_func = pslist.PsList.create_pid_filter(
                [self.config.get("pid", None)]
            )
            procs = pslist.PsList.list_processes(
                self.context,
                kernel.layer_name,
                kernel.symbol_table_name,
                filter_func=filter_func,
            )

        return renderers.TreeGrid(
            [
                ("Cache", str),
                ("FileObject", format_hints.Hex),
                ("FileName", str),
                ("Result", str),
            ],
            self._generator(procs, offsets),
        )
