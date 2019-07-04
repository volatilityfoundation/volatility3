import argparse
import os
from typing import Tuple, Dict
from urllib import request

from volatility.framework import contexts, interfaces
from volatility.framework.layers import physical, msf


class PdbReader:
    """Class to read Microsoft PDB files"""

    def __init__(self, context: interfaces.context.ContextInterface, location: str):
        self._layer_name, self._context = self.load_pdb_layer(context, location)

    @property
    def context(self):
        return self._context

    @property
    def pdb_layer_name(self):
        return self._layer_name

    @classmethod
    def load_pdb_layer(cls, context: interfaces.context.ContextInterface,
                       location: str) -> Tuple[str, interfaces.context.ContextInterface]:
        """Loads a PDB file into a layer within the context and returns the name of the new layer

           Note: the context may be changed by this method
        """
        physical_layer_name = context.layers.free_layer_name("FileLayer")
        physical_config_path = interfaces.configuration.path_join("pdbreader", physical_layer_name)

        # Create the file layer
        # This must be specific to get us started, setup the config and run
        new_context = context.clone()
        new_context.config[interfaces.configuration.path_join(physical_config_path, "location")] = location

        physical_layer = physical.FileLayer(new_context, physical_config_path, physical_layer_name)
        new_context.add_layer(physical_layer)

        # Add on the MSF format layer
        msf_layer_name = context.layers.free_layer_name("MSFLayer")
        msf_config_path = interfaces.configuration.path_join("pdbreader", msf_layer_name)
        new_context.config[interfaces.configuration.path_join(msf_config_path, "base_layer")] = physical_layer_name
        msf_layer = msf.PdbMSF(new_context, msf_config_path, msf_layer_name)
        new_context.add_layer(msf_layer)

        msf_layer.read_streams()

        return msf_layer_name, new_context

    def read_tpi_stream(self):
        tpi_layer = self._context.layers.get(self._layer_name + "_stream2", None)
        if not tpi_layer:
            raise ValueError("No TPI stream available")
        module = self._context.module(module_name = tpi_layer.pdb_symbol_table, layer_name = tpi_layer.name, offset = 0)
        header = module.object(type_name = "TPI_HEADER", offset = 0)

        # Check the header
        if not (56 <= header.header_size < 1024):
            raise ValueError("TPI Stream Header size outside normal bounds")
        if header.index_min < 4096:
            raise ValueError("Minimum TPI index is 4096, found: {}".format(header.index_min))
        if header.index_max < header.index_min:
            raise ValueError("Maximum TPI index is smaller than minimum TPI index, found: {} < {} ".format(
                header.index_max, header.index_min))

        types = {}

        offset = header.header_size
        # Ensure we use the same type everywhere
        length_type = "unsigned short"
        length_len = module.get_type(length_type).size
        while tpi_layer.maximum_address - offset > 0:
            length = module.object(type_name = length_type, offset = offset)
            offset += length_len
            output, consumed = self.consume_type(module, offset, length)
            types.update(output)
            # if consumed != length:
            #     raise ValueError("Bytes unconsumed")
            offset += length
            # Since types can only refer to earlier types, assigning the name at this point is fine

        if tpi_layer.maximum_address - offset != 0:
            raise ValueError("Type values did not fill the TPI stream correctly")

        return header

    def consume_type(self, module: interfaces.context.ModuleInterface, offset: int,
                     length: int) -> Tuple[Dict[str, Dict], int]:
        """Returns the dictionary for the type, and the number of bytes consumed"""
        LeafType = self.context.object(
            module.get_enumeration("LEAF_TYPE"), layer_name = module._layer_name, offset = offset)
        consumed = LeafType.vol.base_type.size
        offset += consumed
        length -= consumed

        if LeafType in [
                LeafType.LF_CLASS, LeafType.LF_CLASS_ST, LeafType.LF_STRUCTURE, LeafType.LF_STRUCTURE_ST,
                LeafType.LF_INTERFACE
        ]:
            structure = module.object(type_name = "LF_STRUCTURE", offset = offset)
            consumed = structure.vol.size
        elif LeafType in [LeafType.LF_MEMBER, LeafType.LF_MEMBER_ST]:
            member = module.object(type_name = "LF_MEMBER", offset = offset)
            name = member.name.cast("string", max_length = 256, encoding = "latin-1")
            consumed += member.vol.size + len(name) + 1
        elif LeafType in [LeafType.LF_MODIFIER]:
            modifier = module.object(type_name = "LF_MODIFIER", offset = offset)
            consumed += modifier.vol.size
            # Lookup and return the modified type
        elif LeafType in [LeafType.LF_POINTER]:
            pointer = module.object(type_name = "LF_POINTER", offset = offset)
            consumed += pointer.vol.size
        elif LeafType in [LeafType.LF_FIELDLIST]:
            sub_length = length
            sub_offset = offset
            field = []
            while length > consumed:
                subfield, sub_consumed = self.consume_type(module, sub_offset, sub_length)
                sub_length -= sub_consumed
                sub_offset += sub_consumed
                consumed += sub_consumed
                field.append(subfield)
            pass
        elif LeafType in [LeafType.LF_ARGLIST]:
            pass
        else:
            raise ValueError("Unhandled leaf_type: {}".format(LeafType))

        # if consumed != length:
        #     import pdb
        #     pdb.set_trace()

        print("LEAF_TYPE", LeafType.lookup())
        return {"leaf_type": LeafType}, consumed


if __name__ == '__main__':

    parser = argparse.ArgumentParser()
    parser.add_argument("-f", "--filename", help = "Provide the name of a pdb file to read", required = True)
    args = parser.parse_args()

    ctx = contexts.Context()
    if not os.path.exists(args.filename):
        parser.error("File {} does not exists".format(args.filename))
    location = "file:" + request.pathname2url(args.filename)

    reader = PdbReader(ctx, location)

    ### TESTING
    # x = ctx.object('pdb1!BIG_MSF_HDR', reader.pdb_layer_name, 0)
    header = reader.read_tpi_stream()

    import pdb

    pdb.set_trace()
