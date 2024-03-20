# This file is Copyright 2022 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

from typing import Dict, Tuple

from volatility3.framework import exceptions, constants
from volatility3.framework import objects, interfaces
from volatility3.framework.objects import utility


class bash_hash_table(objects.StructType):
    def __init__(
        self,
        context: interfaces.context.ContextInterface,
        type_name: str,
        object_info: interfaces.objects.ObjectInformation,
        size: int,
        members: Dict[str, Tuple[int, interfaces.objects.Template]],
    ) -> None:

        super().__init__(
            context=context,
            type_name=type_name,
            object_info=object_info,
            size=size,
            members=members,
        )
        self.context = context
        self.layer_name = self.vol.layer_name
        self.symbol_table_name = self.get_symbol_table_name()

    def is_valid(self):
        try:
            bucket_array = self.bucket_array
            nbuckets = self.nbuckets
            nentries = self.nentries
        except exceptions.InvalidAddressException:
            return False

        return bucket_array and nbuckets == 64 and nentries > 1

    def __iter__(self):
        if self.is_valid():

            seen = {}
            bucket_array = self.context.object(
                self.symbol_table_name + constants.BANG + "array",
                layer_name=self.layer_name,
                offset=self.bucket_array,
                subtype=self.context.symbol_space.get_type(
                    self.symbol_table_name + constants.BANG + "pointer"
                ),
                count=self.nbuckets,
            )

            for i in range(len(bucket_array)):
                try:
                    bucket_ptr = bucket_array[i]
                except exceptions.InvalidAddressException:
                    continue
                if bucket_ptr == 0:
                    continue
                try:
                    bucket_contents = bucket_ptr.dereference().cast(
                        self.symbol_table_name + constants.BANG + "bucket_contents"
                    )
                    while bucket_contents.times_found > 0 or bucket_contents.next != 0:
                        try:
                            if bucket_contents in seen:
                                break
                            seen[bucket_contents] = 1
                            pdata = bucket_contents.data
                            if (
                                0 <= pdata.flags <= 2
                                and bucket_contents.times_found > 0
                            ):
                                try:
                                    path = utility.array_to_string(
                                        bucket_contents.data.path.dereference()
                                    )
                                    if path.startswith("/"):
                                        yield (bucket_contents)
                                except exceptions.InvalidAddressException:
                                    continue

                            bucket_contents = bucket_contents.next
                        except exceptions.InvalidAddressException:
                            continue
                except exceptions.InvalidAddressException:
                    continue
