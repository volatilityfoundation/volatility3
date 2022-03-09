# This file is Copyright 2022 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

from volatility3.framework import objects

import struct

class PARTITION_TABLE(objects.StructType):

    def get_disk_signature(self) -> str:
        signature = self.DiskSignature.values
        return signature

class PARTITION_ENTRY(objects.StructType):
    
    def get_partition_type(self, type: int) -> str:
        
        return "Hello"
