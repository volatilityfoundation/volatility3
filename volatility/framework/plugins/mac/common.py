# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl_v1.0
#

from volatility.framework import interfaces
from volatility.framework import exceptions

def walk_tailq(queue: interfaces.objects.ObjectInterface, next_member: str, max_elements: int = 4096):
    seen = set()

    try:
        current = queue.tqh_first
    except exceptions.PagedInvalidAddressException:
        return

    while current:
        if current.vol.offset in seen:
            break

        seen.add(current.vol.offset)
        
        if len(seen) == max_elements:
            break

        yield current

        try:
            current = current.member(attr = next_member).tqe_next
        except exceptions.PagedInvalidAddressException:
            return


