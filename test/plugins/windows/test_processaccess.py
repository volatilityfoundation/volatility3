from volatility3.framework.plugins.windows import processaccess


class TestWindowsProcessAccess:
    def test_decode_access_mask(self):
        mask = 0x0002 | 0x0008 | 0x0020
        decoded = processaccess.ProcessAccess.decode_access_mask(mask)
        assert decoded == (
            "PROCESS_CREATE_THREAD,PROCESS_VM_OPERATION,PROCESS_VM_WRITE"
        )

    def test_decode_access_mask_preserves_unknown_bits(self):
        decoded = processaccess.ProcessAccess.decode_access_mask(0x2000)
        assert decoded == "UNKNOWN(0x2000)"

    def test_decode_access_mask_none(self):
        assert processaccess.ProcessAccess.decode_access_mask(0) == "NONE"

    def test_memory_related_access(self):
        assert processaccess.ProcessAccess.has_memory_related_access(0x0010)
        assert processaccess.ProcessAccess.has_memory_related_access(0x0020)
        assert not processaccess.ProcessAccess.has_memory_related_access(0x0400)
