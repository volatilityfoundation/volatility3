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

    def test_categorize_memory_read(self):
        assert processaccess.ProcessAccess.categorize_access(0x0010) == "MEMORY_READ"

    def test_categorize_memory_modification(self):
        mask = 0x0008 | 0x0020
        assert (
            processaccess.ProcessAccess.categorize_access(mask)
            == "MEMORY_MODIFICATION"
        )

    def test_categorize_thread_and_memory_modification(self):
        mask = 0x0002 | 0x0008 | 0x0020
        assert (
            processaccess.ProcessAccess.categorize_access(mask)
            == "THREAD_AND_MEMORY_MODIFICATION"
        )

    def test_categorize_combined_capabilities(self):
        mask = 0x0010 | 0x0040 | 0x0800
        assert processaccess.ProcessAccess.categorize_access(mask) == (
            "MEMORY_READ,HANDLE_DUPLICATION,PROCESS_CONTROL"
        )

    def test_categorize_other_process_access(self):
        assert (
            processaccess.ProcessAccess.categorize_access(0x0400)
            == "OTHER_PROCESS_ACCESS"
        )

    def test_memory_related_access(self):
        assert processaccess.ProcessAccess.has_memory_related_access(0x0010)
        assert processaccess.ProcessAccess.has_memory_related_access(0x0020)
        assert not processaccess.ProcessAccess.has_memory_related_access(0x0400)
