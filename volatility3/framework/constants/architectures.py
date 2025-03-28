from volatility3.framework.layers import intel

WIN_ARCHS = ["Intel32", "Intel64"]
"""Windows supported architectures"""
WIN_ARCHS_LAYERS = [intel.Intel]
"""Windows supported architectures layers"""

LINUX_ARCHS = ["Intel32", "Intel64"]
"""Linux supported architectures"""
LINUX_ARCHS_LAYERS = [intel.Intel]
"""Linux supported architectures layers"""

MAC_ARCHS = ["Intel32", "Intel64"]
"""Mac supported architectures"""
MAC_ARCHS_LAYERS = [intel.Intel]
"""Mac supported architectures layers"""

FRAMEWORK_ARCHS = ["Intel32", "Intel64"]
"""Framework supported architectures"""
FRAMEWORK_ARCHS_LAYERS = [intel.Intel]
"""Framework supported architectures layers"""
