from volatility3.framework.layers import arm, intel

WIN_ARCHS = ["Intel32", "Intel64"]
"""Windows supported architectures"""
WIN_ARCHS_LAYERS = [intel.Intel]
"""Windows supported architectures layers"""

LINUX_ARCHS = ["Intel32", "Intel64", "AArch64"]
"""Linux supported architectures"""
LINUX_ARCHS_LAYERS = [intel.Intel, arm.AArch64]
"""Linux supported architectures layers"""

MAC_ARCHS = ["Intel32", "Intel64"]
"""Mac supported architectures"""
MAC_ARCHS_LAYERS = [intel.Intel]
"""Mac supported architectures layers"""

FRAMEWORK_ARCHS = ["Intel32", "Intel64", "AArch64"]
"""Framework supported architectures"""
FRAMEWORK_ARCHS_LAYERS = [intel.Intel, arm.AArch64]
"""Framework supported architectures layers"""
