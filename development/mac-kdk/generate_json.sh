#!/bin/bash

DWARF2JSON=$(which dwarf2json)
KDK_PATH="${1}"

for i in `ls ${KDK_PATH}`;
do
	echo "${i}"
	if [ -f "${KDK_PATH}/${i}/System/DEBUG_Kernel/mach_kernel.dSYM/Contents/Resources/DWARF/mach_kernel" ]; then
		echo "Mach DEBUG_kernel"
		${DWARF2JSON} "${KDK_PATH}/${i}/System/DEBUG_Kernel/mach_kernel.dSYM/Contents/Resources/DWARF/mach_kernel" > JSON/${i}.json
	elif [ -f "${KDK_PATH}/${i}/System/mach_kernel.dSYM/Contents/Resources/DWARF/mach_kernel" ]; then
		echo "Mach kernel"
		${DWARF2JSON} "${KDK_PATH}/${i}/System/mach_kernel.dSYM/Contents/Resources/DWARF/mach_kernel" > JSON/${i}.json
	else
		echo "Library Kernels"
		${DWARF2JSON} "${KDK_PATH}/${i}/System/Library/Kernels/kernel.dSYM/Contents/Resources/DWARF/kernel" > JSON/${i}.json
	fi
done


