#!/bin/bash

DWARF2JSON=$(which dwarf2json)
KDK_PATH="${1}"
JSON_DIR="${2}"

for i in `ls ${KDK_PATH}`;
do
	echo "${i}"
	if [ -f "${KDK_PATH}/${i}/System/Library/Kernels/kernel" ]; then
		echo "Library Kernels"
		${DWARF2JSON} mac --macho "${KDK_PATH}/${i}/System/Library/Kernels/kernel.dSYM/Contents/Resources/DWARF/kernel" --macho-symbols "${KDK_PATH}/${i}/System/Library/Kernels/kernel" > ${JSON_DIR}/${i}.json
	elif [ -f "${KDK_PATH}/${i}/System/mach_kernel.dSYM/Contents/Resources/DWARF/mach_kernel" ]; then
		echo "Mach kernel"
		${DWARF2JSON} mac --macho "${KDK_PATH}/${i}/System/mach_kernel.dSYM/Contents/Resources/DWARF/mach_kernel" --macho-symbols "${KDK_PATH}/${i}/System/mach_kernel" > "${JSON_DIR}/${i}.json" || ${DWARF2JSON} mac --arch i386 --macho "${KDK_PATH}/${i}/System/mach_kernel.dSYM/Contents/Resources/DWARF/mach_kernel" --macho-symbols "${KDK_PATH}/${i}/System/mach_kernel" > "${JSON_DIR}/${i}.json"
	fi
done


