#!/bin/bash

UNPACK_DIR="Unpacked"
KERNEL_DIR="$(basename ${1})"
JSON_DIR="JSON"
DWARF2JSON="dwarf2json"

echo "Operating on ${KERNEL_DIR}"
mkdir tmp
pushd tmp


7z x ../${1}
if [ -f "KernelDebugKit/mach_kernel" ]; then
	echo "7Z unpack successful"
	mv KernelDebugKit System
else
  echo "XAR unpack required"
	xar -x -f Kernel\ Debug\ Kit/KernelDebugKit.pkg
	python2 ../parse_pbzx2.py KDK.pkg/Payload
	if [ $? == 0 ]; then
		xz -d KDK.pkg/*.xz
		cat KDK.pkg/*.cpio > Payload\~
	else
		7z x Kernel\ Debug\ Kit/KernelDebugKit.pkg
	fi
	echo "CPIO unpacking Payload"
	cpio -i < Payload\~
fi

mkdir -p "../${UNPACK_DIR}/${KERNEL_DIR}"

if [ -f "System/Library/Kernels/kernel" ]; then
  cp "System/Library/Kernels/kernel" "../${UNPACK_DIR}/${KERNEL_DIR}/kernel"
  cp "System/Library/Kernels/kernel.dSYM/Contents/Resources/DWARF/kernel" "../${UNPACK_DIR}/${KERNEL_DIR}/kernel.dSYM"
elif [ -f "System/mach_kernel.dSYM/Contents/Resources/DWARF/mach_kernel" ]; then
  cp System/mach_kernel "../${UNPACK_DIR}/${KERNEL_DIR}/kernel"
  cp System/mach_kernel.dSYM/Contents/Resources/DWARF/mach_kernel "../${UNPACK_DIR}/${KERNEL_DIR}/kernel.dSYM"
fi

chmod -R ug+w "../${UNPACK_DIR}/${KERNEL_DIR}"

${DWARF2JSON} 
popd
rm -fr tmp

echo "Running ${DWARF2JSON} mac --macho "${UNPACK_DIR}/${KERNEL_DIR}/kernel.dSYM" --macho-symbols "${UNPACK_DIR}/${KERNEL_DIR}/kernel" | xz -9 > ${JSON_DIR}/${KERNEL_DIR}.json.xz"
${DWARF2JSON} mac --macho "${UNPACK_DIR}/${KERNEL_DIR}/kernel.dSYM" --macho-symbols "${UNPACK_DIR}/${KERNEL_DIR}/kernel" | xz -9 > ${JSON_DIR}/${KERNEL_DIR}.json.xz
if [ $? != 0 ]; then
  ${DWARF2JSON} mac --arch i386 --macho "${UNPACK_DIR}/${KERNEL_DIR}/kernel.dSYM" --macho-symbols "${UNPACK_DIR}/${KERNEL_DIR}/kernel" | xz -9 > ${JSON_DIR}/${KERNEL_DIR}.json.xz
fi
