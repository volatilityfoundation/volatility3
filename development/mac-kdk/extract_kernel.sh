#!/bin/bash

echo "Operating on ${1}"
mkdir tmp
pushd tmp
7z x ../${1}
if [ -f "KernelDebugKit/mach_kernel" ]; then
	mv KernelDebugKit System
else
	xar -x -f Kernel\ Debug\ Kit/KernelDebugKit.pkg
	python2 ../parse_pbzx2.py KDK.pkg/Payload
	if [ $? == 0 ]; then
		xz -d KDK.pkg/*.xz
		cat KDK.pkg/*.cpio > Payload\~
	else
		7z x Kernel\ Debug\ Kit/KernelDebugKit.pkg
	fi
	cpio -i < Payload\~
fi
mkdir -p "../Unpacked/${1}"
cp -r System "../Unpacked/${1}"
chmod -R ug+w "../Unpacked/${1}"
# /home/mike/tmp/dwarf2json/go/bin/dwarf2json "System/Library/Kernels/kernel.dSYM/Contents/Resources/DWARF/kernel" > "../JSON/${1}.json"
popd
rm -fr tmp
mv "${1}" Complete
