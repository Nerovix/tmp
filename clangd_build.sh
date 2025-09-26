export PATH=../prebuilts/clang/host/linux-x86/clang-r416183b/bin:$PATH && make CROSS_COMPILE=aarch64-linux-gnu- LLVM=1 LLVM_IAS=1 ARCH=arm64 kedge2_defconfig android-11.config pcie_wifi.config && make CROSS_COMPILE=aarch64-linux-gnu- LLVM=1 LLVM_IAS=1 ARCH=arm64 -j24
python3 scripts/clang-tools/gen_compile_commands.py \
                -d \
                . \
                -o \
                compile_commands.json