# cxl-mailbox-overflow

PoC for three guest-triggerable bugs in QEMU's CXL Type 3 mailbox emulation (`hw/cxl/cxl-mailbox-utils.c`). OOB read, heap overflow, and write-what-where chain into a full guest-to-host escape with ASLR bypass. Tested against QEMU v11.0.0-rc2.

## Bugs

**Bug 1 (cxl-escape-poc.c):** Out-of-bounds read in `cmd_logs_get_log`. Type confusion between byte offsets and element offsets in the CEL log bounds check vs pointer arithmetic gives a 4x range amplification. Leaks QEMU .text pointers, defeats PIE/ASLR in one mailbox command.

**Bug 2 (cxl-mbox-test.c, test 1):** Heap buffer overflow in `cmd_ccls_get_lsa`. Guest-controlled length checked against the LSA backing store size but not against the 2048-byte payload buffer. Overwrites adjacent CXLDeviceState fields with attacker-controlled content. Does not trigger ASan (intra-object overflow within the 7MB QOM allocation).

**Bug 3 (cxl-mbox-test.c, test 2):** Write-what-where in `cmd_features_set_feature`. Six UUID branches (soft_ppr, hard_ppr, cacheline_sparing, row_sparing, bank_sparing, rank_sparing) accept a guest-controlled offset (0-65535) and payload size without bounds checking. The same validation that patrol_scrub and ecs have is simply missing from these six branches.

## Escape chain

Bugs 1 and 2 chain into a deterministic guest-to-host escape in four mailbox commands:

1. **Get Log** with crafted offset leaks a handler function pointer, giving the PIE base.
2. **Set LSA** plants a fake `cxl_cmd` entry (handler = `system@plt`, name = `/tmp/x`) in the LSA at the exact offset needed to hit `cxl_cmd_set[0][0]` after overflow.
3. **Get LSA** with length=2680 overflows the 2048-byte payload buffer, installing the fake handler into the command dispatch table.
4. **Command (set=0, cmd=0)** dispatches to `system("/tmp/x")`, executing an attacker-controlled script on the host.

Full ASLR bypass, no brute force, no /proc access.

## Files

- `cxl-escape-poc.c` - Full escape chain qtest PoC (bugs 1 + 2 chained)
- `cxl-mbox-test.c` - Individual bug PoCs with ASan validation (bugs 2 + 3)

## Build and run

Tested on Ubuntu 24.04, GCC 13.3.0, QEMU commit `b6a7d06213` (v11.0.0-rc2).

### Individual bugs (with ASan)

```
git clone https://gitlab.com/qemu-project/qemu.git
cd qemu && git checkout b6a7d06213
cp /path/to/cxl-mbox-test.c tests/qtest/
```

Add `'cxl-mbox-test'` alongside `'cxl-test'` in `tests/qtest/meson.build`:

```
- (config_all_devices.has_key('CONFIG_CXL') ? ['cxl-test'] : [])
+ (config_all_devices.has_key('CONFIG_CXL') ? ['cxl-test', 'cxl-mbox-test'] : [])
```

```
mkdir build && cd build
../configure --enable-asan --target-list=x86_64-softmmu --enable-debug
ninja -j$(nproc)
QTEST_QEMU_BINARY=./qemu-system-x86_64 ./tests/qtest/cxl-mbox-test --verbose
```

### Full escape chain (without ASan)

The chain requires stable binary offsets so ASan must be off. The hardcoded values in `cxl-escape-poc.c` (SYSTEM_PLT_OFFSET, IDENTIFY_HANDLER_OFFSET) are specific to the exact build described above. If you're building with a different compiler, optimization level, or QEMU commit, you'll need to update them:

```
objdump -t qemu-system-x86_64 | grep system@plt
objdump -t qemu-system-x86_64 | grep cmd_infostat_identify
```

For the structure layout offsets, use GDB:

```
(gdb) ptype /o CXLType3Dev
```

Then:

```
cp /path/to/cxl-escape-poc.c tests/qtest/
```

Add `'cxl-escape-poc'` in `tests/qtest/meson.build` the same way as above.

```
../configure --target-list=x86_64-softmmu
ninja -j$(nproc) qemu-system-x86_64 tests/qtest/cxl-escape-poc
rm -f /tmp/pwned-by-cxl-guest /tmp/x
QTEST_QEMU_BINARY=./qemu-system-x86_64 tests/qtest/cxl-escape-poc
cat /tmp/pwned-by-cxl-guest
```

## Policy note

CXL emulation is not part of QEMU's security-supported virtualization use case. These bugs were reported to qemu-security in April 2026 and classified as non-security per the published policy. Full writeup on my blog: [link]
