#include "nvt_session_0120.h"
#include <string.h>

static bool authorized(const struct dizi_nvt0120_lease *p)
{
    return p && p->smmu_gpi_sid416_owned && p->smmu_qup_sid403_owned &&
        p->gpi_event_ring_owned && p->qup_data_iova_mapped &&
        p->se9_gcc_tlmm_owned && p->irq54_owned &&
        p->spi_chip_identity_read && p->no_other_touch_reader;
}

static void release_all(struct dizi_nvt0120_session *s)
{
    if (!s) return;
    if (s->ops.contact)
        for (unsigned i = 0; i < DIZI_NVT0120_CONTACTS; ++i)
            if (s->active_mask & (1u << i))
                s->ops.contact(s->ops.context, i, false, s->x[i], s->y[i]);
    s->active_mask = 0;
}

int dizi_nvt0120_start(struct dizi_nvt0120_session *s,
    const struct dizi_nvt0120_lease *lease,
    const struct dizi_nvt0120_ops *ops, const uint8_t *firmware,
    size_t firmware_size)
{
    if (!s || s->state != DIZI_NVT0120_STOPPED || !authorized(lease) ||
        !ops || !ops->contact || !ops->select_page || !ops->write_sram ||
        !ops->verify_boot || !firmware)
        return -1;
    struct dizi_nvt_fw fw;
    if (dizi_nvt_fw_parse(firmware, firmware_size, &fw)) return -1;
    s->state = DIZI_NVT0120_LOADING;
    s->ops = *ops;
    s->active_mask = 0;
    s->consecutive_bad_frames = 0;
    const struct dizi_nvt_fw_transport transport = {
        .context = ops->context, .select_page = ops->select_page,
        .write_sram = ops->write_sram
    };
    if (dizi_nvt_fw_upload(&fw, &transport)) goto fail;
    s->state = DIZI_NVT0120_AWAIT_BOOT;
    if (ops->verify_boot(ops->context, fw.version)) goto fail;
    s->state = DIZI_NVT0120_ACTIVE;
    return 0;
fail:
    release_all(s);
    s->state = DIZI_NVT0120_FAILED;
    return -1;
}

int dizi_nvt0120_frame(struct dizi_nvt0120_session *s,
    const uint8_t *data, size_t size)
{
    if (!s || s->state != DIZI_NVT0120_ACTIVE || !s->ops.contact)
        return -1;
    if (!data || size != DIZI_NVT0120_REPORT) goto malformed;
    unsigned checksum = 0;
    for (unsigned i = 1; i <= 65; ++i) checksum += data[i];
    if (checksum & 255u) goto malformed;
    bool esd = true, wdt = true;
    for (unsigned i = 1; i <= 6; ++i) {
        esd &= data[i] == 0x77u;
        wdt &= data[i] == 0xfdu || data[i] == 0xfeu;
    }
    if (esd || wdt) goto malformed;
    uint32_t next = 0;
    uint16_t nx[DIZI_NVT0120_CONTACTS] = {0};
    uint16_t ny[DIZI_NVT0120_CONTACTS] = {0};
    for (unsigned i = 0; i < DIZI_NVT0120_CONTACTS; ++i) {
        const uint8_t *p = data + 1u + i * 6u;
        unsigned id = p[0] >> 3, state = p[0] & 7u;
        if (!id || id > DIZI_NVT0120_CONTACTS || (state != 1u && state != 2u))
            continue;
        unsigned x = ((unsigned)p[1] << 8) | p[2];
        unsigned y = ((unsigned)p[3] << 8) | p[4];
        if (x >= 16000u || y >= 25600u || (next & (1u << (id - 1u))))
            goto malformed;
        next |= 1u << (id - 1u);
        nx[id - 1u] = (uint16_t)(x / 10u);
        ny[id - 1u] = (uint16_t)(y / 10u);
    }
    /* Atomic malformed rejection: publish AFTER the whole frame validates. */
    for (unsigned id = 0; id < DIZI_NVT0120_CONTACTS; ++id) {
        uint32_t bit = 1u << id;
        if (next & bit) {
            if (!(s->active_mask & bit) || nx[id] != s->x[id] || ny[id] != s->y[id])
                s->ops.contact(s->ops.context, id, true, nx[id], ny[id]);
            s->x[id] = nx[id]; s->y[id] = ny[id];
        } else if (s->active_mask & bit) {
            s->ops.contact(s->ops.context, id, false, s->x[id], s->y[id]);
        }
    }
    s->active_mask = next;
    s->consecutive_bad_frames = 0;
    return 0;
malformed:
    if (++s->consecutive_bad_frames >= 10u) {
        release_all(s);
        s->consecutive_bad_frames = 0;
    }
    return -1;
}

void dizi_nvt0120_stop(struct dizi_nvt0120_session *s)
{
    if (!s) return;
    release_all(s);
    s->state = DIZI_NVT0120_STOPPED;
    memset(&s->ops, 0, sizeof(s->ops));
    s->consecutive_bad_frames = 0;
}
