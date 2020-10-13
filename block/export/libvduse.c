/*
 * VDUSE (vDPA Device in Userspace) library
 *
 * Copyright (C) 2020 Bytedance Inc. and/or its affiliates. All rights reserved.
 *
 * Author:
 *   Xie Yongji <xieyongji@bytedance.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or
 * later.  See the COPYING file in the top-level directory.
 */

#include <sys/ioctl.h>
#include <linux/vduse.h>

#include "standard-headers/linux/vhost_types.h"
#include "qemu/osdep.h"
#include "qemu/main-loop.h"
#include "qemu/sockets.h"
#include "qemu/error-report.h"
#include "hw/virtio/virtio.h"
#include "libvduse.h"

static inline bool has_feature(uint64_t features, unsigned int fbit)
{
    assert(fbit < 64);
    return !!(features & (1ULL << fbit));
}

static inline bool vduse_dev_has_feature(VduseDev *dev, unsigned int fbit)
{
    return has_feature(dev->features, fbit);
}

static void vduse_iova_remove_region(VduseDev *dev, uint64_t start,
                                     uint64_t last)
{
    int i;

    if (last == start) {
        return;
    }

    for (i = 0; i < MAX_IOVA_REGIONS; i++) {
        if (!dev->regions[i].mmap_addr) {
            continue;
        }

        if (start <= dev->regions[i].iova &&
            last >= (dev->regions[i].iova + dev->regions[i].size - 1)) {
            munmap((void *)dev->regions[i].mmap_addr,
                   dev->regions[i].mmap_offset + dev->regions[i].size);
            dev->regions[i].mmap_addr = 0;
            dev->num_regions--;
        }
    }
}

static int vduse_iova_add_region(VduseDev *dev, int fd,
                                 uint64_t offset, uint64_t start,
                                 uint64_t last, int prot)
{
    int i;
    uint64_t size = last - start + 1;
    void *mmap_addr = mmap(0, size + offset, prot, MAP_SHARED, fd, 0);

    if (mmap_addr == MAP_FAILED) {
        return -EINVAL;
    }

    for (i = 0; i < MAX_IOVA_REGIONS; i++) {
        if (!dev->regions[i].mmap_addr) {
             dev->regions[i].mmap_addr = (uint64_t)(uintptr_t)mmap_addr;
             dev->regions[i].mmap_offset = offset;
             dev->regions[i].iova = start;
             dev->regions[i].size = size;
             dev->num_regions++;
             break;
        }
    }

    close(fd);

    return 0;
}

static int perm_to_prot(uint8_t perm)
{
    int prot = 0;

    switch (perm) {
        case VDUSE_ACCESS_WO:
            prot |= PROT_WRITE;
            break;
        case VDUSE_ACCESS_RO:
            prot |= PROT_READ;
            break;
        case VDUSE_ACCESS_RW:
            prot |= PROT_READ | PROT_WRITE;
            break;
        default:
            break;
    }

    return prot;
}

static inline void *iova_to_va(VduseDev *dev, uint64_t iova)
{
    int i, ret;
    struct vduse_iotlb_entry entry;

    for (i = 0; i < MAX_IOVA_REGIONS; i++) {
        if (!dev->regions[i].mmap_addr) {
            continue;
        }

        if ((iova >= dev->regions[i].iova) &&
            (iova < (dev->regions[i].iova + dev->regions[i].size))) {
            return (void *)(uintptr_t)(iova - dev->regions[i].iova +
                   dev->regions[i].mmap_addr + dev->regions[i].mmap_offset);
        }
    }

    entry.start = iova;
    entry.last = iova + 1;
    ret = ioctl(dev->fd, VDUSE_IOTLB_GET_FD, &entry);
    if (ret < 0) {
        return NULL;
    }
    ret = vduse_iova_add_region(dev, ret, entry.offset, entry.start,
                                entry.last, perm_to_prot(entry.perm));
    if (!ret) {
        return iova_to_va(dev, iova);
    }

    return NULL;
}

static inline uint16_t vring_avail_flags(VduseVirtq *vq)
{
    return vq->vring.avail->flags;
}

static inline uint16_t vring_avail_idx(VduseVirtq *vq)
{
    vq->shadow_avail_idx = vq->vring.avail->idx;

    return vq->shadow_avail_idx;
}

static inline uint16_t vring_avail_ring(VduseVirtq *vq, int i)
{
    return vq->vring.avail->ring[i];
}

static inline uint16_t vring_get_used_event(VduseVirtq *vq)
{
    return vring_avail_ring(vq, vq->vring.num);
}

static bool vduse_queue_get_head(VduseVirtq *vq, unsigned int idx,
                                 unsigned int *head)
{
    /* Grab the next descriptor number they're advertising, and increment
     * the index we've seen. */
    *head = vring_avail_ring(vq, idx % vq->vring.num);

    /* If their number is silly, that's a fatal mistake. */
    if (*head >= vq->vring.num) {
        error_report("Guest says index %u is available", *head);
        return false;
    }

    return true;
}

enum {
    VIRTQUEUE_READ_DESC_ERROR = -1,
    VIRTQUEUE_READ_DESC_DONE = 0,   /* end of chain */
    VIRTQUEUE_READ_DESC_MORE = 1,   /* more buffers in chain */
};

static int vduse_queue_read_next_desc(struct vring_desc *desc, int i,
                                      unsigned int max, unsigned int *next)
{
    /* If this descriptor says it doesn't chain, we're done. */
    if (!(desc[i].flags & VRING_DESC_F_NEXT)) {
        return VIRTQUEUE_READ_DESC_DONE;
    }

    /* Check they're not leading us off end of descriptors. */
    *next = desc[i].next;
    /* Make sure compiler knows to grab that: we don't want it changing! */
    smp_wmb();

    if (*next >= max) {
        error_report("Desc next is %u", *next);
        return VIRTQUEUE_READ_DESC_ERROR;
    }

    return VIRTQUEUE_READ_DESC_MORE;
}

/* Fetch avail_idx from VQ memory only when we really need to know if
 * guest has added some buffers. */
static bool vduse_queue_empty(VduseVirtq *vq)
{
    if (unlikely(!vq->vring.avail)) {
        return true;
    }

    if (vq->shadow_avail_idx != vq->last_avail_idx) {
        return false;
    }

    return vring_avail_idx(vq) == vq->last_avail_idx;
}

static bool vduse_queue_should_notify(VduseVirtq *vq)
{
    VduseDev *dev = vq->dev;
    uint16_t old, new;
    bool v;

    /* We need to expose used array entries before checking used event. */
    smp_mb();

    /* Always notify when queue is empty (when feature acknowledge) */
    if (vduse_dev_has_feature(dev, VIRTIO_F_NOTIFY_ON_EMPTY) &&
        !vq->inuse && vduse_queue_empty(vq)) {
        return true;
    }

    if (!vduse_dev_has_feature(dev, VIRTIO_RING_F_EVENT_IDX)) {
        return !(vring_avail_flags(vq) & VRING_AVAIL_F_NO_INTERRUPT);
    }

    v = vq->signalled_used_valid;
    vq->signalled_used_valid = true;
    old = vq->signalled_used;
    new = vq->signalled_used = vq->used_idx;
    return !v || vring_need_event(vring_get_used_event(vq), new, old);
}

void vduse_queue_notify(VduseVirtq *vq)
{
    if (unlikely(!vq->vring.avail)) {
        return;
    }

    if (!vduse_queue_should_notify(vq)) {
        return;
    }

    if (event_notifier_set(&vq->irq_notifier) < 0) {
        error_report("Error writing eventfd: %s", strerror(errno));
    }
}

static inline void vring_used_flags_set_bit(VduseVirtq *vq, int mask)
{
    uint16_t *flags;

    flags = (uint16_t *)((char*)vq->vring.used +
                         offsetof(struct vring_used, flags));
    *flags |= mask;
}

static inline void vring_used_flags_unset_bit(VduseVirtq *vq, int mask)
{
    uint16_t *flags;

    flags = (uint16_t *)((char*)vq->vring.used +
                         offsetof(struct vring_used, flags));
    *flags &= ~mask;
}

static inline void vring_set_avail_event(VduseVirtq *vq, uint16_t val)
{
    *((uint16_t *)&vq->vring.used->ring[vq->vring.num]) = val;
}

static void vduse_queue_map_single_desc(VduseVirtq *vq, unsigned int *p_num_sg,
                                   struct iovec *iov, unsigned int max_num_sg,
                                   bool is_write, uint64_t pa, size_t sz)
{
    unsigned num_sg = *p_num_sg;
    VduseDev *dev = vq->dev;

    assert(num_sg <= max_num_sg);

    if (!sz) {
        error_report("virtio: zero sized buffers are not allowed");
        return;
    }

    if (num_sg == max_num_sg) {
        error_report("virtio: too many descriptors in indirect table");
        return;
    }

    iov[num_sg].iov_base = iova_to_va(dev, pa);
    if (iov[num_sg].iov_base == NULL) {
        error_report("virtio: invalid address for buffers");
        return;
    }
    iov[num_sg].iov_len = sz;

    *p_num_sg = ++num_sg;
}

static void *vduse_queue_alloc_element(size_t sz, unsigned out_num,
                                       unsigned in_num)
{
    VduseVirtqElement *elem;
    size_t in_sg_ofs = QEMU_ALIGN_UP(sz, __alignof__(elem->in_sg[0]));
    size_t out_sg_ofs = in_sg_ofs + in_num * sizeof(elem->in_sg[0]);
    size_t out_sg_end = out_sg_ofs + out_num * sizeof(elem->out_sg[0]);

    assert(sz >= sizeof(VduseVirtqElement));
    elem = g_malloc(out_sg_end);
    elem->out_num = out_num;
    elem->in_num = in_num;
    elem->in_sg = (void *)elem + in_sg_ofs;
    elem->out_sg = (void *)elem + out_sg_ofs;
    return elem;
}

static void *vduse_queue_map_desc(VduseVirtq *vq, unsigned int idx, size_t sz)
{
    struct vring_desc *desc = vq->vring.desc;
    VduseDev *dev = vq->dev;
    uint64_t desc_addr;
    unsigned int desc_len;
    unsigned int max = vq->vring.num;
    unsigned int i = idx;
    VduseVirtqElement *elem;
    struct iovec iov[VIRTQUEUE_MAX_SIZE];
    unsigned int out_num = 0, in_num = 0;
    int rc;

    if (desc[i].flags & VRING_DESC_F_INDIRECT) {
        if (desc[i].len % sizeof(struct vring_desc)) {
            error_report("Invalid size for indirect buffer table");
        }

        /* loop over the indirect descriptor table */
        desc_addr = desc[i].addr;
        desc_len = desc[i].len;
        max = desc_len / sizeof(struct vring_desc);
        desc = iova_to_va(dev, desc_addr);
        if (!desc) {
            error_report("Invalid indirect buffer table");
            return NULL;
        }
        i = 0;
    }

    /* Collect all the descriptors */
    do {
        if (desc[i].flags & VRING_DESC_F_WRITE) {
            vduse_queue_map_single_desc(vq, &in_num, iov + out_num,
                                        VIRTQUEUE_MAX_SIZE - out_num, true,
                                        desc[i].addr, desc[i].len);
        } else {
            if (in_num) {
                error_report("Incorrect order for descriptors");
                return NULL;
            }
            vduse_queue_map_single_desc(vq, &out_num, iov,
                                        VIRTQUEUE_MAX_SIZE, false,
                                        desc[i].addr, desc[i].len);
        }

        /* If we've got too many, that implies a descriptor loop. */
        if ((in_num + out_num) > max) {
            error_report("Looped descriptor");
        }
        rc = vduse_queue_read_next_desc(desc, i, max, &i);
    } while (rc == VIRTQUEUE_READ_DESC_MORE);

    if (rc == VIRTQUEUE_READ_DESC_ERROR) {
        error_report("read descriptor error");
        return NULL;
    }

    /* Now copy what we have collected and mapped */
    elem = vduse_queue_alloc_element(sz, out_num, in_num);
    elem->index = idx;
    for (i = 0; i < out_num; i++) {
        elem->out_sg[i] = iov[i];
    }
    for (i = 0; i < in_num; i++) {
        elem->in_sg[i] = iov[out_num + i];
    }

    return elem;
}

void *vduse_queue_pop(VduseVirtq *vq, size_t sz)
{
    unsigned int head;
    VduseVirtqElement *elem;
    VduseDev *dev = vq->dev;

    if (unlikely(!vq->vring.avail)) {
        error_report("vduse queue pop no avail");
        return NULL;
    }

    if (vduse_queue_empty(vq)) {
        return NULL;
    }
    /*
     * Needed after virtio_queue_empty()
     */
    smp_rmb();

    if (vq->inuse >= vq->vring.num) {
        error_report("Virtqueue size exceeded: %d", vq->inuse);
        return NULL;
    }

    if (!vduse_queue_get_head(vq, vq->last_avail_idx++, &head)) {
        return NULL;
    }

    if (vduse_dev_has_feature(dev, VIRTIO_RING_F_EVENT_IDX)) {
        vring_set_avail_event(vq, vq->last_avail_idx);
    }

    elem = vduse_queue_map_desc(vq, head, sz);

    if (!elem) {
        return NULL;
    }

    vq->inuse++;

    return elem;
}

static inline void vring_used_write(VduseVirtq *vq,
                                    struct vring_used_elem *uelem, int i)
{
    struct vring_used *used = vq->vring.used;

    used->ring[i] = *uelem;
}

static void vduse_queue_fill(VduseVirtq *vq, const VduseVirtqElement *elem,
                             unsigned int len, unsigned int idx)
{
    struct vring_used_elem uelem;

    if (unlikely(!vq->vring.used)) {
        return;
    }

    idx = (idx + vq->used_idx) % vq->vring.num;

    uelem.id = elem->index;
    uelem.len = len;
    vring_used_write(vq, &uelem, idx);
}

static inline void vring_used_idx_set(VduseVirtq *vq, uint16_t val)
{
    vq->vring.used->idx = val;
    vq->used_idx = val;
}

static void vduse_queue_flush(VduseVirtq *vq, unsigned int count)
{
    uint16_t old, new;

    if (unlikely(!vq->vring.used)) {
        return;
    }

    /* Make sure buffer is written before we update index. */
    smp_wmb();

    old = vq->used_idx;
    new = old + count;
    vring_used_idx_set(vq, new);
    vq->inuse -= count;
    if (unlikely((int16_t)(new - vq->signalled_used) < (uint16_t)(new - old))) {
        vq->signalled_used_valid = false;
    }
}

void vduse_queue_push(VduseVirtq *vq, const VduseVirtqElement *elem,
                      unsigned int len)
{
    vduse_queue_fill(vq, elem, len, 0);
    vduse_queue_flush(vq, 1);
}

static void vduse_queue_on_kick(EventNotifier *n)
{
    VduseVirtq *vq = container_of(n, VduseVirtq, kick_notifier);
    VduseDev *dev = vq->dev;

    if (event_notifier_test_and_clear(n)) {
        vq->handler(dev, vq);
    }
}

void vduse_queue_init(VduseVirtq *vq, VduseVQHandler handler)
{
    vq->handler = handler;
}

int vduse_queue_enable(VduseVirtq *vq)
{
    struct VduseDev *dev = vq->dev;
    struct vduse_vq_eventfd eventfd;
    int ret;

    if (vq->enabled) {
        return 0;
    }

    ret = event_notifier_init(&vq->irq_notifier, false);
    if (ret < 0) {
        error_report("Failed to init irq notifier");
        return ret;
    }

    eventfd.index = vq->index;
    eventfd.fd = event_notifier_get_fd(&vq->irq_notifier);
    ret = ioctl(dev->fd, VDUSE_VQ_SETUP_IRQFD, &eventfd);
    if (ret) {
        error_report("Failed to set vq irq fd");
        goto irqfd_cleanup;
    }

    ret = event_notifier_init(&vq->kick_notifier, false);
    if (ret < 0) {
        error_report("Failed to init kick notifier");
        goto irqfd_cleanup;
    }

    eventfd.fd = event_notifier_get_fd(&vq->kick_notifier);
    ret = ioctl(dev->fd, VDUSE_VQ_SETUP_KICKFD, &eventfd);
    if (ret) {
        error_report("Failed to set vq kick fd");
        goto kickfd_cleanup;
    }

    vq->enabled = true;
    event_notifier_set_handler(&vq->kick_notifier, vduse_queue_on_kick);

    return 0;
kickfd_cleanup:
    event_notifier_cleanup(&vq->kick_notifier);
irqfd_cleanup:
    event_notifier_cleanup(&vq->irq_notifier);

    return ret;
}

void vduse_queue_disable(VduseVirtq *vq)
{
    if (!vq->enabled)
        return;

    vq->enabled = false;
    event_notifier_set_handler(&vq->kick_notifier, NULL);
    event_notifier_cleanup(&vq->kick_notifier);
    event_notifier_cleanup(&vq->irq_notifier);
}

static void vduse_dev_reset(VduseDev *dev)
{
    int i;

    for (i = 0; i < dev->num_queues; i++) {
        dev->vqs[i].vring.desc = 0;
        dev->vqs[i].vring.avail = 0;
        dev->vqs[i].vring.used = 0;
        dev->vqs[i].inuse = 0;
        dev->vqs[i].last_avail_idx = 0;
        dev->vqs[i].shadow_avail_idx = 0;
        dev->vqs[i].used_idx = 0;
        dev->vqs[i].signalled_used_valid = false;
    }
}

static void vduse_dev_handler(void *opaque)
{
    VduseDev *dev = opaque;
    struct vduse_dev_request req;
    struct vduse_dev_response resp;
    VduseVirtq *vq;
    int i, ret;

    ret = read(dev->fd, &req, sizeof(req));
    if (ret <= 0) {
        goto out;
    }
    resp.unique = req.unique;

    switch (req.type) {
    case VDUSE_SET_FEATURES:
        resp.result = dev->ops->set_features(dev, req.features);
        dev->features = req.features;
        break;
    case VDUSE_GET_FEATURES:
        resp.result = dev->ops->get_features(dev, (uint64_t *)&resp.features);
        break;
    case VDUSE_SET_STATUS:
        resp.result = dev->ops->set_status(dev, req.status);
        if (req.status == 0) {
            vduse_dev_reset(dev);
        }
        break;
    case VDUSE_GET_STATUS:
        resp.result = dev->ops->get_status(dev, &resp.status);
        break;
    case VDUSE_SET_CONFIG:
        resp.result = dev->ops->set_config(dev, req.config.offset,
                                           req.config.len, req.config.data);
        break;
    case VDUSE_GET_CONFIG:
        resp.config.offset = req.config.offset;
        resp.config.len = req.config.len;
        resp.result = dev->ops->get_config(dev, req.config.offset,
                                           req.config.len, resp.config.data);
        break;
    case VDUSE_SET_VQ_NUM:
        vq = &dev->vqs[req.vq_num.index];
        vq->vring.num = req.vq_num.num;
        resp.result = 0;
        break;
    case VDUSE_SET_VQ_ADDR:
        vq = &dev->vqs[req.vq_addr.index];
        vq->vring.desc_addr = req.vq_addr.desc_addr;
        vq->vring.avail_addr = req.vq_addr.driver_addr;
        vq->vring.used_addr = req.vq_addr.device_addr;
        resp.result = 0;
        break;
    case VDUSE_SET_VQ_READY:
        vq = &dev->vqs[req.vq_ready.index];
        if (req.vq_ready.ready) {
            vq->vring.desc = iova_to_va(dev, vq->vring.desc_addr);
            vq->vring.avail = iova_to_va(dev, vq->vring.avail_addr);
            vq->vring.used = iova_to_va(dev, vq->vring.used_addr);
        }
        vq->ready = req.vq_ready.ready;
        resp.result = 0;
        break;
    case VDUSE_GET_VQ_READY:
        vq = &dev->vqs[req.vq_ready.index];
        resp.vq_ready.index = req.vq_ready.index;
        resp.vq_ready.ready = vq->ready;
        resp.result = 0;
        break;
    case VDUSE_SET_VQ_STATE:
        vq = &dev->vqs[req.vq_state.index];
        vq->last_avail_idx = req.vq_state.avail_idx;
        resp.result = 0;
        break;
    case VDUSE_GET_VQ_STATE:
        vq = &dev->vqs[req.vq_state.index];
        resp.vq_state.avail_idx = vq->last_avail_idx;
        resp.result = 0;
        break;
    case VDUSE_UPDATE_IOTLB:
        vduse_iova_remove_region(dev, req.iova.start, req.iova.last);
        for (i = 0; i < dev->num_queues; i++) {
            if (dev->vqs[i].log->vring.ready) {
                dev->vqs[i].vring.desc = iova_to_va(dev, dev->vqs[i].log->vring.desc);
                dev->vqs[i].vring.avail = iova_to_va(dev, dev->vqs[i].log->vring.avail);
                dev->vqs[i].vring.used = iova_to_va(dev, dev->vqs[i].log->vring.used);
            }
        }
        resp.result = 0;
        break;
    default:
        resp.result = -1;
        break;
    }
    ret = write(dev->fd, &resp, sizeof(resp));
out:
    if (ret <= 0) {
        error_report("vduse_dev_handler error: %d", ret);
    }
}

int vduse_dev_init(VduseDev *dev, uint64_t id, uint32_t device_id,
                   uint32_t vendor_id, uint16_t num_queues,
                   uint16_t queue_size, const VduseOps *ops)
{
    int i, ret, vduse_fd, fd;
    struct vduse_dev_config config;

    vduse_fd = open("/dev/vduse", O_RDWR);
    if (vduse_fd < 0) {
        error_report("Failed to open vduse");
        return vduse_fd;
    }

    config.id = id;
    config.device_id = device_id;
    config.vendor_id = vendor_id;
    config.vq_num = num_queues;
    config.vq_size_max = queue_size;
    config.vq_align = VDUSE_VQ_ALIGN;
    config.bounce_size = VDUSE_BOUNCE_SIZE;

    fd = ioctl(vduse_fd, VDUSE_CREATE_DEV, &config);
    if (fd < 0) {
        ret = fd;
        error_report("Failed to create vduse device: %lu", id);
        goto err;
    }
    qemu_set_nonblock(fd);
    qemu_set_fd_handler(fd, vduse_dev_handler, NULL, dev);

    dev->vqs = g_malloc0(sizeof(VduseVirtq) * num_queues);
    if (!dev->vqs) {
        ret = -errno;
        error_report("Failed to alloc vqs");
        goto err;
    }
    for (i = 0; i < num_queues; i++) {
        dev->vqs[i].index = i;
        dev->vqs[i].dev = dev;
    }

    dev->id = id;
    dev->num_queues = num_queues;
    dev->queue_size = queue_size;
    dev->ops = ops;
    dev->vduse_fd = vduse_fd;
    dev->fd = fd;

    return 0;
err:
    if (dev->vqs) {
        g_free(dev->vqs);
        dev->vqs = NULL;
    }
    if (fd > 0) {
        close(fd);
        ioctl(vduse_fd, VDUSE_DESTROY_DEV, id);
    }
    close(vduse_fd);

    return ret;
}

void vduse_dev_cleanup(VduseDev *dev)
{
    qemu_set_fd_handler(dev->fd, NULL, NULL, NULL);
    close(dev->fd);
    dev->fd = -1;
    ioctl(dev->vduse_fd, VDUSE_DESTROY_DEV, dev->id);
    close(dev->vduse_fd);
    dev->vduse_fd = -1;
}
