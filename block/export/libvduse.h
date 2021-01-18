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

#ifndef LIBVDUSE_H
#define LIBVDUSE_H

#include "qemu/osdep.h"
#include "qemu/event_notifier.h"

#define VDUSE_VQ_ALIGN 4096
#define VDUSE_BOUNCE_SIZE (1024 * 1024 * 1024)

#define MAX_IOVA_REGIONS 256

typedef struct VduseDev VduseDev;

typedef struct VduseVirtq VduseVirtq;

typedef struct VduseOps {
    int (*set_features)(VduseDev *dev, uint64_t features);
    int (*get_features)(VduseDev *dev, uint64_t *features);
    int (*set_status)(VduseDev *dev, uint8_t status);
    int (*get_status)(VduseDev *dev, uint8_t *status);
    int (*set_config)(VduseDev *dev, uint32_t offset, uint32_t len, void *buf);
    int (*get_config)(VduseDev *dev, uint32_t offset, uint32_t len, void *buf);
    void (*free)(VduseDev *dev);
} VduseOps;

typedef void (*VduseVQHandler)(VduseDev *dev, VduseVirtq *vq);

typedef struct VduseRing {
    unsigned int num;
    uint64_t desc_addr;
    uint64_t avail_addr;
    uint64_t used_addr;
    struct vring_desc *desc;
    struct vring_avail *avail;
    struct vring_used *used;
} VduseRing;

struct VduseVirtq {
    VduseRing vring;
    /* Next head to pop */
    uint16_t last_avail_idx;
    /* Last avail_idx read from VQ. */
    uint16_t shadow_avail_idx;
    uint16_t used_idx;
    /* Last used index value we have signalled on */
    uint16_t signalled_used;
    /* Last used index value we have signalled on */
    bool signalled_used_valid;
    int index;
    int inuse;
    bool enabled;
    bool ready;
    EventNotifier kick_notifier;
    EventNotifier irq_notifier;
    VduseVQHandler handler;
    VduseDev *dev;
};

typedef struct VduseVirtqElement {
    unsigned int index;
    unsigned int out_num;
    unsigned int in_num;
    struct iovec *in_sg;
    struct iovec *out_sg;
} VduseVirtqElement;

typedef struct VduseIovaRegion {
    /* I/O virtual address */
    uint64_t iova;
    /* Memory region size. */
    uint64_t size;
    /* Starting offset in mmaped space. */
    uint64_t mmap_offset;
    /* Start address of mmaped space. */
    uint64_t mmap_addr;
} VduseIovaRegion;

struct VduseDev {
    VduseVirtq *vqs;
    VduseIovaRegion regions[MAX_IOVA_REGIONS];
    int num_regions;
    uint64_t id;
    uint32_t device_id;
    uint32_t vendor_id;
    uint16_t num_queues;
    uint16_t queue_size;
    uint64_t features;
    const VduseOps *ops;
    int fd;
    int vduse_fd;
};

void *vduse_queue_pop(VduseVirtq *vq, size_t sz);
void vduse_queue_push(VduseVirtq *vq, const VduseVirtqElement *elem,
                      unsigned int len);
void vduse_queue_notify(VduseVirtq *vq);
void vduse_queue_init(VduseVirtq *vq, VduseVQHandler handler);
int vduse_queue_enable(VduseVirtq *vq);
void vduse_queue_disable(VduseVirtq *vq);

int vduse_dev_init(VduseDev *dev, uint64_t id, uint32_t device_id,
                   uint32_t vendor_id, uint16_t num_queues,
                   uint16_t queue_size, const VduseOps *ops);
void vduse_dev_cleanup(VduseDev *dev);

#endif
