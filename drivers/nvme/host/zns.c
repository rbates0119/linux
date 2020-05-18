// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2020 Western Digital Corporation or its affiliates.
 */

#include <linux/blkdev.h>
#include "nvme.h"

static int nvme_get_max_append(struct nvme_ctrl *ctrl)
{
	struct nvme_command c = { };
	struct nvme_id_ctrl_zns *id;
	int status;

	id = kzalloc(sizeof(*id), GFP_KERNEL);
	if (!id)
		return -ENOMEM;

	c.identify.opcode = nvme_admin_identify;
	c.identify.cns = NVME_ID_CNS_CS_CTRL;
	c.identify.csi = NVME_CSI_ZNS;

	status = nvme_submit_sync_cmd(ctrl->admin_q, &c, id, sizeof(*id));
	if (!status)
		ctrl->max_zone_append = 1 << (id->zamds + 3);
	kfree(id);
	return status;
}

int nvme_update_zone_info(struct gendisk *disk, struct nvme_ns *ns,
			  unsigned lbaf)
{
	struct nvme_command c = { };
	struct request_queue *q = disk->queue;
	struct nvme_id_ns_zns *id;
	int status;

	/* Lazily query controller append limit for the first zoned namespace */
	if (!ns->ctrl->max_zone_append) {
		status = nvme_get_max_append(ns->ctrl);
		if (status)
			return status;
	}

	id = kzalloc(sizeof(*id), GFP_KERNEL);
	if (!id)
		return -ENOMEM;

	c.identify.opcode = nvme_admin_identify;
	c.identify.nsid = cpu_to_le32(ns->head->ns_id);
	c.identify.cns = NVME_ID_CNS_CS_NS;
	c.identify.csi = NVME_CSI_ZNS;

	status = nvme_submit_sync_cmd(ns->ctrl->admin_q, &c, id, sizeof(*id));
	if (status)
		goto free_data;

	/*
	 * We currently do not handle devices requiring any of the zoned
	 * operation characteristics.
	 */
	if (id->zoc) {
		dev_err(ns->ctrl->device,
			"Zone Operation Characteristics is not supported, this field has to be set to zero\n");
		status = -EINVAL;
		goto free_data;
	}

	ns->zsze = nvme_lba_to_sect(ns, le64_to_cpu(id->lbafe[lbaf].zsze));
	dev_err(ns->ctrl->device, "Reported zone size (LBAs): %llu (in sectors: %llu)\n",
		le64_to_cpu(id->lbafe[lbaf].zsze), ns->zsze);
	if (!ns->zsze) {
		status = -EINVAL;
		goto free_data;
	}

	q->limits.zoned = BLK_ZONED_HM;
	blk_queue_flag_set(QUEUE_FLAG_ZONE_RESETALL, q);
	blk_queue_max_zone_append_sectors(q, ns->ctrl->max_zone_append);
	/* TODO: only do this if Zone Append isn't supported, or completely drop this? */
	blk_queue_required_elevator_features(q, ELEVATOR_F_ZBD_SEQ_WRITE);
free_data:
	kfree(id);
	return status;
}

static void *nvme_zns_alloc_report_buffer(struct nvme_ns *ns,
					  unsigned int nr_zones, size_t *buflen)
{
	struct request_queue *q = ns->disk->queue;
	size_t bufsize;
	void *buf;

	const size_t min_bufsize = sizeof(struct nvme_zone_report) +
				   sizeof(struct nvme_zone_descriptor);

	nr_zones = min_t(unsigned int, nr_zones,
			 get_capacity(ns->disk) >> ilog2(ns->zsze));
	dev_err(ns->ctrl->device, "Max number of zones in report: %u\n", nr_zones);

	bufsize = sizeof(struct nvme_zone_report) +
		nr_zones * sizeof(struct nvme_zone_descriptor);
	bufsize = min_t(size_t, bufsize,
			queue_max_hw_sectors(q) << SECTOR_SHIFT);
	bufsize = min_t(size_t, bufsize, queue_max_segments(q) << PAGE_SHIFT);

	while (bufsize >= min_bufsize) {
		buf = __vmalloc(bufsize,
				GFP_KERNEL | __GFP_ZERO | __GFP_NORETRY,
				PAGE_KERNEL);
		if (buf) {
			*buflen = bufsize;
			return buf;
		}
		bufsize >>= 1;
	}
	return NULL;
}

static int __nvme_ns_report_zones(struct nvme_ns *ns, sector_t sector,
				  struct nvme_zone_report *report,
				  size_t buflen)
{
	struct nvme_command c = { };
	int ret;

	c.zmr.opcode = nvme_cmd_zone_mgmt_recv;
	c.zmr.nsid = cpu_to_le32(ns->head->ns_id);
	c.zmr.slba = cpu_to_le64(nvme_sect_to_lba(ns, sector));
	c.zmr.numd = cpu_to_le32(nvme_bytes_to_numd(buflen));
	c.zmr.zra = NVME_ZRA_ZONE_REPORT;
	c.zmr.zrasf = NVME_ZRASF_ZONE_REPORT_ALL;
	c.zmr.pr = NVME_REPORT_ZONE_PARTIAL;

	ret = nvme_submit_sync_cmd(ns->queue, &c, report, buflen);
	if (ret)
		return ret;

	return le64_to_cpu(report->nr_zones);
}

static int nvme_zone_parse_entry(struct nvme_ns *ns,
				 struct nvme_zone_descriptor *entry,
				 unsigned int idx, report_zones_cb cb,
				 void *data)
{
	struct blk_zone zone = { };

	if ((entry->zt & 0xf) != NVME_ZONE_TYPE_SEQWRITE_REQ) {
		dev_err(ns->ctrl->device, "invalid zone type %#x\n",
			entry->zt);
		return -EINVAL;
	}

	zone.type = BLK_ZONE_TYPE_SEQWRITE_REQ;
	zone.cond = entry->zs >> 4;
	zone.len = ns->zsze;
	zone.capacity = nvme_lba_to_sect(ns, le64_to_cpu(entry->zcap));
	zone.start = nvme_lba_to_sect(ns, le64_to_cpu(entry->zslba));
	zone.wp = nvme_lba_to_sect(ns, le64_to_cpu(entry->wp));

	return cb(&zone, idx, data);
}

static int nvme_ns_report_zones(struct nvme_ns *ns, sector_t sector,
			unsigned int nr_zones, report_zones_cb cb, void *data)
{
	struct nvme_zone_report *report;
	int ret, zone_idx = 0;
	unsigned int nz, i;
	size_t buflen;

	report = nvme_zns_alloc_report_buffer(ns, nr_zones, &buflen);
	if (!report)
		return -ENOMEM;

	sector &= ~(ns->zsze - 1);
	while (zone_idx < nr_zones && sector < get_capacity(ns->disk)) {
		memset(report, 0, buflen);
		ret = __nvme_ns_report_zones(ns, sector, report, buflen);
		if (ret < 0)
			goto out_free;

		nz = min_t(unsigned int, ret, nr_zones);
		if (!nz)
			break;

		for (i = 0; i < nz && zone_idx < nr_zones; i++, zone_idx++) {
			ret = nvme_zone_parse_entry(ns, &report->entries[i],
						    zone_idx, cb, data);
			if (ret)
				goto out_free;
		}

		sector += ns->zsze * nz;
	}

	ret = zone_idx;
out_free:
	kvfree(report);
	return ret;
}

int nvme_report_zones(struct gendisk *disk, sector_t sector,
		      unsigned int nr_zones, report_zones_cb cb, void *data)
{
	struct nvme_ns_head *head = NULL;
	struct nvme_ns *ns;
	int srcu_idx, ret;

	ns = nvme_get_ns_from_disk(disk, &head, &srcu_idx);
	if (unlikely(!ns))
		return -EWOULDBLOCK;

	if (ns->head->ids.csi == NVME_CSI_ZNS)
		ret = nvme_ns_report_zones(ns, sector, nr_zones, cb, data);
	else
		ret = -EINVAL;
	nvme_put_ns_from_disk(head, srcu_idx);

	return ret;
}

blk_status_t nvme_setup_zone_mgmt_send(struct nvme_ns *ns, struct request *req,
		struct nvme_command *c, enum nvme_zone_mgmt_action action)
{
	c->zms.opcode = nvme_cmd_zone_mgmt_send;
	c->zms.nsid = cpu_to_le32(ns->head->ns_id);
	c->zms.action = action;

	if (req_op(req) == REQ_OP_ZONE_RESET_ALL)
		c->zms.select = 1;
	else
		c->zms.slba =
			cpu_to_le64(nvme_sect_to_lba(ns, blk_rq_pos(req)));

	return BLK_STS_OK;
}
