#include <linux/slab.h>
#include "sas1068_sas.h"

static int sas1068_find_tag(struct sas_task *task, u32 *tag)
{
	if (task->lldd_task) {
		struct sas1068_ccb_info *ccb;
		ccb = task->lldd_task;
		*tag = ccb->ccb_tag;
		return 1;
	}
	return 0;
}

void sas1068_tag_free(struct sas1068_hba_info *sas1068_ha, u32 tag)
{
	void *bitmap = sas1068_ha->tags;
	clear_bit(tag, bitmap);
}

inline int sas1068_tag_alloc(struct sas1068_hba_info *sas1068_ha, u32 *tag_out)
{
	unsigned int tag;
	void *bitmap = sas1068_ha->tags;
	unsigned long flags;

	spin_lock_irqsave(&sas1068_ha->bitmap_lock, flags);
	tag = find_first_zero_bit(bitmap, sas1068_ha->tags_num);
	if (tag >= sas1068_ha->tags_num) {
		spin_unlock_irqrestore(&sas1068_ha->bitmap_lock, flags);
		return -SAS_QUEUE_FULL;
	}
	set_bit(tag, bitmap);
	spin_unlock_irqrestore(&sas1068_ha->bitmap_lock, flags);
	*tag_out = tag;
	return 0;
}

void sas1068_tag_init(struct sas1068_hba_info *sas1068_ha)
{
	int i;
	for (i = 0; i < sas1068_ha->tags_num; ++i)
		sas1068_tag_free(sas1068_ha, i);
}

int sas1068_mem_alloc(struct pci_dev *pdev, void **virt_addr,
	dma_addr_t *pphys_addr, u32 *pphys_addr_hi,
	u32 *pphys_addr_lo, u32 mem_size, u32 align)
{
	caddr_t mem_virt_alloc;
	dma_addr_t mem_dma_handle;
	u64 phys_align;
	u64 align_offset = 0;
	if (align)
		align_offset = (dma_addr_t)align - 1;
	mem_virt_alloc = pci_zalloc_consistent(pdev, mem_size + align,
					       &mem_dma_handle);
	if (!mem_virt_alloc) {
		SAS1068_printk("memory allocation error\n");
		return -1;
	}
	*pphys_addr = mem_dma_handle;
	phys_align = (*pphys_addr + align_offset) & ~align_offset;
	*virt_addr = (void *)mem_virt_alloc + phys_align - *pphys_addr;
	*pphys_addr_hi = upper_32_bits(phys_align);
	*pphys_addr_lo = lower_32_bits(phys_align);
	return 0;
}

static
struct sas1068_hba_info *sas1068_find_ha_by_dev(struct domain_device *dev)
{
	struct sas_ha_struct *sha = dev->port->ha;
	struct sas1068_hba_info *sas1068_ha = sha->lldd_ha;
	return sas1068_ha;
}

int sas1068_phy_control(struct asd_sas_phy *sas_phy, enum phy_func func,
	void *funcdata)
{
	int rc = 0, phy_id = sas_phy->id;
	struct sas1068_hba_info *sas1068_ha = NULL;
	struct sas_phy_linkrates *rates;
	DECLARE_COMPLETION_ONSTACK(completion);
	unsigned long flags;
	sas1068_ha = sas_phy->ha->lldd_ha;
	sas1068_ha->phy[phy_id].enable_completion = &completion;
	switch (func) {
	case PHY_FUNC_SET_LINK_RATE:
		rates = funcdata;
		if (rates->minimum_linkrate) {
			sas1068_ha->phy[phy_id].minimum_linkrate =
				rates->minimum_linkrate;
		}
		if (rates->maximum_linkrate) {
			sas1068_ha->phy[phy_id].maximum_linkrate =
				rates->maximum_linkrate;
		}
		if (sas1068_ha->phy[phy_id].phy_state == 0) {
			SAS1068_CHIP_DISP->phy_start_req(sas1068_ha, phy_id);
			wait_for_completion(&completion);
		}
		SAS1068_CHIP_DISP->phy_ctl_req(sas1068_ha, phy_id,
					      PHY_LINK_RESET);
		break;
	case PHY_FUNC_HARD_RESET:
		if (sas1068_ha->phy[phy_id].phy_state == 0) {
			SAS1068_CHIP_DISP->phy_start_req(sas1068_ha, phy_id);
			wait_for_completion(&completion);
		}
		SAS1068_CHIP_DISP->phy_ctl_req(sas1068_ha, phy_id,
					      PHY_HARD_RESET);
		break;
	case PHY_FUNC_LINK_RESET:
		if (sas1068_ha->phy[phy_id].phy_state == 0) {
			SAS1068_CHIP_DISP->phy_start_req(sas1068_ha, phy_id);
			wait_for_completion(&completion);
		}
		SAS1068_CHIP_DISP->phy_ctl_req(sas1068_ha, phy_id,
					      PHY_LINK_RESET);
		break;
	case PHY_FUNC_RELEASE_SPINUP_HOLD:
		SAS1068_CHIP_DISP->phy_ctl_req(sas1068_ha, phy_id,
					      PHY_LINK_RESET);
		break;
	case PHY_FUNC_DISABLE:
		SAS1068_CHIP_DISP->phy_stop_req(sas1068_ha, phy_id);
		break;
	case PHY_FUNC_GET_EVENTS:
		spin_lock_irqsave(&sas1068_ha->lock, flags);
		if (sas1068_ha->chip_id == chip_1068) {
			if (-1 == sas1068_bar4_shift(sas1068_ha,
					(phy_id < 4) ? 0x30000 : 0x40000)) {
				spin_unlock_irqrestore(&sas1068_ha->lock, flags);
				return -EINVAL;
			}
		}
		{
			struct sas_phy *phy = sas_phy->phy;
			uint32_t *qp = (uint32_t *)(((char *)
				sas1068_ha->io_mem[2].memvirtaddr)
				+ 0x1034 + (0x4000 * (phy_id & 3)));

			phy->invalid_dword_count = qp[0];
			phy->running_disparity_error_count = qp[1];
			phy->loss_of_dword_sync_count = qp[3];
			phy->phy_reset_problem_count = qp[4];
		}
		if (sas1068_ha->chip_id == chip_1068)
			sas1068_bar4_shift(sas1068_ha, 0);
		spin_unlock_irqrestore(&sas1068_ha->lock, flags);
		return 0;
	default:
		rc = -EOPNOTSUPP;
	}
	msleep(300);
	return rc;
}

void sas1068_scan_start(struct Scsi_Host *shost)
{
	int i;
	struct sas1068_hba_info *sas1068_ha;
	struct sas_ha_struct *sha = SHOST_TO_SAS_HA(shost);
	sas1068_ha = sha->lldd_ha;

	if (sas1068_ha->chip_id == chip_1068)
		SAS1068_CHIP_DISP->sas_re_init_req(sas1068_ha);
	for (i = 0; i < sas1068_ha->chip->n_phy; ++i)
		SAS1068_CHIP_DISP->phy_start_req(sas1068_ha, i);
}

int sas1068_scan_finished(struct Scsi_Host *shost, unsigned long time)
{
	struct sas_ha_struct *ha = SHOST_TO_SAS_HA(shost);

	/* give the phy enabling interrupt event time to come in (1s
	* is empirically about all it takes) */
	if (time < HZ)
		return 0;
	/* Wait for discovery to finish */
	sas_drain_work(ha);
	return 1;
}

static int sas1068_task_prep_smp(struct sas1068_hba_info *sas1068_ha,
	struct sas1068_ccb_info *ccb)
{
	return SAS1068_CHIP_DISP->smp_req(sas1068_ha, ccb);
}

u32 sas1068_get_ncq_tag(struct sas_task *task, u32 *tag)
{
	struct ata_queued_cmd *qc = task->uldd_task;
	if (qc) {
		if (qc->tf.command == ATA_CMD_FPDMA_WRITE ||
		    qc->tf.command == ATA_CMD_FPDMA_READ ||
		    qc->tf.command == ATA_CMD_FPDMA_RECV ||
		    qc->tf.command == ATA_CMD_FPDMA_SEND ||
		    qc->tf.command == ATA_CMD_NCQ_NON_DATA) {
			*tag = qc->tag;
			return 1;
		}
	}
	return 0;
}

static int sas1068_task_prep_ata(struct sas1068_hba_info *sas1068_ha,
	struct sas1068_ccb_info *ccb)
{
	return SAS1068_CHIP_DISP->sata_req(sas1068_ha, ccb);
}

static int sas1068_task_prep_ssp_tm(struct sas1068_hba_info *sas1068_ha,
	struct sas1068_ccb_info *ccb, struct sas1068_tmf_task *tmf)
{
	return SAS1068_CHIP_DISP->ssp_tm_req(sas1068_ha, ccb, tmf);
}

static int sas1068_task_prep_ssp(struct sas1068_hba_info *sas1068_ha,
	struct sas1068_ccb_info *ccb)
{
	return SAS1068_CHIP_DISP->ssp_io_req(sas1068_ha, ccb);
}

 /* Find the local port id that's attached to this device */
static int sas_find_local_port_id(struct domain_device *dev)
{
	struct domain_device *pdev = dev->parent;

	/* Directly attached device */
	if (!pdev)
		return dev->port->id;
	while (pdev) {
		struct domain_device *pdev_p = pdev->parent;
		if (!pdev_p)
			return pdev->port->id;
		pdev = pdev->parent;
	}
	return 0;
}

#define DEV_IS_GONE(sas1068_dev)	\
	((!sas1068_dev || (sas1068_dev->dev_type == SAS_PHY_UNUSED)))
static int sas1068_task_exec(struct sas_task *task,
	gfp_t gfp_flags, int is_tmf, struct sas1068_tmf_task *tmf)
{
	struct domain_device *dev = task->dev;
	struct sas1068_hba_info *sas1068_ha;
	struct sas1068_device *sas1068_dev;
	struct sas1068_port *port = NULL;
	struct sas_task *t = task;
	struct sas1068_ccb_info *ccb;
	u32 tag = 0xdeadbeef, rc, n_elem = 0;
	unsigned long flags = 0;

	if (!dev->port) {
		struct task_status_struct *tsm = &t->task_status;
		tsm->resp = SAS_TASK_UNDELIVERED;
		tsm->stat = SAS_PHY_DOWN;
		if (dev->dev_type != SAS_SATA_DEV)
			t->task_done(t);
		return 0;
	}
	sas1068_ha = sas1068_find_ha_by_dev(task->dev);
	SAS1068_IO_DBG(sas1068_ha, SAS1068_printk("sas1068_task_exec device \n "));
	spin_lock_irqsave(&sas1068_ha->lock, flags);
	do {
		dev = t->dev;
		sas1068_dev = dev->lldd_dev;
		port = &sas1068_ha->port[sas_find_local_port_id(dev)];
		if (DEV_IS_GONE(sas1068_dev) || !port->port_attached) {
			if (sas_protocol_ata(t->task_proto)) {
				struct task_status_struct *ts = &t->task_status;
				ts->resp = SAS_TASK_UNDELIVERED;
				ts->stat = SAS_PHY_DOWN;

				spin_unlock_irqrestore(&sas1068_ha->lock, flags);
				t->task_done(t);
				spin_lock_irqsave(&sas1068_ha->lock, flags);
				continue;
			} else {
				struct task_status_struct *ts = &t->task_status;
				ts->resp = SAS_TASK_UNDELIVERED;
				ts->stat = SAS_PHY_DOWN;
				t->task_done(t);
				continue;
			}
		}
		rc = sas1068_tag_alloc(sas1068_ha, &tag);
		if (rc)
			goto err_out;
		ccb = &sas1068_ha->ccb_info[tag];

		if (!sas_protocol_ata(t->task_proto)) {
			if (t->num_scatter) {
				n_elem = dma_map_sg(sas1068_ha->dev,
					t->scatter,
					t->num_scatter,
					t->data_dir);
				if (!n_elem) {
					rc = -ENOMEM;
					goto err_out_tag;
				}
			}
		} else {
			n_elem = t->num_scatter;
		}

		t->lldd_task = ccb;
		ccb->n_elem = n_elem;
		ccb->ccb_tag = tag;
		ccb->task = t;
		ccb->device = sas1068_dev;
		switch (t->task_proto) {
		case SAS_PROTOCOL_SMP:
			rc = sas1068_task_prep_smp(sas1068_ha, ccb);
			break;
		case SAS_PROTOCOL_SSP:
			if (is_tmf)
				rc = sas1068_task_prep_ssp_tm(sas1068_ha,
					ccb, tmf);
			else
				rc = sas1068_task_prep_ssp(sas1068_ha, ccb);
			break;
		case SAS_PROTOCOL_SATA:
		case SAS_PROTOCOL_STP:
			rc = sas1068_task_prep_ata(sas1068_ha, ccb);
			break;
		default:
			dev_printk(KERN_ERR, sas1068_ha->dev,
				"unknown sas_task proto: 0x%x\n",
				t->task_proto);
			rc = -EINVAL;
			break;
		}

		if (rc) {
			SAS1068_IO_DBG(sas1068_ha,
				SAS1068_printk("rc is %x\n", rc));
			goto err_out_tag;
		}
		/* TODO: select normal or high priority */
		spin_lock(&t->task_state_lock);
		t->task_state_flags |= SAS_TASK_AT_INITIATOR;
		spin_unlock(&t->task_state_lock);
		sas1068_dev->running_req++;
	} while (0);
	rc = 0;
	goto out_done;

err_out_tag:
	sas1068_tag_free(sas1068_ha, tag);
err_out:
	dev_printk(KERN_ERR, sas1068_ha->dev, "sas1068 exec failed[%d]!\n", rc);
	if (!sas_protocol_ata(t->task_proto))
		if (n_elem)
			dma_unmap_sg(sas1068_ha->dev, t->scatter, n_elem,
				t->data_dir);
out_done:
	spin_unlock_irqrestore(&sas1068_ha->lock, flags);
	return rc;
}

int sas1068_queue_command(struct sas_task *task, gfp_t gfp_flags)
{
	return sas1068_task_exec(task, gfp_flags, 0, NULL);
}

void sas1068_ccb_task_free(struct sas1068_hba_info *sas1068_ha,
	struct sas_task *task, struct sas1068_ccb_info *ccb, u32 ccb_idx)
{
	if (!ccb->task)
		return;
	if (!sas_protocol_ata(task->task_proto))
		if (ccb->n_elem)
			dma_unmap_sg(sas1068_ha->dev, task->scatter,
				task->num_scatter, task->data_dir);

	switch (task->task_proto) {
	case SAS_PROTOCOL_SMP:
		dma_unmap_sg(sas1068_ha->dev, &task->smp_task.smp_resp, 1,
			PCI_DMA_FROMDEVICE);
		dma_unmap_sg(sas1068_ha->dev, &task->smp_task.smp_req, 1,
			PCI_DMA_TODEVICE);
		break;

	case SAS_PROTOCOL_SATA:
	case SAS_PROTOCOL_STP:
	case SAS_PROTOCOL_SSP:
	default:
		/* do nothing */
		break;
	}
	task->lldd_task = NULL;
	ccb->task = NULL;
	ccb->ccb_tag = 0xFFFFFFFF;
	ccb->open_retry = 0;
	sas1068_tag_free(sas1068_ha, ccb_idx);
}

 /**
  * sas1068_alloc_dev - find a empty sas1068_device
  * @sas1068_ha: our hba card information
  */
static struct sas1068_device *sas1068_alloc_dev(struct sas1068_hba_info *sas1068_ha)
{
	u32 dev;
	for (dev = 0; dev < SAS1068_MAX_DEVICES; dev++) {
		if (sas1068_ha->devices[dev].dev_type == SAS_PHY_UNUSED) {
			sas1068_ha->devices[dev].id = dev;
			return &sas1068_ha->devices[dev];
		}
	}
	if (dev == SAS1068_MAX_DEVICES) {
		SAS1068_FAIL_DBG(sas1068_ha,
			SAS1068_printk("max support %d devices, ignore ..\n",
			SAS1068_MAX_DEVICES));
	}
	return NULL;
}
/**
  * sas1068_find_dev - find a matching sas1068_device
  * @sas1068_ha: our hba card information
  */
struct sas1068_device *sas1068_find_dev(struct sas1068_hba_info *sas1068_ha,
					u32 device_id)
{
	u32 dev;
	for (dev = 0; dev < SAS1068_MAX_DEVICES; dev++) {
		if (sas1068_ha->devices[dev].device_id == device_id)
			return &sas1068_ha->devices[dev];
	}
	if (dev == SAS1068_MAX_DEVICES) {
		SAS1068_FAIL_DBG(sas1068_ha, SAS1068_printk("NO MATCHING "
				"DEVICE FOUND !!!\n"));
	}
	return NULL;
}

static void sas1068_free_dev(struct sas1068_device *sas1068_dev)
{
	u32 id = sas1068_dev->id;
	memset(sas1068_dev, 0, sizeof(*sas1068_dev));
	sas1068_dev->id = id;
	sas1068_dev->dev_type = SAS_PHY_UNUSED;
	sas1068_dev->device_id = SAS1068_MAX_DEVICES;
	sas1068_dev->sas_device = NULL;
}

static int sas1068_dev_found_notify(struct domain_device *dev)
{
	unsigned long flags = 0;
	int res = 0;
	struct sas1068_hba_info *sas1068_ha = NULL;
	struct domain_device *parent_dev = dev->parent;
	struct sas1068_device *sas1068_device;
	DECLARE_COMPLETION_ONSTACK(completion);
	u32 flag = 0;
	sas1068_ha = sas1068_find_ha_by_dev(dev);
	spin_lock_irqsave(&sas1068_ha->lock, flags);

	sas1068_device = sas1068_alloc_dev(sas1068_ha);
	if (!sas1068_device) {
		res = -1;
		goto found_out;
	}
	sas1068_device->sas_device = dev;
	dev->lldd_dev = sas1068_device;
	sas1068_device->dev_type = dev->dev_type;
	sas1068_device->dcompletion = &completion;
	if (parent_dev && DEV_IS_EXPANDER(parent_dev->dev_type)) {
		int phy_id;
		struct ex_phy *phy;
		for (phy_id = 0; phy_id < parent_dev->ex_dev.num_phys;
		phy_id++) {
			phy = &parent_dev->ex_dev.ex_phy[phy_id];
			if (SAS_ADDR(phy->attached_sas_addr)
				== SAS_ADDR(dev->sas_addr)) {
				sas1068_device->attached_phy = phy_id;
				break;
			}
		}
		if (phy_id == parent_dev->ex_dev.num_phys) {
			SAS1068_FAIL_DBG(sas1068_ha,
			SAS1068_printk("Error: no attached dev:%016llx"
			" at ex:%016llx.\n", SAS_ADDR(dev->sas_addr),
				SAS_ADDR(parent_dev->sas_addr)));
			res = -1;
		}
	} else {
		if (dev->dev_type == SAS_SATA_DEV) {
			sas1068_device->attached_phy =
				dev->rphy->identify.phy_identifier;
				flag = 1; /* directly sata*/
		}
	} /*register this device to HBA*/
	SAS1068_DISC_DBG(sas1068_ha, SAS1068_printk("Found device\n"));
	SAS1068_CHIP_DISP->reg_dev_req(sas1068_ha, sas1068_device, flag);
	spin_unlock_irqrestore(&sas1068_ha->lock, flags);
	wait_for_completion(&completion);
	if (dev->dev_type == SAS_END_DEVICE)
		msleep(50);
	sas1068_ha->flags = SAS1068F_RUN_TIME;
	return 0;
found_out:
	spin_unlock_irqrestore(&sas1068_ha->lock, flags);
	return res;
}

int sas1068_dev_found(struct domain_device *dev)
{
	return sas1068_dev_found_notify(dev);
}

void sas1068_task_done(struct sas_task *task)
{
	if (!del_timer(&task->slow_task->timer))
		return;
	complete(&task->slow_task->completion);
}

static void sas1068_tmf_timedout(struct timer_list *t)
{
	struct sas_task_slow *slow = from_timer(slow, t, timer);
	struct sas_task *task = slow->task;

	task->task_state_flags |= SAS_TASK_STATE_ABORTED;
	complete(&task->slow_task->completion);
}

#define sas1068_TASK_TIMEOUT 20
static int sas1068_exec_internal_tmf_task(struct domain_device *dev,
	void *parameter, u32 para_len, struct sas1068_tmf_task *tmf)
{
	int res, retry;
	struct sas_task *task = NULL;
	struct sas1068_hba_info *sas1068_ha = sas1068_find_ha_by_dev(dev);
	struct sas1068_device *sas1068_dev = dev->lldd_dev;
	DECLARE_COMPLETION_ONSTACK(completion_setstate);

	for (retry = 0; retry < 3; retry++) {
		task = sas_alloc_slow_task(GFP_KERNEL);
		if (!task)
			return -ENOMEM;

		task->dev = dev;
		task->task_proto = dev->tproto;
		memcpy(&task->ssp_task, parameter, para_len);
		task->task_done = sas1068_task_done;
		task->slow_task->timer.function = sas1068_tmf_timedout;
		task->slow_task->timer.expires = jiffies + sas1068_TASK_TIMEOUT*HZ;
		add_timer(&task->slow_task->timer);

		res = sas1068_task_exec(task, GFP_KERNEL, 1, tmf);

		if (res) {
			del_timer(&task->slow_task->timer);
			SAS1068_FAIL_DBG(sas1068_ha,
				SAS1068_printk("Executing internal task "
				"failed\n"));
			goto ex_err;
		}
		wait_for_completion(&task->slow_task->completion);
		if (sas1068_ha->chip_id != chip_1068) {
			sas1068_dev->setds_completion = &completion_setstate;
				SAS1068_CHIP_DISP->set_dev_state_req(sas1068_ha,
					sas1068_dev, 0x01);
			wait_for_completion(&completion_setstate);
		}
		res = -TMF_RESP_FUNC_FAILED;
		/* Even TMF timed out, return direct. */
		if ((task->task_state_flags & SAS_TASK_STATE_ABORTED)) {
			if (!(task->task_state_flags & SAS_TASK_STATE_DONE)) {
				SAS1068_FAIL_DBG(sas1068_ha,
					SAS1068_printk("TMF task[%x]timeout.\n",
					tmf->tmf));
				goto ex_err;
			}
		}

		if (task->task_status.resp == SAS_TASK_COMPLETE &&
			task->task_status.stat == SAM_STAT_GOOD) {
			res = TMF_RESP_FUNC_COMPLETE;
			break;
		}

		if (task->task_status.resp == SAS_TASK_COMPLETE &&
		task->task_status.stat == SAS_DATA_UNDERRUN) {
			/* no error, but return the number of bytes of
			* underrun */
			res = task->task_status.residual;
			break;
		}

		if (task->task_status.resp == SAS_TASK_COMPLETE &&
			task->task_status.stat == SAS_DATA_OVERRUN) {
			SAS1068_FAIL_DBG(sas1068_ha,
				SAS1068_printk("Blocked task error.\n"));
			res = -EMSGSIZE;
			break;
		} else {
			SAS1068_EH_DBG(sas1068_ha,
				SAS1068_printk(" Task to dev %016llx response:"
				"0x%x status 0x%x\n",
				SAS_ADDR(dev->sas_addr),
				task->task_status.resp,
				task->task_status.stat));
			sas_free_task(task);
			task = NULL;
		}
	}
ex_err:
	BUG_ON(retry == 3 && task != NULL);
	sas_free_task(task);
	return res;
}

static int
sas1068_exec_internal_task_abort(struct sas1068_hba_info *sas1068_ha,
	struct sas1068_device *sas1068_dev, struct domain_device *dev, u32 flag,
	u32 task_tag)
{
	int res, retry;
	u32 ccb_tag;
	struct sas1068_ccb_info *ccb;
	struct sas_task *task = NULL;

	for (retry = 0; retry < 3; retry++) {
		task = sas_alloc_slow_task(GFP_KERNEL);
		if (!task)
			return -ENOMEM;

		task->dev = dev;
		task->task_proto = dev->tproto;
		task->task_done = sas1068_task_done;
		task->slow_task->timer.function = sas1068_tmf_timedout;
		task->slow_task->timer.expires = jiffies + sas1068_TASK_TIMEOUT * HZ;
		add_timer(&task->slow_task->timer);

		res = sas1068_tag_alloc(sas1068_ha, &ccb_tag);
		if (res)
			return res;
		ccb = &sas1068_ha->ccb_info[ccb_tag];
		ccb->device = sas1068_dev;
		ccb->ccb_tag = ccb_tag;
		ccb->task = task;
		ccb->n_elem = 0;

		res = SAS1068_CHIP_DISP->task_abort(sas1068_ha,
			sas1068_dev, flag, task_tag, ccb_tag);

		if (res) {
			del_timer(&task->slow_task->timer);
			SAS1068_FAIL_DBG(sas1068_ha,
				SAS1068_printk("Executing internal task "
				"failed\n"));
			goto ex_err;
		}
		wait_for_completion(&task->slow_task->completion);
		res = TMF_RESP_FUNC_FAILED;
		/* Even TMF timed out, return direct. */
		if ((task->task_state_flags & SAS_TASK_STATE_ABORTED)) {
			if (!(task->task_state_flags & SAS_TASK_STATE_DONE)) {
				SAS1068_FAIL_DBG(sas1068_ha,
					SAS1068_printk("TMF task timeout.\n"));
				goto ex_err;
			}
		}

		if (task->task_status.resp == SAS_TASK_COMPLETE &&
			task->task_status.stat == SAM_STAT_GOOD) {
			res = TMF_RESP_FUNC_COMPLETE;
			break;

		} else {
			SAS1068_EH_DBG(sas1068_ha,
				SAS1068_printk(" Task to dev %016llx response: "
					"0x%x status 0x%x\n",
				SAS_ADDR(dev->sas_addr),
				task->task_status.resp,
				task->task_status.stat));
			sas_free_task(task);
			task = NULL;
		}
	}
ex_err:
	BUG_ON(retry == 3 && task != NULL);
	sas_free_task(task);
	return res;
}

static void sas1068_dev_gone_notify(struct domain_device *dev)
{
	unsigned long flags = 0;
	struct sas1068_hba_info *sas1068_ha;
	struct sas1068_device *sas1068_dev = dev->lldd_dev;

	sas1068_ha = sas1068_find_ha_by_dev(dev);
	spin_lock_irqsave(&sas1068_ha->lock, flags);
	if (sas1068_dev) {
		u32 device_id = sas1068_dev->device_id;

		SAS1068_DISC_DBG(sas1068_ha,
			SAS1068_printk("found dev[%d:%x] is gone.\n",
			sas1068_dev->device_id, sas1068_dev->dev_type));
		if (sas1068_dev->running_req) {
			spin_unlock_irqrestore(&sas1068_ha->lock, flags);
			sas1068_exec_internal_task_abort(sas1068_ha, sas1068_dev ,
				dev, 1, 0);
			spin_lock_irqsave(&sas1068_ha->lock, flags);
		}
		SAS1068_CHIP_DISP->dereg_dev_req(sas1068_ha, device_id);
		sas1068_free_dev(sas1068_dev);
	} else {
		SAS1068_DISC_DBG(sas1068_ha,
			SAS1068_printk("Found dev has gone.\n"));
	}
	dev->lldd_dev = NULL;
	spin_unlock_irqrestore(&sas1068_ha->lock, flags);
}

void sas1068_dev_gone(struct domain_device *dev)
{
	sas1068_dev_gone_notify(dev);
}

static int sas1068_issue_ssp_tmf(struct domain_device *dev,
	u8 *lun, struct sas1068_tmf_task *tmf)
{
	struct sas_ssp_task ssp_task;
	if (!(dev->tproto & SAS_PROTOCOL_SSP))
		return TMF_RESP_FUNC_ESUPP;

	strncpy((u8 *)&ssp_task.LUN, lun, 8);
	return sas1068_exec_internal_tmf_task(dev, &ssp_task, sizeof(ssp_task),
		tmf);
}

/* retry commands by ha, by task and/or by device */
void sas1068_open_reject_retry(
	struct sas1068_hba_info *sas1068_ha,
	struct sas_task *task_to_close,
	struct sas1068_device *device_to_close)
{
	int i;
	unsigned long flags;

	if (sas1068_ha == NULL)
		return;

	spin_lock_irqsave(&sas1068_ha->lock, flags);

	for (i = 0; i < SAS1068_MAX_CCB; i++) {
		struct sas_task *task;
		struct task_status_struct *ts;
		struct sas1068_device *sas1068_dev;
		unsigned long flags1;
		u32 tag;
		struct sas1068_ccb_info *ccb = &sas1068_ha->ccb_info[i];

		sas1068_dev = ccb->device;
		if (!sas1068_dev || (sas1068_dev->dev_type == SAS_PHY_UNUSED))
			continue;
		if (!device_to_close) {
			uintptr_t d = (uintptr_t)sas1068_dev
					- (uintptr_t)&sas1068_ha->devices;
			if (((d % sizeof(*sas1068_dev)) != 0)
			 || ((d / sizeof(*sas1068_dev)) >= SAS1068_MAX_DEVICES))
				continue;
		} else if (sas1068_dev != device_to_close)
			continue;
		tag = ccb->ccb_tag;
		if (!tag || (tag == 0xFFFFFFFF))
			continue;
		task = ccb->task;
		if (!task || !task->task_done)
			continue;
		if (task_to_close && (task != task_to_close))
			continue;
		ts = &task->task_status;
		ts->resp = SAS_TASK_COMPLETE;
		/* Force the midlayer to retry */
		ts->stat = SAS_OPEN_REJECT;
		ts->open_rej_reason = SAS_OREJ_RSVD_RETRY;
		if (sas1068_dev)
			sas1068_dev->running_req--;
		spin_lock_irqsave(&task->task_state_lock, flags1);
		task->task_state_flags &= ~SAS_TASK_STATE_PENDING;
		task->task_state_flags &= ~SAS_TASK_AT_INITIATOR;
		task->task_state_flags |= SAS_TASK_STATE_DONE;
		if (unlikely((task->task_state_flags
				& SAS_TASK_STATE_ABORTED))) {
			spin_unlock_irqrestore(&task->task_state_lock,
				flags1);
			sas1068_ccb_task_free(sas1068_ha, task, ccb, tag);
		} else {
			spin_unlock_irqrestore(&task->task_state_lock,
				flags1);
			sas1068_ccb_task_free(sas1068_ha, task, ccb, tag);
			mb();/* in order to force CPU ordering */
			spin_unlock_irqrestore(&sas1068_ha->lock, flags);
			task->task_done(task);
			spin_lock_irqsave(&sas1068_ha->lock, flags);
		}
	}

	spin_unlock_irqrestore(&sas1068_ha->lock, flags);
}

/**
  * Standard mandates link reset for ATA  (type 0) and hard reset for
  * SSP (type 1) , only for RECOVERY
  */
int sas1068_I_T_nexus_reset(struct domain_device *dev)
{
	int rc = TMF_RESP_FUNC_FAILED;
	struct sas1068_device *sas1068_dev;
	struct sas1068_hba_info *sas1068_ha;
	struct sas_phy *phy;

	if (!dev || !dev->lldd_dev)
		return -ENODEV;

	sas1068_dev = dev->lldd_dev;
	sas1068_ha = sas1068_find_ha_by_dev(dev);
	phy = sas_get_local_phy(dev);

	if (dev_is_sata(dev)) {
		if (scsi_is_sas_phy_local(phy)) {
			rc = 0;
			goto out;
		}
		rc = sas_phy_reset(phy, 1);
		if (rc) {
			SAS1068_EH_DBG(sas1068_ha,
			SAS1068_printk("phy reset failed for device %x\n"
			"with rc %d\n", sas1068_dev->device_id, rc));
			rc = TMF_RESP_FUNC_FAILED;
			goto out;
		}
		msleep(2000);
		rc = sas1068_exec_internal_task_abort(sas1068_ha, sas1068_dev ,
			dev, 1, 0);
		if (rc) {
			SAS1068_EH_DBG(sas1068_ha,
			SAS1068_printk("task abort failed %x\n"
			"with rc %d\n", sas1068_dev->device_id, rc));
			rc = TMF_RESP_FUNC_FAILED;
		}
	} else {
		rc = sas_phy_reset(phy, 1);
		msleep(2000);
	}
	SAS1068_EH_DBG(sas1068_ha, SAS1068_printk(" for device[%x]:rc=%d\n",
		sas1068_dev->device_id, rc));
 out:
	sas_put_local_phy(phy);
	return rc;
}

/*
* This function handle the IT_NEXUS_XXX event or completion
* status code for SSP/SATA/SMP I/O request.
*/
int sas1068_I_T_nexus_event_handler(struct domain_device *dev)
{
	int rc = TMF_RESP_FUNC_FAILED;
	struct sas1068_device *sas1068_dev;
	struct sas1068_hba_info *sas1068_ha;
	struct sas_phy *phy;
	u32 device_id = 0;

	if (!dev || !dev->lldd_dev)
		return -1;

	sas1068_dev = dev->lldd_dev;
	device_id = sas1068_dev->device_id;
	sas1068_ha = sas1068_find_ha_by_dev(dev);

	SAS1068_EH_DBG(sas1068_ha,
			SAS1068_printk("I_T_Nexus handler invoked !!"));

	phy = sas_get_local_phy(dev);

	if (dev_is_sata(dev)) {
		DECLARE_COMPLETION_ONSTACK(completion_setstate);
		if (scsi_is_sas_phy_local(phy)) {
			rc = 0;
			goto out;
		}
		/* send internal ssp/sata/smp abort command to FW */
		rc = sas1068_exec_internal_task_abort(sas1068_ha, sas1068_dev ,
							dev, 1, 0);
		msleep(100);

		/* deregister the target device */
		sas1068_dev_gone_notify(dev);
		msleep(200);

		/*send phy reset to hard reset target */
		rc = sas_phy_reset(phy, 1);
		msleep(2000);
		sas1068_dev->setds_completion = &completion_setstate;

		wait_for_completion(&completion_setstate);
	} else {
		/* send internal ssp/sata/smp abort command to FW */
		rc = sas1068_exec_internal_task_abort(sas1068_ha, sas1068_dev ,
							dev, 1, 0);
		msleep(100);

		/* deregister the target device */
		sas1068_dev_gone_notify(dev);
		msleep(200);

		/*send phy reset to hard reset target */
		rc = sas_phy_reset(phy, 1);
		msleep(2000);
	}
	SAS1068_EH_DBG(sas1068_ha, SAS1068_printk(" for device[%x]:rc=%d\n",
		sas1068_dev->device_id, rc));
out:
	sas_put_local_phy(phy);

	return rc;
}
/* mandatory SAM-3, the task reset the specified LUN*/
int sas1068_lu_reset(struct domain_device *dev, u8 *lun)
{
	int rc = TMF_RESP_FUNC_FAILED;
	struct sas1068_tmf_task tmf_task;
	struct sas1068_device *sas1068_dev = dev->lldd_dev;
	struct sas1068_hba_info *sas1068_ha = sas1068_find_ha_by_dev(dev);
	DECLARE_COMPLETION_ONSTACK(completion_setstate);
	if (dev_is_sata(dev)) {
		struct sas_phy *phy = sas_get_local_phy(dev);
		rc = sas1068_exec_internal_task_abort(sas1068_ha, sas1068_dev ,
			dev, 1, 0);
		rc = sas_phy_reset(phy, 1);
		sas_put_local_phy(phy);
		sas1068_dev->setds_completion = &completion_setstate;
		rc = SAS1068_CHIP_DISP->set_dev_state_req(sas1068_ha,
			sas1068_dev, 0x01);
		wait_for_completion(&completion_setstate);
	} else {
		tmf_task.tmf = TMF_LU_RESET;
		rc = sas1068_issue_ssp_tmf(dev, lun, &tmf_task);
	}
	/* If failed, fall-through I_T_Nexus reset */
	SAS1068_EH_DBG(sas1068_ha, SAS1068_printk("for device[%x]:rc=%d\n",
		sas1068_dev->device_id, rc));
	return rc;
}

/* optional SAM-3 */
int sas1068_query_task(struct sas_task *task)
{
	u32 tag = 0xdeadbeef;
	int i = 0;
	struct scsi_lun lun;
	struct sas1068_tmf_task tmf_task;
	int rc = TMF_RESP_FUNC_FAILED;
	if (unlikely(!task || !task->lldd_task || !task->dev))
		return rc;

	if (task->task_proto & SAS_PROTOCOL_SSP) {
		struct scsi_cmnd *cmnd = task->uldd_task;
		struct domain_device *dev = task->dev;
		struct sas1068_hba_info *sas1068_ha =
			sas1068_find_ha_by_dev(dev);

		int_to_scsilun(cmnd->device->lun, &lun);
		rc = sas1068_find_tag(task, &tag);
		if (rc == 0) {
			rc = TMF_RESP_FUNC_FAILED;
			return rc;
		}
		SAS1068_EH_DBG(sas1068_ha, SAS1068_printk("Query:["));
		for (i = 0; i < 16; i++)
			printk(KERN_INFO "%02x ", cmnd->cmnd[i]);
		printk(KERN_INFO "]\n");
		tmf_task.tmf = 	TMF_QUERY_TASK;
		tmf_task.tag_of_task_to_be_managed = tag;

		rc = sas1068_issue_ssp_tmf(dev, lun.scsi_lun, &tmf_task);
		switch (rc) {
		/* The task is still in Lun, release it then */
		case TMF_RESP_FUNC_SUCC:
			SAS1068_EH_DBG(sas1068_ha,
				SAS1068_printk("The task is still in Lun\n"));
			break;
		/* The task is not in Lun or failed, reset the phy */
		case TMF_RESP_FUNC_FAILED:
		case TMF_RESP_FUNC_COMPLETE:
			SAS1068_EH_DBG(sas1068_ha,
			SAS1068_printk("The task is not in Lun or failed,"
			" reset the phy\n"));
			break;
		}
	}
	SAS1068_printk(":rc= %d\n", rc);
	return rc;
}

/*  mandatory SAM-3, still need free task/ccb info, abord the specified task */
int sas1068_abort_task(struct sas_task *task)
{
	unsigned long flags;
	u32 tag;
	u32 device_id;
	struct domain_device *dev ;
	struct sas1068_hba_info *sas1068_ha;
	struct scsi_lun lun;
	struct sas1068_device *sas1068_dev;
	struct sas1068_tmf_task tmf_task;
	int rc = TMF_RESP_FUNC_FAILED;
	u32 phy_id;
	struct sas_task_slow slow_task;
	if (unlikely(!task || !task->lldd_task || !task->dev))
		return TMF_RESP_FUNC_FAILED;
	dev = task->dev;
	sas1068_dev = dev->lldd_dev;
	sas1068_ha = sas1068_find_ha_by_dev(dev);
	device_id = sas1068_dev->device_id;
	phy_id = sas1068_dev->attached_phy;
	rc = sas1068_find_tag(task, &tag);
	if (rc == 0) {
		SAS1068_printk("no tag for task:%p\n", task);
		return TMF_RESP_FUNC_FAILED;
	}
	spin_lock_irqsave(&task->task_state_lock, flags);
	if (task->task_state_flags & SAS_TASK_STATE_DONE) {
		spin_unlock_irqrestore(&task->task_state_lock, flags);
		return TMF_RESP_FUNC_COMPLETE;
	}
	task->task_state_flags |= SAS_TASK_STATE_ABORTED;
	if (task->slow_task == NULL) {
		init_completion(&slow_task.completion);
		task->slow_task = &slow_task;
	}
	spin_unlock_irqrestore(&task->task_state_lock, flags);
	if (task->task_proto & SAS_PROTOCOL_SSP) {
		struct scsi_cmnd *cmnd = task->uldd_task;
		int_to_scsilun(cmnd->device->lun, &lun);
		tmf_task.tmf = TMF_ABORT_TASK;
		tmf_task.tag_of_task_to_be_managed = tag;
		rc = sas1068_issue_ssp_tmf(dev, lun.scsi_lun, &tmf_task);
		sas1068_exec_internal_task_abort(sas1068_ha, sas1068_dev,
			sas1068_dev->sas_device, 0, tag);
	} else if (task->task_proto & SAS_PROTOCOL_SATA ||
		task->task_proto & SAS_PROTOCOL_STP) {
		rc = sas1068_exec_internal_task_abort(sas1068_ha,
			sas1068_dev, sas1068_dev->sas_device, 0, tag);
		rc = TMF_RESP_FUNC_COMPLETE;
	} else if (task->task_proto & SAS_PROTOCOL_SMP) {
		/* SMP */
		rc = sas1068_exec_internal_task_abort(sas1068_ha, sas1068_dev,
			sas1068_dev->sas_device, 0, tag);

	}
	spin_lock_irqsave(&task->task_state_lock, flags);
	if (task->slow_task == &slow_task)
		task->slow_task = NULL;
	spin_unlock_irqrestore(&task->task_state_lock, flags);
	if (rc != TMF_RESP_FUNC_COMPLETE)
		SAS1068_printk("rc= %d\n", rc);
	return rc;
}

int sas1068_abort_task_set(struct domain_device *dev, u8 *lun)
{
	int rc = TMF_RESP_FUNC_FAILED;
	struct sas1068_tmf_task tmf_task;

	tmf_task.tmf = TMF_ABORT_TASK_SET;
	rc = sas1068_issue_ssp_tmf(dev, lun, &tmf_task);
	return rc;
}

int sas1068_clear_aca(struct domain_device *dev, u8 *lun)
{
	int rc = TMF_RESP_FUNC_FAILED;
	struct sas1068_tmf_task tmf_task;

	tmf_task.tmf = TMF_CLEAR_ACA;
	rc = sas1068_issue_ssp_tmf(dev, lun, &tmf_task);

	return rc;
}

int sas1068_clear_task_set(struct domain_device *dev, u8 *lun)
{
	int rc = TMF_RESP_FUNC_FAILED;
	struct sas1068_tmf_task tmf_task;
	struct sas1068_device *sas1068_dev = dev->lldd_dev;
	struct sas1068_hba_info *sas1068_ha = sas1068_find_ha_by_dev(dev);

	SAS1068_EH_DBG(sas1068_ha,
		SAS1068_printk("I_T_L_Q clear task set[%x]\n",
		sas1068_dev->device_id));
	tmf_task.tmf = TMF_CLEAR_TASK_SET;
	rc = sas1068_issue_ssp_tmf(dev, lun, &tmf_task);
	return rc;
}

