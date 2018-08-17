#include <linux/slab.h>
#include "sas1068_sas.h"
#include "sas1068_chips.h"

static struct scsi_transport_template *sas1068_stt;

static const struct sas1068_chip_info sas1068_chips[] = {
	[chip_1068] = {0,  8, &sas1068_dispatch_inst,},
	[chip_1068e] = {0,  8, &sas1068_dispatch_inst,},
};
static int sas1068_id;

LIST_HEAD(hba_list);

struct workqueue_struct *sas1068_wq;

static struct scsi_host_template sas1068_sht = {
	.module			= THIS_MODULE,
	.name			= DRV_NAME,
	.queuecommand		= sas_queuecommand,
	.target_alloc		= sas_target_alloc,
	.slave_configure	= sas_slave_configure,
	.scan_finished		= sas1068_scan_finished,
	.scan_start		= sas1068_scan_start,
	.change_queue_depth	= sas_change_queue_depth,
	.bios_param		= sas_bios_param,
	.can_queue		= 1,
	.this_id		= -1,
	.sg_tablesize		= SG_ALL,
	.max_sectors		= SCSI_DEFAULT_MAX_SECTORS,
	.use_clustering		= ENABLE_CLUSTERING,
	.eh_device_reset_handler = sas_eh_device_reset_handler,
	.eh_target_reset_handler = sas_eh_target_reset_handler,
	.target_destroy		= sas_target_destroy,
	.ioctl			= sas_ioctl,
	.shost_attrs		= sas1068_host_attrs,
	.track_queue_depth	= 1,
};

static struct sas_domain_function_template sas1068_transport_ops = {
	.lldd_dev_found		= sas1068_dev_found,
	.lldd_dev_gone		= sas1068_dev_gone,
	.lldd_execute_task	= sas1068_queue_command,
	.lldd_control_phy	= sas1068_phy_control,
	.lldd_abort_task	= sas1068_abort_task,
	.lldd_abort_task_set	= sas1068_abort_task_set,
	.lldd_clear_aca		= sas1068_clear_aca,
	.lldd_clear_task_set	= sas1068_clear_task_set,
	.lldd_I_T_nexus_reset   = sas1068_I_T_nexus_reset,
	.lldd_lu_reset		= sas1068_lu_reset,
	.lldd_query_task	= sas1068_query_task,
};

static void sas1068_phy_init(struct sas1068_hba_info *sas1068_ha, int phy_id)
{
	struct sas1068_phy *phy = &sas1068_ha->phy[phy_id];
	struct asd_sas_phy *sas_phy = &phy->sas_phy;
	phy->phy_state = 0;
	phy->sas1068_ha = sas1068_ha;
	sas_phy->enabled = (phy_id < sas1068_ha->chip->n_phy) ? 1 : 0;
	sas_phy->class = SAS;
	sas_phy->iproto = SAS_PROTOCOL_ALL;
	sas_phy->tproto = 0;
	sas_phy->type = PHY_TYPE_PHYSICAL;
	sas_phy->role = PHY_ROLE_INITIATOR;
	sas_phy->oob_mode = OOB_NOT_CONNECTED;
	sas_phy->linkrate = SAS_LINK_RATE_UNKNOWN;
	sas_phy->id = phy_id;
	sas_phy->sas_addr = (u8 *)&phy->dev_sas_addr;
	sas_phy->frame_rcvd = &phy->frame_rcvd[0];
	sas_phy->ha = (struct sas_ha_struct *)sas1068_ha->shost->hostdata;
	sas_phy->lldd_phy = phy;
}

static void sas1068_free(struct sas1068_hba_info *sas1068_ha)
{
	int i;
	if (!sas1068_ha)
		return;

	for (i = 0; i < LSI_MAX_MEMCNT; i++) {
		if (sas1068_ha->memoryMap.region[i].virt_ptr != NULL) {
			pci_free_consistent(sas1068_ha->pdev,
				(sas1068_ha->memoryMap.region[i].total_len +
				sas1068_ha->memoryMap.region[i].alignment),
				sas1068_ha->memoryMap.region[i].virt_ptr,
				sas1068_ha->memoryMap.region[i].phys_addr);
			}
	}
	SAS1068_CHIP_DISP->chip_iounmap(sas1068_ha);
	flush_workqueue(sas1068_wq);
	kfree(sas1068_ha->tags);
	kfree(sas1068_ha);
}

#ifdef SAS1068_USE_TASKLET
static void sas1068_tasklet(unsigned long opaque)
{
	struct sas1068_hba_info *sas1068_ha;
	struct isr_param *irq_vector;

	irq_vector = (struct isr_param *)opaque;
	sas1068_ha = irq_vector->drv_inst;
	if (unlikely(!sas1068_ha))
		BUG_ON(1);
	SAS1068_CHIP_DISP->isr(sas1068_ha, irq_vector->irq_id);
}
#endif

static irqreturn_t sas1068_interrupt_handler_msix(int irq, void *opaque)
{
	struct isr_param *irq_vector;
	struct sas1068_hba_info *sas1068_ha;
	irqreturn_t ret = IRQ_HANDLED;
	irq_vector = (struct isr_param *)opaque;
	sas1068_ha = irq_vector->drv_inst;

	if (unlikely(!sas1068_ha))
		return IRQ_NONE;
	if (!SAS1068_CHIP_DISP->is_our_interupt(sas1068_ha))
		return IRQ_NONE;
#ifdef SAS1068_USE_TASKLET
	tasklet_schedule(&sas1068_ha->tasklet[irq_vector->irq_id]);
#else
	ret = SAS1068_CHIP_DISP->isr(sas1068_ha, irq_vector->irq_id);
#endif
	return ret;
}

static irqreturn_t sas1068_interrupt_handler_intx(int irq, void *dev_id)
{
	struct sas1068_hba_info *sas1068_ha;
	irqreturn_t ret = IRQ_HANDLED;
	struct sas_ha_struct *sha = dev_id;
	sas1068_ha = sha->lldd_ha;
	if (unlikely(!sas1068_ha))
		return IRQ_NONE;
	if (!SAS1068_CHIP_DISP->is_our_interupt(sas1068_ha))
		return IRQ_NONE;

#ifdef SAS1068_USE_TASKLET
	tasklet_schedule(&sas1068_ha->tasklet[0]);
#else
	ret = SAS1068_CHIP_DISP->isr(sas1068_ha, 0);
#endif
	return ret;
}

static int sas1068_alloc(struct sas1068_hba_info *sas1068_ha,
			const struct pci_device_id *ent)
{
	int i;
	spin_lock_init(&sas1068_ha->lock);
	spin_lock_init(&sas1068_ha->bitmap_lock);
	SAS1068_INIT_DBG(sas1068_ha,
		SAS1068_printk("sas1068_alloc: PHY:%x\n",
				sas1068_ha->chip->n_phy));
	for (i = 0; i < sas1068_ha->chip->n_phy; i++) {
		sas1068_phy_init(sas1068_ha, i);
		sas1068_ha->port[i].wide_port_phymap = 0;
		sas1068_ha->port[i].port_attached = 0;
		sas1068_ha->port[i].port_state = 0;
		INIT_LIST_HEAD(&sas1068_ha->port[i].list);
	}

	sas1068_ha->tags = kzalloc(SAS1068_MAX_CCB, GFP_KERNEL);
	if (!sas1068_ha->tags)
		goto err_out;
	/* MPI Memory region 1 for AAP Event Log for fw */
	sas1068_ha->memoryMap.region[AAP1].num_elements = 1;
	sas1068_ha->memoryMap.region[AAP1].element_size = SAS1068_EVENT_LOG_SIZE;
	sas1068_ha->memoryMap.region[AAP1].total_len = SAS1068_EVENT_LOG_SIZE;
	sas1068_ha->memoryMap.region[AAP1].alignment = 32;

	/* MPI Memory region 2 for IOP Event Log for fw */
	sas1068_ha->memoryMap.region[IOP].num_elements = 1;
	sas1068_ha->memoryMap.region[IOP].element_size = SAS1068_EVENT_LOG_SIZE;
	sas1068_ha->memoryMap.region[IOP].total_len = SAS1068_EVENT_LOG_SIZE;
	sas1068_ha->memoryMap.region[IOP].alignment = 32;

	for (i = 0; i < SAS1068_MAX_SPCV_INB_NUM; i++) {
		/* MPI Memory region 3 for consumer Index of inbound queues */
		sas1068_ha->memoryMap.region[CI+i].num_elements = 1;
		sas1068_ha->memoryMap.region[CI+i].element_size = 4;
		sas1068_ha->memoryMap.region[CI+i].total_len = 4;
		sas1068_ha->memoryMap.region[CI+i].alignment = 4;

		if ((ent->driver_data) != chip_1068) {
			/* MPI Memory region 5 inbound queues */
			sas1068_ha->memoryMap.region[IB+i].num_elements =
						SAS1068_MPI_QUEUE;
			sas1068_ha->memoryMap.region[IB+i].element_size = 128;
			sas1068_ha->memoryMap.region[IB+i].total_len =
						SAS1068_MPI_QUEUE * 128;
			sas1068_ha->memoryMap.region[IB+i].alignment = 128;
		}
	}

	for (i = 0; i < SAS1068_MAX_SPCV_OUTB_NUM; i++) {
		/* MPI Memory region 4 for producer Index of outbound queues */
		sas1068_ha->memoryMap.region[PI+i].num_elements = 1;
		sas1068_ha->memoryMap.region[PI+i].element_size = 4;
		sas1068_ha->memoryMap.region[PI+i].total_len = 4;
		sas1068_ha->memoryMap.region[PI+i].alignment = 4;

		if (ent->driver_data != chip_1068) {
			/* MPI Memory region 6 Outbound queues */
			sas1068_ha->memoryMap.region[OB+i].num_elements =
						SAS1068_MPI_QUEUE;
			sas1068_ha->memoryMap.region[OB+i].element_size = 128;
			sas1068_ha->memoryMap.region[OB+i].total_len =
						SAS1068_MPI_QUEUE * 128;
			sas1068_ha->memoryMap.region[OB+i].alignment = 128;
		}

	}
	/* Memory region write DMA*/
	sas1068_ha->memoryMap.region[NVMD].num_elements = 1;
	sas1068_ha->memoryMap.region[NVMD].element_size = 4096;
	sas1068_ha->memoryMap.region[NVMD].total_len = 4096;

	/* Memory region for devices*/
	sas1068_ha->memoryMap.region[DEV_MEM].num_elements = 1;
	sas1068_ha->memoryMap.region[DEV_MEM].element_size = SAS1068_MAX_DEVICES *
		sizeof(struct sas1068_device);
	sas1068_ha->memoryMap.region[DEV_MEM].total_len = SAS1068_MAX_DEVICES *
		sizeof(struct sas1068_device);

	/* Memory region for ccb_info*/
	sas1068_ha->memoryMap.region[CCB_MEM].num_elements = 1;
	sas1068_ha->memoryMap.region[CCB_MEM].element_size = SAS1068_MAX_CCB *
		sizeof(struct sas1068_ccb_info);
	sas1068_ha->memoryMap.region[CCB_MEM].total_len = SAS1068_MAX_CCB *
		sizeof(struct sas1068_ccb_info);

	/* Memory region for fw flash */
	sas1068_ha->memoryMap.region[FW_FLASH].total_len = 4096;

	sas1068_ha->memoryMap.region[FORENSIC_MEM].num_elements = 1;
	sas1068_ha->memoryMap.region[FORENSIC_MEM].total_len = 0x10000;
	sas1068_ha->memoryMap.region[FORENSIC_MEM].element_size = 0x10000;
	sas1068_ha->memoryMap.region[FORENSIC_MEM].alignment = 0x10000;
	for (i = 0; i < LSI_MAX_MEMCNT; i++) {
		if (sas1068_mem_alloc(sas1068_ha->pdev,
			&sas1068_ha->memoryMap.region[i].virt_ptr,
			&sas1068_ha->memoryMap.region[i].phys_addr,
			&sas1068_ha->memoryMap.region[i].phys_addr_hi,
			&sas1068_ha->memoryMap.region[i].phys_addr_lo,
			sas1068_ha->memoryMap.region[i].total_len,
			sas1068_ha->memoryMap.region[i].alignment) != 0) {
				SAS1068_FAIL_DBG(sas1068_ha,
					SAS1068_printk("Mem%d alloc failed\n",
					i));
				goto err_out;
		}
	}

	sas1068_ha->devices = sas1068_ha->memoryMap.region[DEV_MEM].virt_ptr;
	for (i = 0; i < SAS1068_MAX_DEVICES; i++) {
		sas1068_ha->devices[i].dev_type = SAS_PHY_UNUSED;
		sas1068_ha->devices[i].id = i;
		sas1068_ha->devices[i].device_id = SAS1068_MAX_DEVICES;
		sas1068_ha->devices[i].running_req = 0;
	}
	sas1068_ha->ccb_info = sas1068_ha->memoryMap.region[CCB_MEM].virt_ptr;
	for (i = 0; i < SAS1068_MAX_CCB; i++) {
		sas1068_ha->ccb_info[i].ccb_dma_handle =
			sas1068_ha->memoryMap.region[CCB_MEM].phys_addr +
			i * sizeof(struct sas1068_ccb_info);
		sas1068_ha->ccb_info[i].task = NULL;
		sas1068_ha->ccb_info[i].ccb_tag = 0xffffffff;
		sas1068_ha->ccb_info[i].device = NULL;
		++sas1068_ha->tags_num;
	}
	sas1068_ha->flags = SAS1068F_INIT_TIME;
	/* Initialize tags */
	sas1068_tag_init(sas1068_ha);
	return 0;
err_out:
	return 1;
}

static int sas1068_ioremap(struct sas1068_hba_info *sas1068_ha)
{
        u8              __iomem *mem;
        int              ii;
        resource_size_t  mem_phys;
        unsigned long    port;
        u32              msize;
        u32              psize;
        int              r = -ENODEV;
        struct pci_dev *pdev;
	pdev = sas1068_ha->pdev;
	
        sas1068_ha->bars = pci_select_bars(pdev, IORESOURCE_MEM);
        if (pci_enable_device_mem(pdev)) {
                printk(MYIOC_s_ERR_FMT "pci_enable_device_mem() "
                |   "failed\n", sas1068_ha->name);
                return r;
        }        
        if (pci_request_selected_regions(pdev, sas1068_ha->bars, "sas1068")) {
                printk(MYIOC_s_ERR_FMT "pci_request_selected_regions() with "
                |   "MEM failed\n", sas1068_ha->name);
                goto out_pci_disable_device;
        }  

        if (sizeof(dma_addr_t) > 4) {
                const uint64_t required_mask =
			dma_get_required_mask(&pdev->dev);
                if (required_mask > DMA_BIT_MASK(32)
                        && !pci_set_dma_mask(pdev, DMA_BIT_MASK(64))
                        && !pci_set_consistent_dma_mask(pdev,
                                                |DMA_BIT_MASK(64))) {
                        sas1068_ha->dma_mask = DMA_BIT_MASK(64);
			/*
                        dinitprintk(ioc, printk(MYIOC_s_INFO_FMT
                                ": 64 BIT PCI BUS DMA ADDRESSING SUPPORTED\n",
                                ioc->name));
			*/
                } else if (!pci_set_dma_mask(pdev, DMA_BIT_MASK(32))
                        && !pci_set_consistent_dma_mask(pdev,
                                                DMA_BIT_MASK(32))) {
                        sas1068_ha->dma_mask = DMA_BIT_MASK(32);
			/*
                        dinitprintk(ioc, printk(MYIOC_s_INFO_FMT
                                ": 32 BIT PCI BUS DMA ADDRESSING SUPPORTED\n",
                                ioc->name));
			*/
                } else {
                        printk(MYIOC_s_WARN_FMT "no suitable DMA mask for %s\n",                                          
                        |   sas1068_ha->name, pci_name(pdev));
                        goto out_pci_release_region;
                }
        } else {
                if (!pci_set_dma_mask(pdev, DMA_BIT_MASK(32))
                        && !pci_set_consistent_dma_mask(pdev,
                                                DMA_BIT_MASK(32))) {
                        sas1068_ha->dma_mask = DMA_BIT_MASK(32);
			/*
                        dinitprintk(ioc, printk(MYIOC_s_INFO_FMT
                                ": 32 BIT PCI BUS DMA ADDRESSING SUPPORTED\n",
                                ioc->name));
			*/
                } else {
                        printk(MYIOC_s_WARN_FMT "no suitable DMA mask for %s\n",
                        |   sas1068_ha->name, pci_name(pdev));
                        goto out_pci_release_region;
                }
        }  
        mem_phys = msize = 0;
        port = psize = 0;
        for (ii = 0; ii < DEVICE_COUNT_RESOURCE; ii++) {
                if (pci_resource_flags(pdev, ii) & PCI_BASE_ADDRESS_SPACE_IO) {
                        if (psize)
                                continue;
                        /* Get I/O space! */
                        port = pci_resource_start(pdev, ii);
                        psize = pci_resource_len(pdev, ii);
                } else {
                        if (msize)
                                continue;
                        /* Get memmap */
                        mem_phys = pci_resource_start(pdev, ii);
                        msize = pci_resource_len(pdev, ii);
                }
        }
         
        mem = NULL;
        /* Get logical ptr for PciMem0 space */
        mem = ioremap(mem_phys, msize);
        if (mem == NULL) {
                printk(MYIOC_s_ERR_FMT ": ERROR - Unable to map adapter"
                        " memory!\n", ioc->name);
                r = -EINVAL;
                goto out_pci_release_region;
        }
        sas1068_ha->io_mem.memsize = msize;
        sas1068_ha->io_mem.membase = mem_phys;
        sas1068_ha->io_mem.memvirtaddr = mem;
         
	sas1068_ha->chip_mmap = (struct  sysif_regs *)mem;
        /* Save Port IO values in case we need to do downloadboot */
        sas1068_ha->pio_mem_phys= port;
         
        return 0;
         
out_pci_release_region:
        pci_release_selected_regions(pdev, sas1068_ha->bars);                                                                    
out_pci_disable_device:
        pci_disable_device(pdev);
        return r;
} 

static struct sas1068_hba_info *sas1068_pci_alloc(struct pci_dev *pdev,
				 const struct pci_device_id *ent,
				struct Scsi_Host *shost)

{
	struct sas1068_hba_info *sas1068_ha;
	struct sas_ha_struct *sha = SHOST_TO_SAS_HA(shost);
	int j;

	sas1068_ha = kzalloc(sizeof(struct sas1068_hba_info), GFP_KERNEL);
	if (!sas1068_ha)
		return NULL;

	sas1068_ha->pdev = pdev;
	sas1068_ha->dev = &pdev->dev;
	sas1068_ha->chip_id = ent->driver_data;
	sas1068_ha->chip = &sas1068_chips[sas1068_ha->chip_id];
	sas1068_ha->irq = pdev->irq;
	sas1068_ha->sas = sha;
	sas1068_ha->shost = shost;
	sas1068_ha->id = sas1068_id++;
	sas1068_ha->logging_level = 0x01;
	sprintf(sas1068_ha->name, "%s%d", DRV_NAME, sas1068_ha->id);
	sas1068_ha->iomb_size = IOMB_SIZE_SPCV;

#ifdef SAS1068_USE_TASKLET
	/* Tasklet for non msi-x interrupt handler */
	if (!pdev->msix_cap || !pci_msi_enabled())
		tasklet_init(&sas1068_ha->tasklet[0], sas1068_tasklet,
			(unsigned long)&(sas1068_ha->irq_vector[0]));
	else
		for (j = 0; j < SAS1068_MAX_MSIX_VEC; j++)
			tasklet_init(&sas1068_ha->tasklet[j], sas1068_tasklet,
				(unsigned long)&(sas1068_ha->irq_vector[j]));
#endif
	sas1068_ioremap(sas1068_ha);

	if (!sas1068_alloc(sas1068_ha, ent))
		return sas1068_ha;
	sas1068_free(sas1068_ha);
	return NULL;
}

static int pci_go_44(struct pci_dev *pdev)
{
	int rc;

	if (!pci_set_dma_mask(pdev, DMA_BIT_MASK(44))) {
		rc = pci_set_consistent_dma_mask(pdev, DMA_BIT_MASK(44));
		if (rc) {
			rc = pci_set_consistent_dma_mask(pdev,
				DMA_BIT_MASK(32));
			if (rc) {
				dev_printk(KERN_ERR, &pdev->dev,
					"44-bit DMA enable failed\n");
				return rc;
			}
		}
	} else {
		rc = pci_set_dma_mask(pdev, DMA_BIT_MASK(32));
		if (rc) {
			dev_printk(KERN_ERR, &pdev->dev,
				"32-bit DMA enable failed\n");
			return rc;
		}
		rc = pci_set_consistent_dma_mask(pdev, DMA_BIT_MASK(32));
		if (rc) {
			dev_printk(KERN_ERR, &pdev->dev,
				"32-bit consistent DMA enable failed\n");
			return rc;
		}
	}
	return rc;
}

static int sas1068_prep_sas_ha_init(struct Scsi_Host *shost,
				   const struct sas1068_chip_info *chip_info)
{
	int phy_nr, port_nr;
	struct asd_sas_phy **arr_phy;
	struct asd_sas_port **arr_port;
	struct sas_ha_struct *sha = SHOST_TO_SAS_HA(shost);

	port_nr = phy_nr = chip_info->n_phy;
	arr_phy = kcalloc(phy_nr, sizeof(void *), GFP_KERNEL);
	if (!arr_phy)
		goto exit;
	arr_port = kcalloc(port_nr, sizeof(void *), GFP_KERNEL);
	if (!arr_port)
		goto exit_free2;

	sha->sas_phy = arr_phy;
	sha->sas_port = arr_port;

	shost->transportt = sas1068_stt;
	shost->max_id = SAS1068_MAX_DEVICES;
	shost->max_lun = 8;
	shost->max_channel = 0;
	shost->unique_id = sas1068_id;
	shost->max_cmd_len = 16;
	shost->can_queue = SAS1068_CAN_QUEUE;
	shost->cmd_per_lun = 32;
	return 0;
exit_free1:
	kfree(arr_port);
exit_free2:
	kfree(arr_phy);
exit:
	return -1;
}

static void  sas1068_post_sas_ha_init(struct Scsi_Host *shost,
				     const struct sas1068_chip_info *chip_info)
{
	int i = 0;
	struct sas1068_hba_info *sas1068_ha;
	struct sas_ha_struct *sha = SHOST_TO_SAS_HA(shost);

	sas1068_ha = sha->lldd_ha;
	for (i = 0; i < chip_info->n_phy; i++) {
		sha->sas_phy[i] = &sas1068_ha->phy[i].sas_phy;
		sha->sas_port[i] = &sas1068_ha->port[i].sas_port;
		sha->sas_phy[i]->sas_addr =
			(u8 *)&sas1068_ha->phy[i].dev_sas_addr;
	}
	sha->sas_ha_name = DRV_NAME;
	sha->dev = sas1068_ha->dev;
	sha->strict_wide_ports = 1;
	sha->lldd_module = THIS_MODULE;
	sha->sas_addr = &sas1068_ha->sas_addr[0];
	sha->num_phys = chip_info->n_phy;
	sha->core.shost = shost;
}

static void sas1068_init_sas_add(struct sas1068_hba_info *sas1068_ha)
{
	u8 i, j;
	u8 sas_add[8];
#ifdef SAS1068_READ_VPD
	DECLARE_COMPLETION_ONSTACK(completion);
	struct sas1068_ioctl_payload payload;
	u16 deviceid;
	int rc;

	pci_read_config_word(sas1068_ha->pdev, PCI_DEVICE_ID, &deviceid);
	sas1068_ha->nvmd_completion = &completion;

	if (sas1068_ha->chip_id == chip_1068) {
		if (deviceid == 0x8081 || deviceid == 0x0042) {
			payload.minor_function = 4;
			payload.length = 4096;
		} else {
			payload.minor_function = 0;
			payload.length = 128;
		}
	} else {
		payload.minor_function = 1;
		payload.length = 4096;
	}
	payload.offset = 0;
	payload.func_specific = kzalloc(payload.length, GFP_KERNEL);
	if (!payload.func_specific) {
		SAS1068_INIT_DBG(sas1068_ha, SAS1068_printk("mem alloc fail\n"));
		return;
	}
	rc = SAS1068_CHIP_DISP->get_nvmd_req(sas1068_ha, &payload);
	if (rc) {
		kfree(payload.func_specific);
		SAS1068_INIT_DBG(sas1068_ha, SAS1068_printk("nvmd failed\n"));
		return;
	}
	wait_for_completion(&completion);

	for (i = 0, j = 0; i <= 7; i++, j++) {
		if (sas1068_ha->chip_id == chip_1068) {
			if (deviceid == 0x8081)
				sas1068_ha->sas_addr[j] =
					payload.func_specific[0x704 + i];
			else if (deviceid == 0x0042)
				sas1068_ha->sas_addr[j] =
					payload.func_specific[0x010 + i];
		} else
			sas1068_ha->sas_addr[j] =
					payload.func_specific[0x804 + i];
	}
	memcpy(sas_add, sas1068_ha->sas_addr, SAS_ADDR_SIZE);
	for (i = 0; i < sas1068_ha->chip->n_phy; i++) {
		if (i && ((i % 4) == 0))
			sas_add[7] = sas_add[7] + 4;
		memcpy(&sas1068_ha->phy[i].dev_sas_addr,
			sas_add, SAS_ADDR_SIZE);
		SAS1068_INIT_DBG(sas1068_ha,
			SAS1068_printk("phy %d sas_addr = %016llx\n", i,
			sas1068_ha->phy[i].dev_sas_addr));
	}
	kfree(payload.func_specific);
#else
	for (i = 0; i < sas1068_ha->chip->n_phy; i++) {
		sas1068_ha->phy[i].dev_sas_addr = 0x50010c600047f9d0ULL;
		sas1068_ha->phy[i].dev_sas_addr =
			cpu_to_be64((u64)
				(*(u64 *)&sas1068_ha->phy[i].dev_sas_addr));
	}
	memcpy(sas1068_ha->sas_addr, &sas1068_ha->phy[0].dev_sas_addr,
		SAS_ADDR_SIZE);
#endif
}

static int sas1068_get_phy_settings_info(struct sas1068_hba_info *sas1068_ha)
{

#ifdef SAS1068_READ_VPD
	/*OPTION ROM FLASH read for the SPC cards */
	DECLARE_COMPLETION_ONSTACK(completion);
	struct sas1068_ioctl_payload payload;
	int rc;

	sas1068_ha->nvmd_completion = &completion;
	/* SAS ADDRESS read from flash / EEPROM */
	payload.minor_function = 6;
	payload.offset = 0;
	payload.length = 4096;
	payload.func_specific = kzalloc(4096, GFP_KERNEL);
	if (!payload.func_specific)
		return -ENOMEM;
	/* Read phy setting values from flash */
	rc = SAS1068_CHIP_DISP->get_nvmd_req(sas1068_ha, &payload);
	if (rc) {
		kfree(payload.func_specific);
		SAS1068_INIT_DBG(sas1068_ha, SAS1068_printk("nvmd failed\n"));
		return -ENOMEM;
	}
	wait_for_completion(&completion);
	sas1068_set_phy_profile(sas1068_ha, sizeof(u8), payload.func_specific);
	kfree(payload.func_specific);
#endif
	return 0;
}

struct sas1068_mpi3_phy_pg_trx_config {
	u32 LaneLosCfg;
	u32 LanePgaCfg1;
	u32 LanePisoCfg1;
	u32 LanePisoCfg2;
	u32 LanePisoCfg3;
	u32 LanePisoCfg4;
	u32 LanePisoCfg5;
	u32 LanePisoCfg6;
	u32 LaneBctCtrl;
};

static
void sas1068_get_internal_phy_settings(struct sas1068_hba_info *sas1068_ha,
		struct sas1068_mpi3_phy_pg_trx_config *phycfg)
{
	phycfg->LaneLosCfg   = 0x00000132;
	phycfg->LanePgaCfg1  = 0x00203949;
	phycfg->LanePisoCfg1 = 0x000000FF;
	phycfg->LanePisoCfg2 = 0xFF000001;
	phycfg->LanePisoCfg3 = 0xE7011300;
	phycfg->LanePisoCfg4 = 0x631C40C0;
	phycfg->LanePisoCfg5 = 0xF8102036;
	phycfg->LanePisoCfg6 = 0xF74A1000;
	phycfg->LaneBctCtrl  = 0x00FB33F8;
}

static
void sas1068_get_external_phy_settings(struct sas1068_hba_info *sas1068_ha,
		struct sas1068_mpi3_phy_pg_trx_config *phycfg)
{
	phycfg->LaneLosCfg   = 0x00000132;
	phycfg->LanePgaCfg1  = 0x00203949;
	phycfg->LanePisoCfg1 = 0x000000FF;
	phycfg->LanePisoCfg2 = 0xFF000001;
	phycfg->LanePisoCfg3 = 0xE7011300;
	phycfg->LanePisoCfg4 = 0x63349140;
	phycfg->LanePisoCfg5 = 0xF8102036;
	phycfg->LanePisoCfg6 = 0xF80D9300;
	phycfg->LaneBctCtrl  = 0x00FB33F8;
}

static
void sas1068_get_phy_mask(struct sas1068_hba_info *sas1068_ha, int *phymask)
{
	switch (sas1068_ha->pdev->subsystem_device) {
	case 0x0070: /* H1280 - 8 external 0 internal */
	case 0x0072: /* H12F0 - 16 external 0 internal */
		*phymask = 0x0000;
		break;

	case 0x0071: /* H1208 - 0 external 8 internal */
	case 0x0073: /* H120F - 0 external 16 internal */
		*phymask = 0xFFFF;
		break;

	case 0x0080: /* H1244 - 4 external 4 internal */
		*phymask = 0x00F0;
		break;

	case 0x0081: /* H1248 - 4 external 8 internal */
		*phymask = 0x0FF0;
		break;

	case 0x0082: /* H1288 - 8 external 8 internal */
		*phymask = 0xFF00;
		break;

	default:
		SAS1068_INIT_DBG(sas1068_ha,
			SAS1068_printk("Unknown subsystem device=0x%.04x",
				sas1068_ha->pdev->subsystem_device));
	}
}

static
int sas1068_set_phy_settings_ven_117c_12G(struct sas1068_hba_info *sas1068_ha)
{
	struct sas1068_mpi3_phy_pg_trx_config phycfg_int;
	struct sas1068_mpi3_phy_pg_trx_config phycfg_ext;
	int phymask = 0;
	int i = 0;

	memset(&phycfg_int, 0, sizeof(phycfg_int));
	memset(&phycfg_ext, 0, sizeof(phycfg_ext));

	sas1068_get_internal_phy_settings(sas1068_ha, &phycfg_int);
	sas1068_get_external_phy_settings(sas1068_ha, &phycfg_ext);
	sas1068_get_phy_mask(sas1068_ha, &phymask);

	for (i = 0; i < sas1068_ha->chip->n_phy; i++) {
		if (phymask & (1 << i)) {/* Internal PHY */
			sas1068_set_phy_profile_single(sas1068_ha, i,
					sizeof(phycfg_int) / sizeof(u32),
					(u32 *)&phycfg_int);

		} else { /* External PHY */
			sas1068_set_phy_profile_single(sas1068_ha, i,
					sizeof(phycfg_ext) / sizeof(u32),
					(u32 *)&phycfg_ext);
		}
	}

	return 0;
}

static int sas1068_configure_phy_settings(struct sas1068_hba_info *sas1068_ha)
{
	switch (sas1068_ha->pdev->subsystem_vendor) {
	case PCI_VENDOR_ID_ATTO:
		if (sas1068_ha->pdev->device == 0x0042) /* 6Gb */
			return 0;
		else
			return sas1068_set_phy_settings_ven_117c_12G(sas1068_ha);

	case PCI_VENDOR_ID_ADAPTEC2:
	case 0:
		return 0;

	default:
		return sas1068_get_phy_settings_info(sas1068_ha);
	}
}

#ifdef SAS1068_USE_MSIX
static u32 sas1068_setup_msix(struct sas1068_hba_info *sas1068_ha)
{
	u32 i = 0, j = 0;
	u32 number_of_intr;
	int flag = 0;
	int rc;
	static char intr_drvname[SAS1068_MAX_MSIX_VEC][sizeof(DRV_NAME)+3];

	/* SPCv controllers supports 64 msi-x */
	if (sas1068_ha->chip_id == chip_1068) {
		number_of_intr = 1;
	} else {
		number_of_intr = SAS1068_MAX_MSIX_VEC;
		flag &= ~IRQF_SHARED;
	}

	rc = pci_alloc_irq_vectors(sas1068_ha->pdev, number_of_intr,
			number_of_intr, PCI_IRQ_MSIX);
	if (rc < 0)
		return rc;
	sas1068_ha->number_of_intr = number_of_intr;

	SAS1068_INIT_DBG(sas1068_ha, SAS1068_printk(
		"pci_alloc_irq_vectors request ret:%d no of intr %d\n",
				rc, sas1068_ha->number_of_intr));

	for (i = 0; i < number_of_intr; i++) {
		snprintf(intr_drvname[i], sizeof(intr_drvname[0]),
				DRV_NAME"%d", i);
		sas1068_ha->irq_vector[i].irq_id = i;
		sas1068_ha->irq_vector[i].drv_inst = sas1068_ha;

		rc = request_irq(pci_irq_vector(sas1068_ha->pdev, i),
			sas1068_interrupt_handler_msix, flag,
			intr_drvname[i], &(sas1068_ha->irq_vector[i]));
		if (rc) {
			for (j = 0; j < i; j++) {
				free_irq(pci_irq_vector(sas1068_ha->pdev, i),
					&(sas1068_ha->irq_vector[i]));
			}
			pci_free_irq_vectors(sas1068_ha->pdev);
			break;
		}
	}

	return rc;
}
#endif

static u32 sas1068_request_irq(struct sas1068_hba_info *sas1068_ha)
{
	struct pci_dev *pdev;
	int rc;

	pdev = sas1068_ha->pdev;

#ifdef SAS1068_USE_MSIX
	if (pdev->msix_cap && pci_msi_enabled())
		return sas1068_setup_msix(sas1068_ha);
	else {
		SAS1068_INIT_DBG(sas1068_ha,
			SAS1068_printk("MSIX not supported!!!\n"));
		goto intx;
	}
#endif

intx:
	/* initialize the INT-X interrupt */
	sas1068_ha->irq_vector[0].irq_id = 0;
	sas1068_ha->irq_vector[0].drv_inst = sas1068_ha;
	rc = request_irq(pdev->irq, sas1068_interrupt_handler_intx, IRQF_SHARED,
		DRV_NAME, SHOST_TO_SAS_HA(sas1068_ha->shost));
	return rc;
}

static int sas1068_pci_probe(struct pci_dev *pdev,
			    const struct pci_device_id *ent)
{
	unsigned int rc;
	u32	pci_reg;
	u8	i = 0;
	struct sas1068_hba_info *sas1068_ha;
	struct Scsi_Host *shost = NULL;
	const struct sas1068_chip_info *chip;

	rc = pci_enable_device(pdev);
	if (rc)
		goto err_out_enable;
	pci_set_master(pdev);

	/*
	 * Enable pci slot busmaster by setting pci command register.
	 * This is required by FW for Cyclone card.
	 */

	/*
	pci_read_config_dword(pdev, PCI_COMMAND, &pci_reg);
	pci_reg |= 0x157;
	pci_write_config_dword(pdev, PCI_COMMAND, pci_reg);
	rc = pci_request_regions(pdev, DRV_NAME);
	if (rc)
		goto err_out_disable;
	rc = pci_go_44(pdev);
	if (rc)
		goto err_out_regions;
	*/

	shost = scsi_host_alloc(&sas1068_sht, sizeof(void *));
	if (!shost) {
		rc = -ENOMEM;
		goto err_out_regions;
	}
	chip = &sas1068_chips[ent->driver_data];
	SHOST_TO_SAS_HA(shost) =
		kzalloc(sizeof(struct sas_ha_struct), GFP_KERNEL);
	if (!SHOST_TO_SAS_HA(shost)) {
		rc = -ENOMEM;
		goto err_out_free_host;
	}

	rc = sas1068_prep_sas_ha_init(shost, chip);
	if (rc) {
		rc = -ENOMEM;
		goto err_out_free;
	}
	pci_set_drvdata(pdev, SHOST_TO_SAS_HA(shost));
	/* ent->driver variable is used to differentiate between controllers */
	sas1068_ha = sas1068_pci_alloc(pdev, ent, shost);
	if (!sas1068_ha) {
		rc = -ENOMEM;
		goto err_out_free;
	}
	SHOST_TO_SAS_HA(shost)->lldd_ha = sas1068_ha;
	list_add_tail(&sas1068_ha->list, &hba_list);
	SAS1068_CHIP_DISP->chip_rst(sas1068_ha);
	rc = SAS1068_CHIP_DISP->chip_init(sas1068_ha);
	if (rc) {
		SAS1068_FAIL_DBG(sas1068_ha, SAS1068_printk(
			"chip_init failed [ret: %d]\n", rc));
		goto err_out_ha_free;
	}

	rc = scsi_add_host(shost, &pdev->dev);
	if (rc)
		goto err_out_ha_free;
	rc = sas1068_request_irq(sas1068_ha);
	if (rc)	{
		SAS1068_FAIL_DBG(sas1068_ha, SAS1068_printk(
			"sas1068_request_irq failed [ret: %d]\n", rc));
		goto err_out_shost;
	}

	SAS1068_CHIP_DISP->interrupt_enable(sas1068_ha, 0);
	if (sas1068_ha->chip_id != chip_1068) {
		for (i = 1; i < sas1068_ha->number_of_intr; i++)
			SAS1068_CHIP_DISP->interrupt_enable(sas1068_ha, i);
	}

	sas1068_init_sas_add(sas1068_ha);
	/* phy setting support for motherboard controller */
	if (sas1068_configure_phy_settings(sas1068_ha))
		goto err_out_shost;

	sas1068_post_sas_ha_init(shost, chip);
	rc = sas_register_ha(SHOST_TO_SAS_HA(shost));
	if (rc)
		goto err_out_shost;
	scsi_scan_host(sas1068_ha->shost);
	return 0;

err_out_shost:
	scsi_remove_host(sas1068_ha->shost);
err_out_ha_free:
	sas1068_free(sas1068_ha);
err_out_free:
	kfree(SHOST_TO_SAS_HA(shost));
err_out_free_host:
	scsi_host_put(shost);
err_out_regions:
	pci_release_regions(pdev);
err_out_disable:
	pci_disable_device(pdev);
err_out_enable:
	return rc;
}

static void sas1068_pci_remove(struct pci_dev *pdev)
{
	struct sas_ha_struct *sha = pci_get_drvdata(pdev);
	struct sas1068_hba_info *sas1068_ha;
	int i, j;
	sas1068_ha = sha->lldd_ha;
	sas_unregister_ha(sha);
	sas_remove_host(sas1068_ha->shost);
	list_del(&sas1068_ha->list);
	SAS1068_CHIP_DISP->interrupt_disable(sas1068_ha, 0xFF);
	SAS1068_CHIP_DISP->chip_soft_rst(sas1068_ha);

#ifdef SAS1068_USE_MSIX
	for (i = 0; i < sas1068_ha->number_of_intr; i++)
		synchronize_irq(pci_irq_vector(pdev, i));
	for (i = 0; i < sas1068_ha->number_of_intr; i++)
		free_irq(pci_irq_vector(pdev, i), &sas1068_ha->irq_vector[i]);
	pci_free_irq_vectors(pdev);
#else
	free_irq(sas1068_ha->irq, sha);
#endif
#ifdef SAS1068_USE_TASKLET
	/* For non-msix and msix interrupts */
	if ((!pdev->msix_cap || !pci_msi_enabled()) ||
	    (sas1068_ha->chip_id == chip_1068))
		tasklet_kill(&sas1068_ha->tasklet[0]);
	else
		for (j = 0; j < SAS1068_MAX_MSIX_VEC; j++)
			tasklet_kill(&sas1068_ha->tasklet[j]);
#endif
	scsi_host_put(sas1068_ha->shost);
	sas1068_free(sas1068_ha);
	kfree(sha->sas_phy);
	kfree(sha->sas_port);
	kfree(sha);
	pci_release_regions(pdev);
	pci_disable_device(pdev);
}

static int sas1068_pci_suspend(struct pci_dev *pdev, pm_message_t state)
{
	struct sas_ha_struct *sha = pci_get_drvdata(pdev);
	struct sas1068_hba_info *sas1068_ha;
	int  i, j;
	u32 device_state;
	sas1068_ha = sha->lldd_ha;
	sas_suspend_ha(sha);
	flush_workqueue(sas1068_wq);
	scsi_block_requests(sas1068_ha->shost);
	if (!pdev->pm_cap) {
		dev_err(&pdev->dev, " PCI PM not supported\n");
		return -ENODEV;
	}
	SAS1068_CHIP_DISP->interrupt_disable(sas1068_ha, 0xFF);
	SAS1068_CHIP_DISP->chip_soft_rst(sas1068_ha);
#ifdef SAS1068_USE_MSIX
	for (i = 0; i < sas1068_ha->number_of_intr; i++)
		synchronize_irq(pci_irq_vector(pdev, i));
	for (i = 0; i < sas1068_ha->number_of_intr; i++)
		free_irq(pci_irq_vector(pdev, i), &sas1068_ha->irq_vector[i]);
	pci_free_irq_vectors(pdev);
#else
	free_irq(sas1068_ha->irq, sha);
#endif
#ifdef SAS1068_USE_TASKLET
	/* For non-msix and msix interrupts */
	if ((!pdev->msix_cap || !pci_msi_enabled()) ||
	    (sas1068_ha->chip_id == chip_1068))
		tasklet_kill(&sas1068_ha->tasklet[0]);
	else
		for (j = 0; j < SAS1068_MAX_MSIX_VEC; j++)
			tasklet_kill(&sas1068_ha->tasklet[j]);
#endif
	device_state = pci_choose_state(pdev, state);
	SAS1068_printk("pdev=0x%p, slot=%s, entering "
		      "operating state [D%d]\n", pdev,
		      sas1068_ha->name, device_state);
	pci_save_state(pdev);
	pci_disable_device(pdev);
	pci_set_power_state(pdev, device_state);
	return 0;
}

static int sas1068_pci_resume(struct pci_dev *pdev)
{
	struct sas_ha_struct *sha = pci_get_drvdata(pdev);
	struct sas1068_hba_info *sas1068_ha;
	int rc;
	u8 i = 0, j;
	u32 device_state;
	DECLARE_COMPLETION_ONSTACK(completion);
	sas1068_ha = sha->lldd_ha;
	device_state = pdev->current_state;

	SAS1068_printk("pdev=0x%p, slot=%s, resuming from previous "
		"operating state [D%d]\n", pdev, sas1068_ha->name, device_state);

	pci_set_power_state(pdev, PCI_D0);
	pci_enable_wake(pdev, PCI_D0, 0);
	pci_restore_state(pdev);
	rc = pci_enable_device(pdev);
	if (rc) {
		SAS1068_printk("slot=%s Enable device failed during resume\n",
			      sas1068_ha->name);
		goto err_out_enable;
	}

	pci_set_master(pdev);
	rc = pci_go_44(pdev);
	if (rc)
		goto err_out_disable;
	sas_prep_resume_ha(sha);
	/* chip soft rst only for spc */
	if (sas1068_ha->chip_id == chip_1068) {
		SAS1068_CHIP_DISP->chip_soft_rst(sas1068_ha);
		SAS1068_INIT_DBG(sas1068_ha,
			SAS1068_printk("chip soft reset successful\n"));
	}
	rc = SAS1068_CHIP_DISP->chip_init(sas1068_ha);
	if (rc)
		goto err_out_disable;

	/* disable all the interrupt bits */
	SAS1068_CHIP_DISP->interrupt_disable(sas1068_ha, 0xFF);

	rc = sas1068_request_irq(sas1068_ha);
	if (rc)
		goto err_out_disable;
#ifdef SAS1068_USE_TASKLET
	/*  Tasklet for non msi-x interrupt handler */
	if ((!pdev->msix_cap || !pci_msi_enabled()) ||
	    (sas1068_ha->chip_id == chip_1068))
		tasklet_init(&sas1068_ha->tasklet[0], sas1068_tasklet,
			(unsigned long)&(sas1068_ha->irq_vector[0]));
	else
		for (j = 0; j < SAS1068_MAX_MSIX_VEC; j++)
			tasklet_init(&sas1068_ha->tasklet[j], sas1068_tasklet,
				(unsigned long)&(sas1068_ha->irq_vector[j]));
#endif
	SAS1068_CHIP_DISP->interrupt_enable(sas1068_ha, 0);
	if (sas1068_ha->chip_id != chip_1068) {
		for (i = 1; i < sas1068_ha->number_of_intr; i++)
			SAS1068_CHIP_DISP->interrupt_enable(sas1068_ha, i);
	}

	sas1068_ha->flags = SAS1068F_RUN_TIME;
	for (i = 0; i < sas1068_ha->chip->n_phy; i++) {
		sas1068_ha->phy[i].enable_completion = &completion;
		SAS1068_CHIP_DISP->phy_start_req(sas1068_ha, i);
		wait_for_completion(&completion);
	}
	sas_resume_ha(sha);
	return 0;

err_out_disable:
	scsi_remove_host(sas1068_ha->shost);
	pci_disable_device(pdev);
err_out_enable:
	return rc;
}

/* update of pci device, vendor id and driver data with
 * unique value for each of the controller
 */
static struct pci_device_id sas1068_pci_table[] = {
	{ 0x1000, 0x0054, PCI_ANY_ID, PCI_ANY_ID, chip_1068 },
	{ 0x1000, 0x0058, PCI_ANY_ID, PCI_ANY_ID, chip_1068e },  
	{} /* terminate list */
};

static struct pci_driver sas1068_pci_driver = {
	.name		= DRV_NAME,
	.id_table	= sas1068_pci_table,
	.probe		= sas1068_pci_probe,
	.remove		= sas1068_pci_remove,
	.suspend	= sas1068_pci_suspend,
	.resume		= sas1068_pci_resume,
};

static int __init sas1068_init(void)
{
	int rc = -ENOMEM;

	sas1068_wq = alloc_workqueue("sas1068", 0, 0);
	if (!sas1068_wq)
		goto err;

	sas1068_id = 0;
	sas1068_stt = sas_domain_attach_transport(&sas1068_transport_ops);
	if (!sas1068_stt)
		goto err_wq;
	rc = pci_register_driver(&sas1068_pci_driver);
	if (rc)
		goto err_tp;
	return 0;

err_tp:
	sas_release_transport(sas1068_stt);
err_wq:
	destroy_workqueue(sas1068_wq);
err:
	return rc;
}

static void __exit sas1068_exit(void)
{
	pci_unregister_driver(&sas1068_pci_driver);
	sas_release_transport(sas1068_stt);
	destroy_workqueue(sas1068_wq);
}

module_init(sas1068_init);
module_exit(sas1068_exit);

MODULE_AUTHOR("Jack Wang <jack_wang@usish.com>");
MODULE_AUTHOR("Anand Kumar Santhanam <AnandKumar.Santhanam@pmcs.com>");
MODULE_AUTHOR("Sangeetha Gnanasekaran <Sangeetha.Gnanasekaran@pmcs.com>");
MODULE_AUTHOR("Nikith Ganigarakoppal <Nikith.Ganigarakoppal@pmcs.com>");
MODULE_DESCRIPTION("SAS1068 controller driver");
MODULE_VERSION(DRV_VERSION);
MODULE_LICENSE("GPL");
MODULE_DEVICE_TABLE(pci, sas1068_pci_table);

