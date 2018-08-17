#include <linux/firmware.h>
#include <linux/slab.h>
#include "sas1068_sas.h"
#include "sas1068_ctl.h"

/* scsi host attributes */

static ssize_t sas1068_ctl_mpi_interface_rev_show(struct device *cdev,
	struct device_attribute *attr, char *buf)
{
	struct Scsi_Host *shost = class_to_shost(cdev);
	struct sas_ha_struct *sha = SHOST_TO_SAS_HA(shost);
	struct sas1068_hba_info *sas1068_ha = sha->lldd_ha;

	if (sas1068_ha->chip_id == chip_1068) {
		return snprintf(buf, PAGE_SIZE, "%d\n",
			sas1068_ha->main_cfg_tbl.sas1068_tbl.interface_rev);
	} else {
		return snprintf(buf, PAGE_SIZE, "%d\n",
			sas1068_ha->main_cfg_tbl.pm80xx_tbl.interface_rev);
	}
}
static
DEVICE_ATTR(interface_rev, S_IRUGO, sas1068_ctl_mpi_interface_rev_show, NULL);

static ssize_t sas1068_ctl_fw_version_show(struct device *cdev,
	struct device_attribute *attr, char *buf)
{
	struct Scsi_Host *shost = class_to_shost(cdev);
	struct sas_ha_struct *sha = SHOST_TO_SAS_HA(shost);
	struct sas1068_hba_info *sas1068_ha = sha->lldd_ha;

	if (sas1068_ha->chip_id == chip_1068) {
		return snprintf(buf, PAGE_SIZE, "%02x.%02x.%02x.%02x\n",
		(u8)(sas1068_ha->main_cfg_tbl.sas1068_tbl.firmware_rev >> 24),
		(u8)(sas1068_ha->main_cfg_tbl.sas1068_tbl.firmware_rev >> 16),
		(u8)(sas1068_ha->main_cfg_tbl.sas1068_tbl.firmware_rev >> 8),
		(u8)(sas1068_ha->main_cfg_tbl.sas1068_tbl.firmware_rev));
	} else {
		return snprintf(buf, PAGE_SIZE, "%02x.%02x.%02x.%02x\n",
		(u8)(sas1068_ha->main_cfg_tbl.pm80xx_tbl.firmware_rev >> 24),
		(u8)(sas1068_ha->main_cfg_tbl.pm80xx_tbl.firmware_rev >> 16),
		(u8)(sas1068_ha->main_cfg_tbl.pm80xx_tbl.firmware_rev >> 8),
		(u8)(sas1068_ha->main_cfg_tbl.pm80xx_tbl.firmware_rev));
	}
}
static DEVICE_ATTR(fw_version, S_IRUGO, sas1068_ctl_fw_version_show, NULL);

static ssize_t sas1068_ctl_ila_version_show(struct device *cdev,
	struct device_attribute *attr, char *buf)
{
	struct Scsi_Host *shost = class_to_shost(cdev);
	struct sas_ha_struct *sha = SHOST_TO_SAS_HA(shost);
	struct sas1068_hba_info *sas1068_ha = sha->lldd_ha;

	if (sas1068_ha->chip_id != chip_1068) {
		return snprintf(buf, PAGE_SIZE, "%02x.%02x.%02x.%02x\n",
		(u8)(sas1068_ha->main_cfg_tbl.pm80xx_tbl.ila_version >> 24),
		(u8)(sas1068_ha->main_cfg_tbl.pm80xx_tbl.ila_version >> 16),
		(u8)(sas1068_ha->main_cfg_tbl.pm80xx_tbl.ila_version >> 8),
		(u8)(sas1068_ha->main_cfg_tbl.pm80xx_tbl.ila_version));
	}
	return 0;
}
static DEVICE_ATTR(ila_version, 0444, sas1068_ctl_ila_version_show, NULL);

static ssize_t sas1068_ctl_inactive_fw_version_show(struct device *cdev,
	struct device_attribute *attr, char *buf)
{
	struct Scsi_Host *shost = class_to_shost(cdev);
	struct sas_ha_struct *sha = SHOST_TO_SAS_HA(shost);
	struct sas1068_hba_info *sas1068_ha = sha->lldd_ha;

	if (sas1068_ha->chip_id != chip_1068) {
		return snprintf(buf, PAGE_SIZE, "%02x.%02x.%02x.%02x\n",
		(u8)(sas1068_ha->main_cfg_tbl.pm80xx_tbl.inc_fw_version >> 24),
		(u8)(sas1068_ha->main_cfg_tbl.pm80xx_tbl.inc_fw_version >> 16),
		(u8)(sas1068_ha->main_cfg_tbl.pm80xx_tbl.inc_fw_version >> 8),
		(u8)(sas1068_ha->main_cfg_tbl.pm80xx_tbl.inc_fw_version));
	}
	return 0;
}
static
DEVICE_ATTR(inc_fw_ver, 0444, sas1068_ctl_inactive_fw_version_show, NULL);

static ssize_t sas1068_ctl_max_out_io_show(struct device *cdev,
	struct device_attribute *attr, char *buf)
{
	struct Scsi_Host *shost = class_to_shost(cdev);
	struct sas_ha_struct *sha = SHOST_TO_SAS_HA(shost);
	struct sas1068_hba_info *sas1068_ha = sha->lldd_ha;

	if (sas1068_ha->chip_id == chip_1068) {
		return snprintf(buf, PAGE_SIZE, "%d\n",
			sas1068_ha->main_cfg_tbl.sas1068_tbl.max_out_io);
	} else {
		return snprintf(buf, PAGE_SIZE, "%d\n",
			sas1068_ha->main_cfg_tbl.pm80xx_tbl.max_out_io);
	}
}
static DEVICE_ATTR(max_out_io, S_IRUGO, sas1068_ctl_max_out_io_show, NULL);

static ssize_t sas1068_ctl_max_devices_show(struct device *cdev,
	struct device_attribute *attr, char *buf)
{
	struct Scsi_Host *shost = class_to_shost(cdev);
	struct sas_ha_struct *sha = SHOST_TO_SAS_HA(shost);
	struct sas1068_hba_info *sas1068_ha = sha->lldd_ha;

	if (sas1068_ha->chip_id == chip_1068) {
		return snprintf(buf, PAGE_SIZE, "%04d\n",
			(u16)(sas1068_ha->main_cfg_tbl.sas1068_tbl.max_sgl >> 16)
			);
	} else {
		return snprintf(buf, PAGE_SIZE, "%04d\n",
			(u16)(sas1068_ha->main_cfg_tbl.pm80xx_tbl.max_sgl >> 16)
			);
	}
}
static DEVICE_ATTR(max_devices, S_IRUGO, sas1068_ctl_max_devices_show, NULL);

static ssize_t sas1068_ctl_max_sg_list_show(struct device *cdev,
	struct device_attribute *attr, char *buf)
{
	struct Scsi_Host *shost = class_to_shost(cdev);
	struct sas_ha_struct *sha = SHOST_TO_SAS_HA(shost);
	struct sas1068_hba_info *sas1068_ha = sha->lldd_ha;

	if (sas1068_ha->chip_id == chip_1068) {
		return snprintf(buf, PAGE_SIZE, "%04d\n",
			sas1068_ha->main_cfg_tbl.sas1068_tbl.max_sgl & 0x0000FFFF
			);
	} else {
		return snprintf(buf, PAGE_SIZE, "%04d\n",
			sas1068_ha->main_cfg_tbl.pm80xx_tbl.max_sgl & 0x0000FFFF
			);
	}
}
static DEVICE_ATTR(max_sg_list, S_IRUGO, sas1068_ctl_max_sg_list_show, NULL);

#define SAS_1_0 0x1
#define SAS_1_1 0x2
#define SAS_2_0 0x4

static ssize_t
show_sas_spec_support_status(unsigned int mode, char *buf)
{
	ssize_t len = 0;

	if (mode & SAS_1_1)
		len = sprintf(buf, "%s", "SAS1.1");
	if (mode & SAS_2_0)
		len += sprintf(buf + len, "%s%s", len ? ", " : "", "SAS2.0");
	len += sprintf(buf + len, "\n");

	return len;
}

static ssize_t sas1068_ctl_sas_spec_support_show(struct device *cdev,
	struct device_attribute *attr, char *buf)
{
	unsigned int mode;
	struct Scsi_Host *shost = class_to_shost(cdev);
	struct sas_ha_struct *sha = SHOST_TO_SAS_HA(shost);
	struct sas1068_hba_info *sas1068_ha = sha->lldd_ha;
	/* fe000000 means supports SAS2.1 */
	if (sas1068_ha->chip_id == chip_1068)
		mode = (sas1068_ha->main_cfg_tbl.sas1068_tbl.ctrl_cap_flag &
							0xfe000000)>>25;
	else
		/* fe000000 means supports SAS2.1 */
		mode = (sas1068_ha->main_cfg_tbl.pm80xx_tbl.ctrl_cap_flag &
							0xfe000000)>>25;
	return show_sas_spec_support_status(mode, buf);
}
static DEVICE_ATTR(sas_spec_support, S_IRUGO,
		   sas1068_ctl_sas_spec_support_show, NULL);

static ssize_t sas1068_ctl_host_sas_address_show(struct device *cdev,
	struct device_attribute *attr, char *buf)
{
	struct Scsi_Host *shost = class_to_shost(cdev);
	struct sas_ha_struct *sha = SHOST_TO_SAS_HA(shost);
	struct sas1068_hba_info *sas1068_ha = sha->lldd_ha;
	return snprintf(buf, PAGE_SIZE, "0x%016llx\n",
			be64_to_cpu(*(__be64 *)sas1068_ha->sas_addr));
}

static DEVICE_ATTR(host_sas_address, S_IRUGO,
		   sas1068_ctl_host_sas_address_show, NULL);

static ssize_t sas1068_ctl_logging_level_show(struct device *cdev,
	struct device_attribute *attr, char *buf)
{
	struct Scsi_Host *shost = class_to_shost(cdev);
	struct sas_ha_struct *sha = SHOST_TO_SAS_HA(shost);
	struct sas1068_hba_info *sas1068_ha = sha->lldd_ha;

	return snprintf(buf, PAGE_SIZE, "%08xh\n", sas1068_ha->logging_level);
}

static ssize_t sas1068_ctl_logging_level_store(struct device *cdev,
	struct device_attribute *attr, const char *buf, size_t count)
{
	struct Scsi_Host *shost = class_to_shost(cdev);
	struct sas_ha_struct *sha = SHOST_TO_SAS_HA(shost);
	struct sas1068_hba_info *sas1068_ha = sha->lldd_ha;
	int val = 0;

	if (sscanf(buf, "%x", &val) != 1)
		return -EINVAL;

	sas1068_ha->logging_level = val;
	return strlen(buf);
}

static DEVICE_ATTR(logging_level, S_IRUGO | S_IWUSR,
	sas1068_ctl_logging_level_show, sas1068_ctl_logging_level_store);

static ssize_t sas1068_ctl_aap_log_show(struct device *cdev,
	struct device_attribute *attr, char *buf)
{
	struct Scsi_Host *shost = class_to_shost(cdev);
	struct sas_ha_struct *sha = SHOST_TO_SAS_HA(shost);
	struct sas1068_hba_info *sas1068_ha = sha->lldd_ha;
	int i;
#define AAP1_MEMMAP(r, c) \
	(*(u32 *)((u8*)sas1068_ha->memoryMap.region[AAP1].virt_ptr + (r) * 32 \
	+ (c)))

	char *str = buf;
	int max = 2;
	for (i = 0; i < max; i++) {
		str += sprintf(str, "0x%08x 0x%08x 0x%08x 0x%08x 0x%08x 0x%08x"
			       "0x%08x 0x%08x\n",
			       AAP1_MEMMAP(i, 0),
			       AAP1_MEMMAP(i, 4),
			       AAP1_MEMMAP(i, 8),
			       AAP1_MEMMAP(i, 12),
			       AAP1_MEMMAP(i, 16),
			       AAP1_MEMMAP(i, 20),
			       AAP1_MEMMAP(i, 24),
			       AAP1_MEMMAP(i, 28));
	}

	return str - buf;
}
static DEVICE_ATTR(aap_log, S_IRUGO, sas1068_ctl_aap_log_show, NULL);
/**
 * sas1068_ctl_ib_queue_log_show - Out bound Queue log
 * @cdev:pointer to embedded class device
 * @buf: the buffer returned
 * A sysfs 'read-only' shost attribute.
 */
static ssize_t sas1068_ctl_ib_queue_log_show(struct device *cdev,
	struct device_attribute *attr, char *buf)
{
	struct Scsi_Host *shost = class_to_shost(cdev);
	struct sas_ha_struct *sha = SHOST_TO_SAS_HA(shost);
	struct sas1068_hba_info *sas1068_ha = sha->lldd_ha;
	int offset;
	char *str = buf;
	int start = 0;
#define IB_MEMMAP(c)	\
		(*(u32 *)((u8 *)sas1068_ha->	\
		memoryMap.region[IB].virt_ptr +	\
		sas1068_ha->evtlog_ib_offset + (c)))

	for (offset = 0; offset < IB_OB_READ_TIMES; offset++) {
		str += sprintf(str, "0x%08x\n", IB_MEMMAP(start));
		start = start + 4;
	}
	sas1068_ha->evtlog_ib_offset += SYSFS_OFFSET;
	if (((sas1068_ha->evtlog_ib_offset) % (PM80XX_IB_OB_QUEUE_SIZE)) == 0)
		sas1068_ha->evtlog_ib_offset = 0;

	return str - buf;
}

static DEVICE_ATTR(ib_log, S_IRUGO, sas1068_ctl_ib_queue_log_show, NULL);

static ssize_t sas1068_ctl_ob_queue_log_show(struct device *cdev,
	struct device_attribute *attr, char *buf)
{
	struct Scsi_Host *shost = class_to_shost(cdev);
	struct sas_ha_struct *sha = SHOST_TO_SAS_HA(shost);
	struct sas1068_hba_info *sas1068_ha = sha->lldd_ha;
	int offset;
	char *str = buf;
	int start = 0;
#define OB_MEMMAP(c)	\
		(*(u32 *)((u8 *)sas1068_ha->	\
		memoryMap.region[OB].virt_ptr +	\
		sas1068_ha->evtlog_ob_offset + (c)))

	for (offset = 0; offset < IB_OB_READ_TIMES; offset++) {
		str += sprintf(str, "0x%08x\n", OB_MEMMAP(start));
		start = start + 4;
	}
	sas1068_ha->evtlog_ob_offset += SYSFS_OFFSET;
	if (((sas1068_ha->evtlog_ob_offset) % (PM80XX_IB_OB_QUEUE_SIZE)) == 0)
		sas1068_ha->evtlog_ob_offset = 0;

	return str - buf;
}
static DEVICE_ATTR(ob_log, S_IRUGO, sas1068_ctl_ob_queue_log_show, NULL);

static ssize_t sas1068_ctl_bios_version_show(struct device *cdev,
	struct device_attribute *attr, char *buf)
{
	struct Scsi_Host *shost = class_to_shost(cdev);
	struct sas_ha_struct *sha = SHOST_TO_SAS_HA(shost);
	struct sas1068_hba_info *sas1068_ha = sha->lldd_ha;
	char *str = buf;
	int bios_index;
	DECLARE_COMPLETION_ONSTACK(completion);
	struct sas1068_ioctl_payload payload;

	sas1068_ha->nvmd_completion = &completion;
	payload.minor_function = 7;
	payload.offset = 0;
	payload.length = 4096;
	payload.func_specific = kzalloc(4096, GFP_KERNEL);
	if (!payload.func_specific)
		return -ENOMEM;
	if (SAS1068_CHIP_DISP->get_nvmd_req(sas1068_ha, &payload)) {
		kfree(payload.func_specific);
		return -ENOMEM;
	}
	wait_for_completion(&completion);
	for (bios_index = BIOSOFFSET; bios_index < BIOS_OFFSET_LIMIT;
		bios_index++)
		str += sprintf(str, "%c",
			*(payload.func_specific+bios_index));
	kfree(payload.func_specific);
	return str - buf;
}
static DEVICE_ATTR(bios_version, S_IRUGO, sas1068_ctl_bios_version_show, NULL);

static ssize_t sas1068_ctl_iop_log_show(struct device *cdev,
	struct device_attribute *attr, char *buf)
{
	struct Scsi_Host *shost = class_to_shost(cdev);
	struct sas_ha_struct *sha = SHOST_TO_SAS_HA(shost);
	struct sas1068_hba_info *sas1068_ha = sha->lldd_ha;
#define IOP_MEMMAP(r, c) \
	(*(u32 *)((u8*)sas1068_ha->memoryMap.region[IOP].virt_ptr + (r) * 32 \
	+ (c)))
	int i;
	char *str = buf;
	int max = 2;
	for (i = 0; i < max; i++) {
		str += sprintf(str, "0x%08x 0x%08x 0x%08x 0x%08x 0x%08x 0x%08x"
			       "0x%08x 0x%08x\n",
			       IOP_MEMMAP(i, 0),
			       IOP_MEMMAP(i, 4),
			       IOP_MEMMAP(i, 8),
			       IOP_MEMMAP(i, 12),
			       IOP_MEMMAP(i, 16),
			       IOP_MEMMAP(i, 20),
			       IOP_MEMMAP(i, 24),
			       IOP_MEMMAP(i, 28));
	}

	return str - buf;
}
static DEVICE_ATTR(iop_log, S_IRUGO, sas1068_ctl_iop_log_show, NULL);

static ssize_t sas1068_ctl_gsm_log_show(struct device *cdev,
	struct device_attribute *attr, char *buf)
{
	ssize_t count;

	count = sas1068_get_gsm_dump(cdev, SYSFS_OFFSET, buf);
	return count;
}

static DEVICE_ATTR(gsm_log, S_IRUGO, sas1068_ctl_gsm_log_show, NULL);

#define FLASH_CMD_NONE      0x00
#define FLASH_CMD_UPDATE    0x01
#define FLASH_CMD_SET_NVMD    0x02

struct flash_command {
     u8      command[8];
     int     code;
};

static struct flash_command flash_command_table[] =
{
     {"set_nvmd",    FLASH_CMD_SET_NVMD},
     {"update",      FLASH_CMD_UPDATE},
     {"",            FLASH_CMD_NONE} /* Last entry should be NULL. */
};

struct error_fw {
     char    *reason;
     int     err_code;
};

static struct error_fw flash_error_table[] =
{
     {"Failed to open fw image file",	FAIL_OPEN_BIOS_FILE},
     {"image header mismatch",		FLASH_UPDATE_HDR_ERR},
     {"image offset mismatch",		FLASH_UPDATE_OFFSET_ERR},
     {"image CRC Error",		FLASH_UPDATE_CRC_ERR},
     {"image length Error.",		FLASH_UPDATE_LENGTH_ERR},
     {"Failed to program flash chip",	FLASH_UPDATE_HW_ERR},
     {"Flash chip not supported.",	FLASH_UPDATE_DNLD_NOT_SUPPORTED},
     {"Flash update disabled.",		FLASH_UPDATE_DISABLED},
     {"Flash in progress",		FLASH_IN_PROGRESS},
     {"Image file size Error",		FAIL_FILE_SIZE},
     {"Input parameter error",		FAIL_PARAMETERS},
     {"Out of memory",			FAIL_OUT_MEMORY},
     {"OK", 0}	/* Last entry err_code = 0. */
};

static int sas1068_set_nvmd(struct sas1068_hba_info *sas1068_ha)
{
	struct sas1068_ioctl_payload	*payload;
	DECLARE_COMPLETION_ONSTACK(completion);
	u8		*ioctlbuffer;
	u32		ret;
	u32		length = 1024 * 5 + sizeof(*payload) - 1;

	if (sas1068_ha->fw_image->size > 4096) {
		sas1068_ha->fw_status = FAIL_FILE_SIZE;
		return -EFAULT;
	}

	ioctlbuffer = kzalloc(length, GFP_KERNEL);
	if (!ioctlbuffer) {
		sas1068_ha->fw_status = FAIL_OUT_MEMORY;
		return -ENOMEM;
	}
	payload = (struct sas1068_ioctl_payload *)ioctlbuffer;
	memcpy((u8 *)&payload->func_specific, (u8 *)sas1068_ha->fw_image->data,
				sas1068_ha->fw_image->size);
	payload->length = sas1068_ha->fw_image->size;
	payload->id = 0;
	payload->minor_function = 0x1;
	sas1068_ha->nvmd_completion = &completion;
	ret = SAS1068_CHIP_DISP->set_nvmd_req(sas1068_ha, payload);
	if (ret) {
		sas1068_ha->fw_status = FAIL_OUT_MEMORY;
		goto out;
	}
	wait_for_completion(&completion);
out:
	kfree(ioctlbuffer);
	return ret;
}

static int sas1068_update_flash(struct sas1068_hba_info *sas1068_ha)
{
	struct sas1068_ioctl_payload	*payload;
	DECLARE_COMPLETION_ONSTACK(completion);
	u8		*ioctlbuffer;
	struct fw_control_info	*fwControl;
	u32		partitionSize, partitionSizeTmp;
	u32		loopNumber, loopcount;
	struct sas1068_fw_image_header *image_hdr;
	u32		sizeRead = 0;
	u32		ret = 0;
	u32		length = 1024 * 16 + sizeof(*payload) - 1;

	if (sas1068_ha->fw_image->size < 28) {
		sas1068_ha->fw_status = FAIL_FILE_SIZE;
		return -EFAULT;
	}
	ioctlbuffer = kzalloc(length, GFP_KERNEL);
	if (!ioctlbuffer) {
		sas1068_ha->fw_status = FAIL_OUT_MEMORY;
		return -ENOMEM;
	}
	image_hdr = (struct sas1068_fw_image_header *)sas1068_ha->fw_image->data;
	while (sizeRead < sas1068_ha->fw_image->size) {
		partitionSizeTmp =
			*(u32 *)((u8 *)&image_hdr->image_length + sizeRead);
		partitionSize = be32_to_cpu(partitionSizeTmp);
		loopcount = DIV_ROUND_UP(partitionSize + HEADER_LEN,
					IOCTL_BUF_SIZE);
		for (loopNumber = 0; loopNumber < loopcount; loopNumber++) {
			payload = (struct sas1068_ioctl_payload *)ioctlbuffer;
			payload->length = 1024*16;
			payload->id = 0;
			fwControl =
			      (struct fw_control_info *)&payload->func_specific;
			fwControl->len = IOCTL_BUF_SIZE;   /* IN */
			fwControl->size = partitionSize + HEADER_LEN;/* IN */
			fwControl->retcode = 0;/* OUT */
			fwControl->offset = loopNumber * IOCTL_BUF_SIZE;/*OUT */

		/* for the last chunk of data in case file size is not even with
		4k, load only the rest*/
		if (((loopcount-loopNumber) == 1) &&
			((partitionSize + HEADER_LEN) % IOCTL_BUF_SIZE)) {
			fwControl->len =
				(partitionSize + HEADER_LEN) % IOCTL_BUF_SIZE;
			memcpy((u8 *)fwControl->buffer,
				(u8 *)sas1068_ha->fw_image->data + sizeRead,
				(partitionSize + HEADER_LEN) % IOCTL_BUF_SIZE);
			sizeRead +=
				(partitionSize + HEADER_LEN) % IOCTL_BUF_SIZE;
		} else {
			memcpy((u8 *)fwControl->buffer,
				(u8 *)sas1068_ha->fw_image->data + sizeRead,
				IOCTL_BUF_SIZE);
			sizeRead += IOCTL_BUF_SIZE;
		}

		sas1068_ha->nvmd_completion = &completion;
		ret = SAS1068_CHIP_DISP->fw_flash_update_req(sas1068_ha, payload);
		if (ret) {
			sas1068_ha->fw_status = FAIL_OUT_MEMORY;
			goto out;
		}
		wait_for_completion(&completion);
		if (fwControl->retcode > FLASH_UPDATE_IN_PROGRESS) {
			sas1068_ha->fw_status = fwControl->retcode;
			ret = -EFAULT;
			goto out;
		}
		}
	}
out:
	kfree(ioctlbuffer);
	return ret;
}
static ssize_t sas1068_store_update_fw(struct device *cdev,
				      struct device_attribute *attr,
				      const char *buf, size_t count)
{
	struct Scsi_Host *shost = class_to_shost(cdev);
	struct sas_ha_struct *sha = SHOST_TO_SAS_HA(shost);
	struct sas1068_hba_info *sas1068_ha = sha->lldd_ha;
	char *cmd_ptr, *filename_ptr;
	int res, i;
	int flash_command = FLASH_CMD_NONE;
	int ret;

	if (!capable(CAP_SYS_ADMIN))
		return -EACCES;

	/* this test protects us from running two flash processes at once,
	 * so we should start with this test */
	if (sas1068_ha->fw_status == FLASH_IN_PROGRESS)
		return -EINPROGRESS;
	sas1068_ha->fw_status = FLASH_IN_PROGRESS;

	cmd_ptr = kzalloc(count*2, GFP_KERNEL);
	if (!cmd_ptr) {
		sas1068_ha->fw_status = FAIL_OUT_MEMORY;
		return -ENOMEM;
	}

	filename_ptr = cmd_ptr + count;
	res = sscanf(buf, "%s %s", cmd_ptr, filename_ptr);
	if (res != 2) {
		sas1068_ha->fw_status = FAIL_PARAMETERS;
		ret = -EINVAL;
		goto out;
	}

	for (i = 0; flash_command_table[i].code != FLASH_CMD_NONE; i++) {
		if (!memcmp(flash_command_table[i].command,
				 cmd_ptr, strlen(cmd_ptr))) {
			flash_command = flash_command_table[i].code;
			break;
		}
	}
	if (flash_command == FLASH_CMD_NONE) {
		sas1068_ha->fw_status = FAIL_PARAMETERS;
		ret = -EINVAL;
		goto out;
	}

	ret = request_firmware(&sas1068_ha->fw_image,
			       filename_ptr,
			       sas1068_ha->dev);

	if (ret) {
		SAS1068_FAIL_DBG(sas1068_ha,
			SAS1068_printk(
			"Failed to load firmware image file %s,	error %d\n",
			filename_ptr, ret));
		sas1068_ha->fw_status = FAIL_OPEN_BIOS_FILE;
		goto out;
	}

	if (FLASH_CMD_UPDATE == flash_command)
		ret = sas1068_update_flash(sas1068_ha);
	else
		ret = sas1068_set_nvmd(sas1068_ha);

	release_firmware(sas1068_ha->fw_image);
out:
	kfree(cmd_ptr);

	if (ret)
		return ret;

	sas1068_ha->fw_status = FLASH_OK;
	return count;
}

static ssize_t sas1068_show_update_fw(struct device *cdev,
				     struct device_attribute *attr, char *buf)
{
	int i;
	struct Scsi_Host *shost = class_to_shost(cdev);
	struct sas_ha_struct *sha = SHOST_TO_SAS_HA(shost);
	struct sas1068_hba_info *sas1068_ha = sha->lldd_ha;

	for (i = 0; flash_error_table[i].err_code != 0; i++) {
		if (flash_error_table[i].err_code == sas1068_ha->fw_status)
			break;
	}
	if (sas1068_ha->fw_status != FLASH_IN_PROGRESS)
		sas1068_ha->fw_status = FLASH_OK;

	return snprintf(buf, PAGE_SIZE, "status=%x %s\n",
			flash_error_table[i].err_code,
			flash_error_table[i].reason);
}

static DEVICE_ATTR(update_fw, S_IRUGO|S_IWUSR|S_IWGRP,
	sas1068_show_update_fw, sas1068_store_update_fw);
struct device_attribute *sas1068_host_attrs[] = {
	&dev_attr_interface_rev,
	&dev_attr_fw_version,
	&dev_attr_update_fw,
	&dev_attr_aap_log,
	&dev_attr_iop_log,
	&dev_attr_gsm_log,
	&dev_attr_max_out_io,
	&dev_attr_max_devices,
	&dev_attr_max_sg_list,
	&dev_attr_sas_spec_support,
	&dev_attr_logging_level,
	&dev_attr_host_sas_address,
	&dev_attr_bios_version,
	&dev_attr_ib_log,
	&dev_attr_ob_log,
	&dev_attr_ila_version,
	&dev_attr_inc_fw_ver,
	NULL,
};

