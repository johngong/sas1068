#ifndef _SAS1068_DEFS_H_
#define _SAS1068_DEFS_H_

enum chip_flavors {
	chip_1068,
	chip_1068e,
};

enum phy_speed {
	PHY_SPEED_15 = 0x01,
	PHY_SPEED_30 = 0x02,
	PHY_SPEED_60 = 0x04,
	PHY_SPEED_120 = 0x08,
};

enum data_direction {
	DATA_DIR_NONE = 0x0,	/* NO TRANSFER */
	DATA_DIR_IN = 0x01,	/* INBOUND */
	DATA_DIR_OUT = 0x02,	/* OUTBOUND */
	DATA_DIR_BYRECIPIENT = 0x04, /* UNSPECIFIED */
};

enum port_type {
	PORT_TYPE_SAS = (1L << 1),
	PORT_TYPE_SATA = (1L << 0),
};

/* driver compile-time configuration */
#define	SAS1068_MAX_CCB		 512	/* max ccbs supported */
#define SAS1068_MPI_QUEUE         1024   /* maximum mpi queue entries */
#define	SAS1068_MAX_INB_NUM	 1
#define	SAS1068_MAX_OUTB_NUM	 1
#define	SAS1068_MAX_SPCV_INB_NUM		1
#define	SAS1068_MAX_SPCV_OUTB_NUM	4
#define	SAS1068_CAN_QUEUE	 508	/* SCSI Queue depth */

/* Inbound/Outbound queue size */
#define IOMB_SIZE_SPC		64
#define IOMB_SIZE_SPCV		128

/* unchangeable hardware details */
#define	SAS1068_MAX_PHYS		 16	/* max. possible phys */
#define	SAS1068_MAX_PORTS	 16	/* max. possible ports */
#define	SAS1068_MAX_DEVICES	 2048	/* max supported device */
#define	SAS1068_MAX_MSIX_VEC	 64	/* max msi-x int for spcv/ve */

#define LSI_MAX_MEMCNT_BASE	5
#define IB			(LSI_MAX_MEMCNT_BASE + 1)
#define CI			(IB + SAS1068_MAX_SPCV_INB_NUM)
#define OB			(CI + SAS1068_MAX_SPCV_INB_NUM)
#define PI			(OB + SAS1068_MAX_SPCV_OUTB_NUM)
#define LSI_MAX_MEMCNT		(PI + SAS1068_MAX_SPCV_OUTB_NUM)
#define SAS1068_MAX_DMA_SG	SG_ALL
enum memory_region_num {
	AAP1 = 0x0, /* application acceleration processor */
	IOP,	    /* IO processor */
	NVMD,	    /* NVM device */
	DEV_MEM,    /* memory for devices */
	CCB_MEM,    /* memory for command control block */
	FW_FLASH,    /* memory for fw flash update */
	FORENSIC_MEM  /* memory for fw forensic data */
};
#define	SAS1068_EVENT_LOG_SIZE	 (128 * 1024)

/*error code*/
enum mpi_err {
	MPI_IO_STATUS_SUCCESS = 0x0,
	MPI_IO_STATUS_BUSY = 0x01,
	MPI_IO_STATUS_FAIL = 0x02,
};

/**
 * Phy Control constants
 */
enum phy_control_type {
	PHY_LINK_RESET = 0x01,
	PHY_HARD_RESET = 0x02,
	PHY_NOTIFY_ENABLE_SPINUP = 0x10,
};

enum SAS1068_hba_info_flags {
	SAS1068F_INIT_TIME	= (1U << 0),
	SAS1068F_RUN_TIME	= (1U << 1),
};

#endif
