#ifndef _SAS1068_CHIPS_H_
#define _SAS1068_CHIPS_H_

static inline u32 sas1068_read_32(void *virt_addr)
{
	return *((u32 *)virt_addr);
}

static inline void sas1068_write_32(void *addr, u32 offset, __le32 val)
{
	*((__le32 *)(addr + offset)) = val;
}

static inline u32 sas1068_cr32(struct sas1068_hba_info *sas1068_ha, u32 bar,
		u32 offset)
{
	return readl(sas1068_ha->io_mem[bar].memvirtaddr + offset);
}

static inline void sas1068_cw32(struct sas1068_hba_info *sas1068_ha, u32 bar,
		u32 addr, u32 val)
{
	writel(val, sas1068_ha->io_mem[bar].memvirtaddr + addr);
}
static inline u32 sas1068_mr32(void __iomem *addr, u32 offset)
{
	return readl(addr + offset);
}
static inline void sas1068_mw32(void __iomem *addr, u32 offset, u32 val)
{
	writel(val, addr + offset);
}
static inline u32 get_pci_bar_index(u32 pcibar)
{
		switch (pcibar) {
		case 0x18:
		case 0x1C:
			return 1;
		case 0x20:
			return 2;
		case 0x24:
			return 3;
		default:
			return 0;
	}
}

#endif  /* _sas1068_CHIPS_H_ */

