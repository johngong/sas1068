#ifndef SAS1068_CTL_H_INCLUDED
#define SAS1068_CTL_H_INCLUDED

#define IOCTL_BUF_SIZE		4096
#define HEADER_LEN			28
#define SIZE_OFFSET			16

#define BIOSOFFSET			56
#define BIOS_OFFSET_LIMIT		61

#define FLASH_OK                        0x000000
#define FAIL_OPEN_BIOS_FILE             0x000100
#define FAIL_FILE_SIZE                  0x000a00
#define FAIL_PARAMETERS                 0x000b00
#define FAIL_OUT_MEMORY                 0x000c00
#define FLASH_IN_PROGRESS               0x001000

#define IB_OB_READ_TIMES                256
#define SYSFS_OFFSET                    1024
#define PM80XX_IB_OB_QUEUE_SIZE         (32 * 1024)
#define SAS1068_IB_OB_QUEUE_SIZE         (16 * 1024)
#endif /* sas1068_CTL_H_INCLUDED */

