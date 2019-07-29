#include "qemu/osdep.h"
#include "qemu-common.h"
#include "qemu/error-report.h"
#include "exec/address-spaces.h"

uint64_t arm_load_macho(struct arm_boot_info *info, uint64_t *pentry, AddressSpace *as);