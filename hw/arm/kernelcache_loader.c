#include "qemu/osdep.h"
#include "qemu-common.h"
#include "qemu/error-report.h"
#include "qemu/log.h"
#include "exec/address-spaces.h"
#include "hw/arm/boot.h"
#include "hw/loader.h"

#include "macho_loader.h"
#include "hw/arm/kernelcache_loader.h"

#define VAtoPA(addr) (((addr) & 0x3fffffff) + mem_base + kernel_load_offset)
#define HI(addr) (((addr) & 0xffffffff00000000) >> 32)
#define ADD16k(addr, size) ((((addr) + (size)) + 0xffffull) & ~0xffffull)

#define xnu_arm64_kBootArgsRevision2		2	/* added boot_args.bootFlags */
#define xnu_arm64_kBootArgsVersion2		2
#define xnu_arm64_BOOT_LINE_LENGTH        256
struct xnu_arm64_Boot_Video {
	unsigned long	v_baseAddr;	/* Base address of video memory */
	unsigned long	v_display;	/* Display Code (if Applicable */
	unsigned long	v_rowBytes;	/* Number of bytes per pixel row */
	unsigned long	v_width;	/* Width */
	unsigned long	v_height;	/* Height */
	unsigned long	v_depth;	/* Pixel Depth and other parameters */
};

struct xnu_arm64_boot_args {
	uint16_t		Revision;			/* Revision of boot_args structure */
	uint16_t		Version;			/* Version of boot_args structure */
	uint64_t		virtBase;			/* Virtual base of memory */
	uint64_t		physBase;			/* Physical base of memory */
	uint64_t		memSize;			/* Size of memory */
	uint64_t		topOfKernelData;	/* Highest physical address used in kernel data area */
	struct xnu_arm64_Boot_Video		Video;				/* Video Information */
	uint32_t		machineType;		/* Machine Type */
	uint64_t		deviceTreeP;		/* Base of flattened device tree */
	uint32_t		deviceTreeLength;	/* Length of flattened tree */
	char			CommandLine[xnu_arm64_BOOT_LINE_LENGTH];	/* Passed in command line */
	uint64_t		bootFlags;		/* Additional flags specified by the bootloader */
	uint64_t		memSizeActual;		/* Actual size of memory */
};

static const ARMInsnFixup bootloader_xnu_aarch64[] = {
    //Fixup CPACR_EL1 register to allow the use of SIMD and FP functionality of arm cpus as set by iBoot
    { 0xD2A00600 }, /* mov x0, #(3 << 20) */
    { 0xD5181040 }, /* msr CPACR_EL1, x0 */
    { 0xD5033FDF }, /* isb sy */
    { 0x580000c0 }, /* ldr x0, arg ; Load the lower 32-bits of DTB */
    { 0xaa1f03e1 }, /* mov x1, xzr */
    { 0xaa1f03e2 }, /* mov x2, xzr */
    { 0xaa1f03e3 }, /* mov x3, xzr */
    { 0x58000084 }, /* ldr x4, entry ; Load the lower 32-bits of kernel entry */
    { 0xd61f0080 }, /* br x4      ; Jump to the kernel entry point */
    { 0, FIXUP_ARGPTR_LO }, /* arg: .word @DTB Lower 32-bits */
    { 0, FIXUP_ARGPTR_HI}, /* .word @DTB Higher 32-bits */
    { 0, FIXUP_ENTRYPOINT_LO }, /* entry: .word @Kernel Entry Lower 32-bits */
    { 0, FIXUP_ENTRYPOINT_HI }, /* .word @Kernel Entry Higher 32-bits */
    { 0, FIXUP_TERMINATOR }
};

static void xnu_arm_macho_highest_lowest(struct mach_header_64* mh, uint64_t *lowaddr, uint64_t *highaddr) {
    struct load_command* cmd = (struct load_command*)((uint8_t*)mh + sizeof(struct mach_header_64));
    // iterate through all the segments once to find highest and lowest addresses
    uint64_t low_addr_kern = ~0;
    uint64_t high_addr_kern = 0;
    for (unsigned int index = 0; index < mh->ncmds; index++) {
        switch (cmd->cmd) {
            case LC_SEGMENT_64: {
                struct segment_command_64* segCmd = (struct segment_command_64*)cmd;
                if (segCmd->vmaddr < low_addr_kern) {
                    low_addr_kern = segCmd->vmaddr;
                }
                if (segCmd->vmaddr + segCmd->vmsize > high_addr_kern) {
                    high_addr_kern = segCmd->vmaddr + segCmd->vmsize;
                }
                break;
            }
        }
        cmd = (struct load_command*)((char*)cmd + cmd->cmdsize);
    }
    *lowaddr = low_addr_kern;
    *highaddr = high_addr_kern;
}

static void xnu_arm_setup_boot_args(struct xnu_arm64_boot_args *boot_args, uint64_t virt_base, uint64_t phys_base, uint64_t memSize, 
                                    uint64_t top_of_kernel_data, struct xnu_arm64_Boot_Video *video, uint64_t dev_tree_addr, 
                                    uint32_t dev_tree_size, const char *CommandLine)
{
    boot_args->Revision = xnu_arm64_kBootArgsRevision2;
    //calculated in iBoot using kBootArgsVersion1 + platform_get_security_epoch, needs to be adapted for the emulator
    boot_args->Version = xnu_arm64_kBootArgsVersion2;
    boot_args->virtBase = virt_base;
    boot_args->physBase = phys_base;
    boot_args->memSize = memSize;
    boot_args->topOfKernelData = ADD16k(top_of_kernel_data, sizeof(*boot_args));
    //boot_args->Video = *video;
    boot_args->deviceTreeP = dev_tree_addr;
    boot_args->deviceTreeLength = dev_tree_size;
    g_strlcpy(boot_args->CommandLine, CommandLine, sizeof(boot_args->CommandLine));
    boot_args->memSizeActual = 0;
}

int arm_load_macho(struct arm_boot_info *info, hwaddr *pentry, AddressSpace *as)
{
    hwaddr kernel_load_offset = 0x00000000;
    hwaddr mem_base = info->loader_start;

    uint8_t *data = NULL;
    bool ret = false;
    uint8_t* rom_buf = NULL;
    gsize len = 0;

    g_file_get_contents(info->kernel_filename, (char**) &data, &len, NULL);
    struct mach_header_64* mh = (struct mach_header_64*)data;
    struct load_command* cmd = (struct load_command*)(data + sizeof(struct mach_header_64));
    uint64_t low_addr_kern;
    uint64_t high_addr_kern;
    uint64_t virt_base = 0;
    uint64_t pc = 0;
    uint64_t high_addr_temp;

    xnu_arm_macho_highest_lowest(mh, &low_addr_kern, &high_addr_kern);
    uint64_t kern_size = high_addr_kern - low_addr_kern;
    high_addr_temp = high_addr_kern;

    rom_buf = g_malloc0(kern_size);
    for (unsigned int index = 0; index < mh->ncmds; index++) {
        switch (cmd->cmd) {
            case LC_SEGMENT_64: {
                struct segment_command_64* segCmd = (struct segment_command_64*)cmd;
                memcpy(rom_buf + (segCmd->vmaddr - low_addr_kern), data + segCmd->fileoff, segCmd->filesize);
                if (virt_base == 0) {
                    virt_base = segCmd->vmaddr;
                }
                break;
            }
            case LC_UNIXTHREAD: {
                // grab just the entry point PC
                uint64_t* ptrPc = (uint64_t*)((char*)cmd + 0x110); // for arm64 only.
                pc = VAtoPA(*ptrPc);
                break;
            }
        }
        cmd = (struct load_command*)((char*)cmd + cmd->cmdsize);
    }
    //add our kernel to memory
    rom_add_blob_fixed_as("kernel", rom_buf, kern_size, VAtoPA(low_addr_kern), as);
    ret = true;
    fprintf(stderr, "low: %lx high: %lx kern_entry: %lx\n", low_addr_kern, high_addr_kern, pc);

    //add the dtb to memory
    uint64_t dtb_addr = 0;
    gsize dtb_size = 0;
    if (info->dtb_filename) {
        uint8_t* dtb_data = NULL;
        if (g_file_get_contents(info->dtb_filename, (char**) &dtb_data, &dtb_size, NULL)) {
            rom_add_blob_fixed_as("dtb", dtb_data, dtb_size, VAtoPA(high_addr_temp), as);
            dtb_addr = high_addr_temp;
            high_addr_temp = ADD16k(high_addr_temp, dtb_size);
            info->dtb_filename = NULL;
            g_free(dtb_data);
        } else {
            fprintf(stderr, "No dtb file provided\n");
            abort();
        }
    }
    fprintf(stderr, "dtb_addr: %lx dtb_size: %lx\n", dtb_addr, dtb_size);

    //build up and add our boot args
    struct xnu_arm64_boot_args boot_args;
    uint64_t boot_arg_addr = VAtoPA(high_addr_temp);
    memset(&boot_args, 0, sizeof(boot_args));
    xnu_arm_setup_boot_args(&boot_args, (mem_base + kernel_load_offset), mem_base, info->ram_size, 
                            VAtoPA(high_addr_temp), NULL, dtb_addr, dtb_size, info->kernel_cmdline);
    fprintf(stderr, "Boot Args {\n");
    fprintf(stderr, "   [%16s]: %lx\n", "virtBase", boot_args.virtBase);
    fprintf(stderr, "   [%16s]: %lx\n", "phyBase", boot_args.physBase);
    fprintf(stderr, "   [%16s]: %lx\n", "topOfKern", boot_args.topOfKernelData);
    fprintf(stderr, "   [%16s]: %lx\n", "devTreeP", boot_args.deviceTreeP);
    fprintf(stderr, "   [%16s]: %x\n", "devTreeSize", boot_args.deviceTreeLength);
    fprintf(stderr, "   [%16s]: %s\n", "cmdLine", boot_args.CommandLine);
    fprintf(stderr, "}\n");
    rom_add_blob_fixed_as("boot_args", &boot_args, sizeof(boot_args), VAtoPA(high_addr_temp), as);

    // write bootloader to fix up boot arg addr and pc
    uint32_t fixupcontext[FIXUP_MAX];
    fixupcontext[FIXUP_ARGPTR_LO] = boot_arg_addr;
    fixupcontext[FIXUP_ARGPTR_HI] = HI(boot_arg_addr);
    fixupcontext[FIXUP_ENTRYPOINT_LO] = pc;
    fixupcontext[FIXUP_ENTRYPOINT_HI] = HI(pc);
    write_bootloader("bootloader", info->loader_start, bootloader_xnu_aarch64, fixupcontext, as);
    *pentry = info->loader_start;

    return ret? kern_size : -1;
}