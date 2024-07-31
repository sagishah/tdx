// SPDX-License-Identifier: GPL-2.0-only

#include <asm/kvm.h>
#include <errno.h>
#include <linux/kvm.h>
#include <stdint.h>
#include <sys/ioctl.h>

#include "kvm_util.h"
#include "test_util.h"
#include "tdx/tdx.h"
#include "tdx/td_boot.h"
#include "processor.h"

/*
 * TDX ioctls
 */

static char *tdx_cmd_str[] = {
	"KVM_TDX_CAPABILITIES",
	"KVM_TDX_INIT_VM",
	"KVM_TDX_INIT_VCPU",
	"KVM_TDX_INIT_MEM_REGION",
	"KVM_TDX_FINALIZE_VM"
};
#define TDX_MAX_CMD_STR (ARRAY_SIZE(tdx_cmd_str))

static int _tdx_ioctl(int fd, int ioctl_no, uint32_t flags, void *data)
{
	struct kvm_tdx_cmd tdx_cmd;

	TEST_ASSERT(ioctl_no < TDX_MAX_CMD_STR, "Unknown TDX CMD : %d\n",
		    ioctl_no);

	memset(&tdx_cmd, 0x0, sizeof(tdx_cmd));
	tdx_cmd.id = ioctl_no;
	tdx_cmd.flags = flags;
	tdx_cmd.data = (uint64_t)data;

	return ioctl(fd, KVM_MEMORY_ENCRYPT_OP, &tdx_cmd);
}

static void tdx_ioctl(int fd, int ioctl_no, uint32_t flags, void *data)
{
	int r;

	r = _tdx_ioctl(fd, ioctl_no, flags, data);
	TEST_ASSERT(r == 0, "%s failed: %d  %d", tdx_cmd_str[ioctl_no], r,
		    errno);
}

static struct kvm_tdx_capabilities *tdx_read_capabilities(struct kvm_vm *vm)
{
	int i;
	int rc = -1;
	int nr_cpuid_configs = 4;
	struct kvm_tdx_capabilities *tdx_cap = NULL;

	do {
		nr_cpuid_configs *= 2;

		tdx_cap = realloc(
			tdx_cap, sizeof(*tdx_cap) +
			nr_cpuid_configs * sizeof(*tdx_cap->cpuid_configs));
		TEST_ASSERT(tdx_cap != NULL,
			    "Could not allocate memory for tdx capability nr_cpuid_configs %d\n",
			    nr_cpuid_configs);

		tdx_cap->nr_cpuid_configs = nr_cpuid_configs;
		rc = _tdx_ioctl(vm->fd, KVM_TDX_CAPABILITIES, 0, tdx_cap);
	} while (rc < 0 && errno == E2BIG);

	TEST_ASSERT(rc == 0, "KVM_TDX_CAPABILITIES failed: %d %d",
		    rc, errno);

	pr_debug("tdx_cap: attrs: fixed0 0x%016llx fixed1 0x%016llx\n"
		 "tdx_cap: xfam fixed0 0x%016llx fixed1 0x%016llx\n",
		 "tdx_cap: supported_gpaw: %d\n",
		 tdx_cap->attrs_fixed0, tdx_cap->attrs_fixed1,
		 tdx_cap->xfam_fixed0, tdx_cap->xfam_fixed1,
		 tdx_cap->supported_gpaw);

	for (i = 0; i < tdx_cap->nr_cpuid_configs; i++) {
		const struct kvm_tdx_cpuid_config *config =
			&tdx_cap->cpuid_configs[i];
		pr_debug("cpuid config[%d]: leaf 0x%x sub_leaf 0x%x eax 0x%08x ebx 0x%08x ecx 0x%08x edx 0x%08x\n",
			 i, config->leaf, config->sub_leaf,
			 config->eax, config->ebx, config->ecx, config->edx);
	}

	return tdx_cap;
}

#define XFEATURE_MASK_CET (XFEATURE_MASK_CET_USER | XFEATURE_MASK_CET_KERNEL)

static void tdx_apply_cpuid_restrictions(struct kvm_cpuid2 *cpuid_data)
{
	for (int i = 0; i < cpuid_data->nent; i++) {
		struct kvm_cpuid_entry2 *e = &cpuid_data->entries[i];

		if (e->function == 0xd && e->index == 0) {
			/*
			 * TDX module requires both XTILE_{CFG, DATA} to be set.
			 * Both bits are required for AMX to be functional.
			 */
			if ((e->eax & XFEATURE_MASK_XTILE) !=
			    XFEATURE_MASK_XTILE) {
				e->eax &= ~XFEATURE_MASK_XTILE;
			}
		}
		if (e->function == 0xd && e->index == 1) {
			/*
			 * TDX doesn't support LBR yet.
			 * Disable bits from the XCR0 register.
			 */
			e->ecx &= ~XFEATURE_MASK_LBR;
			/*
			 * TDX modules requires both CET_{U, S} to be set even
			 * if only one is supported.
			 */
			if (e->ecx & XFEATURE_MASK_CET)
				e->ecx |= XFEATURE_MASK_CET;
		}
	}
}

static void tdx_check_attributes(struct kvm_vm *vm, uint64_t attributes)
{
	struct kvm_tdx_capabilities *tdx_cap;

	tdx_cap = tdx_read_capabilities(vm);

	/* TDX spec: any bits 0 in attrs_fixed0 must be 0 in attributes */
	TEST_ASSERT_EQ(attributes & ~tdx_cap->attrs_fixed0, 0);

	/* TDX spec: any bits 1 in attrs_fixed1 must be 1 in attributes */
	TEST_ASSERT_EQ(attributes & tdx_cap->attrs_fixed1, tdx_cap->attrs_fixed1);

	free(tdx_cap);
}

static void tdx_td_init(struct kvm_vm *vm, uint64_t attributes)
{
	const struct kvm_cpuid2 *cpuid;
	struct kvm_tdx_init_vm *init_vm;

	cpuid = kvm_get_supported_cpuid();

	init_vm =
		calloc(1, sizeof(*init_vm) + sizeof(init_vm->cpuid.entries[0]) *
						     cpuid->nent);
	TEST_ASSERT(init_vm, "vm allocation failed");

	memcpy(&init_vm->cpuid, cpuid, kvm_cpuid2_size(cpuid->nent));

	tdx_check_attributes(vm, attributes);

	init_vm->attributes = attributes;

	tdx_apply_cpuid_restrictions(&init_vm->cpuid);

	tdx_ioctl(vm->fd, KVM_TDX_INIT_VM, 0, init_vm);
}

static void tdx_td_vcpu_init(struct kvm_vcpu *vcpu)
{
	const struct kvm_cpuid2 *cpuid = kvm_get_supported_cpuid();

	vcpu_init_cpuid(vcpu, cpuid);
	tdx_ioctl(vcpu->fd, KVM_TDX_INIT_VCPU, 0, NULL);
}

static void tdx_init_mem_region(struct kvm_vm *vm, void *source_pages,
				uint64_t gpa, uint64_t size)
{
	struct kvm_tdx_init_mem_region mem_region = {
		.source_addr = (uint64_t)source_pages,
		.gpa = gpa,
		.nr_pages = size / PAGE_SIZE,
	};
	struct kvm_pre_fault_memory pre_fault = {
		.gpa = gpa,
		.size = size,
		.flags = 0,
	};
	uint32_t metadata = KVM_TDX_MEASURE_MEMORY_REGION;
	struct kvm_vcpu *vcpu;
	int r;

	vcpu = list_first_entry_or_null(&vm->vcpus, struct kvm_vcpu, list);

	TEST_ASSERT((mem_region.nr_pages > 0) &&
			    ((mem_region.nr_pages * PAGE_SIZE) == size),
		    "Cannot add partial pages to the guest memory.\n");
	TEST_ASSERT(((uint64_t)source_pages & (PAGE_SIZE - 1)) == 0,
		    "Source memory buffer is not page aligned\n");
	r = ioctl(vcpu->fd, KVM_PRE_FAULT_MEMORY, &pre_fault);
	TEST_ASSERT(r == 0, "KVM_PRE_FAULT_MEMORY failed: %d  %d", r, errno);
	tdx_ioctl(vcpu->fd, KVM_TDX_INIT_MEM_REGION, metadata, &mem_region);
}

static void tdx_td_finalize_mr(struct kvm_vm *vm)
{
	tdx_ioctl(vm->fd, KVM_TDX_FINALIZE_VM, 0, NULL);
}

/*
 * Other ioctls
 */

/**
 * Register a memory region that may contain encrypted data in KVM.
 */
static void register_encrypted_memory_region(
	struct kvm_vm *vm, struct userspace_mem_region *region)
{
	vm_set_memory_attributes(vm, region->region.guest_phys_addr,
				 region->region.memory_size,
				 KVM_MEMORY_ATTRIBUTE_PRIVATE);
}

/*
 * TD creation/setup/finalization
 */

static void tdx_enable_capabilities(struct kvm_vm *vm)
{
	int rc;

	rc = kvm_check_cap(KVM_CAP_X2APIC_API);
	TEST_ASSERT(rc, "TDX: KVM_CAP_X2APIC_API is not supported!");
	rc = kvm_check_cap(KVM_CAP_SPLIT_IRQCHIP);
	TEST_ASSERT(rc, "TDX: KVM_CAP_SPLIT_IRQCHIP is not supported!");

	vm_enable_cap(vm, KVM_CAP_X2APIC_API,
		      KVM_X2APIC_API_USE_32BIT_IDS |
			      KVM_X2APIC_API_DISABLE_BROADCAST_QUIRK);
	vm_enable_cap(vm, KVM_CAP_SPLIT_IRQCHIP, 24);
}

static void tdx_apply_cr4_restrictions(struct kvm_sregs *sregs)
{
	/* TDX spec 11.6.2: CR4 bit MCE is fixed to 1 */
	sregs->cr4 |= X86_CR4_MCE;

	/* Set this because UEFI also sets this up, to handle XMM exceptions */
	sregs->cr4 |= X86_CR4_OSXMMEXCPT;

	/* TDX spec 11.6.2: CR4 bit VMXE and SMXE are fixed to 0 */
	sregs->cr4 &= ~(X86_CR4_VMXE | X86_CR4_SMXE);
}

static void load_td_boot_code(struct kvm_vm *vm)
{
	void *boot_code_hva = addr_gpa2hva(vm, FOUR_GIGABYTES_GPA - TD_BOOT_CODE_SIZE);

	TEST_ASSERT(td_boot_code_end - reset_vector == 16,
		"The reset vector must be 16 bytes in size.");
	memcpy(boot_code_hva, td_boot, TD_BOOT_CODE_SIZE);
}

static void load_td_per_vcpu_parameters(struct td_boot_parameters *params,
					struct kvm_sregs *sregs,
					struct kvm_vcpu *vcpu,
					void *guest_code)
{
	struct td_per_vcpu_parameters *vcpu_params = &params->per_vcpu[vcpu->id];

	TEST_ASSERT(vcpu->initial_stack_addr != 0,
		"initial stack address should not be 0");
	TEST_ASSERT(vcpu->initial_stack_addr <= 0xffffffff,
		"initial stack address must fit in 32 bits");
	TEST_ASSERT((uint64_t)guest_code <= 0xffffffff,
		"guest_code must fit in 32 bits");
	TEST_ASSERT(sregs->cs.selector != 0, "cs.selector should not be 0");

	vcpu_params->esp_gva = (uint32_t)(uint64_t)vcpu->initial_stack_addr;
	vcpu_params->ljmp_target.eip_gva = (uint32_t)(uint64_t)guest_code;
	vcpu_params->ljmp_target.code64_sel = sregs->cs.selector;
}

static void load_td_common_parameters(struct td_boot_parameters *params,
				struct kvm_sregs *sregs)
{
	/* Set parameters! */
	params->cr0 = sregs->cr0;
	params->cr3 = sregs->cr3;
	params->cr4 = sregs->cr4;
	params->gdtr.limit = sregs->gdt.limit;
	params->gdtr.base = sregs->gdt.base;
	params->idtr.limit = sregs->idt.limit;
	params->idtr.base = sregs->idt.base;

	TEST_ASSERT(params->cr0 != 0, "cr0 should not be 0");
	TEST_ASSERT(params->cr3 != 0, "cr3 should not be 0");
	TEST_ASSERT(params->cr4 != 0, "cr4 should not be 0");
	TEST_ASSERT(params->gdtr.base != 0, "gdt base address should not be 0");
	TEST_ASSERT(params->idtr.base != 0, "idt base address should not be 0");
}

static void load_td_boot_parameters(struct td_boot_parameters *params,
				struct kvm_vcpu *vcpu, void *guest_code)
{
	struct kvm_sregs sregs;

	/* Assemble parameters in sregs */
	memset(&sregs, 0, sizeof(struct kvm_sregs));
	vcpu_setup_mode_sregs(vcpu->vm, &sregs);
	tdx_apply_cr4_restrictions(&sregs);

	if (!params->cr0)
		load_td_common_parameters(params, &sregs);

	load_td_per_vcpu_parameters(params, &sregs, vcpu, guest_code);
}

/**
 * Adds a vCPU to a TD (Trusted Domain) with minimum defaults. It will not set
 * up any general purpose registers as they will be initialized by the TDX. In
 * TDX, vCPUs RIP is set to 0xFFFFFFF0. See Intel TDX EAS Section "Initial State
 * of Guest GPRs" for more information on vCPUs initial register values when
 * entering the TD first time.
 *
 * Input Args:
 *   vm - Virtual Machine
 *   vcpuid - The id of the VCPU to add to the VM.
 */
struct kvm_vcpu *td_vcpu_add(struct kvm_vm *vm, uint32_t vcpu_id, void *guest_code)
{
	struct kvm_vcpu *vcpu;

	vcpu = vm_arch_vcpu_add(vm, vcpu_id);

	tdx_td_vcpu_init(vcpu);

	load_td_boot_parameters(addr_gpa2hva(vm, TD_BOOT_PARAMETERS_GPA),
				vcpu, guest_code);

	return vcpu;
}

static void load_td_memory_region(struct kvm_vm *vm,
				  struct userspace_mem_region *region)
{
	const struct sparsebit *pages = region->protected_phy_pages;
	const uint64_t hva_base = region->region.userspace_addr;
	const vm_paddr_t gpa_base = region->region.guest_phys_addr;
	const sparsebit_idx_t lowest_page_in_region = gpa_base >>
						      vm->page_shift;

	sparsebit_idx_t i;
	sparsebit_idx_t j;

	TEST_ASSERT(region->region.guest_memfd != -1,
		    "TDX requires the use of guest_memfd.");

	if (!sparsebit_any_set(pages))
		return;

	register_encrypted_memory_region(vm, region);

	sparsebit_for_each_set_range(pages, i, j) {
		const uint64_t size_to_load = (j - i + 1) * vm->page_size;
		const uint64_t offset =
			(i - lowest_page_in_region) * vm->page_size;
		const uint64_t hva = hva_base + offset;
		const uint64_t gpa = gpa_base + offset;

		tdx_init_mem_region(vm, (void *)hva, gpa, size_to_load);
	}
}

static void load_td_private_memory(struct kvm_vm *vm)
{
	int ctr;
	struct userspace_mem_region *region;

	hash_for_each(vm->regions.slot_hash, ctr, region, slot_node) {
		load_td_memory_region(vm, region);
	}
}

struct kvm_vm *td_create(void)
{
	const struct vm_shape shape = {
		.mode = VM_MODE_DEFAULT,
		.type = KVM_X86_TDX_VM,
	};

	return ____vm_create(shape);
}

static void td_setup_boot_code(struct kvm_vm *vm, enum vm_mem_backing_src_type src_type)
{
	vm_vaddr_t addr;
	size_t boot_code_allocation = round_up(TD_BOOT_CODE_SIZE, PAGE_SIZE);
	vm_paddr_t boot_code_base_gpa = FOUR_GIGABYTES_GPA - boot_code_allocation;
	size_t npages = DIV_ROUND_UP(boot_code_allocation, PAGE_SIZE);

	vm_userspace_mem_region_add(vm, src_type, boot_code_base_gpa, 1, npages,
				    KVM_MEM_GUEST_MEMFD);
	vm->memslots[MEM_REGION_CODE] = 1;
	addr = vm_vaddr_identity_alloc(vm, boot_code_allocation,
				       boot_code_base_gpa, MEM_REGION_CODE);
	TEST_ASSERT_EQ(addr, boot_code_base_gpa);

	load_td_boot_code(vm);
}

static size_t td_boot_parameters_size(void)
{
	int max_vcpus = kvm_check_cap(KVM_CAP_MAX_VCPUS);
	size_t total_per_vcpu_parameters_size =
		max_vcpus * sizeof(struct td_per_vcpu_parameters);

	return sizeof(struct td_boot_parameters) + total_per_vcpu_parameters_size;
}

static void td_setup_boot_parameters(struct kvm_vm *vm, enum vm_mem_backing_src_type src_type)
{
	vm_vaddr_t addr;
	size_t boot_params_size = td_boot_parameters_size();
	int npages = DIV_ROUND_UP(boot_params_size, PAGE_SIZE);
	size_t total_size = npages * PAGE_SIZE;

	vm_userspace_mem_region_add(vm, src_type, TD_BOOT_PARAMETERS_GPA, 2,
				    npages, KVM_MEM_GUEST_MEMFD);
	vm->memslots[MEM_REGION_TDX_BOOT_PARAMS] = 2;
	addr = vm_vaddr_identity_alloc(vm, total_size, TD_BOOT_PARAMETERS_GPA,
				       MEM_REGION_TDX_BOOT_PARAMS);
	TEST_ASSERT_EQ(addr, TD_BOOT_PARAMETERS_GPA);
}

void td_initialize(struct kvm_vm *vm, enum vm_mem_backing_src_type src_type,
		   uint64_t attributes)
{
	uint64_t nr_pages_required;

	tdx_enable_capabilities(vm);

	tdx_td_init(vm, attributes);

	nr_pages_required = vm_nr_pages_required(VM_MODE_DEFAULT, 1, 0);

	/*
	 * Add memory (add 0th memslot) for TD. This will be used to setup the
	 * CPU (provide stack space for the CPU) and to load the elf file.
	 */
	vm_userspace_mem_region_add(vm, src_type, 0, 0, nr_pages_required,
				    KVM_MEM_GUEST_MEMFD);

	kvm_vm_elf_load(vm, program_invocation_name);

	vm_init_descriptor_tables(vm);

	td_setup_boot_code(vm, src_type);
	td_setup_boot_parameters(vm, src_type);
}

void td_finalize(struct kvm_vm *vm)
{
	sync_exception_handlers_to_guest(vm);

	load_td_private_memory(vm);

	tdx_td_finalize_mr(vm);
}

void td_vcpu_run(struct kvm_vcpu *vcpu)
{
	vcpu_run(vcpu);

	/* Handle TD VMCALLs that require userspace handling. */
	if (vcpu->run->exit_reason == KVM_EXIT_TDX &&
	    vcpu->run->tdx.type == KVM_EXIT_TDX_VMCALL) {
		handle_userspace_tdg_vp_vmcall_exit(vcpu);
	}
}

/**
 * Handle conversion of memory with @size beginning @gpa for @vm. Set
 * @shared_to_private to true for shared to private conversions and false
 * otherwise.
 *
 * Since this is just for selftests, we will just keep both pieces of backing
 * memory allocated and not deallocate/allocate memory; we'll just do the
 * minimum of calling KVM_MEMORY_ENCRYPT_REG_REGION and
 * KVM_MEMORY_ENCRYPT_UNREG_REGION.
 */
void handle_memory_conversion(struct kvm_vm *vm, uint64_t gpa, uint64_t size,
			bool shared_to_private)
{
	struct kvm_memory_attributes range;

	range.address = gpa;
	range.size = size;
	range.attributes = shared_to_private ? KVM_MEMORY_ATTRIBUTE_PRIVATE : 0;
	range.flags = 0;

	printf("\t ... calling KVM_SET_MEMORY_ATTRIBUTES ioctl with gpa=%#lx, size=%#lx, attributes=%#llx\n", gpa, size, range.attributes);

	vm_ioctl(vm, KVM_SET_MEMORY_ATTRIBUTES, &range);
}
