// SPDX-License-Identifier: GPL-2.0-only

#include <signal.h>
#include "kvm_util.h"
#include "tdx/tdcall.h"
#include "tdx/tdx.h"
#include "tdx/tdx_util.h"
#include "tdx/test_util.h"
#include "test_util.h"

static void guest_code_lifecycle(void)
{
	tdx_test_success();
}

static void verify_td_lifecycle(void)
{
	struct kvm_vm *vm;
	struct kvm_vcpu *vcpu;

	vm = td_create();
	td_initialize(vm, VM_MEM_SRC_ANONYMOUS, 0);
	vcpu = td_vcpu_add(vm, 0, guest_code_lifecycle);
	td_finalize(vm);

	printf("Verifying TD lifecycle:\n");

	TDX_RUN(vcpu);
	TDX_TEST_ASSERT_SUCCESS(vcpu);

	kvm_vm_free(vm);
	printf("\t ... PASSED\n");
}

void guest_code_report_fatal_error(void)
{
	uint64_t err;

	/*
	 * Note: err should follow the GHCI spec definition:
	 * bits 31:0 should be set to 0.
	 * bits 62:32 are used for TD-specific extended error code.
	 * bit 63 is used to mark additional information in shared memory.
	 */
	err = 0x0BAAAAAD00000000;
	tdx_test_fatal(err);

	tdx_test_success();
}
void verify_report_fatal_error(void)
{
	struct kvm_vm *vm;
	struct kvm_vcpu *vcpu;

	vm = td_create();
	td_initialize(vm, VM_MEM_SRC_ANONYMOUS, 0);
	vcpu = td_vcpu_add(vm, 0, guest_code_report_fatal_error);
	td_finalize(vm);

	printf("Verifying report_fatal_error:\n");

	td_vcpu_run(vcpu);

	TEST_ASSERT_EQ(vcpu->run->exit_reason, KVM_EXIT_SYSTEM_EVENT);
	TEST_ASSERT_EQ(vcpu->run->system_event.ndata, 3);
	TEST_ASSERT_EQ(vcpu->run->system_event.data[0], TDG_VP_VMCALL_REPORT_FATAL_ERROR);
	TEST_ASSERT_EQ(vcpu->run->system_event.data[1], 0x0BAAAAAD00000000);
	TEST_ASSERT_EQ(vcpu->run->system_event.data[2], 0);

	TDX_RUN(vcpu);
	TDX_TEST_ASSERT_SUCCESS(vcpu);

	kvm_vm_free(vm);
	printf("\t ... PASSED\n");
}

#define TDX_IOEXIT_TEST_PORT 0x50

/*
 * Verifies IO functionality by writing a |value| to a predefined port.
 * Verifies that the read value is |value| + 1 from the same port.
 * If all the tests are passed then write a value to port TDX_TEST_PORT
 */
void guest_ioexit(void)
{
	uint64_t data_out, data_in;
	uint64_t ret;

	data_out = 0xAB;
	ret = tdg_vp_vmcall_instruction_io(TDX_IOEXIT_TEST_PORT, 1, PORT_WRITE,
					   &data_out);
	tdx_assert_error(ret);

	ret = tdg_vp_vmcall_instruction_io(TDX_IOEXIT_TEST_PORT, 1, PORT_READ,
					   &data_in);
	tdx_assert_error(ret);

	if (data_in != 0xAC)
		tdx_test_fatal(data_in);

	tdx_test_success();
}

void verify_td_ioexit(void)
{
	struct kvm_vm *vm;
	struct kvm_vcpu *vcpu;

	uint32_t port_data;

	vm = td_create();
	td_initialize(vm, VM_MEM_SRC_ANONYMOUS, 0);
	vcpu = td_vcpu_add(vm, 0, guest_ioexit);
	td_finalize(vm);

	printf("Verifying TD IO Exit:\n");

	/* Wait for guest to do a IO write */
	TDX_RUN(vcpu);
	TDX_TEST_ASSERT_IO(vcpu, TDX_IOEXIT_TEST_PORT, 1, PORT_WRITE);
	port_data = *(uint8_t *)((void *)vcpu->run + vcpu->run->io.data_offset);

	printf("\t ... IO WRITE: DONE\n");

	/*
	 * Wait for the guest to do a IO read. Provide the previous written data
	 * + 1 back to the guest
	 */
	TDX_RUN(vcpu);
	TDX_TEST_ASSERT_IO(vcpu, TDX_IOEXIT_TEST_PORT, 1, PORT_READ);
	*(uint8_t *)((void *)vcpu->run + vcpu->run->io.data_offset) =
		port_data + 1;

	printf("\t ... IO READ: DONE\n");

	/*
	 * Wait for the guest to complete execution successfully. The read
	 * value is checked within the guest.
	 */
	TDX_RUN(vcpu);
	TDX_TEST_ASSERT_SUCCESS(vcpu);

	printf("\t ... IO verify read/write values: OK\n");
	kvm_vm_free(vm);
	printf("\t ... PASSED\n");
}

int main(int argc, char **argv)
{
	setbuf(stdout, NULL);

	if (!is_tdx_enabled()) {
		print_skip("TDX is not supported by the KVM");
		exit(KSFT_SKIP);
	}

	run_in_new_process(&verify_td_lifecycle);
	run_in_new_process(&verify_report_fatal_error);
	run_in_new_process(&verify_td_ioexit);

	return 0;
}
