#include "panda/plugin.h"
#include "panda/plugins/syscalls2/syscalls_ext_typedefs.h"

#include "panda/rr/rr_log.h"
#include "panda/rr/kernel_rr.h"
#include "panda/callbacks/cb-support.h"

#include <stdlib.h>
#include <string.h>

// Save syscall && exceptions
const char *kernel_rr_log = "kernel_rr.log";
const char *kernel_cfu_log = "kernel_cfu.log";

event_node *syscall_head;
event_node *syscall_current;

event_node *syscall_replay_head = NULL;
event_node *syscall_replay_current = NULL;

cfu *cfu_head = NULL;
cfu *cfu_current = NULL;

int cached_syscall_num = 0;
int max_cached_syscall_record = 1000;

static bool in_cfu = false;
static bool interrupt_in_cfu = false;

static int kernel_syscall_number = 0;
static int kernel_exception_number = 0;
static int kernel_cfu_number = 0;


int kernel_rr_get_past_syscall_num(void) {
	return kernel_syscall_number;
}

int kernel_rr_get_past_exception_num(void) {
	return kernel_exception_number;
}

int kernel_rr_get_past_cfu_num(void) {
	return kernel_cfu_number;
}

void kernel_rr_do_end_replay(void) {
	rr_do_end_replay(0);
	exit(0);
}

static cfu* new_cfu(void) {
	cfu *node = (struct cfu*)malloc(sizeof(struct cfu));
	node->next = NULL;
	return node;
}

bool kernel_rr_node_empty(void) {
	return cfu_head == NULL && syscall_head == NULL;
}


void kernel_record_cfu(CPUState *cs, hwaddr src_addr, hwaddr dest_addr, int len) {    
	uint64_t inst_num = rr_get_guest_instr_count();
	if (cfu_head == NULL) {
		cfu_head = new_cfu();
		cfu_head->src_addr = src_addr;
		cfu_head->dest_addr = dest_addr;
		cfu_head->inst_num_before = inst_num;
		cfu_head->len = len;
		cfu_current = cfu_head;
	} else {
		cfu_current->next = new_cfu();
		cfu_current->next->src_addr = src_addr;
		cfu_current->next->dest_addr = dest_addr;
		cfu_current->next->inst_num_before = inst_num;
		cfu_current->next->len = len;
		cfu_current = cfu_current->next;
	}

	qemu_log("Read from $0x%016" PRIx64 ", len=%d\n", dest_addr, len);

	for (int i = 0; i < len; i++) {
		int ret = panda_virtual_memory_read(cs, dest_addr + i, &cfu_current->data[i], 1);

		if (ret != 0) {
			printf("Read failed!");
			exit(1);
		}
		// qemu_log("Read from $0x%016" PRIx64 ", val=%u, ret=%d\n", dest_addr, cfu_current->data[i], ret);
	}

	return;
}

void kernel_replay_cfu(CPUState *cs, hwaddr dest_addr) {
	qemu_log("Write to $0x%" TCG_PRIlx ", len=%d ", dest_addr, cfu_head->len);
	// uint8_t v = 0;
	for (int i = 0; i < cfu_head->len; i++) {
		panda_virtual_memory_write(cs, dest_addr + i, &cfu_head->data[i], 1);
	}
	// qemu_log("val %d=%u\n", i, cfu_head->data[i]);

	qemu_log("\n");

	kernel_cfu_number++;
	cfu_head = cfu_head->next;
	return;
}

static void persist_cfu(cfu *node, FILE *fptr) {
	fwrite(node, sizeof(struct cfu), 1, fptr);
}

void persist_cfus(void) {
	FILE *fptr = fopen(kernel_cfu_log, "a");
	cfu *cur= cfu_head;
	int i = 1;

	while (cur != NULL) {
		persist_cfu(cur, fptr);
		printf("persist cfu src=$0x%" TCG_PRIlx " dest=$0x%" TCG_PRIlx ", len=%d, ", cur->src_addr, cur->dest_addr, cur->len);
		for (int i = 0; i < cur->len; i++) {
			printf("data %d=%u, ", i, cur->data[i]);
		}
		printf("\n");
		cur = cur->next;
		i++;
	}

	fclose(fptr);
	return;
}

void load_cfus(void) {
	panda_enable_memcb();

	FILE *fptr = fopen(kernel_cfu_log, "r");

	struct cfu loaded_node;

	while(fread(&loaded_node, sizeof(struct cfu), 1, fptr)) {
		cfu* node = new_cfu();

		node->src_addr = loaded_node.src_addr;
		node->dest_addr = loaded_node.dest_addr;
		node->inst_num_before = loaded_node.inst_num_before;
		node->len = loaded_node.len;

		for (int i = 0; i < node->len; i++) {
			node->data[i] = loaded_node.data[i];
		}

		if (cfu_head == NULL) {
			cfu_head = node;
			cfu_current = cfu_head;
		} else {
			cfu_current->next = node;
			cfu_current = cfu_current->next;
		}
		// printf("loaded cfu src=$0x%" TCG_PRIlx " dest=$0x%" TCG_PRIlx "\n", cfu_current->src_addr, cfu_current->dest_addr);
		// for (int i = 0; i < node->len; i++) {
		// 	printf("data %d=%u", i, node->data[i]);
		// }
		// printf("\n");
	}
}

event_node* fetch_next_syscall(void) {
	event_node *cur = syscall_replay_head;
	syscall_replay_head = syscall_replay_head->next;
	return cur;
}

event_node* get_next_syscall(void) {
	return syscall_replay_head;
}

uint64_t rr_inst_num_before_next_syscall(bool *is_over) {
	if(syscall_replay_head == NULL) {
		*is_over = true;
		return 0;
	}

	*is_over = false;

	return syscall_replay_head->inst_num_before - rr_get_guest_instr_count();
}

static void free_all_nodes(void) {
	struct event_node *node = syscall_head;

	while (node != NULL) {
		struct event_node *tmp = node;
		node = node->next;
		free(tmp);
	}
}

static void load_node_regs(event_node *node, event_node loaded_node) {
	for (int i=0; i < CPU_NB_REGS; i++) {
		 node->args[i] = loaded_node.args[i];
	}
}


void load_kernel_log(void) {
	FILE *fptr = fopen(kernel_rr_log, "r");

	struct event_node loaded_node;

	while(fread(&loaded_node, sizeof(struct event_node), 1, fptr)) {
		event_node* node = (struct event_node*)malloc(sizeof(struct event_node));
		node->type = loaded_node.type;

		if (node->type == 1) {
			node->exception_index = loaded_node.exception_index;
			node->cr2 = loaded_node.cr2;
			node->error_code = loaded_node.error_code;
		}
		// node->id_no = loaded_node.id_no;
		// node->type = KERNEL_INPUT_TYPE_SYSCALL;
		node->inst_num_before = loaded_node.inst_num_before;
		// printf("loaded type %d number inst: %ld \n", node->type, node->inst_num_before);
		// printf("replay kernel syscall: %ld, arg1: %ld, arg2: %ld, arg3: %ld, arg4: %ld, arg5: %ld, arg6: %ld, arg7: %ld\n",
		// 	   loaded_node.args[0], loaded_node.args[1], loaded_node.args[2], loaded_node.args[3], loaded_node.args[4], 
		// 	   loaded_node.args[5], loaded_node.args[6], loaded_node.args[7]);
		load_node_regs(node, loaded_node);

		if (syscall_replay_head == NULL) {
			syscall_replay_head = node;
			syscall_replay_current = node;
		} else {
			syscall_replay_current->next = node;
			syscall_replay_current = syscall_replay_current->next;
		}
		syscall_replay_current->next = NULL;
	}
	// exit(0);
	// printf("Loaded all the kernel syscalls\n");
}

static void persist_bin(event_node *node, FILE *fptr) {
	fwrite (node, sizeof(struct event_node), 1, fptr);
}

static void persist_syscalls(void) {
	printf("Flushing all nodes %d\n", cached_syscall_num);
	FILE *fptr = fopen(kernel_rr_log, "a");
	event_node *cur= syscall_head;
	int i = 1;

	while (cur != NULL) {
		persist_bin(cur, fptr);
		if (cur->type == 0)
			printf("persisted syscall, inst before %ld\n", cur->inst_num_before);
		else
			printf("persisted exception, inst before %ld, index %u\n", cur->inst_num_before, cur->exception_index);
		cur = cur->next;
		i+=1;
	}

	fclose(fptr);
	return;
}

void flush_event_records(void) {
	persist_syscalls();
	free_all_nodes();
	syscall_head = NULL;
	syscall_current = NULL;
	cached_syscall_num = 0;
}

static void post_handle_event(event_node* node) {
	/* currently we don't flush them yet */
	// if (cached_syscall_num == max_cached_syscall_record)
	// 	flush_event_records();

	if (syscall_current != NULL) {
		syscall_current->next = node;
	}

	if (syscall_head == NULL) {
		syscall_head = node;
	}

	syscall_current = node;
	cached_syscall_num++;
}

void kernel_rr_record_event_kernel_load(CPUX86State *env, int target_reg) {
	event_node* node = (struct event_node*)malloc(sizeof(struct event_node));

	node->inst_num_before = rr_get_guest_instr_count();
	node->next = NULL;
	
	post_handle_event(node);
}

static void replay_regs_of_node(CPUX86State *env, event_node *node) {
	for (int i=0; i < CPU_NB_REGS; i++) {
		 env->regs[i] = node->args[i];
	}
}

static void record_regs_on_node(CPUX86State *env, event_node *node) {
	for (int i=0; i < CPU_NB_REGS; i++) {
		node->args[i] = env->regs[i];
	}
}

void kernel_rr_record_event_syscall(CPUX86State *env) {
	event_node* node = (struct event_node*)malloc(sizeof(struct event_node));
	node->type = 0;

	node->inst_num_before = rr_get_guest_instr_count();

	record_regs_on_node(env, node);
	node->next = NULL;

	post_handle_event(node);
}

void kernel_rr_replay_event_syscall(CPUX86State *env, event_node *node) {
	if (node == NULL) {
		printf("Replay is over\n");
		kernel_rr_do_end_replay();
	}

	replay_regs_of_node(env, node);
	kernel_syscall_number++;
}

void print_node_regs(event_node *node) {
	qemu_log_lock();
	qemu_log("Node Regs:");
	for (int i=0; i < CPU_NB_REGS; i++) {
		qemu_log("%d=$0x%"TCG_PRIlx",", i, node->args[i]);
	}
	qemu_log("\n");
	qemu_log_unlock();
}

void kernel_rr_record_event_exception(CPUState *cs, CPUX86State *env) {
	event_node* node = (struct event_node*)malloc(sizeof(struct event_node));

	node->type = 1;
	node->exception_index = cs->exception_index;
	node->error_code = env->error_code;
	node->cr2 = env->cr[2];

	node->inst_num_before = rr_get_guest_instr_count();

	record_regs_on_node(env, node);
	node->next = NULL;

	qemu_log("recording exception: %d, error_code %d\n", node->exception_index, node->error_code);
	print_node_regs(node);

	post_handle_event(node);
}

void kernel_rr_replay_event_exception(CPUState *cs, CPUX86State *env, event_node *node) {
	cs->exception_index = node->exception_index;
	env->error_code = node->error_code;
	env->cr[2] = node->cr2;
	qemu_log("replaying exception: %d error_code=%d\n", node->exception_index, node->error_code);

	replay_regs_of_node(env, node);
	kernel_exception_number++;
}


void print_regs(CPUX86State *env) {
	qemu_log_lock();
	qemu_log("Regs:");
	for (int i=0; i < CPU_NB_REGS; i++) {
		qemu_log("%d=%016"PRIx64",", i, env->regs[i]);
		// qemu_log("%d=%lu,", i, env->regs[i]);
	}
	qemu_log("\n");
	qemu_log_unlock();
}


void rr_cfu_start(void) {
	in_cfu = true;
}

void rr_cfu_end(void) {
	in_cfu = false;
}

bool rr_in_cfu(void) {
	return in_cfu;
}

bool rr_in_int_during_cfu(void) {
	return interrupt_in_cfu;
}

void rr_int_during_cfu_start(void) {
	interrupt_in_cfu = true;
}

void rr_int_during_cfu_end(void) {
	interrupt_in_cfu = false;
}

// void kernel_rr_record_event(CPUState *cpu, target_ptr_t pc, int id_no, int type, void* ctx) {

// 	event_node* node = (struct event_node*)malloc(sizeof(struct event_node));
// 	node->id_no = id_no;
// 	node->next = NULL;
//     node->type = type;
// 	// syscall_ctx_t *ctxp = (syscall_ctx_t *)ctx;

	// X86CPU *x86_cpu = X86_CPU(cpu);
    // CPUX86State *env = &x86_cpu->env;

// 	if (type != KERNEL_INPUT_TYPE_SYSCALL) {
// 		return;
// 	}

// 	node->inst_num_before = rr_get_guest_instr_count();

// 	// printf("number inst: %ld\n", node->inst_num_before);
	// node->args[R_EAX] = env->regs[R_EAX];
// 	node->args[R_EBX] = env->regs[R_EBX];
// 	node->args[R_EDX] = env->regs[R_EDX];
// 	node->args[R_ESP] = env->regs[R_ESP];
// 	node->args[R_EBP] = env->regs[R_EBP];
// 	node->args[R_ESI] = env->regs[R_ESI];
// 	node->args[R_EDI] = env->regs[R_EDI];

// 	if (cached_syscall_num == max_cached_syscall_record)
// 		flush_event_records();

// 	if (syscall_current != NULL) {
// 		syscall_current->next = node;
// 	}

// 	if (syscall_head == NULL) {
// 		syscall_head = node;
// 		syscall_current = syscall_head;
// 	}

// 	syscall_current = node;
// 	cached_syscall_num++;

//     return;
// }
