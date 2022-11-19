#include "panda/plugin.h"
#include "panda/plugins/syscalls2/syscalls_ext_typedefs.h"

#include "panda/rr/rr_log.h"
#include "panda/rr/kernel_rr.h"
#include "panda/callbacks/cb-support.h"

#include <stdlib.h>
#include <string.h>

// Save syscall && exceptions
const char *kernel_rr_log = "kernel_rr.log";
const char *kernel_ld_blk_log = "kernel_ld_blk.log";
const char *kernel_ld_entry_log = "kernel_ld_entry.log";
const char *kernel_cfu_log = "kernel_cfu.log";

event_node *syscall_head;
event_node *syscall_current;

event_node *syscall_replay_head = NULL;
event_node *syscall_replay_current = NULL;

load_block *lb_replay_head;

load_block *lb_head;
load_block *lb_current;

cfu *cfu_head = NULL;
cfu *cfu_current = NULL;

int cached_syscall_num = 0;
int max_cached_syscall_record = 1000;

static bool in_cfu = false;
static bool interrupt_in_cfu = false;


static cfu* new_cfu(void) {
	cfu *node = (struct cfu*)malloc(sizeof(struct cfu));
	node->next = NULL;
	return node;
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
		printf("loaded cfu src=$0x%" TCG_PRIlx " dest=$0x%" TCG_PRIlx "\n", cfu_current->src_addr, cfu_current->dest_addr);
		for (int i = 0; i < node->len; i++) {
			printf("data %d=%u", i, node->data[i]);
		}
		printf("\n");
	}
}

static void persist_ld_blk(load_block *node, FILE *fptr) {
	fwrite(node, sizeof(struct load_block), 1, fptr);
}

static void persist_ld_entry(load_entry *entry, FILE *fptr) {
	fwrite(entry, sizeof(struct load_entry), 1, fptr);
}

static void persist_ld_entries(FILE *fptr, load_block *lb) {	
	load_entry *cur = lb->head;
	int i = 0;
	while (cur != NULL)
	{
		persist_ld_entry(cur, fptr);
		qemu_log("Persist entry %d, target %d value %ld\n", i, cur->target_reg, cur->target_val);
		cur = cur->next;
		i++;
	}
	// printf("number of entries %d of blk\n", lb->entry_num);
}

static void persist_ld_blks(void) {
	FILE *fptr = fopen(kernel_ld_blk_log, "a");
	FILE *entry_fptr = fopen(kernel_ld_entry_log, "a");

	load_block *cur= lb_head;
	int i = 0;

	if (cur == NULL) {
		qemu_log("No ld block is recorded\n");
	}

	while (cur != NULL) {
		qemu_log("Persist ld blk %d, entry num %d, inst num: %ld\n", i, cur->entry_num, cur->inst_num_before);
		persist_ld_blk(cur, fptr);
		persist_ld_entries(entry_fptr, cur);
		cur = cur->next;
		i++;
	}

	fclose(fptr);
	fclose(entry_fptr);
	return;
}


static void replay_ld_entries(CPUX86State *env, load_block *lb) {
	load_entry *cur = lb->head;
	while(cur != NULL) {
		printf("Write to reg %d\n", cur->target_reg);
		env->regs[cur->target_reg] = cur->target_val;
		cur = cur->next;
	}
}

static load_entry* new_ld_entry(int target_reg) {
	load_entry* entry = (struct load_entry*)malloc(sizeof(struct load_entry));
	entry->next = NULL;
	entry->target_reg = target_reg;

	return entry;
}

static void record_feed_ld_entries(CPUX86State *env, load_block *lb) {
	load_entry *cur = lb->head;

	while(cur != NULL) {
		cur->target_val = env->regs[cur->target_reg];
		cur = cur->next;
	}

	return;
}

static void record_create_ld_entry(load_block *lb, int target_reg) {


	if (lb->head == NULL) {
		lb->head = new_ld_entry(target_reg);
		return;
	}

	load_entry *cur = lb->head;

	while(cur->next != NULL) {
		cur = cur->next;
	}

	cur->next = new_ld_entry(target_reg);
	
	return;
}

static load_block* new_ld_block(void) {
	load_block* blk = (struct load_block*)malloc(sizeof(struct load_block));

	blk->feed = false;
	blk->inst_num_before = rr_get_guest_instr_count();
	blk->next = NULL;
	blk->head = NULL;
	blk->entry_num = 0;

	// qemu_log("new block: inst before=%ld\n", blk->inst_num_before);
	return blk;
}

void kernel_replay_lb(CPUX86State *env) {
	// return;
	uint64_t inst_num = rr_get_guest_instr_count();

	if (lb_replay_head != NULL) {
		// while (lb_replay_head->inst_num_before < inst_num) {
		// 	lb_replay_head = lb_replay_head->next;
		// }
		if (lb_replay_head->inst_num_before == inst_num) {
			printf("replaying lb inst before %ld\n", inst_num);
			replay_ld_entries(env, lb_replay_head);
			lb_replay_head = lb_replay_head->next;
		}
	} else {
		printf("reached end of ld blocks\n");
		// printf("inst number not match, expected %ld, actual %ld\n", lb_replay_head->inst_num_before, inst_num);
	}
}


void kernel_record_ld_start(CPUX86State *env, int target_reg) {
	if (lb_head == NULL) {
		lb_head = new_ld_block();
		lb_current = lb_head;
	}

	if (lb_current != NULL && lb_current->feed) {
		lb_current->next = new_ld_block();
		lb_current = lb_current->next;
	}

	record_create_ld_entry(lb_current, target_reg);
	lb_current->entry_num++;
}

void kernel_record_ld_start_mark_inst_cnt(uint64_t inst_cnt) {
	if (lb_current != NULL && !lb_current->feed) {
		lb_current->inst_num_before += inst_cnt;
	}
}


void kernel_record_ld_end(CPUState *cpu) {
	if (lb_current == NULL) {
		return;
	}

	if (lb_current->feed){
		return;
	} 

	X86CPU *x86_cpu = X86_CPU(cpu);
    CPUX86State *env = &x86_cpu->env;

	record_feed_ld_entries(env, lb_current);

	lb_current->feed = true;
	// lb_current->inst_num_before = rr_get_guest_instr_count();
}

void flush_ld_blk_records(void) {
	persist_ld_blks();
}

void load_kernel_load_log(void) {
	FILE *fptr = fopen(kernel_ld_blk_log, "r");
	FILE *entry_fptr = fopen(kernel_ld_entry_log, "r");

	struct load_block blk;

	load_block *lb_replay_current = NULL;
	int n = 0;

	while(fread(&blk, sizeof(struct load_block), 1, fptr)) {
		load_block *new_blk = new_ld_block();
		new_blk->inst_num_before = blk.inst_num_before;
		new_blk->feed = blk.feed;
		new_blk->entry_num = blk.entry_num;
		new_blk->head = NULL;

		// qemu_log("Persist ld blk %d, entry num %d, inst num: %ld\n", n, new_blk->entry_num, new_blk->inst_num_before);

		struct load_entry ld_replay_entry;
		load_entry *dummy = new_ld_entry(0);
		load_entry *cur = dummy;

		for (int i = 0; i < new_blk->entry_num; i++) {
			if(fread(&ld_replay_entry, sizeof(struct load_entry), 1, entry_fptr)) {
				cur->next = new_ld_entry(ld_replay_entry.target_reg);
				cur->next->target_val = ld_replay_entry.target_val;
				// qemu_log("Persist entry %d, target %d value %ld\n", i, cur->next->target_reg, cur->next->target_val);
				cur = cur->next;
			}else {
				printf("failed to read entry\n");
			}
		}

		new_blk->head = dummy->next;

		if (lb_replay_head == NULL) {
			lb_replay_head = new_blk;
			lb_replay_current = new_blk;
		} else {
			lb_replay_current->next = new_blk;
			lb_replay_current = lb_replay_current->next;
		}
		n++;
	}
	// exit(0);
}


event_node* fetch_next_syscall(void) {
	event_node *cur = syscall_replay_head;
	syscall_replay_head = syscall_replay_head->next;
	return cur;
}

event_node* get_next_syscall(void) {
	return syscall_replay_head;
}

uint64_t rr_inst_num_before_next_syscall(void) {
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
		}
		// node->id_no = loaded_node.id_no;
		// node->type = KERNEL_INPUT_TYPE_SYSCALL;
		node->inst_num_before = loaded_node.inst_num_before;
		printf("loaded type %d number inst: %ld \n", node->type, node->inst_num_before);
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
	if (cached_syscall_num == max_cached_syscall_record)
		flush_event_records();

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
		exit(0);
	}

	replay_regs_of_node(env, node);
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
