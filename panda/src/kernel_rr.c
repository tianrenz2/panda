#include "panda/plugin.h"

#include "panda/plugins/syscalls2/syscalls_ext_typedefs.h"

#include "panda/rr/kernel_rr.h"

#include <stdlib.h>
#include <string.h>


const char *kernel_rr_log = "kernel_rr.log";

event_node *syscall_head;
event_node *syscall_current;

int cached_syscall_num = 0;
int max_cached_syscall_record = 1000;


static void free_all_nodes(void) {
	struct event_node *node = syscall_head;

	while (node != NULL) {
		struct event_node *tmp = node;
		node = node->next;
		free(tmp);
	}
}

void load_kernel_log(void) {
	FILE *fptr = fopen(kernel_rr_log, "r");

	struct event_node loaded_node;

	while(fread(&loaded_node, sizeof(struct event_node), 1, fptr)) {
		printf("%d %ld\n", loaded_node.id_no, loaded_node.args[0]);
	}
	
}

static void persist_bin(event_node *node, FILE *fptr) {
	fwrite (node, sizeof(struct event_node), 1, fptr);
}

static void persist_syscalls(void) {
	FILE *fptr = fopen(kernel_rr_log, "a");
	event_node *cur= syscall_head;

	while (cur != NULL) {
		persist_bin(cur, fptr);
		cur = cur->next;
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

void kernel_rr_record_event(CPUState *cpu, target_ptr_t pc, int id_no, int type, void* ctx) {

	event_node* node = (struct event_node*)malloc(sizeof(struct event_node));
	node->id_no = id_no;
	node->next = NULL;
    node->type = type;
	syscall_ctx_t *ctxp = (syscall_ctx_t *)ctx;

	if (type != KERNEL_INPUT_TYPE_SYSCALL) {
		return;
	}

	memcpy(&(node->args[0]), &(ctxp->args[0]), sizeof(uint32_t));
	memcpy(&(node->args[1]), &(ctxp->args[1]), sizeof(uint32_t));
	memcpy(&(node->args[2]), &(ctxp->args[2]), sizeof(uint32_t));
	memcpy(&(node->args[3]), &(ctxp->args[3]), sizeof(uint32_t));
	memcpy(&(node->args[4]), &(ctxp->args[4]), sizeof(uint32_t));
	memcpy(&(node->args[5]), &(ctxp->args[5]), sizeof(uint32_t));

	if (cached_syscall_num == max_cached_syscall_record)
		flush_event_records();

	if (syscall_current != NULL) {
		syscall_current->next = node;
	}

	if (syscall_head == NULL) {
		syscall_head = node;
		syscall_current = syscall_head;
	}

	syscall_current = node;
	cached_syscall_num++;

    return;
}
