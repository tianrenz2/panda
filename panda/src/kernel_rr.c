#include "panda/plugin.h"

#include "panda/plugins/syscalls2/syscalls_ext_typedefs.h"

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

static void persist_syscalls(void) {
	FILE *fptr = fopen(kernel_rr_log, "a");
	event_node *cur= syscall_head;
    char buffer[10];

	while (cur != NULL) {
        sprintf(buffer, "%d-%d\n", cur->type, cur->id_no);
        fputs(buffer, fptr);
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

	if (type == KERNEL_INPUT_TYPE_SYSCALL) {
		if (id_no == 39) {
			syscall_ctx_t *ctx1 = (syscall_ctx_t *)ctx;
			printf("getpid called: Arg: %ud %ud\n", *ctx1->args[0], *ctx1->args[1]);
		}
	}

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
