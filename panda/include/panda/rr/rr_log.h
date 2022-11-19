#ifndef __RR_LOG_H_
#define __RR_LOG_H_

/* Target-specific code for record and replay.
   This is mostly code that relies on things like hwaddr and
   ram_addr_t. Note that record/replay currently only works in whole-system
   mode.
*/

#ifndef __cplusplus
#include "qemu/osdep.h"
#include "cpu.h"
#else
#include "panda/cheaders.h"
#endif
#include "panda/rr/rr_log_all.h"
#include "panda/types.h"

// accessors
uint64_t rr_get_pc(void);
uint64_t rr_get_secondary(void);

// mz structure for arguments to cpu_physical_memory_rw()
typedef struct {
    hwaddr addr;
    uint8_t* buf;
    uint32_t len;
} RR_cpu_mem_rw_args;

// mz structure for arguments to cpu_register_physical_memory()
typedef struct {
    hwaddr start_addr;
    uint64_t size;
    char *name;
    uint32_t len;
    RR_mem_type mtype;
    bool added;
} RR_mem_region_change_args;

// structure for arguments to cpu_physical_memory_unmap
typedef struct {
    hwaddr addr;
    uint8_t* buf;
    hwaddr len;
} RR_cpu_mem_unmap;

// structure for arguments to gdb_write_register
typedef struct {
    int cpu_index;
    uint8_t* buf;
    int reg;
    int len;
} RR_cpu_reg_write_args;

typedef struct RR_MapList {
    void *ptr;
    hwaddr addr;
    hwaddr len;
    uint32_t crc;
    QLIST_ENTRY(RR_MapList) link;
} RR_MapList;

void rr_cpu_physical_memory_unmap_record(hwaddr addr, uint8_t* buf,
                                         hwaddr len, int is_write);
void rr_cpu_reg_write_call_record(int cpu_index, const uint8_t* buf,
                                  int reg, int len);
void rr_device_mem_rw_call_record(hwaddr addr, const uint8_t* buf,
                                  int len, int is_write);
void rr_device_mem_unmap_call_record(hwaddr addr, const uint8_t* buf,
                                  int len, int is_write);
void rr_mem_region_change_record(hwaddr start_addr, uint64_t size,
                                 const char *name, RR_mem_type mtype, bool added);
void rr_mem_region_transaction_record(bool begin);

void rr_eliminate_outdate_items(uint64_t current_inst);

// mz using uint8_t for kind and callsite_loc to control space - enums default
// to int.
// mz NOTE: make sure RR_callsite_id has at most 255 members
// mz NOTE: make sure RR_log_entry_kind has at most 255 members
typedef struct {
    RR_prog_point prog_point;
    uint64_t file_pos;
    RR_log_entry_kind kind;
    RR_callsite_id callsite_loc; // mz This is used for another sanity check
    int cpl;
} RR_header;

// mz generic args
typedef struct {
    RR_skipped_call_kind kind;
    union {
        RR_mem_region_change_args mem_region_change_args;
        RR_cpu_mem_rw_args cpu_mem_rw_args;
        RR_cpu_mem_unmap cpu_mem_unmap;
        RR_hd_transfer_args hd_transfer_args;
        RR_net_transfer_args net_transfer_args;
        RR_handle_packet_args handle_packet_args;
        RR_serial_receive_args serial_receive_args;
        RR_serial_read_args serial_read_args;
        RR_serial_send_args serial_send_args;
        RR_serial_write_args serial_write_args;
        RR_cpu_reg_write_args cpu_reg_write_args;
    } variant;
    // mz XXX HACK
    uint64_t buf_addr_rec;
} RR_skipped_call_args;

// an item in a program-point indexed record/replay log
typedef struct rr_log_entry_t {
    RR_header header;
    // mz all possible options, depending on log_entry.kind
    union {
        // if log_entry.kind == RR_INPUT_1
        uint8_t input_1;
        // if log_entry.kind == RR_INPUT_2
        uint16_t input_2;
        // if log_entry.kind == RR_INPUT_4
        uint32_t input_4;
        // if log_entry.kind == RR_INPUT_8
        uint64_t input_8;
        // if log_entry.kind == RR_INTERRUPT_REQUEST
        int32_t interrupt_request; // mz 2-bytes is enough for the interrupt
                                    // request value!
        // if log_entry.kind == RR_EXIT_REQUEST
        uint16_t exit_request;
        // pending interrupts for PPC
        uint32_t pending_interrupts;

        // Exception number in cpu
        int32_t exception_index;

        // if log_entry.kind == RR_SKIPPED_CALL
        RR_skipped_call_args call_args;
        // if log_entry.kind == RR_LAST
        // no variant fields
    } variant;
} RR_log_entry;

// a program-point indexed record/replay log
typedef enum { RECORD, REPLAY } RR_log_type;
typedef struct RR_log_t {
    // mz TODO this field seems redundant given existence of rr_control.mode
    RR_log_type type;              // record or replay
    RR_prog_point last_prog_point; // to report progress

    char* name; // file name
    FILE* fp;   // file pointer for log
    unsigned long long
        size; // for a log being opened for read, this will be the size in bytes
    uint64_t bytes_read;
} RR_log;

RR_log_entry* rr_get_queue_head(void);

static inline uint64_t rr_get_guest_instr_count(void) {
    assert(first_cpu);
    return first_cpu->rr_guest_instr_count;
}

static inline void rr_dec_guest_instr_count(void) {
    assert(first_cpu);
    first_cpu->rr_guest_instr_count--;
}

static inline void rr_set_guest_instr_count(uint64_t inst_num) {
    assert(first_cpu);
    first_cpu->rr_guest_instr_count = inst_num;
}


//mz program execution state
static inline RR_prog_point rr_prog_point(void) {
    RR_prog_point ret = {0};
    ret.guest_instr_count = first_cpu->rr_guest_instr_count;
    return ret;
}

static inline void qemu_log_rr(target_ulong pc) {
    if (qemu_loglevel_mask(CPU_LOG_RR)) {
        RR_prog_point pp = rr_prog_point();
        qemu_log_mask(CPU_LOG_RR,
                "Prog point: 0x" TARGET_FMT_lx " {guest_instr_count=%llu}\n",
                pc, (unsigned long long)pp.guest_instr_count);
    }
}

extern RR_log *rr_nondet_log;
// Defined in rr_log.c.
extern unsigned rr_next_progress;
static inline void rr_maybe_progress(void) {
    if (!rr_in_replay()) return;

    if (unlikely(rr_get_percentage() >= rr_next_progress)) {
        if (rr_next_progress == 1) {
            printf("%s:  %10" PRIu64 " instrs total.\n", rr_nondet_log->name,
                    rr_nondet_log->last_prog_point.guest_instr_count);
        }
        replay_progress();
        rr_next_progress++;
    }
}

extern void rr_fill_queue(void);
extern RR_log_entry *rr_queue_tail;
static inline uint64_t rr_num_instr_before_next_interrupt(void) {
    if (!rr_queue_tail) rr_fill_queue();
    if (!rr_queue_tail) return -1;

    RR_header last_header = rr_queue_tail->header;
    switch (last_header.kind) {
        case RR_SKIPPED_CALL:
            if (last_header.callsite_loc != RR_CALLSITE_MAIN_LOOP_WAIT) {
                return -1;
            } // otherwise fall through
        case RR_LAST:
        case RR_END_OF_LOG:
        case RR_INTERRUPT_REQUEST:
            return last_header.prog_point.guest_instr_count -
                rr_get_guest_instr_count();
        default:
            return -1;
    }
}

static inline uint64_t rr_num_instr_before_next_log_entry(void) {
    RR_log_entry *head = rr_get_queue_head();
    if (!head) rr_fill_queue();

    return head->header.prog_point.guest_instr_count - rr_get_guest_instr_count();
}

static inline void print_head_tail(void) {
    printf("head: %ld ", rr_get_queue_head()->header.prog_point.guest_instr_count);
    printf("tail: %ld\n", rr_queue_tail->header.prog_point.guest_instr_count);
}

static inline const char* rr_get_next_interrupt_kind(void) {
    if (!rr_queue_tail) rr_fill_queue();
    if (!rr_queue_tail) return NULL;

    RR_header last_header = rr_queue_tail->header;
    return get_log_entry_kind_string(last_header.kind);
}

static inline const char* rr_get_next_interrupt_callsite(void) {
    if (!rr_queue_tail) rr_fill_queue();
    if (!rr_queue_tail) return NULL;

    RR_header last_header = rr_queue_tail->header;
    return get_callsite_string(last_header.callsite_loc);
}


uint32_t rr_checksum_memory(void);
uint32_t rr_checksum_regs(void);

bool rr_queue_empty(void);


typedef struct event_node {
    int type;
    struct event_node *next;
    target_ulong args[CPU_NB_REGS];
    uint64_t inst_num_before;
    int32_t exception_index;
    int error_code;
    target_ulong cr2;
} event_node;

typedef struct cfu {
    struct cfu *next;
    uint8_t data[128];
    uint64_t inst_num_before;
    hwaddr src_addr;
    hwaddr dest_addr;
    int len;
} cfu;

typedef struct load_block {
    uint64_t inst_num_before;
    struct load_entry *head;
    struct load_block *next;
    bool feed;
    int entry_num;
} load_block;

typedef struct load_entry {
    int target_reg;
    target_ulong target_val;
    struct load_entry *next;
} load_entry;

/* syscall record */
event_node* fetch_next_syscall(void);

/*  */
void kernel_record_cfu(CPUState *cs, hwaddr src_addr, hwaddr dest_addr, int len);
void kernel_replay_cfu(CPUState *cs, hwaddr dest_addr);
void load_cfus(void);
void persist_cfus(void);

/* ld record */
void kernel_record_ld_start(CPUX86State *env, int target_reg);
void kernel_record_ld_end(CPUState *env);
void kernel_replay_lb(CPUX86State *env);
void kernel_record_ld_start_mark_inst_cnt(uint64_t inst_cnt);
void flush_ld_blk_records(void);
void load_kernel_load_log(void);

uint64_t rr_inst_num_before_next_syscall(void);
event_node* get_next_syscall(void);

void kernel_rr_callbacks_mem_before_read(CPUState *env, target_ptr_t pc, target_ptr_t addr, size_t data_size, void *ram_ptr);

void print_regs(CPUX86State *env);
void print_node_regs(event_node *node);

bool rr_in_cfu(void);
void rr_cfu_start(void);
void rr_cfu_end(void);
void rr_int_during_cfu_start(void);
void rr_int_during_cfu_end(void);
bool rr_in_int_during_cfu(void);

void rr_eliminate_non_interrupt_items(void);
void rr_eliminate_userspace_items(void);
void rr_pop_front_item(void);
void rr_clear_low_prviledge_entry(void);

void kernel_rr_record_event_syscall(CPUX86State *env);
void kernel_rr_record_event_kernel_load(CPUX86State *env, int target_reg);
void kernel_rr_record_event_exception(CPUState *cs, CPUX86State *env);
void kernel_rr_replay_event_syscall(CPUX86State *env, event_node *node);
void kernel_rr_replay_event_exception(CPUState *cs, CPUX86State *env, event_node *node);
#endif
