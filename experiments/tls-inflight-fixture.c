/* Host harness for the actual TLS probe functions. Not a BPF verifier test. */
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
typedef uint8_t __u8;
typedef uint16_t __u16;
typedef uint32_t __u32;
typedef uint64_t __u64;
#undef __always_inline
#define __always_inline inline
#define SEC(section)
#define __uint(name, value) int name
#define __type(name, type) type name
#define BPF_UPROBE(name, ...) name(void *ctx, __VA_ARGS__)
#define BPF_URETPROBE(name, ...) name(void *ctx, __VA_ARGS__)
#define BPF_CORE_READ(task, leader, field) ((task)->leader->field)
#define BPF_MAP_TYPE_LRU_HASH 1
#define BPF_MAP_TYPE_HASH 2
#define BPF_MAP_TYPE_RINGBUF 3
#define BPF_MAP_TYPE_PERCPU_ARRAY 4
#define LIBBPF_PIN_BY_NAME 1
#define BPF_NOEXIST 1
#define BPF_ANY 0
#define BPF_EXIST 2
struct task_struct { struct task_struct *group_leader; __u64 start_boottime, self_exec_id; };
static struct task_struct task;
static __u64 thread_id = ((__u64)7 << 32) | 9, clock_ns;
static __u64 fixture_cookie = 1;
static bool enabled = true, in_scope = true;
static __u64 bpf_get_attach_cookie(void *ctx) { return *(__u64 *)ctx; }
static void *bpf_get_current_task_btf(void) { return &task; }
static __u64 bpf_get_current_pid_tgid(void) { return thread_id; }
static __u64 bpf_get_current_cgroup_id(void) { return 17; }
static __u64 bpf_ktime_get_ns(void) { return ++clock_ns; }
static __u32 bpf_get_smp_processor_id(void) { return 0; }
static void bpf_get_current_comm(void *dst, size_t size) { memset(dst,0,size); memcpy(dst,"fixture",7); }
static void *bpf_map_lookup_elem(void *, const void *);
static int bpf_map_update_elem(void *, const void *, const void *, __u64);
static int bpf_map_delete_elem(void *, const void *);
static void *bpf_ringbuf_reserve(void *, size_t, __u64);
static void bpf_ringbuf_submit(void *, __u64);
static int bpf_probe_read_user(void *, size_t, const void *);
#include "tls-probe-under-test.c"
#define ssl_new_exit(...) ssl_new_exit(&fixture_cookie, __VA_ARGS__)
#define ssl_free_entry(...) ssl_free_entry(&fixture_cookie, __VA_ARGS__)
#define ssl_clear_entry(...) ssl_clear_entry(&fixture_cookie, __VA_ARGS__)
#define ssl_write_entry(...) ssl_write_entry(&fixture_cookie, __VA_ARGS__)
#define ssl_write_exit(...) ssl_write_exit(&fixture_cookie, __VA_ARGS__)
#define ssl_write_ex_entry(...) ssl_write_ex_entry(&fixture_cookie, __VA_ARGS__)
#define ssl_write_ex_exit(...) ssl_write_ex_exit(&fixture_cookie, __VA_ARGS__)
#define ssl_read_entry(...) ssl_read_entry(&fixture_cookie, __VA_ARGS__)
#define ssl_read_exit(...) ssl_read_exit(&fixture_cookie, __VA_ARGS__)
#define ssl_read_ex_entry(...) ssl_read_ex_entry(&fixture_cookie, __VA_ARGS__)
#define ssl_read_ex_exit(...) ssl_read_ex_exit(&fixture_cookie, __VA_ARGS__)

static struct { bool used; struct tls_connection_key key; struct tls_connection_val value; } lives[8];
static struct { bool used; struct tls_inflight_key key; struct tls_inflight_val value; } calls[2];
static __u64 counters[6];
static struct tls_record records[32];
static size_t emitted;
static bool fail_read, fail_reserve, fail_map;
static void *bpf_map_lookup_elem(void *map, const void *key) {
    static __u8 tracked_value = 1;
    if (map == &cgroup_filter) return in_scope ? &tracked_value : NULL;
    if (map == &tls_enabled_libraries) return enabled && *(__u64 *)key == 1 ? &tracked_value : NULL;
    if (map == &tls_connections) {
        for (size_t i=0;i<8;i++) if (lives[i].used && !memcmp(&lives[i].key,key,sizeof(lives[i].key))) return &lives[i].value;
        return NULL;
    }
    if (map == &tls_inflight) {
        const struct tls_inflight_key *k=key;
        assert(k->direction<2);
        return calls[k->direction].used && !memcmp(&calls[k->direction].key,k,sizeof(*k)) ? &calls[k->direction].value : NULL;
    }
    void *maps[]={&tls_reserve_fail,&tls_inflight_collision,&tls_map_fail,&tls_missing_state,&tls_outparam_fail,&tls_close_lost};
    for (size_t i=0;i<6;i++) if (map==maps[i]) return &counters[i];
    assert(!"unknown map"); return NULL;
}
static int bpf_map_update_elem(void *map,const void *key,const void *value,__u64 flags) {
    if (fail_map) return -1;
    if (map==&tls_inflight) {
        const struct tls_inflight_key *k=key;
        if (flags==BPF_NOEXIST && calls[k->direction].used) return -1;
        calls[k->direction].used=true; calls[k->direction].key=*k;
        calls[k->direction].value=*(const struct tls_inflight_val *)value; return 0;
    }
    assert(map==&tls_connections);
    if (flags==BPF_EXIST && !bpf_map_lookup_elem(map,key)) return -1;
    for (size_t i=0;i<8;i++) if (lives[i].used && !memcmp(&lives[i].key,key,sizeof(lives[i].key))) {
        lives[i].value=*(const struct tls_connection_val *)value; return 0;
    }
    for (size_t i=0;i<8;i++) {
        if (!lives[i].used) {
            lives[i].used=true; lives[i].key=*(const struct tls_connection_key *)key;
            lives[i].value=*(const struct tls_connection_val *)value; return 0;
        }
    }
    return -1;
}
static int bpf_map_delete_elem(void *map,const void *key) {
    if (map==&tls_inflight) {
        const struct tls_inflight_key *k=key; calls[k->direction].used=false; return 0;
    }
    assert(map==&tls_connections);
    for (size_t i=0;i<8;i++) if (lives[i].used && !memcmp(&lives[i].key,key,sizeof(lives[i].key))) { lives[i].used=false; return 0; }
    return -1;
}
static void *bpf_ringbuf_reserve(void *map,size_t size,__u64 flags) {
    (void)flags; assert(map==&events_tls && size==sizeof(struct tls_record));
    if (fail_reserve) return NULL;
    assert(emitted<32); return &records[emitted];
}
static void bpf_ringbuf_submit(void *record,__u64 flags) { (void)flags; assert(record==&records[emitted]); emitted++; }
static int bpf_probe_read_user(void *dst,size_t size,const void *src) {
    if (fail_read) return -1;
    memcpy(dst,src,size); return 0;
}
static void reset(void) {
    memset(lives,0,sizeof(lives)); memset(calls,0,sizeof(calls)); memset(counters,0,sizeof(counters));
    memset(records,0,sizeof(records)); emitted=0; clock_ns=100;
    fail_read=fail_reserve=fail_map=false;
    enabled=in_scope=true; fixture_cookie=1;
    task.group_leader=&task; task.start_boottime=11; task.self_exec_id=1;
}
static struct tls_connection_val *life(void *ssl) {
    struct tls_connection_key k=connection_key((__u64)ssl,process_start());
    return bpf_map_lookup_elem(&tls_connections,&k);
}
int main(void) {
    void *ssl=(void *)0x1234, *other=(void *)0x5678;
    char bytes[]="abcdefg";
    size_t accepted=2;
    reset(); enabled=false;
    ssl_new_exit(ssl);
    assert(!life(ssl));
    ssl_write_entry(ssl,bytes,7); ssl_write_exit(2);
    ssl_read_entry(ssl,bytes,7); ssl_read_exit(2);
    ssl_write_ex_entry(ssl,bytes,7,&accepted); ssl_write_ex_exit(1);
    ssl_read_ex_entry(ssl,bytes,7,&accepted); ssl_read_ex_exit(1);
    assert(!calls[0].used && !calls[1].used && !emitted && !counters[3]);
    enabled=true; ssl_new_exit(ssl); enabled=false;
    ssl_free_entry(ssl); ssl_clear_entry(ssl);
    assert(life(ssl));
    enabled=true; fixture_cookie=2;
    ssl_write_entry(ssl,bytes,7); ssl_write_exit(2);
    ssl_free_entry(ssl); ssl_clear_entry(ssl);
    assert(life(ssl) && !calls[0].used && !emitted);
    fixture_cookie=1; ssl_write_entry(ssl,bytes,7); ssl_write_exit(2);
    assert(emitted==1 && life(ssl)->sequence[0]==1);
    ssl_write_entry(ssl,bytes,7); enabled=false; ssl_write_exit(2);
    assert(emitted==1 && calls[0].used); // Detaching cannot emit half-covered calls.
    tls_thread_exit(NULL);
    assert(!calls[0].used && life(ssl)->loss_epoch[0]>0);

    /* A known stream leaving scope loses trust without copying its payload. */
    reset(); ssl_new_exit(ssl); in_scope=false;
    ssl_write_entry(ssl,bytes,7); ssl_write_exit(2);
    assert(!calls[0].used && !emitted && life(ssl)->loss_epoch[0]>0);
    ssl_write_entry(ssl,bytes,7); in_scope=true; ssl_write_exit(2);
    assert(!emitted && !calls[0].used && counters[3]==1);
    ssl_write_entry(ssl,bytes,7); ssl_write_exit(2);
    assert(emitted==1 && records[0].pl.loss_epoch>0);
    reset(); ssl_new_exit(ssl); ssl_write_entry(ssl,bytes,7);
    in_scope=false; ssl_write_entry(ssl,bytes,7); ssl_write_exit(2);
    assert(calls[0].value.depth==1 && !emitted && life(ssl)->loss_epoch[0]>0);
    in_scope=true; ssl_write_exit(2);
    assert(!calls[0].used && emitted==1 && records[0].pl.loss_epoch>0);

    reset(); ssl_new_exit(ssl);
    enter(ssl,bytes,7,NULL,0,0); leave(-1,0,0);
    assert(!calls[0].used && emitted==0 && life(ssl)->sequence[0]==0);
    enter(ssl,bytes,7,NULL,0,0); leave(3,0,0);
    assert(!calls[0].used && emitted==1 && life(ssl)->accepted_bytes[0]==3);
    assert(records[0].pl.chunk_bytes==3 && !memcmp(records[0].plaintext,"abc",3));
    /* Offsets size later gaps: the next call starts where this one ended, and
     * a lost reservation advances the offset without a loss epoch. */
    assert(records[0].pl.stream_offset==0);
    enter(ssl,bytes,7,NULL,0,0); fail_reserve=true; leave(2,0,0); fail_reserve=false;
    assert(emitted==1 && life(ssl)->accepted_bytes[0]==5 && life(ssl)->loss_epoch[0]==0);
    enter(ssl,bytes,7,NULL,0,0); leave(4,0,0);
    assert(emitted==2 && records[1].pl.stream_offset==5 && records[1].pl.call_sequence==3);

    reset(); ssl_new_exit(ssl);
    enter(ssl,bytes,7,&accepted,0,1); leave(1,0,1);
    assert(emitted==1 && records[0].pl.total_bytes==2 && life(ssl)->accepted_bytes[0]==2);
    enter(ssl,bytes,7,&accepted,0,1); leave(3,0,0);
    assert(!calls[0].used && emitted==1 && life(ssl)->loss_epoch[0]>0 && counters[3]==1);

    reset(); ssl_new_exit(ssl);
    enter(ssl,bytes,7,NULL,0,0); enter(ssl,bytes,7,NULL,0,0);
    assert(calls[0].value.depth==2 && life(ssl)->loss_epoch[0]>0);
    leave(2,0,0); assert(emitted==0); leave(2,0,0);
    assert(!calls[0].used && emitted==1 && records[0].pl.loss_epoch>0);

    reset(); ssl_new_exit(ssl); ssl_new_exit(other);
    enter(ssl,bytes,7,NULL,0,0); enter(other,bytes,7,NULL,0,0);
    assert(life(ssl)->loss_epoch[0]>0 && life(other)->loss_epoch[0]>0);
    leave(2,0,0); leave(2,0,0); assert(!calls[0].used);

    reset(); ssl_new_exit(ssl); enter(ssl,bytes,7,NULL,0,0);
    task.self_exec_id=2; ssl_new_exit(ssl); enter(ssl,bytes,7,NULL,0,0);
    assert(calls[0].value.depth==1 && calls[0].value.exec_generation==2 && counters[3]==1);
    leave(2,0,0); assert(!calls[0].used && records[0].pl.exec_generation==2);

    reset(); ssl_new_exit(ssl); enter(ssl,bytes,7,NULL,0,0);
    task.start_boottime=12; ssl_new_exit(ssl); enter(ssl,bytes,7,NULL,0,0);
    assert(calls[0].value.depth==1 && calls[0].value.process_start==12);
    leave(2,0,0); assert(!calls[0].used && records[0].pl.process_start==12);

    reset(); ssl_new_exit(ssl); enter(ssl,bytes,7,NULL,0,0); enter(ssl,bytes,7,NULL,1,0);
    tls_thread_exit(NULL);
    assert(!calls[0].used && !calls[1].used && counters[3]==2 && emitted==0);

    reset(); ssl_new_exit(ssl); enter(ssl,bytes,7,&accepted,0,1); fail_read=true; leave(1,0,1);
    assert(!calls[0].used && emitted==0 && counters[4]==1 && life(ssl)->loss_epoch[0]>0);
    reset(); ssl_new_exit(ssl); enter(ssl,bytes,7,NULL,0,0); fail_reserve=true; leave(2,0,0);
    assert(!calls[0].used && emitted==0 && counters[0]==1 && life(ssl)->sequence[0]==1 && life(ssl)->accepted_bytes[0]==2 && life(ssl)->loss_epoch[0]==0);
    reset(); ssl_new_exit(ssl); fail_map=true; enter(ssl,bytes,7,NULL,0,0); leave(2,0,0);
    assert(emitted==0 && counters[2]==1 && counters[3]==1 && life(ssl)->loss_epoch[0]>0);

    /* Closure: both END records emitted, entry deleted, nothing lost. */
    reset(); ssl_new_exit(ssl); enter(ssl,bytes,7,NULL,0,0); leave(2,0,0); ssl_free_entry(ssl);
    assert(emitted==3 && !life(ssl) && !counters[5]);
    assert(records[1].pl.flags & TLS_FLAG_END && records[1].pl.call_sequence==1 && records[2].pl.direction==1);
    assert(records[1].pl.stream_offset==2 && records[2].pl.stream_offset==0);
    /* A closure that cannot be recorded destroys the only other inventory copy. */
    reset(); ssl_new_exit(ssl); fail_reserve=true; ssl_free_entry(ssl);
    assert(!life(ssl) && counters[5]==1);
    /* So does replacing a lifetime whose closure was never observed. */
    reset(); ssl_new_exit(ssl); ssl_new_exit(ssl);
    assert(counters[5]==1 && life(ssl));
    /* The handshake's SSL_clear closes the empty lifetime and opens a new
     * generation; the data that follows is tracked under it. */
    reset(); ssl_new_exit(ssl);
    __u64 first_generation = life(ssl)->generation;
    ssl_clear_entry(ssl);
    assert(emitted==2 && records[0].pl.flags & TLS_FLAG_END && records[0].pl.call_sequence==0);
    assert(life(ssl) && life(ssl)->generation > first_generation && !counters[5]);
    enter(ssl,bytes,7,NULL,0,0); leave(4,0,0);
    assert(emitted==3 && records[2].pl.connection_generation==life(ssl)->generation);
    assert(records[2].pl.call_sequence==1 && records[2].pl.stream_offset==0);
    assert(!(records[2].pl.flags & TLS_FLAG_LIFETIME_UNKNOWN));
    /* A clear after data closes that stream at its final offset. */
    ssl_clear_entry(ssl);
    assert(emitted==5 && records[3].pl.call_sequence==1 && records[3].pl.stream_offset==4);
    assert(life(ssl)->sequence[0]==0 && life(ssl)->accepted_bytes[0]==0);
    /* Clearing an object never seen by SSL_new creates nothing. */
    reset(); ssl_clear_entry(ssl);
    assert(!life(ssl) && !emitted);
    puts("TLS inflight fixture: readiness, scope migration, acceptance, retry, nesting, mismatch, exec/PID reuse, exit, closure and loss checks passed");
    return 0;
}
