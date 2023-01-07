/* -*- c-basic-offset: 4; tab-width: 8; indent-tabs-mode:nil; -*- */
/*
 * Load nanosleep.bpf.o to the kernel and attach it to the entry point
 * of __x86_sys_nanosleep.
 */
#include <stdio.h>
#include <time.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>

#include <bpf/libbpf.h>

#define BPF_OBJ_NAME "sample_map.bpf.o"
#define BPF_PROG_NAME "sample_map_bpf"
#define FUNC_NAME "nanosleep_fentry"
#define BSS_MAP_NAME "sample_m.bss"

/* content of the .bss section of the nanosleep.bpf.o */
struct bss_t {
    int pid;
};

/* All required variables to load an ebpf program */
struct ebpf_prog_required {
    struct bpf_object_skeleton skeleton;
    struct bpf_object *obj;
    struct bpf_map *maps[2];
    void *bss_mapped;
    struct bpf_program *prog;
    struct bpf_link *link;
};

/*
 * Load an ebpf program to the kernel.
 */
int load(const char *obj_name,
         const char *prog_name,
         const char *func_name,
         const char * const*map_names,
         int map_cnt,
         /* Required variables */
         struct bpf_object_skeleton *skeleton,
         struct bpf_object **obj,
         struct bpf_map **maps,
         void **bss_mapped,
         struct bpf_program **prog,
         struct bpf_link **link) {
    int fd = -1;
    char *objfile = NULL;
    struct bpf_object_skeleton *s = skeleton;

    fd = open(obj_name, O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "fail to open the object file: %s\n", obj_name);
        return fd;
    }
    struct stat statbuf;
    int err = fstat(fd, &statbuf);
    if (err < 0) {
        printf("fail to call fstat()\n");
        goto err_out;
    }

    objfile = (char *)malloc(statbuf.st_size);
    int cp = read(fd, objfile, statbuf.st_size);
    if (cp != statbuf.st_size) {
        fprintf(stderr, "expect %ld bytes, but get %d bytes.\n", statbuf.st_size, cp);
        goto err_out;
    }

    s->sz = sizeof(*s);
    s->name = prog_name;
    s->obj = obj;

    /* maps */
    s->map_cnt = map_cnt;
    s->map_skel_sz = sizeof(*s->maps);
    s->maps = (struct bpf_map_skeleton *)calloc(s->map_cnt, s->map_skel_sz);
    if (!s->maps) {
        fprintf(stderr, "fail to allocate memory\n");
        goto err_out;
    }

    int map_idx = 0;
    for (; map_idx < map_cnt; map_idx++) {
        s->maps[map_idx].name = map_names[map_idx];
        s->maps[map_idx].map = maps + map_idx;
    }
    s->maps[map_cnt - 1].mmaped = bss_mapped;

    /* progs */
    s->prog_cnt = 1;
    s->prog_skel_sz = sizeof(*s->progs);
    s->progs = (struct bpf_prog_skeleton *)calloc(s->prog_cnt, s->prog_skel_sz);
    if (!s->progs) {
        fprintf(stderr, "fail to allocate memory\n");
        goto err_out;
    }

    s->progs[0].name = func_name;
    s->progs[0].prog = prog;
    s->progs[0].link = link;

    s->data_sz = statbuf.st_size;
    s->data = objfile;

    err = bpf_object__open_skeleton(s, NULL);
    if (err) {
        fprintf(stderr, "fail to open skeleton\n");
        goto err_out;
    }

    err = bpf_object__load_skeleton(s);
    if (err) {
        fprintf(stderr, "fail to load skeleton\n");
        goto err_out;
    }

    return 0;

err_out:
    if (fd >= 0)
        close(fd);
    if (objfile)
        free(objfile);
    bpf_object__destroy_skeleton(skeleton);
    return -1;
}

int main() {
    /* All variables required to load an eBPF program. */
    struct ebpf_prog_required *required =
        (struct ebpf_prog_required *)
        calloc(1, sizeof(struct ebpf_prog_required));

    printf("Load " BPF_OBJ_NAME " to the kernel\n");
    const char * const map_names[] = {
        "array",
        BSS_MAP_NAME,
    };
    int err = load(BPF_OBJ_NAME,
                   BPF_PROG_NAME,
                   FUNC_NAME,
                   map_names,
                   2,
                   /* Required variables */
                   &required->skeleton,
                   &required->obj,
                   required->maps,
                   &required->bss_mapped,
                   &required->prog,
                   &required->link);
    if (err) {
        fprintf(stderr, "fail to load the program\n");
        return 255;
    }

    /* Attach the program. */
    printf("Attach the program to the entry point of __x86_sys_nanosleep\n");
    err = bpf_object__attach_skeleton(&required->skeleton);
    if (err) {
        fprintf(stderr, "fail to attach the program\n");
        return 255;
    }

    int array_fd = bpf_map__fd(required->maps[0]);
    if (array_fd < 0) {
        fprintf(stderr, "fail to load map\n");
        return 255;
    }
    /* The .bss section of the ebpf program */
    struct bss_t* bss = (struct bss_t *)required->bss_mapped;

    bss->pid = getpid();
    __u32 key = 0;
    __u64 cnt = 0;
    err = bpf_map_update_elem(array_fd, &key, &cnt, BPF_ANY);
    if (err) {
        fprintf(stderr, "fail to update the map");
        return 255;
    }

    printf("Call nanosleep 3 times\n");
    int i;
    for (i = 0; i < 3; i++) {
        struct timespec ts1 = {
            1,
            0
        };

        (void)syscall(__NR_nanosleep, &ts1, NULL);
    }

    err = bpf_map_lookup_elem(array_fd, &key, &cnt);
    if (err) {
        fprintf(stderr, "fail to lookup the map");
        return 255;
    }
    printf("Results: pid=%d count=%lld\n", bss->pid, cnt);

    bpf_object__destroy_skeleton(&required->skeleton);
    return 0;
}
