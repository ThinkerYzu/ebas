/* -*- c-basic-offset: 4; tab-width: 8; indent-tabs-mode:nil; -*- */
#include <stdio.h>
#include <time.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>

#include <bpf/libbpf.h>

#define BPF_OBJ_NAME "nanosleep.bpf.o"
#define BPF_NAME "nanosleep_bpf"
#define PROG_NAME "nanosleep_fentry"
#define BSS_MAP_NAME "nanoslee.bss"

struct bss_t {
    int pid;
    int cnt;
};

int load(struct bpf_object_skeleton *skeleton,
         struct bpf_object **obj,
         struct bpf_map **bss,
         void **bss_mapped,
         struct bpf_program **prog,
         struct bpf_link **link) {
    int fd = open(BPF_OBJ_NAME, O_RDONLY);
    if (fd < 0)
        return fd;
    struct stat statbuf;

    int err = fstat(fd, &statbuf);
    if (err < 0)
        return err;
    char *objfile = (char *)malloc(statbuf.st_size);
    int cp = read(fd, objfile, statbuf.st_size);
    if (cp != statbuf.st_size) {
        printf("expect %ld bytes, but get %d bytes.\n", statbuf.st_size, cp);
        goto err_out;
    }

    struct bpf_object_skeleton *s = skeleton;
    s->sz = sizeof(*s);
    s->name = BPF_NAME;
    s->obj = obj;

    /* maps */
    s->map_cnt = 1;
    s->map_skel_sz = sizeof(*s->maps);
    s->maps = (struct bpf_map_skeleton *)calloc(s->map_cnt, s->map_skel_sz);
    if (!s->maps)
        goto err_out;

    s->maps[0].name = BSS_MAP_NAME;
    s->maps[0].map = bss;
    s->maps[0].mmaped = bss_mapped;

    s->prog_cnt = 1;
    s->prog_skel_sz = sizeof(*s->progs);
    s->progs = (struct bpf_prog_skeleton *)calloc(s->prog_cnt, s->prog_skel_sz);

    s->progs[0].name = PROG_NAME;
    s->progs[0].prog = prog;
    s->progs[0].link = link;

    s->data_sz = statbuf.st_size;
    s->data = objfile;

    err = bpf_object__open_skeleton(s, NULL);
    if (err) {
        printf("fail to open skeleton\n");
        goto err_out;
    }

    err = bpf_object__load_skeleton(s);
    if (err) {
        printf("fail to load skeleton\n");
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
    struct bpf_object_skeleton *skeleton =
        (struct bpf_object_skeleton *)
        calloc(1, sizeof(struct bpf_object_skeleton));
    struct bpf_object *obj = NULL;
    struct bpf_map *bss_m = NULL;
    void *bss_mapped = NULL;
    struct bpf_program *prog = NULL;
    struct bpf_link *link = NULL;

    int err = load(skeleton, &obj, &bss_m, &bss_mapped, &prog, &link);
    if (err) {
        printf("fail to load the program\n");
        return 255;
    }

    err = bpf_object__attach_skeleton(skeleton);
    if (err) {
        printf("fail to attach the program\n");
        return 255;
    }

    struct bss_t* bss = (struct bss_t *)bss_mapped;
    bss->pid = getpid();
    int i;
    for (i = 0; i < 3; i++) {
        struct timespec ts1 = {
            1,
            0
        };

        (void)syscall(__NR_nanosleep, &ts1, NULL);
    }

    printf("pid=%d count=%d\n", bss->pid, bss->cnt);

    bpf_object__destroy_skeleton(skeleton);
    return 0;
}
