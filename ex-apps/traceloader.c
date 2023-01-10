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
#include <ctype.h>

#include <bpf/libbpf.h>
#include <libelf.h>

#define LINK_PIN_PATH "/sys/fs/bpf"

/* content of the .bss section of the nanosleep.bpf.o */
struct bss_t {
    int pid;
};

/* All required variables to load an ebpf program */
struct ebpf_prog_required {
    const char *obj_name;
    const char *prog_name;
    int func_num;
    const char **func_names;
    int map_num;
    const char **map_names;

    struct bpf_object_skeleton *skeleton;
    struct bpf_object *obj;
    struct bpf_map **maps;
    struct bpf_program **progs;
    struct bpf_link **links;
};

extern void ebpf_prog_required_free(struct ebpf_prog_required *);

struct ebpf_prog_required*
ebpf_prog_required_create(int func_num, int map_num) {
    struct ebpf_prog_required* required =
        (struct ebpf_prog_required *)calloc(1, sizeof(struct ebpf_prog_required));
    if (required == NULL)
        return NULL;

    required->skeleton =
        (struct bpf_object_skeleton *)calloc(1, sizeof(struct bpf_object_skeleton));
    required->func_num = func_num;

    required->func_names =
        (const char **)calloc(func_num, sizeof(const char*));
    if (required->func_names == NULL)
        goto err_out;

    required->map_num = map_num;

    required->map_names =
        (const char **)calloc(map_num, sizeof(const char *));
    if (required->map_names == NULL)
        goto err_out;

    required->maps =
        (struct bpf_map **)calloc(map_num, sizeof(struct bpf_map *));
    if (required->maps == NULL)
        goto err_out;

    required->progs =
        (struct bpf_program **)calloc(func_num, sizeof(struct bpf_program *));
    if (required->progs == NULL)
        goto err_out;

    required->links =
        (struct bpf_link **)calloc(func_num, sizeof(struct bpf_link *));
    if (required->links == NULL)
        goto err_out;

    return required;
 err_out:
    ebpf_prog_required_free(required);
}

#define FREE_OR_NULL(x) if (x) free((void *)(x))

void ebpf_prog_required_free(struct ebpf_prog_required *required) {
    int i;
    if (required == NULL)
        return;
    bpf_object__destroy_skeleton(required->skeleton);
    FREE_OR_NULL(required->obj_name);
    FREE_OR_NULL(required->prog_name);
    if (required->func_names)
        for (i = 0; i < required->func_num; i++)
            FREE_OR_NULL(required->func_names[i]);
    FREE_OR_NULL(required->func_names);
    if (required->map_names)
        for (i = 0; i < required->map_num; i++)
            FREE_OR_NULL(required->map_names[i]);
    FREE_OR_NULL(required->map_names);
    FREE_OR_NULL(required->maps);
    FREE_OR_NULL(required->progs);
    FREE_OR_NULL(required->links);
    free(required);
}

struct ebpf_prog_required *
ebpf_prog_required_prepare(const char *objfile_name) {
    struct ebpf_prog_required *required = NULL;

    int fd = open(objfile_name, O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "fail to open: %s\n", objfile_name);
        return NULL;
    }

    elf_version(EV_CURRENT);
    Elf *elf = elf_begin(fd, ELF_C_READ, NULL);
    if (!elf) {
        fprintf(stderr, "elf_begin: %s\n", objfile_name);
        close(fd);
        return NULL;
    }

    Elf64_Ehdr *ehdr = elf64_getehdr(elf);
    int sect_num = ehdr->e_shnum;
    int shstrndx = ehdr->e_shstrndx;
    Elf_Scn *strtab_scn = elf_getscn(elf, shstrndx);
    Elf_Data *strtab_data = elf_rawdata(strtab_scn, NULL);

    int *is_tracing = (int *)calloc(sect_num, sizeof(int));
    int func_num = 0;
    int maps_ndx = -1;
    Elf_Scn *symtab_scn = NULL;
    int i;
    for (i = 0; i < sect_num; i++) {
        Elf_Scn *scn = elf_getscn(elf, i);
        Elf64_Shdr *shdr = elf64_getshdr(scn);
        const char *sectname =
            (const char *)strtab_data->d_buf + shdr->sh_name;
        if (strncmp(sectname, "fentry/", 7) == 0 ||
            strncmp(sectname, "fexit/", 6) == 0) {
            is_tracing[i] = 1;
            func_num++;
        } else if (strcmp(sectname, ".maps") == 0) {
            maps_ndx = i;
        } else if (strcmp(sectname, ".symtab") == 0) {
            symtab_scn = scn;
        }
    }

    if (!symtab_scn) {
        fprintf(stderr, "no .symtab\n");
        goto errout;
    }

    int map_num = 1;
    Elf_Data *symtab_data = elf_rawdata(symtab_scn, NULL);
    Elf64_Sym *syms = (Elf64_Sym *)symtab_data->d_buf;
    int sym_num = symtab_data->d_size / sizeof(Elf64_Sym);
    for (i = 0; i < sym_num; i++) {
        int shndx = syms[i].st_shndx;
        if (shndx == maps_ndx && ELF32_ST_TYPE(syms[i].st_info) == STT_OBJECT) {
            map_num++;
        }
    }

    required =
        ebpf_prog_required_create(func_num, map_num);

    required->obj_name = strdup(objfile_name);
    /*
     * Set prog_name
     */
    char *prog_name = strdup(objfile_name);
    /* remove chars after last '.' */
    char *dot = strchr(prog_name, '.');
    if (dot) *dot = 0;
    required->prog_name = prog_name;

    /* Collect program names and the number of maps */
    required->func_num = func_num;
    const char **func_names = required->func_names;
    int pn_idx = 0;
    for (i = 0; i < sym_num; i++) {
        int shndx = syms[i].st_shndx;
        if (shndx < sect_num && ELF32_ST_TYPE(syms[i].st_info) == STT_FUNC && is_tracing[shndx]) {
            if (pn_idx >= func_num) {
                fprintf(stderr, "too many programs\n");
                ebpf_prog_required_free(required);
                elf_end(elf);
                return NULL;
            }
            func_names[pn_idx++] =
                strdup((const char *)strtab_data->d_buf + syms[i].st_name);
        }
    }

    /* collect map names */
    required->map_num = map_num;
    const char** map_names = required->map_names;
    int map_idx = 0;
    for (i = 0; i < sym_num; i++) {
        int shndx = syms[i].st_shndx;
        if (shndx == maps_ndx && ELF32_ST_TYPE(syms[i].st_info) == STT_OBJECT) {
            const char *map_name =
                (const char *)strtab_data->d_buf + syms[i].st_name;
            map_names[map_idx++] = strdup(map_name);
        }
    }

    /* .bss map name is the prog_name up to 8-chars followed by a
     * ".bss" string.
     */
    char bss_map_name[13];
    /* translate all non-alpha-number chars to '_' */
    for (i = 0; prog_name[i]; i++) {
        if (!isalnum(prog_name[i]))
            prog_name[i] = '_';
    }
    char prefix_buf[9];
    strncpy(prefix_buf, prog_name, 8);
    prefix_buf[8] = 0;
    sprintf(bss_map_name, "%s.bss", prefix_buf);
    map_names[map_idx] = strdup(bss_map_name);

    free(is_tracing);
    elf_end(elf);
    return required;

 errout:
    if (required) ebpf_prog_required_free(required);
    FREE_OR_NULL(is_tracing);
    elf_end(elf);
    return NULL;
}

/*
 * Load an ebpf program to the kernel.
 */
int load(const char *obj_name,
         const char *prog_name,
         const char * const *func_names,
         int func_num,
         const char * const *map_names,
         int map_num,
         /* Required variables */
         struct bpf_object_skeleton *skeleton,
         struct bpf_object **obj,
         struct bpf_map **maps,
         struct bpf_program **progs,
         struct bpf_link **links) {
    int fd = -1;
    char *objfile = NULL;
    struct bpf_object_skeleton *s = skeleton;
    bool skeleton_opened = false;

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
    s->name = strdup(prog_name);
    s->obj = obj;

    /* maps */
    s->map_cnt = map_num;
    s->map_skel_sz = sizeof(*s->maps);
    s->maps = (struct bpf_map_skeleton *)calloc(s->map_cnt, s->map_skel_sz);
    if (!s->maps) {
        fprintf(stderr, "fail to allocate memory\n");
        goto err_out;
    }

    int map_idx = 0;
    for (; map_idx < map_num; map_idx++) {
        s->maps[map_idx].name = strdup(map_names[map_idx]);
        s->maps[map_idx].map = maps + map_idx;
    }

    /* progs */
    s->prog_cnt = func_num;
    s->prog_skel_sz = sizeof(*s->progs);
    s->progs = (struct bpf_prog_skeleton *)calloc(s->prog_cnt, s->prog_skel_sz);
    if (!s->progs) {
        fprintf(stderr, "fail to allocate memory\n");
        goto err_out;
    }

    int i;
    for (i = 0; i < func_num; i++) {
        s->progs[i].name = strdup(func_names[i]);
        s->progs[i].prog = progs + i;
        s->progs[i].link = links + i;
    }

    s->data_sz = statbuf.st_size;
    s->data = objfile;

    err = bpf_object__open_skeleton(s, NULL);
    if (err) {
        fprintf(stderr, "fail to open skeleton\n");
        goto err_out;
    }
    skeleton_opened = true;

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
    return -1;
}

int load_objfile(const char *objfile_name) {
    /* All variables required to load an eBPF program. */
    struct ebpf_prog_required *required =
        ebpf_prog_required_prepare(objfile_name);

    printf("Load %s to the kernel\n", objfile_name);
    int err = load(objfile_name,
                   required->prog_name,
                   required->func_names,
                   required->func_num,
                   required->map_names,
                   required->map_num,
                   /* Required variables */
                   required->skeleton,
                   &required->obj,
                   required->maps,
                   required->progs,
                   required->links);
    if (err) {
        fprintf(stderr, "fail to load the program\n");
        return 255;
    }

    /* Attach the program. */
    printf("Attach the program to the entry point of __x86_sys_nanosleep\n");
    err = bpf_object__attach_skeleton(required->skeleton);
    if (err) {
        fprintf(stderr, "fail to attach the program\n");
        return 255;
    }

    int i;
    for (i = 0; i < required->func_num; i++) {
        char *path =
            (char *)malloc(strlen(LINK_PIN_PATH) +
                           strlen(required->prog_name) +
                           strlen(required->func_names[i]) + 3);
        sprintf(path, "%s/%s/%s",
                LINK_PIN_PATH, required->prog_name, required->func_names[i]);
        printf("pin a program at %s\n", path);
        if (bpf_link__pin(required->links[i],
                          path) < 0) {
            printf("fail\n");
        }
        free(path);
    }

    ebpf_prog_required_free(required);
    return 0;
}

void usage(const char *bin) {
    fprintf(stderr, "Usage: %s <obj-file>\n", bin);
}

int main(int argc, const char *argv[]) {
    if (argc != 2) {
        usage(argv[0]);
        return 255;
    }

    const char *objfile_name = argv[1];
    return load_objfile(objfile_name);
}

