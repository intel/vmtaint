/*
 * Copyright (C) 2021 Intel Corporation
 * SPDX-License-Identifier: MIT
 */
#include <vector>
#include <iostream>
#include <triton/api.hpp>
#include <triton/x86Specifications.hpp>
#include <intel-pt.h>
#include <libvmi/libvmi.h>
#include <getopt.h>
#include <cpuid.h>

using namespace std;
using namespace triton;
using namespace triton::arch;
using namespace triton::arch::x86;
triton::API triton_api;

static vmi_instance_t vmi;
addr_t kpgd;
#define KERNEL_64 0xffffffff80000000ULL
#define CHUNK_SIZE 1000000UL //10m

static void run_taint(addr_t ip, const unsigned char* buf, uint8_t size)
{
    Instruction inst;

    inst.setOpcode(buf, size);
    inst.setAddress(ip);

    triton_api.processing(inst);

    cout << std::hex << ip << "\t";
    cout << inst.getDisassembly() << endl;

    /*
    std::unordered_set<triton::uint64> tainted_mem = triton_api.getTaintedMemory();

    for (auto itr = tainted_mem.begin(); itr != tainted_mem.end(); ++itr)
        std::cout << "\t Tainted mem: " << std::hex << *itr << endl;
    */

    std::unordered_set<const triton::arch::Register *> tainted_regs = triton_api.getTaintedRegisters();

    for (auto itr = tainted_regs.begin(); itr != tainted_regs.end(); ++itr)
    {
        const triton::arch::Register *reg = *itr;
        if ( (*itr)->getId() != ID_REG_INVALID && (*itr)->getSize() )
            std::cout << "\t Tainted reg: " << reg->getName() << ": " << hex << triton_api.getConcreteRegisterValue(*reg) << endl;
    }
}

static bool save_state(const char *filepath)
{
    registers_t regs;
    memset(&regs, 0, sizeof(regs));

    vmi_get_vcpuregs(vmi, &regs, 0);

    FILE *i = fopen(filepath, "w+");
	fwrite(&regs, sizeof(regs), 1, i);
	fclose(i);

    return true;
}

static void load_state(const char *filepath)
{
    x86_registers_t regs;
    memset(&regs, 0, sizeof(regs));

    FILE *i = fopen(filepath, "r");
    fread(&regs, 1, sizeof(x86_registers_t), i);
	fclose(i);

    triton_api.setConcreteRegisterValue(triton_api.getRegister("rax"), regs.rax);
    triton_api.setConcreteRegisterValue(triton_api.getRegister("rbx"), regs.rbx);
    triton_api.setConcreteRegisterValue(triton_api.getRegister("rcx"), regs.rcx);
    triton_api.setConcreteRegisterValue(triton_api.getRegister("rdx"), regs.rdx);
    triton_api.setConcreteRegisterValue(triton_api.getRegister("rdi"), regs.rdi);
    triton_api.setConcreteRegisterValue(triton_api.getRegister("rsi"), regs.rsi);
    triton_api.setConcreteRegisterValue(triton_api.getRegister("rbp"), regs.rbp);
    triton_api.setConcreteRegisterValue(triton_api.getRegister("rsp"), regs.rsp);
    triton_api.setConcreteRegisterValue(triton_api.getRegister("rip"), regs.rip);
    triton_api.setConcreteRegisterValue(triton_api.getRegister("r8"), regs.r8);
    triton_api.setConcreteRegisterValue(triton_api.getRegister("r9"), regs.r9);
    triton_api.setConcreteRegisterValue(triton_api.getRegister("r10"), regs.r10);
    triton_api.setConcreteRegisterValue(triton_api.getRegister("r11"), regs.r11);
    triton_api.setConcreteRegisterValue(triton_api.getRegister("r12"), regs.r12);
    triton_api.setConcreteRegisterValue(triton_api.getRegister("r13"), regs.r13);
    triton_api.setConcreteRegisterValue(triton_api.getRegister("r14"), regs.r14);
    triton_api.setConcreteRegisterValue(triton_api.getRegister("r15"), regs.r15);
    triton_api.setConcreteRegisterValue(triton_api.getRegister("eflags"), regs.rflags);
    triton_api.setConcreteRegisterValue(triton_api.getRegister("fs"), regs.fs_base);
    triton_api.setConcreteRegisterValue(triton_api.getRegister("gs"), regs.fs_base);
}

static int read_mem(uint8_t *buffer, size_t size, const struct pt_asid *asid, uint64_t ip, void *context)
{
    addr_t cr3 = kpgd && (ip >= KERNEL_64 || asid->cr3 == ~0ull) ? kpgd : asid->cr3;;

    size_t read = 0;
    access_context_t ctx = {
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .addr = ip,
        .dtb = cr3
    };

    vmi_read(vmi, &ctx, size, buffer, &read);

    if ( !read )
        return -pte_invalid;

    return read;
}

static bool process_pt_chunk(struct pt_config *config, struct pt_image *image, bool skip_userspace)
{
    struct pt_insn_decoder *decoder = pt_insn_alloc_decoder(config);
    pt_insn_set_image(decoder, image);
    bool ret = false;
    int s;
    struct pt_insn insn;

    if ( (s = pt_insn_sync_set(decoder, 0)) < 0 )
        goto done;

    while ( true )
    {
        memset(&insn, 0, sizeof(insn));

        while ( s & pts_event_pending )
        {
            struct pt_event event;

            s = pt_insn_event(decoder, &event, sizeof(event));
            if ( s < 0 )
                goto done;
        }

        s = pt_insn_next(decoder, &insn, sizeof(insn));
        if ( s < 0 && !insn.iclass )
            continue;

        int l = insn.size > sizeof(insn.raw) ? sizeof(insn.raw) : insn.size;

            /*
            printf("0x%lx %u", insn.ip, insn.size);
            for (int i = 0; i < l; i++)
                printf(" %02x", insn.raw[i]);
            printf("\n");
            */

        if ( !skip_userspace || insn.ip >= KERNEL_64 )
            run_taint(insn.ip, (const unsigned char*)&insn.raw, l);

        if ( s < 0 )
            goto done;
    }

    ret = true;

done:
    pt_insn_free_decoder(decoder);
    return ret;
}

static unsigned long find_last_sync_point(struct pt_config *config, struct pt_image *image)
{
    struct pt_insn_decoder *decoder = pt_insn_alloc_decoder(config);
    pt_insn_set_image(decoder, image);

    unsigned long sync_point = ~0ul;

    while ( pt_insn_sync_forward(decoder) >= 0 )
        pt_insn_get_sync_offset(decoder, &sync_point);

    pt_insn_free_decoder(decoder);

    return sync_point;
}

static inline void pt_cpu_init(struct pt_cpu *cpu)
{
    uint32_t eax = 0, ebx, ecx, edx;

    __get_cpuid(1u, &eax, &ebx, &ecx, &edx);

    cpu->family = ((eax >> 8) & 0xf) | ((eax >> 20) & 0xf);
    cpu->model = ((eax >> 4) & 0xf) | ((eax >> 12) & 0xf0);
    cpu->stepping = eax & 0xf;
    cpu->vendor = pcv_intel;
}

static void process_pt(const char *pt, bool skip_userspace)
{
    unsigned long processed = 0;
    struct pt_config config;

    pt_config_init(&config);
    pt_cpu_init(&config.cpu);

    if ( pt_cpu_errata(&config.errata, &config.cpu) < 0 )
        return;

    FILE *ptf = fopen(pt, "r");
    if (!ptf)
        return;

    fseek(ptf, 0, SEEK_END);
    unsigned long size = ftell(ptf);
    fseek(ptf, 0, SEEK_SET);

    uint8_t *ptbuf = (uint8_t*)malloc(CHUNK_SIZE);
    if ( !ptbuf ) {
        fclose(ptf);
        return;
    }

    config.begin = ptbuf;

    struct pt_image *image = pt_image_alloc(NULL);
    pt_image_set_callback(image, read_mem, NULL);

    while ( processed < size )
    {
        memset(ptbuf, 0, CHUNK_SIZE);

        fseek(ptf, processed, SEEK_SET);

        unsigned long read;
        if ( !(read = fread(ptbuf, 1, CHUNK_SIZE, ptf)) )
            break;

        config.end = ptbuf + read;

        unsigned long last_sync = find_last_sync_point(&config, image);

        if ( last_sync == ~0ul )
            break;

        if ( last_sync )
        {
            config.end = ptbuf + last_sync;
            processed += last_sync;
        } else {
            config.end = ptbuf + read;
            processed += read;
        }

        if ( !process_pt_chunk(&config, image, skip_userspace) )
            break;
    }

    pt_image_free(image);
    free(ptbuf);
    fclose(ptf);
}

static void usage(void)
{
    printf("Usage:\n");
    printf("\t --domid <domid>\n");
}

int main(int argc, char *const *argv)
{

    int c, long_index = 0;
    const struct option long_opts[] =
    {
        {"domid", required_argument, NULL, 'd'},
        {"taint-address", required_argument, NULL, 't'},
        {"taint-size", required_argument, NULL, 'T'},
        {"save-state", required_argument, NULL, 's'},
        {"load-state", required_argument, NULL, 'l'},
        {"pt", required_argument, NULL, 'p'},
        {"json", required_argument, NULL, 'j'},
        {"skip-userspace", no_argument, NULL, 'u'},
        {NULL, 0, NULL, 0}
    };
    const char* opts = "d:t:T:s:l:u";
    uint64_t domid = 0;
    addr_t taint_address = 0;
    size_t taint_size = 0;
    bool save = false;
    bool skip_userspace = false;
    const char* statefile;
    const char* pt = NULL;
    const char* json = NULL;

    while ((c = getopt_long (argc, argv, opts, long_opts, &long_index)) != -1)
    {
        switch(c)
        {
        case 'd':
            domid = strtoull(optarg, NULL, 0);
            break;
        case 't':
            taint_address = strtoull(optarg, NULL, 0);
            break;
        case 'T':
            taint_size = atoi(optarg);
            break;
        case 's':
            save = true;
            statefile = optarg;
            break;
        case 'l':
            statefile = optarg;
            break;
        case 'p':
            pt = optarg;
            break;
        case 'u':
            skip_userspace = true;
            break;
        case 'j':
            json = optarg;
            break;
        case 'h': /* fall-through */
        default:
            usage();
            return -1;
        };
    }

    if ( !statefile )
    {
        cout << "No state file specified" << endl;
        return -1;
    }

    if ( !domid )
    {
        cout << "No domid specified\n" << endl;
        return -1;
    }

    if ( VMI_FAILURE == vmi_init(&vmi, VMI_XEN, &domid, VMI_INIT_DOMAINID, NULL, NULL) )
        return -1;

    if ( save )
    {
        printf("Saving state\n");
        save_state(statefile);
        vmi_destroy(vmi);
        return 0;
    }

    if ( json )
    {
        vmi_init_os(vmi, VMI_CONFIG_JSON_PATH, (void*)json, NULL);
        vmi_get_offset(vmi, "kpgd", &kpgd);
    } else
        vmi_init_paging(vmi, 0);

    triton_api.setArchitecture(ARCH_X86_64);
    triton_api.enableTaintEngine(1);
    triton_api.enableSymbolicEngine(0);

    load_state(statefile);

    for (unsigned int i = 0; i < taint_size; i++ )
        triton_api.taintMemory(taint_address + i);

    process_pt(pt, skip_userspace);

    return 0;
}
