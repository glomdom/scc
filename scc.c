#include "ctype.h"
#include "stdarg.h"
#include "stdint.h"
#include "stdio.h"
#include "stdlib.h"
#include "string.h"

#ifndef FALSE
#define FALSE (0)
#endif

#ifndef TRUE
#define TRUE (1)
#endif

#define PROG_START (0x80)

#if defined(__linux__)

#include <elf.h>

#define SYSCALL(no) ADD_CODE(0xb8, (no), (no) >> 8, (no) >> 16, (no) >> 24, 0x0f, 0x05)
#define SYSCALL_EXIT (60)
#define START_ADDRESS (0x1000000 + PROG_START)

#else
#error Target not supported
#endif

#define LOAD_ADDRESS START_ADDRESS

void error(const char* fmt, ...) {
    va_list ap;

    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);

    exit(1);
}

enum TokenType {
    TK_NUM = 256,   // integer
    TK_EOF,         // end of file
};

typedef struct {
    int type;
    long val;
    const char* input;
} Token;

Token tokens[100];

void tokenize(const char* p) {
    int i = 0;

    while (*p != '\0') {
        if (isspace(*p)) {
            ++p;
            
            continue;
        }

        if (*p == '+' || *p == '-' || *p == '*' || *p == '/' || *p == '(' || *p == ')') {
            tokens[i].type = *p;
            tokens[i].input = p;
            ++i; ++p;

            continue;
        }

        if (isdigit(*p)) {
            tokens[i].type = TK_NUM;
            tokens[i].input = p;
            tokens[i].val = strtol(p, (char**)&p, 10);
            ++i;

            continue;
        }

        fprintf(stderr, "cannot tokenize `%s`\n", p);
        exit(1);
    }

    tokens[i].type = TK_EOF;
    tokens[i].input = p;
}

enum {
    ND_NUM = 256,
};

typedef struct Node {
    int type;

    union {
        struct {
            struct Node* lhs;
            struct Node* rhs;
        } bop;

        long val;
    };
} Node;

int pos;

Node* new_node(int type, Node* lhs, Node* rhs) {
    Node* node = malloc(sizeof(Node));
    node->type = type;
    node->bop.lhs = lhs;
    node->bop.rhs = rhs;

    return node;
}

Node* new_node_num(int val) {
    Node* node = malloc(sizeof(Node));
    node->type = ND_NUM;
    node->val = val;

    return node;
}

int consume(int type) {
    if (tokens[pos].type != type) {
        return FALSE;
    }

    ++pos;

    return TRUE;
}

Node* add();

Node* term() {
    if (consume('(')) {
        Node* node = add();

        if (!consume(')')) {
            error("no closed paren: %s", tokens[pos].input);
        }

        return node;
    }

    if (tokens[pos].type == TK_NUM) {
        return new_node_num(tokens[pos++].val);
    }

    error("number or open paren expected: %s", tokens[pos].input);

    return NULL;
}

Node* mul() {
    Node* node = term();

    for (;;) {
        if (consume('*')) {
            node = new_node('*', node, term());
        } else if (consume('/')) {
            node = new_node('/', node, term());
        } else {
            return node;
        }
    }
}

Node* add() {
    Node* node = mul();

    for (;;) {
        if (consume('+')) {
            node = new_node('+', node, mul());
        } else if (consume('-')) {
            node = new_node('-', node, mul());
        } else {
            return node;
        }
    }
}

unsigned char* code;
size_t codesize;

void add_code(const unsigned char* buf, size_t size) {
    size_t newsize = codesize + size;
    code = realloc(code, newsize);

    if (code == NULL) {
        error("not enough memory\n");
    }

    memcpy(code + codesize, buf, size);
    codesize = newsize;
}

#define ADD_CODE(...) do { unsigned char buf[] = { __VA_ARGS__ }; add_code(buf, sizeof(buf)); } while (0)
#define IM32(x) (x), ((x) >> 8), ((x) >> 16), ((x) >> 24)
#define IM64(x) (x), ((x) >> 8), ((x) >> 16), ((x) >> 24), ((x) >> 32), ((x) >> 40), ((x) >> 48), ((x) >> 56)

#define MOV_I32_EAX(x)  ADD_CODE(0xb8, IM32(x))             // mov $0xNN, %eax
#define MOV_I64_RAX(x)  ADD_CODE(0x48, 0xb8, IM64(x))       // mov $0x123456789abcdef0, %rax
#define MOV_I64_RDI(x)  ADD_CODE(0x48, 0xbf, IM64(x))       // mov $0x123456789abcdef0, %rdi
#define MOV_I32_RDX(x)  ADD_CODE(0x48, 0xc7, 0xc2, IM32(x)) // mov $0x0, %rdx
#define MOVSX_EAX_RDI() ADD_CODE(0x48, 0x63, 0xf8)          // movsx %eax, %rdi
#define MOV_RAX_RDI()   ADD_CODE(0x48, 0x89, 0xc7)          // mov %rax, %rdi
#define ADD_RDI_RAX()   ADD_CODE(0x48, 0x01, 0xf8)          // add %rdi, %rax
#define ADD_IM32_RAX(x) ADD_CODE(0x48, 0x05, IM32(x))       // add $12345678, %rax
#define SUB_RDI_RAX()   ADD_CODE(0x48, 0x29, 0xf8)          // sub %rdi, %rax
#define SUB_IM32_RAX(x) ADD_CODE(0x48, 0x2d, IM32(x))       // sub $12345678, %rax
#define MUL_RDI()       ADD_CODE(0x48, 0xf7, 0xe7)          // mul %rdi
#define DIV_RDI()       ADD_CODE(0x48, 0xf7, 0xf7)          // div %rdi
#define PUSH_RAX()      ADD_CODE(0x50)                      // push %rax
#define POP_RAX()       ADD_CODE(0x58)                      // pop %rax
#define POP_RDI()       ADD_CODE(0x5f)                      // pop %rdi

void gen(Node* node) {
    if (node->type == ND_NUM) {
        MOV_I64_RAX(node->val);
        PUSH_RAX();

        return;
    }

    gen(node->bop.lhs);
    gen(node->bop.rhs);

    POP_RDI();
    POP_RAX();

    switch (node->type) {
    case '+':
        ADD_RDI_RAX();

        break;

    case '-':
        SUB_RDI_RAX();

        break;

    case '*':
        MUL_RDI();

        break;
    
    case '/':
        MOV_I32_RDX(0);
        DIV_RDI();

        break;
    }

    PUSH_RAX();
}

void compile(const char* source) {
    tokenize(source);

    Node* node = add();
    gen(node);

    POP_RAX();
    
    // PROLOGUE
    MOV_RAX_RDI();
    SYSCALL(SYSCALL_EXIT);
}

void output_code(FILE* fp) {
    fwrite(code, codesize, 1, fp);
}

void out_elf_header(FILE* fp, uintptr_t entry) {
    Elf64_Ehdr ehdr = {
        .e_ident = {ELFMAG0, ELFMAG1, ELFMAG2, ELFMAG3, ELFCLASS64, ELFDATA2LSB, EV_CURRENT, ELFOSABI_SYSV},
        .e_type = ET_EXEC,
        .e_machine = EM_X86_64,
        .e_version = EV_CURRENT,
        .e_entry = entry,
        .e_phoff = sizeof(Elf64_Ehdr),
        .e_shoff = 0, // dummy
        .e_flags = 0x0,
        .e_ehsize = sizeof(Elf64_Ehdr),
        .e_phentsize = sizeof(Elf64_Phdr),
        .e_phnum = 1,
        .e_shentsize = 0, // dummy
        .e_shnum = 0,
        .e_shstrndx = 0, // dummy
    };

    fwrite(&ehdr, sizeof(Elf64_Ehdr), 1, fp);
}

void out_program_header(FILE* fp, uintptr_t offset, uintptr_t vaddr, uintptr_t filesz, uintptr_t memsz) {
    Elf64_Phdr phdr = {
        .p_type = PT_LOAD,
        .p_offset = offset,
        .p_vaddr = vaddr,
        .p_paddr = 0, // dummy
        .p_filesz = filesz,
        .p_memsz = memsz,
        .p_flags = PF_R | PF_X,
        .p_align = 0x10,
    };

    fwrite(&phdr, sizeof(Elf64_Phdr), 1, fp);
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        error("incorrect amount of arguments\n");
    }

    compile(argv[1]);

    FILE* fp = stdout;
    out_elf_header(fp, LOAD_ADDRESS);
    out_program_header(fp, PROG_START, LOAD_ADDRESS, codesize, codesize);

    {
        char buf[PROG_START];

        memset(buf, 0, PROG_START);
        fwrite(buf, PROG_START - (sizeof(Elf64_Ehdr) + sizeof(Elf64_Phdr)), 1, fp);
    }

    output_code(fp);

    return 0;
}
