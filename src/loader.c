#include "z_asm.h"
#include "z_syscalls.h"
#include "z_utils.h"
#include "z_elf.h"
#include <stdio.h>
#include <sys/mman.h>
#include <errno.h>
#include <link.h>

#define Z_PROG 0
#define Z_INTERP 1

#define FILENAMESIZE 1024
typedef char *VA; /* VA = virtual address */

#define _1GB 0x40000000
#define _32KB 0x8000

#define PAGE_SIZE 4096
#define ALIGN (PAGE_SIZE - 1)
#define ROUND_PG(x) (((x) + (ALIGN)) & ~(ALIGN))
#define TRUNC_PG(x) ((x) & ~(ALIGN))
#define PFLAGS(x) ((((x)&PF_R) ? PROT_READ : 0) |  \
				   (((x)&PF_W) ? PROT_WRITE : 0) | \
				   (((x)&PF_X) ? PROT_EXEC : 0))
#define LOAD_ERR ((unsigned long)-1)

// FIXME: 0x1000 is one page; Use sysconf(PAGESIZE) instead.
#define ROUND_DOWN(x) ((unsigned long long)(x) & ~(unsigned long long)(PAGE_SIZE - 1))
#define ROUND_UP(x) (((unsigned long long)(x) + PAGE_SIZE - 1) & \
					 ~(PAGE_SIZE - 1))
#define PAGE_OFFSET(x) ((x) & (PAGE_SIZE - 1))

// Based on the entries in /proc/<pid>/stat as described in `man 5 proc`
enum Procstat_t
{
	PID = 1,
	COMM,  // 2
	STATE, // 3
	PPID,  // 4
	NUM_THREADS = 19,
	STARTSTACK = 27,
};

typedef union ProcMapsArea
{
	struct
	{
		union
		{
			VA addr; // args required for mmap to restore memory area
			uint64_t __addr;
		};
		union
		{
			VA endAddr; // args required for mmap to restore memory area
			uint64_t __endAddr;
		};
		union
		{
			size_t size;
			uint64_t __size;
		};
		union
		{
			off_t offset;
			uint64_t __offset;
		};
		union
		{
			int prot;
			uint64_t __prot;
		};
		union
		{
			int flags;
			uint64_t __flags;
		};
		union
		{
			unsigned int long devmajor;
			uint64_t __devmajor;
		};
		union
		{
			unsigned int long devminor;
			uint64_t __devminor;
		};
		union
		{
			ino_t inodenum;
			uint64_t __inodenum;
		};

		uint64_t properties;

		char name[FILENAMESIZE];
	};
	char _padding[4096];
} ProcMapsArea;

typedef ProcMapsArea Area;

void run_child_process(unsigned long *sp)
{
	fprintf(stdout, "child process\n");
}

unsigned long *duplicate_stack(unsigned long *const sp)
{
	unsigned long *new_sp = (unsigned long *)mmap(NULL, _32KB, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);

	char **p = NULL;
	int argc = (int)*sp;
	char **argv = (char **)(sp + 1);
	char **env = p = (char **)&argv[argc + 1];

	while (*p++ != NULL)
		;

	Elf_auxv_t *av = (Elf_auxv_t *)p;
	while (av->a_type != AT_NULL)
		++av;

	size_t n = (unsigned long)av - (unsigned long)sp;
	unsigned char *des = (unsigned char *)new_sp;
	const unsigned char *src = (unsigned char *)sp, *e = src + n;
	while (src < e)
		*des++ = *src++;

	return new_sp;
}

/* Read non-null character, return null if EOF */
static char
readChar(int fd)
{
	char c;
	int rc;

	do
	{
		rc = read(fd, &c, 1);
	} while (rc == -1 && errno == EINTR);
	if (rc <= 0)
		return 0;
	return c;
}

/* Read decimal number, return value and terminating character */
static char
readDec(int fd, VA *value)
{
	char c;
	unsigned long int v = 0;

	while (1)
	{
		c = readChar(fd);
		if ((c >= '0') && (c <= '9'))
			c -= '0';
		else
			break;
		v = v * 10 + c;
	}
	*value = (VA)v;
	return c;
}

/* Read decimal number, return value and terminating character */
static char
readHex(int fd, VA *virt_mem_addr)
{
	char c;
	unsigned long int v = 0;

	while (1)
	{
		c = readChar(fd);
		if ((c >= '0') && (c <= '9'))
			c -= '0';
		else if ((c >= 'a') && (c <= 'f'))
			c -= 'a' - 10;
		else if ((c >= 'A') && (c <= 'F'))
			c -= 'A' - 10;
		else
			break;
		v = v * 16 + c;
	}
	*virt_mem_addr = (VA)v;
	return c;
}

int readMapsLine(int mapsfd, Area *area)
{
	char c, rflag, sflag, wflag, xflag;
	int i;
	off_t offset;
	unsigned int long devmajor, devminor, inodenum;
	VA startaddr, endaddr;

	c = readHex(mapsfd, &startaddr);
	if (c != '-')
	{
		if ((c == 0) && (startaddr == 0))
			return (0);
		goto skipeol;
	}
	c = readHex(mapsfd, &endaddr);
	if (c != ' ')
		goto skipeol;
	if (endaddr < startaddr)
		goto skipeol;

	rflag = c = readChar(mapsfd);
	if ((c != 'r') && (c != '-'))
		goto skipeol;
	wflag = c = readChar(mapsfd);
	if ((c != 'w') && (c != '-'))
		goto skipeol;
	xflag = c = readChar(mapsfd);
	if ((c != 'x') && (c != '-'))
		goto skipeol;
	sflag = c = readChar(mapsfd);
	if ((c != 's') && (c != 'p'))
		goto skipeol;

	c = readChar(mapsfd);
	if (c != ' ')
		goto skipeol;

	c = readHex(mapsfd, (VA *)&offset);
	if (c != ' ')
		goto skipeol;
	area->offset = offset;

	c = readHex(mapsfd, (VA *)&devmajor);
	if (c != ':')
		goto skipeol;
	c = readHex(mapsfd, (VA *)&devminor);
	if (c != ' ')
		goto skipeol;
	c = readDec(mapsfd, (VA *)&inodenum);
	area->name[0] = '\0';
	while (c == ' ')
		c = readChar(mapsfd);
	if (c == '/' || c == '[')
	{ /* absolute pathname, or [stack], [vdso], etc. */
		i = 0;
		do
		{
			area->name[i++] = c;
			if (i == sizeof area->name)
				goto skipeol;
			c = readChar(mapsfd);
		} while (c != '\n');
		area->name[i] = '\0';
	}

	if (c != '\n')
		goto skipeol;

	area->addr = startaddr;
	area->endAddr = endaddr;
	area->size = endaddr - startaddr;
	area->prot = 0;
	if (rflag == 'r')
		area->prot |= PROT_READ;
	if (wflag == 'w')
		area->prot |= PROT_WRITE;
	if (xflag == 'x')
		area->prot |= PROT_EXEC;
	area->flags = MAP_FIXED;
	if (sflag == 's')
		area->flags |= MAP_SHARED;
	if (sflag == 'p')
		area->flags |= MAP_PRIVATE;
	if (area->name[0] == '\0')
		area->flags |= MAP_ANONYMOUS;

	area->devmajor = devmajor;
	area->devminor = devminor;
	area->inodenum = inodenum;
	return (1);

skipeol:
	fprintf(stderr, "ERROR: readMapsLine*: bad maps line <%c", c);
	while ((c != '\n') && (c != '\0'))
	{
		c = readChar(mapsfd);
		printf("%c", c);
	}
	printf(">\n");
	abort();
	return 0; /* NOTREACHED : stop compiler warning */
}

// Returns the [stack] area by reading the proc maps
static void
getStackRegion(Area *stack) // OUT
{
	Area area;
	int mapsfd = open("/proc/self/maps", O_RDONLY);
	while (readMapsLine(mapsfd, &area))
	{
		if (strstr(area.name, "[stack]") && area.endAddr >= (VA)&area)
		{
			*stack = area;
			break;
		}
	}
	close(mapsfd);
}

// Returns the /proc/self/stat entry in the out string (of length len)
static void
getProcStatField(enum Procstat_t type, char *out, size_t len)
{
	const char *procPath = "/proc/self/stat";
	char sbuf[1024] = {0};
	int field_counter = 0;
	char *field_str = NULL;
	int fd, num_read;

	fd = open(procPath, O_RDONLY);
	if (fd < 0)
	{
		fprintf("Failed to open %s. Error: %s\n", procPath, strerror(errno));
		return;
	}

	num_read = read(fd, sbuf, sizeof sbuf - 1);
	close(fd);
	if (num_read <= 0)
		return;
	sbuf[num_read] = '\0';

	field_str = strtok(sbuf, " ");
	while (field_str && field_counter != type)
	{
		field_str = strtok(NULL, " ");
		field_counter++;
	}

	if (field_str)
	{
		strncpy(out, field_str, len);
	}
	else
	{
		fprintf("Failed to parse %s.\n", procPath);
	}
}

// Given a pointer to aux vector, parses the aux vector, and patches the
// following three entries: AT_PHDR, AT_ENTRY, and AT_PHNUM
static void
patchAuxv(ElfW(auxv_t) * av, unsigned long phnum,
		  unsigned long phdr, unsigned long entry)
{
	for (; av->a_type != AT_NULL; ++av)
	{
		switch (av->a_type)
		{
		case AT_PHNUM:
			av->a_un.a_val = phnum;
			break;
		case AT_PHDR:
			av->a_un.a_val = phdr;
			break;
		case AT_ENTRY:
			av->a_un.a_val = entry;
			break;
		case AT_RANDOM:
			fprintf("AT_RANDOM value: 0%lx\n", av->a_un.a_val);
			break;
		default:
			break;
		}
	}
}

// Returns pointer to argc, given a pointer to end of stack
static inline void *
GET_ARGC_ADDR(const void *stackEnd)
{
	return (void *)((uintptr_t)(stackEnd) + sizeof(uintptr_t));
}

// Returns pointer to argv[0], given a pointer to end of stack
static inline void *
GET_ARGV_ADDR(const void *stackEnd)
{
	return (void *)((unsigned long)(stackEnd) + 2 * sizeof(uintptr_t));
}

// Returns pointer to env[0], given a pointer to end of stack
static inline void *
GET_ENV_ADDR(char **argv, int argc)
{
	return (void *)&argv[argc + 1];
}

// Returns a pointer to aux vector, given a pointer to the environ vector
// on the stack
static inline ElfW(auxv_t) *
	GET_AUXV_ADDR(const char **env)
{
	ElfW(auxv_t) * auxvec;
	const char **evp = env;
	while (*evp++ != NULL)
		;
	auxvec = (ElfW(auxv_t) *)evp;
	return auxvec;
}

// Creates a deep copy of the stack region pointed to be `origStack` at the
// location pointed to be `newStack`. Returns the start-of-stack pointer
// in the new stack region.
static void *
deepCopyStack(void *newStack, const void *origStack, size_t len,
			  const void *newStackEnd, const void *origStackEnd/*,
			  const DynObjInfo_t *info*/)
{
	// Return early if any pointer is NULL
	if (!newStack || !origStack ||
		!newStackEnd || !origStackEnd/* ||
		!info*/)
	{
		return NULL;
	}

	// First, we do a shallow copy, which is essentially, just copying the
	// bits from the original stack into the new stack.
	memcpy(newStack, origStack, len);

	// Next, turn the shallow copy into a deep copy.
	//
	// The main thing we need to do is to patch the argv and env vectors in
	// the new stack to point to addresses in the new stack region. Note that
	// the argv and env are simply arrays of pointers. The pointers point to
	// strings in other locations in the stack.

	void *origArgcAddr = (void *)GET_ARGC_ADDR(origStackEnd);
	int origArgc = *(int *)origArgcAddr;
	char **origArgv = (char **)GET_ARGV_ADDR(origStackEnd);
	const char **origEnv = (const char **)GET_ENV_ADDR(origArgv, origArgc);

	void *newArgcAddr = (void *)GET_ARGC_ADDR(newStackEnd);
	int newArgc = *(int *)newArgcAddr;
	char **newArgv = (char **)GET_ARGV_ADDR(newStackEnd);
	const char **newEnv = (const char **)GET_ENV_ADDR(newArgv, newArgc);
	ElfW(auxv_t) *newAuxv = GET_AUXV_ADDR(newEnv);

	// Patch the argv vector in the new stack
	//   First, set up the argv vector based on the original stack
	for (int i = 0; origArgv[i] != NULL; i++)
	{
		off_t argvDelta = (uintptr_t)origArgv[i] - (uintptr_t)origArgv;
		newArgv[i] = (char *)((uintptr_t)newArgv + (uintptr_t)argvDelta);
	}

	//   Next, we patch argv[0], the first argument, on the new stack
	//   to point to "/path/to/ld.so".
	//
	//   From the point of view of ld.so, it would appear as if it was called
	//   like this: $ /lib/ld.so /path/to/target.exe app-args ...
	//
	//   NOTE: The kernel loader needs to be called with at least two arguments
	//   to get a stack that is 16-byte aligned at the start. Since we want to
	//   be able to jump into ld.so with at least two arguments (ld.so and the
	//   target exe) on the new stack, we also need two arguments on the
	//   original stack.
	//
	//   If the original stack had just one argument, we would have inherited
	//   that alignment in the new stack. Trying to push in another argument
	//   (target exe) on the new stack would destroy the 16-byte alignment
	//   on the new stack. This would lead to a crash later on in ld.so.
	//
	//   The problem is that there are instructions (like, "movaps") in ld.so's
	//   code that operate on the stack memory region and require their
	//   operands to be 16-byte aligned. A non-16-byte-aligned operand (for
	//   example, the stack base pointer) leads to a general protection
	//   exception (#GP), which translates into a segfault for the user
	//   process.
	//
	//   The Linux kernel ensures that the start of stack is always 16-byte
	//   aligned. It seems like this is part of the Linux kernel x86-64 ABI.
	//   For example, see here:
	//
	//     https://elixir.bootlin.com/linux/v4.18.11/source/fs/binfmt_elf.c#L150
	//
	//     https://elixir.bootlin.com/linux/v4.18.11/source/fs/binfmt_elf.c#L288
	//
	//   (The kernel uses the STACK_ROUND macro to first set up the stack base
	//    at a 16-byte aligned address, and then pushes items on the stack.)
	//
	//   We could do something similar on the new stack region. But perhaps it's
	//   easier to just depend on the original stack having at least two args:
	//   "/path/to/kernel-loader" and "/path/to/target.exe".
	//
	//   NOTE: We don't need to patch newArgc, since the original stack,
	//   from where we would have inherited the data in the new stack, already
	//   had the correct value for origArgc. We just make argv[0] in the
	//   new stack to point to "/path/to/ld.so", instead of
	//   "/path/to/kernel-loader".
	/*
	// off_t argvDelta = (uintptr_t)getenv("TARGET_LD") - (uintptr_t)origArgv;
	// newArgv[0] = (char *)((uintptr_t)newArgv + (uintptr_t)argvDelta);

	// // Patch the env vector in the new stack
	// for (int i = 0; origEnv[i] != NULL; i++)
	// {
	// 	off_t envDelta = (uintptr_t)origEnv[i] - (uintptr_t)origEnv;
	// 	newEnv[i] = (char *)((uintptr_t)newEnv + (uintptr_t)envDelta);
	// }

	// // Change "UH_PRELOAD" to "LD_PRELOAD". This way, upper half's ld.so
	// // will preload the upper half wrapper library.
	// char **newEnvPtr = (char **)newEnv;
	// for (; *newEnvPtr; newEnvPtr++)
	// {
	// 	if (strstr(*newEnvPtr, "UH_PRELOAD"))
	// 	{
	// 		(*newEnvPtr)[0] = 'L';
	// 		(*newEnvPtr)[1] = 'D';
	// 		break;
	// 	}
	// }

	// // The aux vector, which we would have inherited from the original stack,
	// // has entries that correspond to the kernel loader binary. In particular,
	// // it has these entries AT_PHNUM, AT_PHDR, and AT_ENTRY that correspond
	// // to kernel-loader. So, we atch the aux vector in the new stack to
	// // correspond to the new binary: the freshly loaded ld.so.
	// patchAuxv(newAuxv, info->phnum,
	// 		  (uintptr_t)info->phdr,
	// 		  (uintptr_t)info->entryPoint);

	// printf("newArgv[-2]: %lu \n", (unsigned long)&newArgv[0]);

	// // We clear out the rest of the new stack region just in case ...
	// memset(newStack, 0, (size_t)((uintptr_t)&newArgv[-2] - (uintptr_t)newStack));
	*/

	// Return the start of new stack.
	return (void *)newArgcAddr;
}

/* External fini function that the caller can provide us. */
static void (*x_fini)(void);

static void z_fini(void)
{
	z_printf("Fini at work: x_fini %p\n", x_fini);
	if (x_fini != NULL)
		x_fini();
}

static int check_ehdr(Elf_Ehdr *ehdr)
{
	unsigned char *e_ident = ehdr->e_ident;
	return (e_ident[EI_MAG0] != ELFMAG0 || e_ident[EI_MAG1] != ELFMAG1 ||
			e_ident[EI_MAG2] != ELFMAG2 || e_ident[EI_MAG3] != ELFMAG3 ||
			e_ident[EI_CLASS] != ELFCLASS ||
			e_ident[EI_VERSION] != EV_CURRENT ||
			(ehdr->e_type != ET_EXEC && ehdr->e_type != ET_DYN))
			   ? 0
			   : 1;
}

static unsigned long loadelf_anon(int fd, Elf_Ehdr *ehdr, Elf_Phdr *phdr)
{
	unsigned long minva, maxva;
	Elf_Phdr *iter;
	ssize_t sz;
	int flags, dyn = ehdr->e_type == ET_DYN;
	unsigned char *p, *base, *hint;

	minva = (unsigned long)-1;
	maxva = 0;

	for (iter = phdr; iter < &phdr[ehdr->e_phnum]; iter++)
	{
		if (iter->p_type != PT_LOAD)
			continue;
		if (iter->p_vaddr < minva)
			minva = iter->p_vaddr;
		if (iter->p_vaddr + iter->p_memsz > maxva)
			maxva = iter->p_vaddr + iter->p_memsz;
	}

	minva = TRUNC_PG(minva);
	maxva = ROUND_PG(maxva);

	/* For dynamic ELF let the kernel chose the address. */
	hint = dyn ? NULL : (void *)minva;
	flags = dyn ? 0 : MAP_FIXED;
	flags |= (MAP_PRIVATE | MAP_ANONYMOUS);

	/* Check that we can hold the whole image. */
	base = z_mmap(hint, maxva - minva, PROT_NONE, flags, -1, 0);
	if (base == (void *)-1)
		return -1;
	z_munmap(base, maxva - minva);

	flags = MAP_FIXED | MAP_ANONYMOUS | MAP_PRIVATE;
	/* Now map each segment separately in precalculated address. */
	for (iter = phdr; iter < &phdr[ehdr->e_phnum]; iter++)
	{
		unsigned long off, start;
		if (iter->p_type != PT_LOAD)
			continue;
		off = iter->p_vaddr & ALIGN;
		start = dyn ? (unsigned long)base : 0;
		start += TRUNC_PG(iter->p_vaddr);
		sz = ROUND_PG(iter->p_memsz + off);

		p = z_mmap((void *)start, sz, PROT_WRITE, flags, -1, 0);
		if (p == (void *)-1)
			goto err;
		if (z_lseek(fd, iter->p_offset, SEEK_SET) < 0)
			goto err;
		if (z_read(fd, p + off, iter->p_filesz) !=
			(ssize_t)iter->p_filesz)
			goto err;
		z_mprotect(p, sz, PFLAGS(iter->p_flags));
	}

	return (unsigned long)base;
err:
	z_munmap(base, maxva - minva);
	return LOAD_ERR;
}

void entry(unsigned long *sp, void (*fini)(void))
{
	unsigned long *new_sp = duplicate_stack(sp);

	Area stack_;
	getStackRegion(&stack_);
	size_t length = ROUND_UP(stack_.size);
	void *newStack = mmap(NULL, length, PROT_READ | PROT_WRITE,
						  MAP_GROWSDOWN | MAP_PRIVATE | MAP_ANONYMOUS,
						  -1, 0);
	if (newStack == MAP_FAILED)
	{
		fprintf("Failed to mmap new stack region: %s\n", strerror(errno));
		return NULL;
	}

	// 3. Get pointer to the beginning of the stack in the new stack region
	// The idea here is to look at the beginning of stack in the original
	// stack region, and use that to index into the new memory region. The
	// same offsets are valid in both the stack regions.
	char stackEndStr[20] = {0};
	getProcStatField(STARTSTACK, stackEndStr, sizeof stackEndStr);

	// NOTE: The kernel sets up the stack in the following format.
	//      -1(%rsp)                       Stack end for application
	//      0(%rsp)                        argc (Stack start for application)
	//      LP_SIZE(%rsp)                  argv[0]
	//      (2*LP_SIZE)(%rsp)              argv[1]
	//      ...
	//      (LP_SIZE*(argc))(%rsp)         NULL
	//      (LP_SIZE*(argc+1))(%rsp)       envp[0]
	//      (LP_SIZE*(argc+2))(%rsp)       envp[1]
	//      ...
	//                                     NULL
	//
	// NOTE: proc-stat returns the address of argc on the stack.
	// argv[0] is 1 LP_SIZE ahead of argc, i.e., startStack + sizeof(void*)
	// Stack End is 1 LP_SIZE behind argc, i.e., startStack - sizeof(void*)
	// sizeof(unsigned long) == sizeof(void*) == 8 on x86-64
	unsigned long origStackEnd = atol(stackEndStr) - sizeof(unsigned long);
	unsigned long origStackOffset = origStackEnd - (unsigned long)stack_.addr;
	unsigned long newStackOffset = origStackOffset;
	void *newStackEnd = (void*)((unsigned long)newStack + newStackOffset);	

  	newStackEnd = deepCopyStack(newStack, stack_.addr, stack_.size,
                              (void*)newStackEnd, (void*)origStackEnd/*, info*/);


	void *reserved = mmap(NULL, _1GB, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	if (reserved == MAP_FAILED)
		z_errx(1, "reserve failed");

	pid_t pid = fork();
	if (pid == 0) // child
	{
		run_child_process(sp);
		return;
	}

	Elf_Ehdr ehdrs[2], *ehdr = ehdrs;
	Elf_Phdr *phdr, *iter;
	Elf_auxv_t *av;
	char **argv, **env, **p, *elf_interp = NULL;
	unsigned long base[2], entry[2];
	const char *file;
	ssize_t sz;
	int argc, fd, i;

	x_fini = fini;
	argc = (int)*(sp);
	argv = (char **)(sp + 1);
	env = p = (char **)&argv[argc + 1];
	while (*p++ != NULL)
		;
	av = (void *)p;

	(void)env;
	if (argc < 2)
		z_errx(1, "no input file");
	file = argv[1];

	for (i = 0;; i++, ehdr++)
	{
		/* Open file, read and than check ELF header.*/
		if ((fd = z_open(file, O_RDONLY)) < 0)
			z_errx(1, "can't open %s", file);
		if (z_read(fd, ehdr, sizeof(*ehdr)) != sizeof(*ehdr))
			z_errx(1, "can't read ELF header %s", file);
		if (!check_ehdr(ehdr))
			z_errx(1, "bogus ELF header %s", file);

		/* Read the program header. */
		sz = ehdr->e_phnum * sizeof(Elf_Phdr);
		phdr = z_alloca(sz);
		if (z_lseek(fd, ehdr->e_phoff, SEEK_SET) < 0)
			z_errx(1, "can't lseek to program header %s", file);
		if (z_read(fd, phdr, sz) != sz)
			z_errx(1, "can't read program header %s", file);
		/* Time to load ELF. */
		if ((base[i] = loadelf_anon(fd, ehdr, phdr)) == LOAD_ERR)
			z_errx(1, "can't load ELF %s", file);

		/* Set the entry point, if the file is dynamic than add bias. */
		entry[i] = ehdr->e_entry + (ehdr->e_type == ET_DYN ? base[i] : 0);
		/* The second round, we've loaded ELF interp. */
		if (file == elf_interp)
			break;
		for (iter = phdr; iter < &phdr[ehdr->e_phnum]; iter++)
		{
			if (iter->p_type != PT_INTERP)
				continue;
			elf_interp = z_alloca(iter->p_filesz);
			if (z_lseek(fd, iter->p_offset, SEEK_SET) < 0)
				z_errx(1, "can't lseek interp segment");
			if (z_read(fd, elf_interp, iter->p_filesz) !=
				(ssize_t)iter->p_filesz)
				z_errx(1, "can't read interp segment");
			if (elf_interp[iter->p_filesz - 1] != '\0')
				z_errx(1, "bogus interp path");
			file = elf_interp;
		}
		/* Looks like the ELF is static -- leave the loop. */
		if (elf_interp == NULL)
			break;
	}

	/* Reassign some vectors that are important for
	 * the dynamic linker and for lib C. */
#define AVSET(t, v, expr)         \
	case (t):                     \
		(v)->a_un.a_val = (expr); \
		break
	while (av->a_type != AT_NULL)
	{
		switch (av->a_type)
		{
			AVSET(AT_PHDR, av, base[Z_PROG] + ehdrs[Z_PROG].e_phoff);
			AVSET(AT_PHNUM, av, ehdrs[Z_PROG].e_phnum);
			AVSET(AT_PHENT, av, ehdrs[Z_PROG].e_phentsize);
			AVSET(AT_ENTRY, av, entry[Z_PROG]);
			AVSET(AT_EXECFN, av, (unsigned long)argv[1]);
			AVSET(AT_BASE, av, elf_interp ? base[Z_INTERP] : av->a_un.a_val);
		}
		++av;
	}
#undef AVSET
	++av;

	// /* SP points to argc. */
	// unsigned long* reserved_argc = (unsigned long*)reserved;
	// *reserved_argc = --(*sp);

	// unsigned long* reserved_argv = reserved_argc+1;

	// /* Shift argv, env and av. */
	// z_memcpy(reserved_argv, &argv[1],
	// 	 (unsigned long)av - (unsigned long)&argv[1]);

	// z_trampo((void (*)(void))(elf_interp ? entry[Z_INTERP] : entry[Z_PROG]), reserved, z_fini);

	/* Shift argv, env and av. */
	z_memcpy(&argv[0], &argv[1],
			 (unsigned long)av - (unsigned long)&argv[1]);
	/* SP points to argc. */
	(*sp)--;
	z_trampo((void (*)(void))(elf_interp ? entry[Z_INTERP] : entry[Z_PROG]), sp, z_fini);

	// asm volatile (
	// 	"mov %0, %%rsp;\n\t"
	// 	"jmp *%1;\n\t"
	// 	"hlt; /* Should not reach.*/\n\t"
	// 	:
	// 	:"r" (elf_interp ? entry[Z_INTERP] : entry[Z_PROG]), "r" (sp)
	// );

	/* Should not reach. */
	z_exit(0);
}
