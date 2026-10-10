#include "common.h"
#include "macho.h"
#include <libproc.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <sys/wait.h>

static size_t mappings(const string& path, uint64_t* base = nullptr, uint64_t* length = nullptr)
{
	size_t count = 0;
	uint64_t address = 0;
	proc_regionwithpathinfo region = {};
	while (proc_pidinfo(getpid(), PROC_PIDREGIONPATHINFO, address, &region, sizeof(region)) == sizeof(region)) {
		if (path == region.prp_vip.vip_path) {
			count++;
			if (base) *base = region.prp_prinfo.pri_address;
			if (length) *length = region.prp_prinfo.pri_size;
		}
		uint64_t next = region.prp_prinfo.pri_address + region.prp_prinfo.pri_size;
		if (next <= address) break;
		address = next;
	}
	return count;
}

int main(int argc, char** argv)
{
	if (argc != 2) return 2;
	int failures = 0;
	auto check = [&](bool condition, const char* message) {
		if (!condition) {
			fprintf(stderr, "FAIL: %s\n", message);
			failures++;
		}
	};
	auto fixture = [&](const char* name, bool valid = true) {
		string path = string(argv[1]) + "/" + name;
		mach_header_64 header = {};
		header.magic = valid ? MH_MAGIC_64 : 0;
		header.cputype = CPU_TYPE_ARM64;
		header.filetype = MH_DYLIB;
		if (!ZFile::WriteFile(path.c_str(), (const char*)&header, sizeof(header))) exit(2);
		char resolved[PATH_MAX];
		if (!realpath(path.c_str(), resolved)) exit(2);
		return string(resolved);
	};
	{
		string path = fixture("explicit-free");
		ZMachO file;
		check(file.Init(path.c_str()), "valid fixture initializes");
		check(mappings(path) > 0, "initialized file has an observable mapping");
		check(file.Free(), "explicit Free succeeds");
		check(mappings(path) == 0, "explicit Free releases mapping");
		check(file.Free(), "repeated Free is harmless");
	}
	{
		string path = fixture("destructor");
		{ ZMachO file; check(file.Init(path.c_str()), "destructor fixture initializes"); }
		check(mappings(path) == 0, "destructor releases mapping");
	}
	{
		string path = fixture("reopen");
		ZMachO file;
		check(file.Init(path.c_str()), "reopen fixture initializes");
		size_t initial = mappings(path);
		check(file.Init(path.c_str()), "same object reopens successfully");
		check(mappings(path) == initial, "reopening releases the previous mapping");
		file.Free();
		check(mappings(path) == 0, "reopened mapping is released");
	}
	{
		string path = fixture("invalid-init", false);
		ZMachO file;
		check(!file.Init(path.c_str()), "invalid fixture is rejected");
		check(mappings(path) == 0, "failed initialization releases mapping immediately");
	}
	{
		string path = fixture("repeated-analysis");
		for (int i = 0; i < 64; i++) {
			ZMachO file;
			check(file.Init(path.c_str()), "analysis fixture initializes");
			file.ListDylibs();
			file.Free();
		}
		check(mappings(path) == 0, "repeated dependency analysis leaves no mappings");
	}
	{
		string path = fixture("invalid-name-offset");
		mach_header_64 header = {};
		header.magic = MH_MAGIC_64;
		header.cputype = CPU_TYPE_ARM64;
		header.filetype = MH_DYLIB;
		header.ncmds = 1;
		header.sizeofcmds = sizeof(dylib_command);
		dylib_command command = {};
		command.cmd = LC_LOAD_DYLIB;
		command.cmdsize = sizeof(command);
		command.dylib.name.offset = UINT32_MAX;
		string data((const char*)&header, sizeof(header));
		data.append((const char*)&command, sizeof(command));
		check(ZFile::WriteFile(path.c_str(), data.data(), data.size()), "malformed fixture is written");
		// 子进程隔离越界崩溃，父进程检查真实 API 是否安全拒绝损坏命令。
		pid_t child = fork();
		if (child == 0) {
			ZMachO file;
			if (!file.Init(path.c_str())) _exit(2);
			uint64_t base = 0, length = 0;
			if (mappings(path, &base, &length) != 1) _exit(2);
			mach_vm_address_t guard = 0;
			bool allocated = false;
			for (uint64_t i = 0; i < 1024; i++) {
				guard = base + length + i * vm_page_size;
				if (mach_vm_allocate(mach_task_self(), &guard, vm_page_size, VM_FLAGS_FIXED) == KERN_SUCCESS) {
					allocated = true;
					break;
				}
			}
			if (!allocated || guard - base > UINT32_MAX ||
				mach_vm_protect(mach_task_self(), guard, vm_page_size, false, VM_PROT_NONE) != KERN_SUCCESS) _exit(2);
			// 偏移明确指向不可读页，确保越界预读一定会被捕获，不依赖地址布局。
			dylib_command* mapped = (dylib_command*)(base + sizeof(header));
			mapped->dylib.name.offset = (uint32_t)(guard - base - sizeof(header));
			bool changed = file.ChangeDylibPath("/old.dylib", "/new.dylib");
			file.Free();
			_exit(changed ? 1 : 0);
		}
		int status = 0;
		check(child > 0 && waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0,
			"invalid dependency name offset is rejected without an out-of-bounds read");
	}
	if (failures) return 1;
	puts("Zsign Mach-O lifecycle: release, destructor, reopen, failed initialization, repeated analysis and malformed dependency rejection passed");
	return 0;
}
