#include <capstone/capstone.h>
#include <cstdio>
#include <keystone/keystone.h>

auto main() -> int {
	ks_engine* ks{};
	[[maybe_unused]] ks_err err1 = ks_open(KS_ARCH_X86, KS_MODE_64, &ks);
	ks_close(ks);

	csh cs{};
	[[maybe_unused]] cs_err err2 = cs_open(CS_ARCH_X86, CS_MODE_64, &cs);
	cs_close(&cs);

	std::puts("Hello world!");
}