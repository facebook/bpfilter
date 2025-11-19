#include "mock.h"

void bft_mock_clean(bft_mock *mock)
{
    mock->disable();
}

bft_mock_define(btf__load_vmlinux_btf);
bft_mock_define(isatty);
bft_mock_define(setns);
bft_mock_define(syscall);
