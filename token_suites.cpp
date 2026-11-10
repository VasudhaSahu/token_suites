// token_suites.cpp .
#include "TokenInspector.h"
#include "Win32Error.h"

#include <cstdio>
#include <cstdlib>
#include <cwchar>
#include <exception>
#include <string>
#include <conio.h>
using namespace std;

namespace {

    void PrintUsage() {
        std::fprintf(stderr,
            "Usage:\n"
            "  token_suite inspect [--pid N]   Show user, integrity, groups, privileges\n"
            "  token_suite enable <Privilege>  Enable a privilege on THIS process's token\n");
    }

    bool ParsePid(const wchar_t* text, DWORD* pid) {
        wchar_t* end = nullptr;
        unsigned long value = std::wcstoul(text, &end, 10);
        if (end == text || *end != L'\0') {
            return false;
        }
        *pid = static_cast<DWORD>(value);
        return true;
    }

    int CmdInspect(int argc, wchar_t** argv) {
        bool havePid = false;
        DWORD pid = 0;

        for (int i = 2; i < argc; ++i) {
            std::wstring arg = argv[i];
            if (arg == L"--pid" && i + 1 < argc) {
                if (!ParsePid(argv[++i], &pid)) {
                    std::fprintf(stderr, "error: --pid needs a number\n");
                    return 2;
                }
                havePid = true;
            }
            else {
                PrintUsage();
                return 2;
            }
        }

        w32::ScopedHandle token = havePid ? w32::OpenTokenOfPid(pid)
            : w32::OpenTokenOfProcess(::GetCurrentProcess());

        if (havePid) {
            std::wprintf(L"Process      : PID %lu\n", static_cast<unsigned long>(pid));
        }
        else {
            std::wprintf(L"Process      : current (PID %lu)\n",
                static_cast<unsigned long>(::GetCurrentProcessId()));
        }

        w32::PrintReport(w32::InspectToken(token.get()));
        return 0;
    }
}  // namespace
#if !defined(RUN_SELFTEST)
int wmain(int argc, wchar_t** argv) {
    try {
        if (argc < 2) {
            PrintUsage();
            return 2;
        }
        const std::wstring command = argv[1];
        if (command == L"inspect") {
            return CmdInspect(argc, argv);
        }
        PrintUsage();
        return 2;
    }
    catch (const w32::Win32Error& e) {
        std::fprintf(stderr, "error: %s\n", e.what());
        return 1;
    }
    catch (const std::exception& e) {
        std::fprintf(stderr, "error: %s\n", e.what());
        return 1;
    }
	_getch();
	return 0;

}
#endif