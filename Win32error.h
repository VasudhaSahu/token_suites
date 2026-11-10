// Win32Error.h - exception type for failed Win32 calls. C++14, header-only.
//
// Design choice: the library layer (TokenInspector, later TokenMutator/ProcessLauncher)
// THROWS, and main() is the single place that catches and prints. That keeps every
// function body free of "if (!ok) { cleanup; return false; }" ladders; the RAII wrappers
// from Win32Utils.h do the cleanup during stack unwinding.
#pragma once

#include "Win32Utils.h"

#include <stdexcept>
#include <string>

namespace w32 {

    class Win32Error : public std::runtime_error {
    public:
		// Construct a Win32Error with the API name and the error code. It calling base class constructor with a message that includes the API name and the error code, as well as a human-readable description of the error.
        Win32Error(const char* api, DWORD code) : std::runtime_error(Build(api, code)), code_(code) {}
        DWORD code() const noexcept { return code_; }

    private:
        static std::string Build(const char* api, DWORD code) {
            std::string msg = std::string(api) + " failed: error " + std::to_string(code);

            char* raw = nullptr;
			// FormatMessageA allocates a buffer with LocalAlloc; we must free it with LocalFree.
            DWORD n = ::FormatMessageA(
                FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
                FORMAT_MESSAGE_IGNORE_INSERTS,
                nullptr, code, 0, reinterpret_cast<LPSTR>(&raw), 0, nullptr);
            LocalPtr<char> guard(raw);  // FormatMessage's buffer is LocalAlloc'd: same deleter
            if (n != 0 && raw != nullptr) {
                std::string text(raw, n);
                while (!text.empty() &&
                    (text.back() == '\r' || text.back() == '\n' || text.back() == ' ')) {
                    text.pop_back();
                }
                msg += " (" + text + ")";
            }
            return msg;
        }

        DWORD code_;
    };

    // Call IMMEDIATELY after the failing API: GetLastError() is overwritten by the next
    // Win32 call, including ones made from destructors or logging.
    [[noreturn]] inline void ThrowLastError(const char* api) {
        throw Win32Error(api, ::GetLastError());
    }

}  // namespace w32