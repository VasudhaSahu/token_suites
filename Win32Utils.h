// Win32Utils.h
// Slice 0 (Problem 8): move-only RAII wrappers for Win32 resources. C++14.
//
// Design in one sentence:
//   UniqueResource<Traits> owns exactly one resource; each Traits type supplies
//   three facts: the value type, what "invalid" looks like, and how to close it.
//
// Rule for the rest of the suite: no raw HANDLE / SC_HANDLE / HKEY / CredHandle
// lives in a variable. Every API that returns one goes straight into a wrapper.#pragma once

#pragma once // this is a header guard used by the compiler to avoid including this header multiple times

#ifndef WIN32_LEAN_AND_MEAN 
#define WIN32_LEAN_AND_MEAN // this is used to define the macro 
#endif // !WIN32_LEAN_AND_MEAN 
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef SECURITY_WIN32
#define SECURITY_WIN32  // sspi.h refuses to compile without SECURITY_WIN32 (or _KERNEL)
#endif

#include <windows.h> // for Win32 APIs
#include <winsvc.h> // for OpenSCManager / OpenService / StartService / ControlService
#include <wtsapi32.h> // for WTSQueryUserToken
#include <userenv.h> // for CreateEnvironmentBlock / DestroyEnvironmentBlock
#include <sspi.h> // for CredHandle / SecInvalidateHandle / SecIsValidHandle / FreeCredentialsHandle

#include <memory> // for std::unique_ptr
#include <utility> // for std::swap


// Convenience for a single-file Visual Studio project (e.g. a live coding round).
// CMake links the same libraries; duplicates are harmless.
#ifdef _MSC_VER
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "wtsapi32.lib")
#pragma comment(lib, "userenv.lib")
#pragma comment(lib, "secur32.lib")
#endif

namespace w32
{
	// ---------------------------------------------------------------------------
	// Generic owner. Traits requirements:
	//   using type = ...;                          // the raw resource type
	//   static type invalid() noexcept;            // the "no resource" value
	//   static bool is_valid(type) noexcept;       // never compare with == (CredHandle is a struct)
	//   static void close(type) noexcept;          // release the resource
	// --------------------

	template <class Traits>
	class UniqueResource
	{
	public:
		using type = typename Traits::type;
		//Constructor
		UniqueResource() noexcept : value_(Traits::invalid()) {}
		UniqueResource(type v) noexcept : value_(v) {}
		//Destructor
		~UniqueResource() { reset(); }

		//Copy Constructor and Copy Assignment are deleted to make this class move-only
		UniqueResource(const UniqueResource&) = delete;
		UniqueResource& operator=(const UniqueResource&) = delete;

		//Move Constructor
		UniqueResource(UniqueResource&& other) noexcept :value_(other.release()) {}
		//Move Assignment
		UniqueResource& operator=(UniqueResource&& other)noexcept
		{
			if (this != &other)
			{
				reset(other.release());
			}
			return *this;
		}
		//get method
		type get() const noexcept { return value_; }
		// valid method
		bool valid() const noexcept { return Traits::is_valid(value_); }
		//
		explicit operator bool() const noexcept { return valid(); }

		// Give up ownership WITHOUT closing. Caller is now responsible.
		type release() noexcept {
			type t = value_;
			value_ = Traits::invalid();
			return t;
		}

		// Close the current resource (if any) and adopt v.
		// Swap-then-close order keeps the object consistent even if close() is slow.
		void reset(type v = Traits::invalid()) noexcept {
			type old = value_;
			value_ = v;
			if (Traits::is_valid(old)) {
				Traits::close(old);
			}
		}

		// For out-parameters: OpenProcessToken(..., token.receive()).
		// Closes anything held first so a reused wrapper cannot leak.
		// Named method instead of operator& (overloading & breaks std::addressof and containers).
		type* receive() noexcept {
			reset();
			return &value_;
		}

		void swap(UniqueResource& other) noexcept { std::swap(value_, other.value_); }

	private:
		type value_;
	};

	// ---------------------------------------------------------------------------
	// Traits. Note the TWO flavours of HANDLE: the failure value depends on the API.
	//   OpenProcess / OpenProcessToken / CreateEvent / CreateMutex ... fail with nullptr
	//   CreateFile / FindFirstFile-family-ish APIs ...... fail with INVALID_HANDLE_VALUE
	// Wrapping CreateFile in the nullptr flavour makes a failed open look "valid",
	// and the destructor then calls CloseHandle(INVALID_HANDLE_VALUE).
	// ---------------------------------------------------------------------------

	// Traits for a Win32 HANDLE. The value type is HANDLE, the invalid value is
	// nullptr, and the close function is CloseHandle().
	struct NullHandleTraits {
		using type = HANDLE;
		static type invalid() noexcept { return nullptr; }
		static bool is_valid(type h) noexcept { return h != nullptr; }
		static void close(type h) noexcept { ::CloseHandle(h); }
	};

	struct FileHandleTraits {
		using type = HANDLE;
		static type invalid() noexcept { return INVALID_HANDLE_VALUE; }
		static bool is_valid(type h) noexcept { return h != INVALID_HANDLE_VALUE; }
		static void close(type h) noexcept { ::CloseHandle(h); }
	};

	// Traits for a Win32 SC_HANDLE. The value type is SC_HANDLE, the invalid
	// value is nullptr, and the close function is CloseServiceHandle().
	struct ServiceHandleTraits {
		using type = SC_HANDLE;
		static type invalid() noexcept { return nullptr; }
		static bool is_valid(type h) noexcept { return h != nullptr; }
		static void close(type h) noexcept { ::CloseServiceHandle(h); }
	};

	// Traits for a Win32 HKEY. The value type is HKEY, the invalid value is
	// nullptr, and the close function is RegCloseKey().
	// Only wrap keys you opened/created. Predefined keys (HKEY_CURRENT_USER,
	// HKEY_LOCAL_MACHINE, ...) must never be closed by you.
	struct RegKeyTraits {
		using type = HKEY;
		static type invalid() noexcept { return nullptr; }
		static bool is_valid(type k) noexcept { return k != nullptr; }
		static void close(type k) noexcept { ::RegCloseKey(k); }
	};

	// CredHandle is a struct { ULONG_PTR dwLower, dwUpper; }, not a pointer.
	// Its "invalid" state is both fields == (ULONG_PTR)-1 (SecInvalidateHandle).
	struct CredHandleTraits {
		using type = CredHandle;
		static type invalid() noexcept {
			CredHandle h;
			SecInvalidateHandle(&h);
			return h;
		}
		static bool is_valid(type h) noexcept {
			return SecIsValidHandle(&h) != 0;
		}
		static void close(type h) noexcept { ::FreeCredentialsHandle(&h); }
	};

	using ScopedHandle = UniqueResource<NullHandleTraits>;
	using ScopedFileHandle = UniqueResource<FileHandleTraits>;
	using ScopedServiceHandle = UniqueResource<ServiceHandleTraits>;
	using ScopedRegKey = UniqueResource<RegKeyTraits>;
	using ScopedCredHandle = UniqueResource<CredHandleTraits>;

	// ---------------------------------------------------------------------------
	// Pointer-style resources: std::unique_ptr with a custom deleter.
	// Usage pattern: receive into a raw local, then adopt it immediately.
	//     LPWSTR raw = nullptr;
	//     if (!ConvertSidToStringSidW(sid, &raw)) { ...error... }
	//     LocalPtr<wchar_t> str(raw);
	// ---------------------------------------------------------------------------
	struct LocalFreeDeleter {
		void operator()(void* p) const noexcept { ::LocalFree(p); }
	};
	struct EnvBlockDeleter {
		void operator()(void* p) const noexcept { ::DestroyEnvironmentBlock(p); }
	};
	struct WtsFreeDeleter {
		void operator()(void* p) const noexcept { ::WTSFreeMemory(p); }
	};

	template< class T> using LocalPtr = std::unique_ptr<T, LocalFreeDeleter>;
	template<class T> using WtsMemPtr = std::unique_ptr<T, WtsFreeDeleter>;
	using EnvBlockPtr = std::unique_ptr<void, EnvBlockDeleter>;

} // namespace winutils