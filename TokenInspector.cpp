/* This file is a small Win32 utility layer for inspecting a Windows access token.
*/


#include "TokenInspector.h"
#include "Win32Error.h"
#include <sddl.h>

namespace w32 {

    // ===========================================================================
    // Handle acquisition
    // ===========================================================================
    ScopedHandle OpenTokenOfProcess(HANDLE process) {
        ScopedHandle token;
        // This call is expected to succeed if the process handle is valid and has PROCESS_QUERY_INFORMATION or PROCESS_QUERY_LIMITED_INFORMATION access.
        // If it fails, ThrowLastError will throw a Win32Error exception with the API name and the last error code.
        // The token handle is independent of the process handle, so the process handle can be closed as soon as we return (the wrapper does it).
        // This calls the global Win32 API function OpenProcessToken, which retrieves a handle to the access token associated with a process.
        if (!::OpenProcessToken(process, TOKEN_QUERY, token.receive())) {
            ThrowLastError("OpenProcessToken");
        }
        return token;
    }

    ScopedHandle OpenTokenOfPid(DWORD pid) {
        // PROCESS_QUERY_LIMITED_INFORMATION is enough to read the token of most processes
        // and works in more cases than PROCESS_QUERY_INFORMATION.
        ScopedHandle process(::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid));
        if (!process) {
            ThrowLastError("OpenProcess");
        }
        // The token handle is independent of the process handle, so the process handle can
        // be closed as soon as we return (the wrapper does it).
        return OpenTokenOfProcess(process.get());
    }

    // ===========================================================================
    // The two-call pattern
    // ===========================================================================
    std::vector<BYTE> QueryTokenInfo(HANDLE token, TOKEN_INFORMATION_CLASS cls) {
        DWORD needed = 0;

        // Call 1: null buffer. This is EXPECTED to fail with ERROR_INSUFFICIENT_BUFFER
        // and report the required size in `needed`.
        if (::GetTokenInformation(token, cls, nullptr, 0, &needed)) {
            return std::vector<BYTE>();  // succeeded with no data
        }
        DWORD err = ::GetLastError();
        if (err != ERROR_INSUFFICIENT_BUFFER) {
            throw Win32Error("GetTokenInformation (size query)", err);
        }

        // Call 2: real fetch. The data can grow between the calls (e.g. groups added),
        // so retry a few times instead of assuming the first size stays correct.
        for (int attempt = 0; attempt < 3; ++attempt) {
            std::vector<BYTE> buffer(needed);
            if (::GetTokenInformation(token, cls, buffer.data(), static_cast<DWORD>(buffer.size()),
                &needed)) {
                return buffer;
            }
            err = ::GetLastError();
            if (err != ERROR_INSUFFICIENT_BUFFER) {
                throw Win32Error("GetTokenInformation", err);
            }
        }
        throw Win32Error("GetTokenInformation (size kept changing)", ERROR_INSUFFICIENT_BUFFER);
    }

    // ===========================================================================
    // SID helpers
    // ===========================================================================
    std::wstring SidToString(PSID sid) {
        LPWSTR raw = nullptr;
        if (!::ConvertSidToStringSidW(sid, &raw)) {
            ThrowLastError("ConvertSidToStringSidW");
        }
        LocalPtr<wchar_t> guard(raw);  // LocalFree on every path, including exceptions
        return std::wstring(guard.get());
    }

    std::wstring LookupAccount(PSID sid) {
        // Same two-call idea: sizes are in characters.
        DWORD nameLen = 0;
        DWORD domainLen = 0;
        SID_NAME_USE use;
        BOOL ok = ::LookupAccountSidW(nullptr, sid, nullptr, &nameLen, nullptr, &domainLen, &use);
        if (ok || ::GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
            return std::wstring();  // not resolvable: that is normal for some SIDs
        }

        std::vector<wchar_t> name(nameLen);
        std::vector<wchar_t> domain(domainLen);
        if (!::LookupAccountSidW(nullptr, sid, name.data(), &nameLen, domain.data(), &domainLen,
            &use)) {
            return std::wstring();
        }
        // On success the lengths exclude the terminating null.
        std::wstring result;
        if (domainLen != 0) {
            result.assign(domain.data(), domainLen);
            result += L'\\';
        }
        result.append(name.data(), nameLen);
        return result;
    }

    // ===========================================================================
    // Integrity level
    // ===========================================================================
    DWORD GetIntegrityRid(HANDLE token) {
        std::vector<BYTE> buffer = QueryTokenInfo(token, TokenIntegrityLevel);
        if (buffer.size() < sizeof(TOKEN_MANDATORY_LABEL)) {
            throw std::runtime_error("TokenIntegrityLevel buffer too small");
        }
        const TOKEN_MANDATORY_LABEL* label =
            reinterpret_cast<const TOKEN_MANDATORY_LABEL*>(buffer.data());
        PSID sid = label->Label.Sid;  // points inside `buffer`: still alive here

        if (!::IsValidSid(sid)) {
            throw std::runtime_error("integrity label SID is not valid");
        }
        // Integrity level = the LAST sub-authority (RID) of the label SID.
        UCHAR count = *::GetSidSubAuthorityCount(sid);
        if (count == 0) {
            throw std::runtime_error("integrity label SID has no sub-authorities");
        }
        return *::GetSidSubAuthority(sid, static_cast<DWORD>(count - 1));
    }

    std::wstring IntegrityName(DWORD rid) {
        switch (rid) {
        case SECURITY_MANDATORY_UNTRUSTED_RID:         return L"Untrusted";
        case SECURITY_MANDATORY_LOW_RID:               return L"Low";
        case SECURITY_MANDATORY_MEDIUM_RID:            return L"Medium";
        case SECURITY_MANDATORY_MEDIUM_PLUS_RID:       return L"Medium Plus";
        case SECURITY_MANDATORY_HIGH_RID:              return L"High";
        case SECURITY_MANDATORY_SYSTEM_RID:            return L"System";
        case SECURITY_MANDATORY_PROTECTED_PROCESS_RID: return L"Protected Process";
        default: {
            wchar_t text[32];
            std::swprintf(text, 32, L"Unknown (0x%04lX)", static_cast<unsigned long>(rid));
            return text;
        }
        }
    }

    // Privilege name lookup (two-call again: buffer size in characters)
    static std::wstring PrivilegeName(const LUID& luid) {
        std::vector<wchar_t> buffer(64);
        for (int attempt = 0; attempt < 2; ++attempt) {
            DWORD cch = static_cast<DWORD>(buffer.size());
            if (::LookupPrivilegeNameW(nullptr, const_cast<LUID*>(&luid), buffer.data(), &cch)) {
                return std::wstring(buffer.data(), cch);  // cch excludes the terminator on success.It creates a string without copying the trailing null.
            }
            if (::GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
                ThrowLastError("LookupPrivilegeNameW");
            }
            buffer.resize(cch);  // on failure cch is the required size including the terminator
        }
        ThrowLastError("LookupPrivilegeNameW (retry)");
    }

    // Build the report
    TokenReport InspectToken(HANDLE token) {
        TokenReport r;

        // --- User ---------------------------------------------------------------
        {
            std::vector<BYTE> buffer = QueryTokenInfo(token, TokenUser);
            if (buffer.size() < sizeof(TOKEN_USER)) {
                throw std::runtime_error("TokenUser buffer too small");
            }
            const TOKEN_USER* user = reinterpret_cast<const TOKEN_USER*>(buffer.data());
            r.userSid = SidToString(user->User.Sid);
            r.userAccount = LookupAccount(user->User.Sid);
        }

        // --- Session, type, impersonation level ---------------------------------
        r.sessionId = QueryTokenValue<DWORD>(token, TokenSessionId);
        r.type = QueryTokenValue<TOKEN_TYPE>(token, TokenType);
        if (r.type == TokenImpersonation) {
            // Querying TokenImpersonationLevel on the token as it's imppersonation token and not primary, so only ask here.
            r.impersonationLevel =
                QueryTokenValue<SECURITY_IMPERSONATION_LEVEL>(token, TokenImpersonationLevel);
            r.hasImpersonationLevel = true;
        }

        // --- Integrity ----------------------------------------------------------
        r.integrityRid = GetIntegrityRid(token);

        // --- UAC: elevation type, elevated flag, linked token -------------------
        r.elevationType = QueryTokenValue<TOKEN_ELEVATION_TYPE>(token, TokenElevationType);
        r.isElevated = QueryTokenValue<TOKEN_ELEVATION>(token, TokenElevation).TokenIsElevated != 0;

        if (r.elevationType != TokenElevationTypeDefault) {
            // TOKEN_LINKED_TOKEN is fixed-size, so one direct call is enough.
            TOKEN_LINKED_TOKEN linked = {};
            DWORD returned = 0;
            if (::GetTokenInformation(token, TokenLinkedToken, &linked, sizeof(linked), &returned)) {
                ScopedHandle linkedToken(linked.LinkedToken);
                r.hasLinkedToken = true;
                r.linkedType = QueryTokenValue<TOKEN_TYPE>(linkedToken.get(), TokenType);
                r.linkedIntegrityRid = GetIntegrityRid(linkedToken.get());
            }
            else {
                r.linkedTokenError = ::GetLastError();
            }
        }

        // --- Groups -------------------------------------------------------------
        {
            std::vector<BYTE> buffer = QueryTokenInfo(token, TokenGroups);
            if (buffer.size() < sizeof(DWORD)) {
                throw std::runtime_error("TokenGroups buffer too small");
            }
            const TOKEN_GROUPS* groups = reinterpret_cast<const TOKEN_GROUPS*>(buffer.data());
            r.groups.reserve(groups->GroupCount);
            for (DWORD i = 0; i < groups->GroupCount; ++i) {
                GroupEntry entry;
                entry.sid = SidToString(groups->Groups[i].Sid);
                entry.account = LookupAccount(groups->Groups[i].Sid);
                entry.attributes = groups->Groups[i].Attributes;
                r.groups.push_back(std::move(entry));
            }
        }

        // --- Privileges ---------------------------------------------------------
        {
            std::vector<BYTE> buffer = QueryTokenInfo(token, TokenPrivileges);
            if (buffer.size() < sizeof(DWORD)) {
                throw std::runtime_error("TokenPrivileges buffer too small");
            }
            const TOKEN_PRIVILEGES* privs = reinterpret_cast<const TOKEN_PRIVILEGES*>(buffer.data());
            r.privileges.reserve(privs->PrivilegeCount);
            for (DWORD i = 0; i < privs->PrivilegeCount; ++i) {
                PrivilegeEntry entry;
                entry.name = PrivilegeName(privs->Privileges[i].Luid);
                entry.attributes = privs->Privileges[i].Attributes;
                r.privileges.push_back(std::move(entry));
            }
        }

        return r;
    }

    // Printing
    static const wchar_t* TokenTypeName(TOKEN_TYPE t) {
        return t == TokenPrimary ? L"Primary" : L"Impersonation";
    }

    static const wchar_t* ImpersonationLevelName(SECURITY_IMPERSONATION_LEVEL l) {
        switch (l) {
        case SecurityAnonymous:      return L"Anonymous";
        case SecurityIdentification: return L"Identification";
        case SecurityImpersonation:  return L"Impersonation";
        case SecurityDelegation:     return L"Delegation";
        default:                     return L"Unknown";
        }
    }

    static const wchar_t* ElevationTypeName(TOKEN_ELEVATION_TYPE t) {
        switch (t) {
        case TokenElevationTypeDefault: return L"Default (no split token)";
        case TokenElevationTypeFull:    return L"Full (elevated)";
        case TokenElevationTypeLimited: return L"Limited (filtered)";
        default:                        return L"Unknown";
        }
    }

    static std::wstring GroupFlags(DWORD attributes) {
        std::wstring text;
        auto add = [&](DWORD bits, const wchar_t* label) {
            if ((attributes & bits) == bits) {  // SE_GROUP_LOGON_ID spans two bits
                if (!text.empty()) text += L',';
                text += label;
            }
            };
        add(SE_GROUP_ENABLED, L"Enabled");
        add(SE_GROUP_USE_FOR_DENY_ONLY, L"DenyOnly");
        add(SE_GROUP_MANDATORY, L"Mandatory");
        add(SE_GROUP_LOGON_ID, L"LogonId");
        add(SE_GROUP_INTEGRITY, L"Integrity");
        add(SE_GROUP_OWNER, L"Owner");
        return text;
    }

    void PrintReport(const TokenReport& r) {
        std::wprintf(L"User         : %ls\n", r.userAccount.empty() ? L"(unresolved)" : r.userAccount.c_str());
        std::wprintf(L"User SID     : %ls\n", r.userSid.c_str());
        std::wprintf(L"Session      : %lu\n", static_cast<unsigned long>(r.sessionId));
        std::wprintf(L"Token type   : %ls", TokenTypeName(r.type));
        if (r.hasImpersonationLevel) {
            std::wprintf(L" (level: %ls)", ImpersonationLevelName(r.impersonationLevel));
        }
        std::wprintf(L"\n");
        std::wprintf(L"Integrity    : %ls (0x%04lX)\n", IntegrityName(r.integrityRid).c_str(),
            static_cast<unsigned long>(r.integrityRid));
        std::wprintf(L"Elevation    : %ls, IsElevated=%d\n", ElevationTypeName(r.elevationType),
            r.isElevated ? 1 : 0);

        if (r.elevationType == TokenElevationTypeDefault) {
            std::wprintf(L"Linked token : none (token is not split)\n");
        }
        else if (r.hasLinkedToken) {
            std::wprintf(L"Linked token : %ls, integrity %ls\n", TokenTypeName(r.linkedType),
                IntegrityName(r.linkedIntegrityRid).c_str());
        }
        else {
            std::wprintf(L"Linked token : unavailable (error %lu)\n",
                static_cast<unsigned long>(r.linkedTokenError));
        }

        std::wprintf(L"\nGroups (%u)\n", static_cast<unsigned>(r.groups.size()));
        for (const GroupEntry& g : r.groups) {
            std::wprintf(L"  %-40ls %ls\n", g.account.empty() ? g.sid.c_str() : g.account.c_str(),
                GroupFlags(g.attributes).c_str());
        }

        std::wprintf(L"\nPrivileges (%u)\n", static_cast<unsigned>(r.privileges.size()));
        for (const PrivilegeEntry& p : r.privileges) {
            std::wprintf(L"  %-36ls %ls%ls\n", p.name.c_str(), p.enabled() ? L"Enabled" : L"Disabled",
                (p.attributes & SE_PRIVILEGE_ENABLED_BY_DEFAULT) ? L" (default)" : L"");
        }
    }
}