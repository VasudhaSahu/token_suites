// TokenInspector.h - Slice 1 (Problem 1): read-only inspection of a Windows access token.
#pragma once

#include "Win32Utils.h"

#include <cstring>
#include <stdexcept>
#include <string>
#include <vector>

namespace w32 {

    // ---- Handle acquisition ----------------------------------------------------
    ScopedHandle OpenTokenOfProcess(HANDLE process);
    ScopedHandle OpenTokenOfPid(DWORD pid);

    // ---- The two-call pattern --------------------------------------------------
    // Call 1 asks "how big?" (expected to FAIL with ERROR_INSUFFICIENT_BUFFER),
    // call 2 fetches into a buffer of exactly that size.
    std::vector<BYTE> QueryTokenInfo(HANDLE token, TOKEN_INFORMATION_CLASS cls);

    // Fixed-size classes (TokenType, TokenSessionId, TokenElevation, ...): same pattern,
    // copied out into a T so the caller never touches the byte buffer.
    template <class T>
    T QueryTokenValue(HANDLE token, TOKEN_INFORMATION_CLASS cls) {
        std::vector<BYTE> buffer = QueryTokenInfo(token, cls);
        if (buffer.size() < sizeof(T)) {
            throw std::runtime_error("GetTokenInformation returned fewer bytes than expected");
        }
        T value;
        std::memcpy(&value, buffer.data(), sizeof(T));
        return value;
    }

    // ---- SID helpers -----------------------------------------------------------
    std::wstring SidToString(PSID sid);    // ConvertSidToStringSidW + LocalFree via LocalPtr
    std::wstring LookupAccount(PSID sid);  // "DOMAIN\name", or L"" if it cannot be resolved

    // ---- Integrity level -------------------------------------------------------
    DWORD GetIntegrityRid(HANDLE token);   // last sub-authority of the label SID
    std::wstring IntegrityName(DWORD rid);

    // ---- Report ----------------------------------------------------------------
    struct GroupEntry {
        std::wstring sid;
        std::wstring account;
        DWORD attributes = 0;
    };

    struct PrivilegeEntry {
        std::wstring name;
        DWORD attributes = 0;
        bool enabled() const { return (attributes & SE_PRIVILEGE_ENABLED) != 0; }
    };

    struct TokenReport {
        std::wstring userSid;
        std::wstring userAccount;
        DWORD sessionId = 0;

        TOKEN_TYPE type = TokenPrimary;
        bool hasImpersonationLevel = false;
        SECURITY_IMPERSONATION_LEVEL impersonationLevel = SecurityAnonymous;

        DWORD integrityRid = 0;

        TOKEN_ELEVATION_TYPE elevationType = TokenElevationTypeDefault;
        bool isElevated = false;

        bool hasLinkedToken = false;
        DWORD linkedTokenError = 0;  // why the query failed, if it did
        TOKEN_TYPE linkedType = TokenPrimary;
        DWORD linkedIntegrityRid = 0;

        std::vector<GroupEntry> groups;
        std::vector<PrivilegeEntry> privileges;
    };

    TokenReport InspectToken(HANDLE token);
    void PrintReport(const TokenReport& report);

}  // namespace w32