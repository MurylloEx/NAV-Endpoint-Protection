#include "pch.h"
#include "system.h"

PSID WINAPI GetLocalSystemSid() {
    PSID SystemSid = NULL;
    SID_IDENTIFIER_AUTHORITY IdentifierAuthority = SECURITY_NT_AUTHORITY;

    if (!AllocateAndInitializeSid(&IdentifierAuthority, 1, SECURITY_LOCAL_SYSTEM_RID, 0, 0, 0, 0, 0, 0, 0, &SystemSid)) {
        return NULL;
    }

    return SystemSid;
}

BOOL WINAPI IsRunningAsLocalSystem() {
    HANDLE TokenHandle = NULL;
    DWORD TokenSize = 0;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &TokenHandle)) {
        return FALSE;
    }

    if (!GetTokenInformation(TokenHandle, TOKEN_INFORMATION_CLASS::TokenUser, NULL, NULL, &TokenSize)) {
        if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
            CloseHandle(TokenHandle);
            return FALSE;
        }
    }

    PTOKEN_USER TokenUser = (PTOKEN_USER)GlobalAlloc(GMEM_FIXED | GMEM_ZEROINIT, TokenSize);

    if (!TokenUser) {
        CloseHandle(TokenHandle);
        return FALSE;
    }

    if (!GetTokenInformation(TokenHandle, TOKEN_INFORMATION_CLASS::TokenUser, TokenUser, TokenSize, &TokenSize)) {
        CloseHandle(TokenHandle);
        GlobalFree(TokenUser);
        return FALSE;
    }

    CloseHandle(TokenHandle);

    PSID LocalSystemSid = GetLocalSystemSid();

    if (!LocalSystemSid) {
        GlobalFree(TokenUser);
        return FALSE;
    }

    BOOL IsLocalSystem = EqualSid(TokenUser->User.Sid, LocalSystemSid);

    FreeSid(LocalSystemSid);
    GlobalFree(TokenUser);

    return IsLocalSystem;
}
