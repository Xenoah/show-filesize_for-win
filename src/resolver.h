// SPDX-License-Identifier: GPL-3.0-only
#pragma once
#include "common.h"
#include "symbol_names.h"
#include <dbghelp.h>
#include <winhttp.h>
#include <shlobj.h>
#include <functional>
#include <algorithm>

namespace fsgwin {
using Log=std::function<void(const std::wstring&)>;
inline std::wstring keyFor(const Identity& id) {
    wchar_t s[80];const auto& g=id.guid;
    swprintf(s,80,L"%08lX%04X%04X%02X%02X%02X%02X%02X%02X%02X%02X%lX",
        g.Data1,g.Data2,g.Data3,g.Data4[0],g.Data4[1],g.Data4[2],g.Data4[3],g.Data4[4],g.Data4[5],g.Data4[6],g.Data4[7],id.age);
    return s;
}
inline void ensureDirectory(const std::wstring& p) {
    if(!CreateDirectoryW(p.c_str(),nullptr)&&GetLastError()!=ERROR_ALREADY_EXISTS)
        throw std::runtime_error("Cannot create private application directory");
    DWORD a=GetFileAttributesW(p.c_str());
    if(a==INVALID_FILE_ATTRIBUTES||!(a&FILE_ATTRIBUTE_DIRECTORY)||(a&FILE_ATTRIBUTE_REPARSE_POINT))
        throw std::runtime_error("Unexpected application directory/reparse point");
}
inline std::wstring dataDirectory() {
    wchar_t root[MAX_PATH];
    if(FAILED(SHGetFolderPathW(nullptr,CSIDL_LOCAL_APPDATA,nullptr,SHGFP_TYPE_CURRENT,root)))
        throw std::runtime_error("LocalAppData unavailable");
    std::wstring p=std::wstring(root)+L"\\FolderSizeGuard";ensureDirectory(p);
    p+=L"\\standalone-v0.2";ensureDirectory(p);return p;
}
struct InternetHandle {HINTERNET h;explicit InternetHandle(HINTERNET v):h(v){}~InternetHandle(){if(h)WinHttpCloseHandle(h);}InternetHandle(const InternetHandle&)=delete;};
inline void downloadSymbols(const Identity& id,const std::wstring& folder,Log log) {
    std::wstring target=folder+L"\\windows.storage.pdb";
    DWORD attr=GetFileAttributesW(target.c_str());
    if(attr!=INVALID_FILE_ATTRIBUTES) {
        if(attr&(FILE_ATTRIBUTE_DIRECTORY|FILE_ATTRIBUTE_REPARSE_POINT))throw std::runtime_error("Unexpected symbol cache entry");
        log(L"保存済みのMicrosoftシンボルを照合します。");return;
    }
    log(L"Microsoftから、このWindows版に対応するシンボルを取得中…");
    InternetHandle session(WinHttpOpen(L"FolderSizeGuard/0.2",WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
        WINHTTP_NO_PROXY_NAME,WINHTTP_NO_PROXY_BYPASS,0));
    if(!session.h)throw std::runtime_error("WinHTTP unavailable");
    WinHttpSetTimeouts(session.h,10000,10000,15000,15000);
    InternetHandle connection(WinHttpConnect(session.h,L"msdl.microsoft.com",INTERNET_DEFAULT_HTTPS_PORT,0));
    if(!connection.h)throw std::runtime_error("Cannot connect to Microsoft symbol server");
    std::wstring url=L"/download/symbols/windows.storage.pdb/"+keyFor(id)+L"/windows.storage.pdb";
    InternetHandle request(WinHttpOpenRequest(connection.h,L"GET",url.c_str(),nullptr,
        WINHTTP_NO_REFERER,WINHTTP_DEFAULT_ACCEPT_TYPES,WINHTTP_FLAG_SECURE));
    if(!request.h)throw std::runtime_error("Cannot create symbol request");
    DWORD policy=WINHTTP_OPTION_REDIRECT_POLICY_DISALLOW_HTTPS_TO_HTTP;
    WinHttpSetOption(request.h,WINHTTP_OPTION_REDIRECT_POLICY,&policy,sizeof(policy));
    if(!WinHttpSendRequest(request.h,WINHTTP_NO_ADDITIONAL_HEADERS,0,WINHTTP_NO_REQUEST_DATA,0,0,0)||
       !WinHttpReceiveResponse(request.h,nullptr))throw std::runtime_error("Symbol download connection/TLS failed");
    DWORD status=0,bytes=sizeof(status);
    if(!WinHttpQueryHeaders(request.h,WINHTTP_QUERY_STATUS_CODE|WINHTTP_QUERY_FLAG_NUMBER,
        WINHTTP_HEADER_NAME_BY_INDEX,&status,&bytes,WINHTTP_NO_HEADER_INDEX)||status!=200)
        throw std::runtime_error("Microsoft symbol unavailable (HTTP response was not 200)");
    std::wstring partial=folder+L"\\download-"+std::to_wstring(GetCurrentProcessId())+L"-"+std::to_wstring(GetTickCount64())+L".part";
    Handle file(CreateFileW(partial.c_str(),GENERIC_WRITE,0,nullptr,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,nullptr));
    if(file.h==INVALID_HANDLE_VALUE)throw std::runtime_error("Cannot create symbol cache file");
    std::vector<BYTE> buffer(65536);uint64_t total=0;ULONGLONG start=GetTickCount64();
    for(;;) {
        DWORD read=0,wrote=0;
        if(!WinHttpReadData(request.h,buffer.data(),(DWORD)buffer.size(),&read))throw std::runtime_error("Symbol download interrupted");
        if(!read)break;
        total+=read;
        if(total>256ull*1024*1024 || GetTickCount64()-start>180000)throw std::runtime_error("Symbol download limit exceeded");
        if(!WriteFile(file.h,buffer.data(),read,&wrote,nullptr)||wrote!=read)throw std::runtime_error("Cannot write private symbol cache");
    }
    if(total<64)throw std::runtime_error("Symbol response too small");
    FlushFileBuffers(file.h);CloseHandle(file.h);file.h=nullptr;
    // Only renames a new file within our own symbol cache. Never replaces a file.
    if(!MoveFileExW(partial.c_str(),target.c_str(),0))throw std::runtime_error("Cannot finalize private symbol cache");
}
struct SymbolContext {Config* config;DWORD64 base;const Image* image;bool duplicate=false;};
inline BOOL CALLBACK enumSymbol(PSYMBOL_INFOW s,ULONG,void* raw) {
    auto* c=static_cast<SymbolContext*>(raw);
    try {
        if(s->Address<c->base||s->Address-c->base>UINT32_MAX)return TRUE;
        DWORD rva=(DWORD)(s->Address-c->base);
        if(!c->image->executable(rva))return TRUE;
        std::wstring decorated(s->Name,s->NameLen);wchar_t full[8192];
        for(DWORD flags:{DWORD(0x20800),DWORD(0x800),DWORD(0)}) {
            std::wstring name=decorated;
            if(UnDecorateSymbolNameW(decorated.c_str(),full,8192,flags))name=full;
            for(unsigned i=0;i<SymbolCount;i++)if(name==symbolNames[i]) {
                if(c->config->rvas[i]&&c->config->rvas[i]!=rva)c->duplicate=true;
                c->config->rvas[i]=rva;
            }
        }
    }catch(...){c->duplicate=true;return FALSE;}
    return TRUE;
}
inline Config resolve(Log log) {
    Config c;c.ownerPid=GetCurrentProcessId();c.ownerCreated=createdAt(GetCurrentProcess());
    std::wstring path=systemFile(L"windows.storage.dll");Image image(path);c.identity=image.identity();
#ifdef _WIN64
    if(c.identity.machine!=IMAGE_FILE_MACHINE_AMD64)throw std::runtime_error("Unsupported architecture (x64 required)");
#else
    if(c.identity.machine!=IMAGE_FILE_MACHINE_I386)throw std::runtime_error("Unsupported architecture (x86 required)");
#endif
    std::wstring cache=dataDirectory()+L"\\symbols";ensureDirectory(cache);
    cache+=L"\\"+keyFor(c.identity);ensureDirectory(cache);
    downloadSymbols(c.identity,cache,log);
    log(L"Windows標準DbgHelpで内部関数を厳密照合中…");
    HANDLE process=GetCurrentProcess();
    SymSetOptions(SYMOPT_EXACT_SYMBOLS|SYMOPT_FAIL_CRITICAL_ERRORS|SYMOPT_NO_PROMPTS|SYMOPT_IGNORE_NT_SYMPATH);
    if(!SymInitializeW(process,cache.c_str(),FALSE))throw std::runtime_error("Windows DbgHelp initialization failed");
    struct SymGuard {HANDLE p;~SymGuard(){SymCleanup(p);}} guard{process};
    DWORD64 base=SymLoadModuleExW(process,nullptr,path.c_str(),L"fsg_storage",0x10000000,image.size,nullptr,0);
    if(!base)throw std::runtime_error("Windows DbgHelp could not load matching PDB");
    IMAGEHLP_MODULEW64 info{};info.SizeOfStruct=sizeof(info);
    if(!SymGetModuleInfoW64(process,base,&info)||info.SymType!=SymPdb||info.PdbUnmatched||
       info.PdbAge!=c.identity.age||memcmp(&info.PdbSig70,&c.identity.guid,16))
        throw std::runtime_error("PDB GUID/age verification failed; no hooks installed");
    SymbolContext context{&c,base,&image};
    if(!SymEnumSymbolsW(process,base,nullptr,enumSymbol,&context)||context.duplicate)
        throw std::runtime_error("Symbol enumeration was ambiguous or failed");
    for(unsigned i:{0u,1u,2u,5u,6u,7u})if(!c.rvas[i])throw std::runtime_error("Required exact Explorer signature unavailable; no hooks installed");
    if(bool(c.rvas[3])!=bool(c.rvas[4]))throw std::runtime_error("Partial collection signature pair; no hooks installed");
    for(unsigned i=0;i<SymbolCount;i++)for(unsigned j=i+1;j<SymbolCount;j++)
        if(c.rvas[i]&&c.rvas[i]==c.rvas[j])throw std::runtime_error("Duplicate hook address rejected");
    log(L"シンボルとDLLの版が一致しました。");return c;
}
}
