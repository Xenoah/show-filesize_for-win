// SPDX-License-Identifier: GPL-3.0-only
#pragma once
#include "common.h"
#include <tlhelp32.h>
#include <algorithm>
#include <set>

namespace fsgwin {
inline std::vector<BYTE> userToken(HANDLE process) {
    HANDLE raw=nullptr;
    if(!OpenProcessToken(process,TOKEN_QUERY,&raw))return {};
    Handle token(raw);DWORD size=0;GetTokenInformation(raw,TokenUser,nullptr,0,&size);
    if(!size||size>1024*1024)return {};
    std::vector<BYTE> result(size);
    if(!GetTokenInformation(raw,TokenUser,result.data(),size,&size))return {};
    return result;
}
inline bool ownedExplorer(HANDLE process,DWORD pid) {
    DWORD session=0,current=0;
    if(!ProcessIdToSessionId(pid,&session)||!ProcessIdToSessionId(GetCurrentProcessId(),&current)||session!=current)return false;
    wchar_t p[32768];DWORD length=32768;
    if(!QueryFullProcessImageNameW(process,0,p,&length))return false;
    wchar_t root[32768];UINT n=GetWindowsDirectoryW(root,32768);
    if(!n||n>=32768||_wcsicmp(p,(std::wstring(root)+L"\\explorer.exe").c_str()))return false;
    auto a=userToken(GetCurrentProcess()),b=userToken(process);
    return !a.empty()&&!b.empty()&&EqualSid(reinterpret_cast<TOKEN_USER*>(a.data())->User.Sid,
                                          reinterpret_cast<TOKEN_USER*>(b.data())->User.Sid);
}
inline std::vector<DWORD> explorerPids() {
    std::vector<DWORD> result;Handle snapshot(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0));
    if(snapshot.h==INVALID_HANDLE_VALUE)throw std::runtime_error("Process list unavailable");
    PROCESSENTRY32W e{};e.dwSize=sizeof(e);
    if(Process32FirstW(snapshot.h,&e))do {
        if(_wcsicmp(e.szExeFile,L"explorer.exe"))continue;
        Handle process(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,FALSE,e.th32ProcessID));
        if(process.h&&ownedExplorer(process.h,e.th32ProcessID))result.push_back(e.th32ProcessID);
    }while(Process32NextW(snapshot.h,&e));
    return result;
}
struct Module {ULONG_PTR base=0;DWORD size=0;std::wstring path;};
inline Module findModule(DWORD pid,const std::wstring& name,bool fullPath=false) {
    Handle snapshot(CreateToolhelp32Snapshot(TH32CS_SNAPMODULE|TH32CS_SNAPMODULE32,pid));
    if(snapshot.h==INVALID_HANDLE_VALUE)return {};
    MODULEENTRY32W e{};e.dwSize=sizeof(e);
    if(Module32FirstW(snapshot.h,&e))do {
        if(!_wcsicmp(fullPath?e.szExePath:e.szModule,name.c_str()))
            return {reinterpret_cast<ULONG_PTR>(e.modBaseAddr),e.modBaseSize,e.szExePath};
    }while(Module32NextW(snapshot.h,&e));
    return {};
}
inline DWORD remoteCall(HANDLE process,ULONG_PTR address,const void* data,size_t bytes,DWORD timeout=15000) {
    void* remote=nullptr;
    if(bytes) {
        remote=VirtualAllocEx(process,nullptr,bytes,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE);
        if(!remote)throw std::runtime_error("Explorer allocation denied");
        SIZE_T written=0;
        if(!WriteProcessMemory(process,remote,data,bytes,&written)||written!=bytes) {
            VirtualFreeEx(process,remote,0,MEM_RELEASE);throw std::runtime_error("Explorer request transfer failed");
        }
    }
    Handle thread(CreateRemoteThread(process,nullptr,0,reinterpret_cast<LPTHREAD_START_ROUTINE>(address),remote,0,nullptr));
    if(!thread.h){if(remote)VirtualFreeEx(process,remote,0,MEM_RELEASE);throw std::runtime_error("Explorer extension launch denied");}
    if(WaitForSingleObject(thread.h,timeout)!=WAIT_OBJECT_0) {
        // Never terminate an Explorer thread or free memory it may still use.
        throw std::runtime_error("Explorer request pending; no thread was terminated. Retry after a few seconds.");
    }
    DWORD code=ERROR_GEN_FAILURE;GetExitCodeThread(thread.h,&code);
    if(remote)VirtualFreeEx(process,remote,0,MEM_RELEASE);
    return code;
}
inline Module loadBridge(HANDLE process,DWORD pid,const std::wstring& dll) {
    Module existing=findModule(pid,L"FolderSizeGuardBridge.dll");
    if(existing.base) {
        if(_wcsicmp(existing.path.c_str(),dll.c_str()))throw std::runtime_error("A bridge from another folder is still loaded. Sign out/in before changing versions or paths.");
        return existing;
    }
    HMODULE kernel=GetModuleHandleW(L"kernel32.dll");
    FARPROC loader=GetProcAddress(kernel,"LoadLibraryW");HMODULE owner=nullptr;
    if(!loader||!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS|GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
        reinterpret_cast<LPCWSTR>(loader),&owner))throw std::runtime_error("System loader unavailable");
    auto ownerPath=modulePath(owner);Module remoteOwner=findModule(pid,ownerPath,true);
    if(!remoteOwner.base)throw std::runtime_error("Matching system loader module not found");
    ULONG_PTR offset=reinterpret_cast<ULONG_PTR>(loader)-reinterpret_cast<ULONG_PTR>(owner);
    if(offset>=remoteOwner.size)throw std::runtime_error("System loader address outside module");
    remoteCall(process,remoteOwner.base+offset,dll.c_str(),(dll.size()+1)*sizeof(wchar_t));
    Module loaded=findModule(pid,dll,true);
    if(!loaded.base)throw std::runtime_error("Bridge did not load (architecture or security policy)");
    return loaded;
}
inline DWORD commandExplorer(DWORD pid,const std::wstring& dll,const char* command,const Config* config) {
    Handle process(OpenProcess(PROCESS_QUERY_INFORMATION|PROCESS_QUERY_LIMITED_INFORMATION|PROCESS_CREATE_THREAD|
        PROCESS_VM_OPERATION|PROCESS_VM_WRITE|PROCESS_VM_READ|SYNCHRONIZE,FALSE,pid));
    if(!process.h||!ownedExplorer(process.h,pid))throw std::runtime_error("Cannot access current user's Explorer");
    Module remote=config?loadBridge(process.h,pid,dll):findModule(pid,dll,true);
    if(!remote.base)return ERROR_NOT_FOUND;
    Image image(dll);DWORD rva=image.exported(command);
    if(!rva||rva>=remote.size)throw std::runtime_error("Bridge export mismatch");
    return remoteCall(process.h,remote.base+rva,config,config?sizeof(Config):0);
}
}
