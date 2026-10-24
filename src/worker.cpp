// SPDX-License-Identifier: GPL-3.0-only
#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <cstdlib>
#include "scan_core.h"

static std::wstring extended(const std::wstring& p) {return L"\\\\?\\"+p;}
// Check EVERY component, including the root, before enumerating. Reparse
// entries are also checked again immediately before descent (best effort;
// a concurrently modified filesystem is not an atomic snapshot).
static bool allowedDirectory(const std::wstring& path) {
    if(!fsg::plainLocalPath(path)) return false;
    std::wstring drive=path.substr(0,3);
    if(GetDriveTypeW(drive.c_str())!=DRIVE_FIXED) return false;
    for(size_t i=3;i<=path.size();++i) {
        if(i!=path.size() && path[i]!=L'\\') continue;
        std::wstring p=extended(path.substr(0,i));
        DWORD attributes=GetFileAttributesW(p.c_str());
        if(attributes==INVALID_FILE_ATTRIBUTES || !(attributes&FILE_ATTRIBUTE_DIRECTORY) ||
           fsg::unsafe(attributes)) return false;
    }
    return true;
}
template<class Visitor>
static uint32_t enumerate(const std::wstring& path, Visitor visitor) {
    if(!allowedDirectory(path)) return ERROR_ACCESS_DENIED;
    std::wstring pattern=extended(path)+(path.back()==L'\\'?L"*":L"\\*");
    WIN32_FIND_DATAW data{};
    HANDLE handle=FindFirstFileExW(pattern.c_str(),FindExInfoBasic,&data,
                                 FindExSearchNameMatch,nullptr,FIND_FIRST_EX_LARGE_FETCH);
    if(handle==INVALID_HANDLE_VALUE && GetLastError()==ERROR_INVALID_PARAMETER)
        handle=FindFirstFileExW(pattern.c_str(),FindExInfoBasic,&data,
                               FindExSearchNameMatch,nullptr,0);
    if(handle==INVALID_HANDLE_VALUE) {
        DWORD err=GetLastError();
        return err==ERROR_FILE_NOT_FOUND?0:err;
    }
    uint32_t error=0;
    try {
        for(;;) {
            fsg::Entry e{data.cFileName,data.dwFileAttributes,
                (uint64_t(data.nFileSizeHigh)<<32)|data.nFileSizeLow};
            if(!visitor(e)) break;
            if(!FindNextFileW(handle,&data)) {
                DWORD err=GetLastError();
                if(err!=ERROR_NO_MORE_FILES) error=err;
                break;
            }
        }
    } catch(...) {FindClose(handle); throw;}
    FindClose(handle);
    return error;
}
int wmain(int argc, wchar_t** argv) {
    SetErrorMode(SEM_FAILCRITICALERRORS|SEM_NOOPENFILEERRORBOX|SEM_NOGPFAULTERRORBOX);
    SetPriorityClass(GetCurrentProcess(),BELOW_NORMAL_PRIORITY_CLASS);
    fsg::Result result;
    try {
        if(argc==4) {
            wchar_t* end1=nullptr; wchar_t* end2=nullptr;
            uint64_t budget=wcstoull(argv[2],&end1,10), maxEntries=wcstoull(argv[3],&end2,10);
            if(*end1 || *end2 || budget<100 || budget>30000 || maxEntries<1 || maxEntries>10000000)
                result.status=(uint32_t)fsg::Status::Unsupported;
            else if(!allowedDirectory(argv[1])) result.status=(uint32_t)fsg::Status::Unsupported;
            else result=fsg::scan(argv[1],fsg::Limits{budget,maxEntries,1024,128},
                [](const std::wstring& p, auto v){return enumerate(p,v);},
                []{return GetTickCount64();});
        }
    } catch(...) {result.status=(uint32_t)fsg::Status::Failed;}
    // The only output goes to the pipe supplied by the parent process.
    DWORD written=0;
    if(!WriteFile(GetStdHandle(STD_OUTPUT_HANDLE),&result,sizeof(result),&written,nullptr) ||
        written!=sizeof(result)) return 10;
    return 0;
}
