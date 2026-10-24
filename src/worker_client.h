// SPDX-License-Identifier: GPL-3.0-only
#pragma once
#include "common.h"
#include "quote_argument.h"
namespace fsgwin {
struct ScanReply {uint32_t magic=0,status=5;uint64_t bytes=0,entries=0,skipped=0,errors=0;};
static_assert(sizeof(ScanReply)==40);
inline ScanReply scanWorker(const std::wstring& workerPath,const std::wstring& path,DWORD budget,DWORD maxEntries,HANDLE stopEvent,HANDLE ownerHandle) {
    ScanReply result;
    Handle job(CreateJobObjectW(nullptr,nullptr));
    if(!job.h) return result;
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limit{};
    limit.BasicLimitInformation.LimitFlags=JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE|
        JOB_OBJECT_LIMIT_ACTIVE_PROCESS|JOB_OBJECT_LIMIT_PROCESS_MEMORY;
    limit.BasicLimitInformation.ActiveProcessLimit=1;
    limit.ProcessMemoryLimit=128*1024*1024;
    if(!SetInformationJobObject(job.h,JobObjectExtendedLimitInformation,&limit,sizeof(limit))) return result;
    SECURITY_ATTRIBUTES sa{sizeof(sa),nullptr,TRUE};
    HANDLE readRaw=nullptr,writeRaw=nullptr;
    if(!CreatePipe(&readRaw,&writeRaw,&sa,4096)) return result;
    Handle reader(readRaw),writer(writeRaw);
    if(!SetHandleInformation(reader.h,HANDLE_FLAG_INHERIT,0)) return result;
    SIZE_T attrSize=0;
    InitializeProcThreadAttributeList(nullptr,1,0,&attrSize);
    std::vector<BYTE> attrBuffer(attrSize);
    auto attrs=reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(attrBuffer.data());
    if(!InitializeProcThreadAttributeList(attrs,1,0,&attrSize)) return result;
    struct AttrGuard {LPPROC_THREAD_ATTRIBUTE_LIST p; ~AttrGuard(){DeleteProcThreadAttributeList(p);}} attrGuard{attrs};
    HANDLE inherited[]={writer.h};
    if(!UpdateProcThreadAttribute(attrs,0,PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
                                  inherited,sizeof(inherited),nullptr,nullptr)) return result;
    STARTUPINFOEXW startup{}; startup.StartupInfo.cb=sizeof(startup);
    startup.StartupInfo.dwFlags=STARTF_USESTDHANDLES;
    startup.StartupInfo.hStdOutput=writer.h;
    startup.StartupInfo.hStdError=writer.h;
    startup.lpAttributeList=attrs;
    std::wstring command=quoteArgument(workerPath)+L" "+quoteArgument(path)+L" "+
        std::to_wstring(budget)+L" "+std::to_wstring(maxEntries);
    if(command.size()>=32767) return result;
    PROCESS_INFORMATION pi{};
    if(!CreateProcessW(workerPath.c_str(),command.data(),nullptr,nullptr,TRUE,
        CREATE_NO_WINDOW|CREATE_SUSPENDED|EXTENDED_STARTUPINFO_PRESENT|BELOW_NORMAL_PRIORITY_CLASS,
        nullptr,nullptr,&startup.StartupInfo,&pi)) return result;
    Handle process(pi.hProcess),thread(pi.hThread);
    if(!AssignProcessToJobObject(job.h,process.h)) {
        // Only the newly created, still suspended worker is terminated.
        TerminateProcess(process.h,11); return result;
    }
    CloseHandle(writer.h); writer.h=nullptr;
    if(ResumeThread(thread.h)==DWORD(-1)) return result;
    HANDLE waits[]={stopEvent,process.h,ownerHandle};
    DWORD wait=WaitForMultipleObjects(3,waits,FALSE,budget+1500);
    if(wait!=WAIT_OBJECT_0+1) {result.status=2; return result;}
    DWORD code=0,available=0,got=0;
    if(!GetExitCodeProcess(process.h,&code) || code!=0 ||
       !PeekNamedPipe(reader.h,nullptr,0,nullptr,&available,nullptr) || available!=sizeof(result) ||
       !ReadFile(reader.h,&result,sizeof(result),&got,nullptr) || got!=sizeof(result) ||
       result.magic!=0x31475346 || result.status>5) return ScanReply{};
    if(result.status==0 && (result.errors || result.skipped)) return ScanReply{};
    return result;
}

}
