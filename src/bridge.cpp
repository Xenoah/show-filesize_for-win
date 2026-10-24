// SPDX-License-Identifier: GPL-3.0-only
// Folder Size Guard Standalone 0.2.0 preview.
// Explorer signatures / cache workaround adapted from Michael Maltsev (m417z),
// Better file sizes in Explorer details v1.6. See THIRD_PARTY_NOTICES.md.
#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <cstddef>
using std::nullptr_t;
#include "common.h"
#include "worker_client.h"
#include "../vendor/minhook/include/MinHook.h"
#include <shlobj.h>
#include <propsys.h>
#include <shlwapi.h>
#include <algorithm>
#include <atomic>
#include <cstdint>
#include <deque>
#include <map>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

namespace {
constexpr PROPERTYKEY SizeKey={{0xB725F130,0x47EF,0x101A,{0xA5,0xF1,0x02,0x60,0x8C,0x9E,0xEB,0xAC}},12};
using Reply=fsgwin::ScanReply;
static_assert(sizeof(Reply)==40);
struct Handle {
    HANDLE h=nullptr;
    explicit Handle(HANDLE value=nullptr):h(value){}
    ~Handle(){if(h && h!=INVALID_HANDLE_VALUE) CloseHandle(h);}
    Handle(const Handle&)=delete; Handle& operator=(const Handle&)=delete;
};
struct Cached {std::optional<uint64_t> bytes; ULONGLONG expires=0; bool pending=true;};
std::wstring workerPath;
DWORD budget=5000, maxEntries=1000000, cacheMs=120000;
std::atomic<bool> enabled{false};
HANDLE ownerHandle=nullptr;
HMODULE selfModule=nullptr;
std::mutex lifecycle;
bool initialized=false;
std::atomic<bool> stopping{false};
std::atomic<unsigned> activeHooks{0}, fileOperations{0};
thread_local unsigned operationDepth=0, compareDepth=0;
thread_local bool collectionSize=false;
HANDLE stopEvent=nullptr, wakeEvent=nullptr, workerThread=nullptr;
std::mutex cacheMutex;
// Exact (case-sensitive) keys prevent aliasing different items in directories
// where Windows case sensitivity was explicitly enabled.
std::map<std::wstring,Cached> cache;
std::deque<std::wstring> queue;
struct HookScope {HookScope(){++activeHooks;} ~HookScope(){--activeHooks;}};
struct OperationScope {OperationScope(){++operationDepth;++fileOperations;} ~OperationScope(){--operationDepth;--fileOperations;}};
struct BoolScope {bool& v; bool prev; BoolScope(bool& r,bool n):v(r),prev(r){v=n;} ~BoolScope(){v=prev;}};
struct CountScope {unsigned& v; explicit CountScope(unsigned& n):v(n){++v;} ~CountScope(){--v;}};

bool localSyntax(const std::wstring& p) {
    if(p.size()<3 || p.size()>30000 || !((p[0]>=L'A'&&p[0]<=L'Z')||(p[0]>=L'a'&&p[0]<=L'z')) ||
       p[1]!=L':' || p[2]!=L'\\') return false;
    return p.find_first_of(L"\"*?",3)==std::wstring::npos && p.find(L':',2)==std::wstring::npos;
}

std::wstring parentOf(const std::wstring& p) {
    const size_t last=p.find_last_of(L'\\');
    return last<=2?p.substr(0,3):p.substr(0,last);
}
void notifyParent(const std::wstring& p) {
    // Invalidates only Shell view metadata. It does not change the directory.
    SHChangeNotify(SHCNE_UPDATEDIR,SHCNF_PATHW|SHCNF_FLUSHNOWAIT,p.c_str(),nullptr);
}

Reply runWorker(const std::wstring& path) {
    return fsgwin::scanWorker(workerPath,path,budget,maxEntries,stopEvent,ownerHandle);
}

std::optional<uint64_t> lookup(const std::wstring& path) {
    std::lock_guard<std::mutex> lock(cacheMutex);
    if(stopping || !enabled || fileOperations) return {};
    auto it=cache.find(path);
    if(it!=cache.end()) {
        if(it->second.pending || GetTickCount64()<it->second.expires) return it->second.bytes;
        cache.erase(it);
    }
    if(queue.size()>=128 || cache.size()>=512) return {};
    cache.emplace(path,Cached{});
    try {queue.push_back(path);} catch(...) {cache.erase(path); throw;}
    SetEvent(wakeEvent);
    return {};
}

DWORD WINAPI background(void*) {
    std::vector<std::wstring> changed;
    ULONGLONG lastNotify=0;
    try {
        for(;;) {
            if(stopping || WaitForSingleObject(ownerHandle,0)==WAIT_OBJECT_0) {enabled=false;stopping=true;break;}
            std::wstring path;
            {
                std::lock_guard<std::mutex> lock(cacheMutex);
                const auto now=GetTickCount64();
                for(auto it=cache.begin();it!=cache.end();) {
                    if(!it->second.pending && now>=it->second.expires) {
                        if(changed.size()<512) changed.push_back(parentOf(it->first));
                        it=cache.erase(it);
                    } else ++it;
                }
                if(!queue.empty() && !fileOperations) {path=std::move(queue.front());queue.pop_front();}
            }
            if(!path.empty()) {
                Reply r=runWorker(path);
                if(stopping || WaitForSingleObject(ownerHandle,0)==WAIT_OBJECT_0) {enabled=false;stopping=true;break;}
                {
                    std::lock_guard<std::mutex> lock(cacheMutex);
                    auto it=cache.find(path);
                    if(it!=cache.end()) {
                        it->second.pending=false;
                        it->second.expires=GetTickCount64()+(r.status==0?cacheMs:60000);
                        if(r.magic==0x31475346 && r.status==0) it->second.bytes=r.bytes;
                    }
                }
                if(r.magic==0x31475346 && r.status==0) changed.push_back(parentOf(path));
            }
            if(!changed.empty() && GetTickCount64()-lastNotify>=750 && !fileOperations) {
                std::sort(changed.begin(),changed.end());
                changed.erase(std::unique(changed.begin(),changed.end()),changed.end());
                for(const auto& parent:changed) {if(stopping || WaitForSingleObject(ownerHandle,0)==WAIT_OBJECT_0) {enabled=false;stopping=true;break;} notifyParent(parent);}
                changed.clear(); lastNotify=GetTickCount64();
            }
            if(path.empty()) {
                HANDLE waits[]={stopEvent,wakeEvent,ownerHandle};
                DWORD w=WaitForMultipleObjects(3,waits,FALSE,500);
                if(w==WAIT_OBJECT_0 || w==WAIT_OBJECT_0+2) {enabled=false;stopping=true;break;}
            }
        }
    } catch(...) {OutputDebugStringW(L"Folder Size Guard: background error; disabled.\n");enabled=false;stopping=true;}
    return 0;
}

std::wstring itemPath(void* folder,const ITEMID_CHILD* item) {
    IShellFolder2* sf=nullptr;
    if(FAILED(reinterpret_cast<IUnknown*>(folder)->QueryInterface(IID_IShellFolder2,reinterpret_cast<void**>(&sf)))) return {};
    struct Release {IShellFolder2* p; ~Release(){p->Release();}} release{sf};
    STRRET str{}; PWSTR path=nullptr;
    if(FAILED(sf->GetDisplayNameOf(item,SHGDN_FORPARSING,&str))) return {};
    if(FAILED(StrRetToStrW(&str,item,&path)) || !path) return {};
    struct Free {PWSTR p; ~Free(){CoTaskMemFree(p);}} free{path};
    std::wstring value=path;
    if(value.rfind(L"\\\\?\\",0)==0) value.erase(0,4);
    return localSyntax(value)?value:std::wstring{};
}

using GetSize_t=HRESULT(WINAPI*)(void*,const ITEMID_CHILD*,const void*,PROPVARIANT*);
GetSize_t originalSize=nullptr;
HRESULT WINAPI getSize(void* folder,const ITEMID_CHILD* child,const void* id,PROPVARIANT* value) {
    HookScope scope;
    HRESULT hr=originalSize(folder,child,id,value);
    if(stopping || !enabled || operationDepth || fileOperations || hr!=S_OK || !value ||
       value->vt!=VT_EMPTY || !child) return hr;
    try {
        const auto path=itemPath(folder,child);
        if(!path.empty()) if(auto bytes=lookup(path)) {
            value->uhVal.QuadPart=*bytes; value->vt=VT_UI8;
        }
    } catch(...) { /* Preserve original result if allocation/lookup fails. */ }
    return hr;
}
using Operation_t=HRESULT(__thiscall*)(void*);
Operation_t originalPrepare=nullptr,originalDo=nullptr;
HRESULT __thiscall prepare(void* p){HookScope h;OperationScope s;return originalPrepare(p);}
HRESULT __thiscall doOperation(void* p){HookScope h;OperationScope s;return originalDo(p);}
using ItemValue_t=HRESULT(WINAPI*)(void*,const void*,int,const PROPERTYKEY*,PROPVARIANT*,int*);
ItemValue_t originalItemValue=nullptr;
HRESULT WINAPI itemValue(void* p,const void* item,int mode,const PROPERTYKEY* key,PROPVARIANT* value,int* state) {
    HookScope h; BoolScope s(collectionSize,key && IsEqualPropertyKey(*key,SizeKey));
    return originalItemValue(p,item,mode,key,value,state);
}
using ItemProperty_t=HRESULT(__thiscall*)(void*,void*,const void*,int,const PROPERTYKEY*,int*,PROPVARIANT*);
ItemProperty_t originalItemProperty=nullptr;
HRESULT __thiscall itemProperty(void* p,void* store,const void* item,int type,const PROPERTYKEY* key,int* dirty,PROPVARIANT* value) {
    HookScope h;
    HRESULT hr=originalItemProperty(p,store,item,type,key,dirty,value);
    if(stopping || !enabled || fileOperations || !collectionSize || type==0 ||
       (SUCCEEDED(hr) && !(dirty && *dirty)) || !key || !value || !IsEqualPropertyKey(*key,SizeKey)) return hr;
    PropVariantClear(value);
    hr=originalItemProperty(p,store,item,0,key,nullptr,value);
    if(SUCCEEDED(hr) && dirty) *dirty=0;
    return hr;
}
using MapColumn_t=HRESULT(WINAPI*)(void*,unsigned,PROPERTYKEY*);
using Details_t=HRESULT(WINAPI*)(void*,const ITEMID_CHILD*,const PROPERTYKEY*,VARIANT*);
#ifdef _WIN64
using ColumnParam=INT_PTR;
#else
using ColumnParam=LONG;
#endif
using Compare_t=HRESULT(WINAPI*)(void*,ColumnParam,const ITEMIDLIST_RELATIVE*,const ITEMIDLIST_RELATIVE*);
MapColumn_t originalMap=nullptr; Details_t originalDetails=nullptr; Compare_t originalCompare=nullptr;
HRESULT WINAPI compare(void* p,ColumnParam column,const ITEMIDLIST_RELATIVE* a,const ITEMIDLIST_RELATIVE* b) {
    HookScope h;
    auto fallback=[&]{return originalCompare(p,column,a,b);};
    if(stopping || !enabled || fileOperations || compareDepth || !a || !b) return fallback();
    CountScope depth(compareDepth);
    // SHCIDS_ALLFIELDS / SHCIDS_CANONICALONLY requests aren't view sorting.
    if((static_cast<ULONG_PTR>(column)&~ULONG_PTR(SHCIDS_COLUMNMASK))!=0) return fallback();
    PROPERTYKEY key{};
    if(FAILED(originalMap(p,static_cast<unsigned>(column),&key)) || !IsEqualPropertyKey(key,SizeKey)) return fallback();
    VARIANT va{},vb{};
    bool ka=SUCCEEDED(originalDetails(p,reinterpret_cast<const ITEMID_CHILD*>(a),&key,&va)) && va.vt==VT_UI8;
    bool kb=SUCCEEDED(originalDetails(p,reinterpret_cast<const ITEMID_CHILD*>(b),&key,&vb)) && vb.vt==VT_UI8;
    uint64_t av=ka?va.ullVal:0,bv=kb?vb.ullVal:0;
    VariantClear(&va);VariantClear(&vb);
    if(ka!=kb) return ka?0xFFFF:1;
    if(ka && av!=bv) return av<bv?0xFFFF:1;
    return fallback();
}
}


namespace {
bool installNativeHooks(const fsgwin::Config& config) {
    using namespace fsgwin;
    HMODULE storage=GetModuleHandleW(L"windows.storage.dll");
    if(!storage)storage=LoadLibraryExW(L"windows.storage.dll",nullptr,LOAD_LIBRARY_SEARCH_SYSTEM32);
    if(!storage)return false;
    Image file(systemFile(L"windows.storage.dll"));
    if(!sameIdentity(file.identity(),config.identity))return false;
    auto* base=reinterpret_cast<const BYTE*>(storage);
    auto* nt=reinterpret_cast<const IMAGE_NT_HEADERS*>(base+reinterpret_cast<const IMAGE_DOS_HEADER*>(base)->e_lfanew);
    if(nt->FileHeader.TimeDateStamp!=config.identity.timestamp||nt->OptionalHeader.SizeOfImage!=config.identity.imageSize||
       nt->FileHeader.Machine!=config.identity.machine)return false;
    auto debug=nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];bool guidMatches=false;
    if(debug.VirtualAddress>=config.identity.imageSize||debug.Size>config.identity.imageSize-debug.VirtualAddress)return false;
    for(size_t pos=0;pos+sizeof(IMAGE_DEBUG_DIRECTORY)<=debug.Size;pos+=sizeof(IMAGE_DEBUG_DIRECTORY)) {
        auto* e=reinterpret_cast<const IMAGE_DEBUG_DIRECTORY*>(base+debug.VirtualAddress+pos);
        if(e->Type!=IMAGE_DEBUG_TYPE_CODEVIEW||e->SizeOfData<24||e->AddressOfRawData>=config.identity.imageSize||
           e->SizeOfData>config.identity.imageSize-e->AddressOfRawData)continue;
        const BYTE* p=base+e->AddressOfRawData;DWORD age=0;memcpy(&age,p+20,4);
        if(!memcmp(p,"RSDS",4)&&!memcmp(p+4,&config.identity.guid,16)&&age==config.identity.age)guidMatches=true;
    }
    if(!guidMatches)return false;
    void** originals[]={reinterpret_cast<void**>(&originalSize),reinterpret_cast<void**>(&originalPrepare),
        reinterpret_cast<void**>(&originalDo),reinterpret_cast<void**>(&originalItemValue),
        reinterpret_cast<void**>(&originalItemProperty),reinterpret_cast<void**>(&originalMap),
        reinterpret_cast<void**>(&originalDetails),reinterpret_cast<void**>(&originalCompare)};
    void* hooks[]={reinterpret_cast<void*>(getSize),reinterpret_cast<void*>(prepare),reinterpret_cast<void*>(doOperation),
        reinterpret_cast<void*>(itemValue),reinterpret_cast<void*>(itemProperty),nullptr,nullptr,reinterpret_cast<void*>(compare)};
    for(unsigned i:{0u,1u,2u,5u,6u,7u})if(!config.rvas[i])return false;
    if(bool(config.rvas[3])!=bool(config.rvas[4]))return false;
    for(unsigned i=0;i<SymbolCount;i++) {
        if(!config.rvas[i])continue;
        if(!file.executable(config.rvas[i]))return false;
        const BYTE* target=base+config.rvas[i];MEMORY_BASIC_INFORMATION m{};
        if(!VirtualQuery(target,&m,sizeof(m))||m.AllocationBase!=storage||m.Type!=MEM_IMAGE||
           !(m.Protect&(PAGE_EXECUTE|PAGE_EXECUTE_READ|PAGE_EXECUTE_READWRITE|PAGE_EXECUTE_WRITECOPY)))return false;
        // Refuse common entry detours. No attempt to overwrite another mod.
        if(hooks[i]&&(target[0]==0xE9||target[0]==0xEB||(target[0]==0xFF&&target[1]==0x25)))return false;
        for(unsigned j=0;j<i;j++)if(config.rvas[j]==config.rvas[i])return false;
    }
    if(MH_Initialize()!=MH_OK)return false;
    for(unsigned i=0;i<SymbolCount;i++)if(config.rvas[i]) {
        void* target=const_cast<BYTE*>(base)+config.rvas[i];
        if(!hooks[i]) {*originals[i]=target;continue;}
        if(MH_CreateHook(target,hooks[i],originals[i])!=MH_OK) {MH_Uninitialize();return false;}
    }
    // Keep DLL + trampolines resident until Explorer exits. Disabling switches
    // every callback to pass-through, avoiding an unsafe in-flight unload.
    HMODULE pinned=nullptr;
    if(!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS|GET_MODULE_HANDLE_EX_FLAG_PIN,
        reinterpret_cast<LPCWSTR>(&getSize),&pinned)) {MH_Uninitialize();return false;}
    if(MH_EnableHook(MH_ALL_HOOKS)!=MH_OK) {
        MH_DisableHook(MH_ALL_HOOKS);return false;
    }
    return true;
}
}

extern "C" __declspec(dllexport) DWORD WINAPI FsgStart(void* raw) {
    using namespace fsgwin;
    try {
        std::lock_guard<std::mutex> guard(lifecycle);
        if(!raw)return ERROR_INVALID_PARAMETER;
        const Config config=*static_cast<const Config*>(raw);
        if(config.magic!=0x32475346||config.version!=2||config.length!=sizeof(Config)||
           config.budget<100||config.budget>30000||config.entries<1||config.entries>10000000||
           config.cacheSeconds<10||config.cacheSeconds>600)return ERROR_INVALID_PARAMETER;
        if(enabled) {
            if(ownerHandle&&WaitForSingleObject(ownerHandle,0)==WAIT_TIMEOUT)return ERROR_ALREADY_EXISTS;
            enabled=false;stopping=true;SetEvent(stopEvent);
        }
        if(workerThread) {
            if(WaitForSingleObject(workerThread,0)!=WAIT_OBJECT_0)return ERROR_BUSY;
            CloseHandle(workerThread);workerThread=nullptr;
        }
        if(ownerHandle){CloseHandle(ownerHandle);ownerHandle=nullptr;}
        ownerHandle=OpenProcess(SYNCHRONIZE|PROCESS_QUERY_LIMITED_INFORMATION,FALSE,config.ownerPid);
        if(!ownerHandle||createdAt(ownerHandle)!=config.ownerCreated)return ERROR_INVALID_OWNER;
        workerPath=directory(modulePath(selfModule))+L"\\FolderSizeWorker.exe";
        DWORD attr=GetFileAttributesW(workerPath.c_str());
        if(attr==INVALID_FILE_ATTRIBUTES||(attr&FILE_ATTRIBUTE_DIRECTORY))return ERROR_FILE_NOT_FOUND;
        budget=config.budget;maxEntries=config.entries;cacheMs=config.cacheSeconds*1000;
        if(!stopEvent)stopEvent=CreateEventW(nullptr,TRUE,FALSE,nullptr);
        if(!wakeEvent)wakeEvent=CreateEventW(nullptr,FALSE,FALSE,nullptr);
        if(!stopEvent||!wakeEvent)return ERROR_NOT_ENOUGH_MEMORY;
        stopping=true;enabled=false;
        if(!initialized) {
            if(!installNativeHooks(config))return ERROR_REVISION_MISMATCH;
            initialized=true;
        }
        {std::lock_guard<std::mutex> lock(cacheMutex);cache.clear();queue.clear();}
        ResetEvent(stopEvent);ResetEvent(wakeEvent);stopping=false;
        enabled=true;
        workerThread=CreateThread(nullptr,0,background,nullptr,0,nullptr);
        if(!workerThread){enabled=false;stopping=true;return ERROR_NOT_ENOUGH_MEMORY;}
        return ERROR_SUCCESS;
    }catch(...){enabled=false;stopping=true;if(stopEvent)SetEvent(stopEvent);return ERROR_UNHANDLED_EXCEPTION;}
}
extern "C" __declspec(dllexport) DWORD WINAPI FsgDisable(void*) {
    enabled=false;stopping=true;if(stopEvent)SetEvent(stopEvent);return ERROR_SUCCESS;
}
extern "C" __declspec(dllexport) DWORD WINAPI FsgStatus(void*) {return enabled?1:0;}
BOOL WINAPI DllMain(HINSTANCE h,DWORD reason,void*) {
    if(reason==DLL_PROCESS_ATTACH) {selfModule=h;DisableThreadLibraryCalls(h);}
    return TRUE;
}
