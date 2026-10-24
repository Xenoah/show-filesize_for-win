// SPDX-License-Identifier: GPL-3.0-only
#pragma once
#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <string>
#include <vector>
#include <stdexcept>
#include <cstdint>
#include <cstring>

namespace fsgwin {
struct Handle {
    HANDLE h=nullptr;
    explicit Handle(HANDLE p=nullptr):h(p){}
    ~Handle(){if(h && h!=INVALID_HANDLE_VALUE)CloseHandle(h);}
    Handle(const Handle&)=delete; Handle& operator=(const Handle&)=delete;
};
inline std::wstring modulePath(HMODULE module=nullptr) {
    std::vector<wchar_t> b(32768);
    DWORD n=GetModuleFileNameW(module,b.data(),(DWORD)b.size());
    if(!n||n>=b.size())throw std::runtime_error("Module path unavailable");
    return {b.data(),n};
}
inline std::wstring directory(const std::wstring& p){return p.substr(0,p.find_last_of(L'\\'));}
inline std::wstring systemFile(const wchar_t* name) {
    wchar_t dir[32768];UINT n=GetSystemDirectoryW(dir,32768);
    if(!n||n>=32768)throw std::runtime_error("System directory unavailable");
    return std::wstring(dir)+L"\\"+name;
}
struct Identity {GUID guid{};DWORD age=0,timestamp=0,imageSize=0;WORD machine=0;};
constexpr unsigned SymbolCount=8;
struct Config {
    DWORD magic=0x32475346, version=2, length=sizeof(Config), ownerPid=0;
    uint64_t ownerCreated=0;
    Identity identity{};
    DWORD rvas[SymbolCount]{};
    DWORD budget=5000, entries=1000000, cacheSeconds=120;
};
inline uint64_t filetime(FILETIME f){return (uint64_t(f.dwHighDateTime)<<32)|f.dwLowDateTime;}
inline uint64_t createdAt(HANDLE process){FILETIME c,e,k,u;return GetProcessTimes(process,&c,&e,&k,&u)?filetime(c):0;}

// A read-only PE image mapping. Never executes an image's DllMain.
struct Image {
    HMODULE handle=nullptr;const BYTE* base=nullptr;DWORD size=0;
    explicit Image(const std::wstring& p) {
        handle=LoadLibraryExW(p.c_str(),nullptr,LOAD_LIBRARY_AS_IMAGE_RESOURCE);
        if(!handle)throw std::runtime_error("Cannot map image");
        base=reinterpret_cast<const BYTE*>(reinterpret_cast<ULONG_PTR>(handle)&~ULONG_PTR(3));
        const auto* dos=reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
        if(dos->e_magic!=IMAGE_DOS_SIGNATURE || dos->e_lfanew<0 || dos->e_lfanew>1024*1024) {FreeLibrary(handle);handle=nullptr;throw std::runtime_error("Bad DOS header");}
        const auto* nt=reinterpret_cast<const IMAGE_NT_HEADERS*>(base+dos->e_lfanew);
        if(nt->Signature!=IMAGE_NT_SIGNATURE) {FreeLibrary(handle);handle=nullptr;throw std::runtime_error("Bad PE header");}
        size=nt->OptionalHeader.SizeOfImage;
    }
    ~Image(){if(handle)FreeLibrary(handle);}
    Image(const Image&)=delete;
    const IMAGE_NT_HEADERS* nt()const{return reinterpret_cast<const IMAGE_NT_HEADERS*>(base+reinterpret_cast<const IMAGE_DOS_HEADER*>(base)->e_lfanew);}
    bool contains(uint64_t rva,uint64_t bytes=1)const{return rva<size&&bytes<=size-rva;}
    bool executable(DWORD rva)const{
        auto* n=nt();auto* s=IMAGE_FIRST_SECTION(n);
        for(unsigned i=0;i<n->FileHeader.NumberOfSections;i++)
            if(rva>=s[i].VirtualAddress&&uint64_t(rva)-s[i].VirtualAddress<s[i].Misc.VirtualSize)
                return (s[i].Characteristics&IMAGE_SCN_MEM_EXECUTE)!=0;
        return false;
    }
    Identity identity()const {
        Identity out;auto* n=nt();out.machine=n->FileHeader.Machine;
        out.timestamp=n->FileHeader.TimeDateStamp;out.imageSize=size;
        auto d=n->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];
        if(!contains(d.VirtualAddress,d.Size))throw std::runtime_error("Missing debug directory");
        for(size_t at=0;at+sizeof(IMAGE_DEBUG_DIRECTORY)<=d.Size;at+=sizeof(IMAGE_DEBUG_DIRECTORY)) {
            auto* e=reinterpret_cast<const IMAGE_DEBUG_DIRECTORY*>(base+d.VirtualAddress+at);
            if(e->Type!=IMAGE_DEBUG_TYPE_CODEVIEW||e->SizeOfData<25||!contains(e->AddressOfRawData,e->SizeOfData))continue;
            const BYTE* p=base+e->AddressOfRawData;
            if(std::memcmp(p,"RSDS",4))continue;
            std::memcpy(&out.guid,p+4,16);std::memcpy(&out.age,p+20,4);
            return out;
        }
        throw std::runtime_error("RSDS identity unavailable");
    }
    DWORD exported(const char* name)const {
        auto d=nt()->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        if(!contains(d.VirtualAddress,sizeof(IMAGE_EXPORT_DIRECTORY)))return 0;
        auto* e=reinterpret_cast<const IMAGE_EXPORT_DIRECTORY*>(base+d.VirtualAddress);
        if(!contains(e->AddressOfNames,uint64_t(e->NumberOfNames)*4)||
           !contains(e->AddressOfNameOrdinals,uint64_t(e->NumberOfNames)*2)||
           !contains(e->AddressOfFunctions,uint64_t(e->NumberOfFunctions)*4))return 0;
        auto* names=reinterpret_cast<const DWORD*>(base+e->AddressOfNames);
        auto* ords=reinterpret_cast<const WORD*>(base+e->AddressOfNameOrdinals);
        auto* functions=reinterpret_cast<const DWORD*>(base+e->AddressOfFunctions);
        for(DWORD i=0;i<e->NumberOfNames;i++){
            if(!contains(names[i],strlen(name)+1)||memcmp(base+names[i],name,strlen(name)+1))continue;
            if(ords[i]>=e->NumberOfFunctions)return 0;
            DWORD rva=functions[ords[i]];
            if(rva>=d.VirtualAddress&&uint64_t(rva)-d.VirtualAddress<d.Size)return 0;
            return executable(rva)?rva:0;
        }
        return 0;
    }
};
inline bool sameIdentity(const Identity& a,const Identity& b){return !memcmp(&a.guid,&b.guid,16)&&a.age==b.age&&a.timestamp==b.timestamp&&a.imageSize==b.imageSize&&a.machine==b.machine;}
}
