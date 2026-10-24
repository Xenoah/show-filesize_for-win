// SPDX-License-Identifier: GPL-3.0-only
#pragma once
#include <cstdint>
#include <limits>
#include <string>
#include <vector>

namespace fsg {
enum class Status : uint32_t { Complete=0, Incomplete=1, Timeout=2, Limit=3, Unsupported=4, Failed=5 };
constexpr uint32_t Directory=0x10, Reparse=0x400, Offline=0x1000;
constexpr uint32_t RecallOnOpen=0x40000, RecallOnAccess=0x400000;
struct Result {
    uint32_t magic=0x31475346, status=static_cast<uint32_t>(Status::Failed);
    uint64_t bytes=0, entries=0, skipped=0, errors=0;
};
static_assert(sizeof(Result)==40, "IPC layout");
struct Entry { std::wstring name; uint32_t attributes; uint64_t bytes; };
struct Limits { uint64_t milliseconds=5000, entries=1000000; size_t pending=1024, depth=128; };
inline bool unsafe(uint32_t attributes) {
    return (attributes & (Reparse|Offline|RecallOnOpen|RecallOnAccess))!=0;
}
inline bool plainLocalPath(const std::wstring& path) {
    if(path.size()<3 || path.size()>30000 ||
       !((path[0]>=L'A'&&path[0]<=L'Z')||(path[0]>=L'a'&&path[0]<=L'z')) ||
       path[1]!=L':' || path[2]!=L'\\') return false;
    size_t start=3;
    for(size_t i=3;i<=path.size();++i) {
        if(i<path.size() && (path[i]<32 || path[i]==L':' || path[i]==L'/' ||
           path[i]==L'*' || path[i]==L'?' || path[i]==L'"' || path[i]==L'<' ||
           path[i]==L'>' || path[i]==L'|')) return false;
        if(i==path.size() || path[i]==L'\\') {
            const auto part=path.substr(start,i-start);
            if(part==L"." || part==L".." || (!part.empty() &&
                (part.back()==L'.' || part.back()==L' '))) return false;
            if(part.empty() && i!=path.size()) return false;
            start=i+1;
        }
    }
    return true;
}
// enumerate(path, visitor) returns 0 on success, otherwise an OS error code.
// No filesystem mutation is part of this interface.
template<class Enumerate, class Tick>
Result scan(const std::wstring& root, Limits limits, Enumerate enumerate, Tick tick) {
    Result result;
    if(!plainLocalPath(root)) {result.status=(uint32_t)Status::Unsupported; return result;}
    struct Pending {std::wstring path; size_t depth;};
    std::vector<Pending> stack{{root,0}};
    const uint64_t began=tick();
    Status state=Status::Complete;
    bool stopped=false;
    while(!stack.empty() && !stopped) {
        if(tick()-began>=limits.milliseconds) {state=Status::Timeout; break;}
        Pending current=std::move(stack.back()); stack.pop_back();
        const uint32_t error=enumerate(current.path,[&](const Entry& e) {
            if(tick()-began>=limits.milliseconds) {state=Status::Timeout; stopped=true; return false;}
            if(e.name==L"." || e.name==L"..") return true;
            if(++result.entries>limits.entries) {state=Status::Limit; stopped=true; return false;}
            if(unsafe(e.attributes)) {++result.skipped; return true;}
            if(e.attributes&Directory) {
                if(stack.size()>=limits.pending || current.depth>=limits.depth) {
                    state=Status::Limit; stopped=true; return false;
                }
                std::wstring next=current.path+(current.path.back()==L'\\'?L"":L"\\")+e.name;
                if(!plainLocalPath(next)) {++result.skipped; return true;}
                stack.push_back({std::move(next), current.depth+1});
            } else {
                if(e.bytes>std::numeric_limits<uint64_t>::max()-result.bytes) {
                    state=Status::Limit; stopped=true; return false;
                }
                result.bytes+=e.bytes;
            }
            return true;
        });
        if(error) ++result.errors;
    }
    if(state==Status::Complete && (result.errors || result.skipped)) state=Status::Incomplete;
    result.status=(uint32_t)state;
    return result;
}
}
