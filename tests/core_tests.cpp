// SPDX-License-Identifier: GPL-3.0-only
#include "../src/scan_core.h"
#include <cassert>
#include <iostream>
#include <map>

using namespace fsg;
struct FakeFS {
    std::map<std::wstring,std::vector<Entry>> dirs;
    std::vector<std::wstring> visited{};
    uint64_t now=0, step=0;
    Result run(Limits limits={}) {
        return scan(L"C:\\test",limits,[&](const std::wstring& p,auto visitor){
            visited.push_back(p);
            auto it=dirs.find(p);
            if(it==dirs.end()) return uint32_t(5);
            for(auto& e:it->second) {now+=step;if(!visitor(e)) break;}
            return uint32_t(0);
        },[&]{return now;});
    }
};
int main() {
    unsigned tests=0;
    auto check=[&](bool condition){assert(condition);++tests;};
    check(plainLocalPath(L"C:\\test"));
    check(plainLocalPath(L"C:\\"));
    check(plainLocalPath(L"D:\\日本語\\資料"));
    for(auto p:{L"\\\\server\\share",L"\\\\?\\C:\\test",L"C:test",L"C:\\..\\test",L"C:\\x:stream",
                L"C:\\*",L"C:\\x.\\y",L"C:\\x \\y",L"C:\\a\\\\b",L"C:\\x/y"}) check(!plainLocalPath(p));
    {
        FakeFS fs{{{L"C:\\test",{{L".",Directory,0},{L"..",Directory,0},{L"a",0,7},{L"sub",Directory,0}}},
                   {L"C:\\test\\sub",{{L"b",0,(uint64_t(1)<<33)+4},{L"zero",0,0}}}}};
        auto r=fs.run();check(r.status==0);check(r.bytes==(uint64_t(1)<<33)+11);check(r.entries==4);
    }
    {FakeFS fs{{{L"C:\\test",{}}}};auto r=fs.run();check(r.status==0&&r.bytes==0);}
    for(uint32_t attr:{Reparse,Offline,RecallOnOpen,RecallOnAccess}) {
        FakeFS fs{{{L"C:\\test",{{L"skip",attr|Directory,999},{L"safe",0,8}}}}};
        auto r=fs.run();check(r.status==(uint32_t)Status::Incomplete);check(r.bytes==8&&r.skipped==1);check(fs.visited.size()==1);
    }
    {FakeFS fs{{{L"C:\\test",{{L"denied",Directory,0}}}}};auto r=fs.run();check(r.status==1&&r.errors==1);}
    {FakeFS fs{{{L"C:\\test",{{L"a",0,1},{L"b",0,2}}}}};auto r=fs.run(Limits{5000,1});check(r.status==3&&r.bytes==1);}
    {FakeFS fs{{{L"C:\\test",{{L"a",0,1},{L"b",0,2}}}}};fs.step=10;auto r=fs.run(Limits{15,100});check(r.status==2&&r.bytes==1);}
    {FakeFS fs{{{L"C:\\test",{{L"a",Directory,0},{L"b",Directory,0}}}}};auto r=fs.run(Limits{5000,100,1});check(r.status==3);}
    {FakeFS fs{{{L"C:\\test",{{L"a",Directory,0}}}}};auto r=fs.run(Limits{5000,100,100,0});check(r.status==3);}
    {FakeFS fs{{{L"C:\\test",{{L"a",0,UINT64_MAX},{L"b",0,1}}}}};auto r=fs.run();check(r.status==3);}
    {FakeFS fs{{{L"C:\\test",{{L"unsafe.",Directory,0}}}}};auto r=fs.run();check(r.status==1&&r.skipped==1);}
    std::cout<<tests<<" assertions passed\n";
}
