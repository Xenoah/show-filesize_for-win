// SPDX-License-Identifier: GPL-3.0-only
#pragma once
#include "resolver.h"
#include "worker_client.h"
#include <array>
namespace fsgwin {
inline void verifyWorker(Log log) {
    GUID id;CoCreateGuid(&id);wchar_t label[64];StringFromGUID2(id,label,64);
    std::wstring root=dataDirectory()+L"\\test-"+label;ensureDirectory(root);
    std::wstring data=root+L"\\data",sub=data+L"\\nested",empty=root+L"\\empty";
    ensureDirectory(data);ensureDirectory(sub);ensureDirectory(empty);
    struct File {std::wstring path;DWORD length;FILETIME write{};};
    std::array<File,3> files{{{data+L"\\a.bin",1027,{}},{sub+L"\\b.bin",8192,{}},{sub+L"\\zero.bin",0,{}}}};
    for(auto& f:files) {
        Handle h(CreateFileW(f.path.c_str(),GENERIC_WRITE,0,nullptr,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,nullptr));
        if(h.h==INVALID_HANDLE_VALUE)throw std::runtime_error("Cannot create new self-test fixture");
        std::vector<BYTE> zeros(f.length);DWORD n=0;
        if(f.length&&(!WriteFile(h.h,zeros.data(),f.length,&n,nullptr)||n!=f.length))throw std::runtime_error("Cannot write fixture");
        // LastWriteTime is finalized when the write handle closes.
        CloseHandle(h.h);h.h=nullptr;
        WIN32_FILE_ATTRIBUTE_DATA attributes{};
        if(!GetFileAttributesExW(f.path.c_str(),GetFileExInfoStandard,&attributes))throw std::runtime_error("Fixture attributes unavailable");
        f.write=attributes.ftLastWriteTime;
    }
    std::wstring worker=directory(modulePath())+L"\\FolderSizeWorker.exe";
    Handle cancel(CreateEventW(nullptr,TRUE,FALSE,nullptr));
    if(!cancel.h)throw std::runtime_error("Self-test event unavailable");
    auto check=[&](const std::wstring& p,DWORD count,uint32_t expected,uint64_t bytes){
        auto r=scanWorker(worker,p,5000,count,cancel.h,GetCurrentProcess());
        if(r.magic!=0x31475346||r.status!=expected||(expected==0&&r.bytes!=bytes))
            throw std::runtime_error("Worker self-test failed. See retained fixtures; LocalAppData must be on a fixed local disk without reparse ancestors.");
    };
    check(data,1000000,0,9219);log(L"合計 9,219 bytes: OK");
    check(empty,1000000,0,0);log(L"空フォルダー: OK");
    check(data,1,3,0);log(L"項目数上限: OK");
    check(root+L"\\missing",1000000,4,0);log(L"存在しないパス: OK");
    check(L"\\\\invalid-host\\share",1000000,4,0);log(L"ネットワークパス拒否: OK");
    SetEvent(cancel.h);
    auto cancelled=scanWorker(worker,data,5000,1000000,cancel.h,GetCurrentProcess());
    if(cancelled.status!=2)throw std::runtime_error("Cancellation self-test failed");
    log(L"中止・ワーカー終了: OK");
    for(const auto& f:files) {
        WIN32_FILE_ATTRIBUTE_DATA a{};
        if(!GetFileAttributesExW(f.path.c_str(),GetFileExInfoStandard,&a)||a.nFileSizeHigh||a.nFileSizeLow!=f.length||
           CompareFileTime(&a.ftLastWriteTime,&f.write))throw std::runtime_error("Fixture size/write time changed");
        Handle h(CreateFileW(f.path.c_str(),GENERIC_READ,FILE_SHARE_READ,nullptr,OPEN_EXISTING,0,nullptr));
        std::vector<BYTE> b(f.length);DWORD n=0;
        if(h.h==INVALID_HANDLE_VALUE||(f.length&&(!ReadFile(h.h,b.data(),f.length,&n,nullptr)||n!=f.length))||
           std::any_of(b.begin(),b.end(),[](BYTE x){return x!=0;}))throw std::runtime_error("Fixture contents changed");
    }
    log(L"対象ファイルの内容・更新日時不変: OK");
    log(L"集計テストが完了しました。表示フックの検証は別です。");
    log(L"テスト用ファイルは確認のため残しています: "+root);
}
}
