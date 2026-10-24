// SPDX-License-Identifier: GPL-3.0-only
#include "resolver.h"
#include "injector.h"
#include "selftest.h"
#include <atomic>
#include <commctrl.h>
#include <exception>
#include <memory>

namespace {
HWND window=nullptr,logView=nullptr,startButton=nullptr,stopButton=nullptr,testButton=nullptr;
HFONT font=nullptr,titleFont=nullptr;
std::atomic<bool> busy{false},closing{false};
constexpr UINT LogMessage=WM_APP+1,DoneMessage=WM_APP+2;
constexpr int StartId=101,StopId=102,TestId=103;
void writeLog(const std::wstring& text) {
    if(closing)return;
    auto* copy=new std::wstring(text);
    if(!PostMessageW(window,LogMessage,0,reinterpret_cast<LPARAM>(copy)))delete copy;
}
std::wstring widen(const char* s){int n=MultiByteToWideChar(CP_UTF8,0,s,-1,nullptr,0);std::wstring w(n,L'\0');if(n)MultiByteToWideChar(CP_UTF8,0,s,-1,w.data(),n);if(!w.empty())w.pop_back();return w;}
DWORD WINAPI action(void* raw) {
    using namespace fsgwin;
    int id=(int)reinterpret_cast<INT_PTR>(raw);
    try {
        auto log=[](const std::wstring& t){if(closing)throw std::runtime_error("Controller closed");writeLog(t);};
        std::wstring dll=directory(modulePath())+L"\\FolderSizeGuardBridge.dll";
        if(id==TestId) {log(L"新規のテスト用データでワーカーを確認します。");verifyWorker(log);}
        else {
            Config config;
            if(id==StartId) {
                config=resolve(log);
                const auto settings=directory(directory(modulePath()))+L"\\settings.ini";
                config.budget=std::clamp<int>((int)GetPrivateProfileIntW(L"Scan",L"TimeoutMs",5000,settings.c_str()),100,30000);
                config.entries=std::clamp<int>((int)GetPrivateProfileIntW(L"Scan",L"MaxEntries",1000000,settings.c_str()),1,10000000);
                config.cacheSeconds=std::clamp<int>((int)GetPrivateProfileIntW(L"Scan",L"CacheSeconds",120,settings.c_str()),10,600);
                log(L"集計上限 "+std::to_wstring(config.budget)+L" ms / "+std::to_wstring(config.entries)+L" 項目、キャッシュ "+std::to_wstring(config.cacheSeconds)+L" 秒。");
            }
            if(closing)throw std::runtime_error("Controller closed");
            auto pids=explorerPids();unsigned done=0;
            if(pids.empty())throw std::runtime_error("No Explorer process in the current user's session");
            for(DWORD pid:pids) {
                if(closing)break;
                try {
                    DWORD result=commandExplorer(pid,dll,id==StartId?"FsgStart":"FsgDisable",id==StartId?&config:nullptr);
                    if(result==ERROR_NOT_FOUND&&id==StopId)continue;
                    if(result==ERROR_ALREADY_EXISTS&&id==StartId){log(L"既に有効です (PID "+std::to_wstring(pid)+L")。");++done;continue;}
                    if(result==ERROR_REVISION_MISMATCH){log(L"Windows内部版・既存フックとの照合に失敗しました。旧容量表示Modを無効化し、転送終了後に再試行してください。");continue;}
                    if(result==ERROR_BUSY){log(L"停止処理中です。数秒待ってから再度「表示を開始」を押してください。");continue;}
                    if(result!=ERROR_SUCCESS)throw std::runtime_error(("Bridge returned Windows error "+std::to_string(result)).c_str());
                    ++done;log((id==StartId?L"表示を有効化: PID ":L"表示・集計を停止: PID ")+std::to_wstring(pid));
                }catch(const std::exception& e){log(L"PID "+std::to_wstring(pid)+L": "+widen(e.what()));}
            }
            if(id==StartId&&done)log(L"有効化しました。詳細表示に切り替えてF5で更新してください。サイズ列をクリックすると並べ替えます。");
            if(id==StartId&&!done)log(L"有効化できませんでした。上のエラーを確認してください。既存の容量表示Modは無効化してください。");
            if(id==StopId)log(L"停止処理が終わりました。表示はF5で更新してください。DLLはサインアウトまで休止状態で残ります。");
        }
    }catch(const std::exception& e){writeLog(L"処理を中止しました: "+widen(e.what()));}
     catch(...){writeLog(L"予期しないエラーで処理を中止しました。");}
    busy=false;if(!closing)PostMessageW(window,DoneMessage,0,0);return 0;
}
void startAction(int id) {
    if(busy.exchange(true))return;
    EnableWindow(startButton,FALSE);EnableWindow(stopButton,FALSE);EnableWindow(testButton,FALSE);
    HANDLE h=CreateThread(nullptr,0,action,reinterpret_cast<void*>(static_cast<INT_PTR>(id)),0,nullptr);
    if(h)CloseHandle(h);else{busy=false;PostMessageW(window,DoneMessage,0,0);writeLog(L"処理スレッドを開始できませんでした。");}
}
HWND control(const wchar_t* cls,const wchar_t* text,DWORD style,int x,int y,int w,int h,int id=0) {
    HWND result=CreateWindowExW(0,cls,text,WS_CHILD|WS_VISIBLE|style,x,y,w,h,window,reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)),nullptr,nullptr);
    SendMessageW(result,WM_SETFONT,reinterpret_cast<WPARAM>(font),TRUE);return result;
}
LRESULT CALLBACK wndProc(HWND h,UINT msg,WPARAM wp,LPARAM lp) {
    switch(msg) {
    case WM_CREATE: {
        window=h;
        font=CreateFontW(-16,0,0,0,FW_NORMAL,FALSE,FALSE,FALSE,DEFAULT_CHARSET,0,0,CLEARTYPE_QUALITY,0,L"Yu Gothic UI");
        titleFont=CreateFontW(-25,0,0,0,FW_SEMIBOLD,FALSE,FALSE,FALSE,DEFAULT_CHARSET,0,0,CLEARTYPE_QUALITY,0,L"Yu Gothic UI");
        HWND title=control(L"STATIC",L"Folder Size Guard",0,24,18,550,36);
        SendMessageW(title,WM_SETFONT,reinterpret_cast<WPARAM>(titleFont),TRUE);
        control(L"STATIC",L"Standalone 0.2.0 preview  |  Windhawk・追加ランタイム不要",0,25,58,710,26);
        control(L"STATIC",L"標準の「サイズ」列へ表示。初回・Windows更新後はMicrosoftシンボルを取得します。",0,25,91,735,26);
        control(L"STATIC",L"Windows実機での表示・安定性は未検証です。まず集計テストを実行してください。",0,25,120,735,26);
        startButton=control(L"BUTTON",L"表示を開始",BS_PUSHBUTTON|WS_TABSTOP,25,160,180,40,StartId);
        stopButton=control(L"BUTTON",L"表示を停止",BS_PUSHBUTTON|WS_TABSTOP,220,160,180,40,StopId);
        testButton=control(L"BUTTON",L"集計テスト",BS_PUSHBUTTON|WS_TABSTOP,415,160,180,40,TestId);
        logView=control(L"EDIT",L"",WS_BORDER|ES_MULTILINE|ES_READONLY|ES_AUTOVSCROLL|WS_VSCROLL,25,218,730,285);
        SendMessageW(logView,EM_SETLIMITTEXT,400000,0);
        control(L"STATIC",L"この画面を閉じると集計・容量表示を停止します。停止後はエクスプローラーでF5を押してください。",0,25,518,735,40);
        writeLog(L"準備完了。集計対象の削除・移動・権限変更は行いません。集計時間とキャッシュ期間はsettings.iniで変更できます。");
        writeLog(L"開始・停止は、エクスプローラーのコピー／移動作業が終わってから操作してください。");
        break;
    }
    case WM_COMMAND: if(HIWORD(wp)==BN_CLICKED&&(LOWORD(wp)==StartId||LOWORD(wp)==StopId||LOWORD(wp)==TestId))startAction(LOWORD(wp));break;
    case LogMessage: {
        std::unique_ptr<std::wstring> line(reinterpret_cast<std::wstring*>(lp));
        if(GetWindowTextLengthW(logView)>350000)SetWindowTextW(logView,L"");
        SendMessageW(logView,EM_SETSEL,-1,-1);line->append(L"\r\n");
        SendMessageW(logView,EM_REPLACESEL,FALSE,reinterpret_cast<LPARAM>(line->c_str()));break;
    }
    case DoneMessage: EnableWindow(startButton,TRUE);EnableWindow(stopButton,TRUE);EnableWindow(testButton,TRUE);break;
    case WM_DESTROY:closing=true;PostQuitMessage(0);break;
    default:return DefWindowProcW(h,msg,wp,lp);
    }
    return 0;
}
}
int WINAPI wWinMain(HINSTANCE instance,HINSTANCE,PWSTR,int show) {
    SYSTEM_INFO sys{};GetNativeSystemInfo(&sys);
    if(sys.wProcessorArchitecture==PROCESSOR_ARCHITECTURE_ARM64){MessageBoxW(nullptr,L"このプレビュー版はARM64に対応していません。",L"Folder Size Guard",MB_ICONINFORMATION);return 1;}
#ifndef _WIN64
    if(sys.wProcessorArchitecture==PROCESSOR_ARCHITECTURE_AMD64){MessageBoxW(nullptr,L"64bit Windowsではx64フォルダーのEXEを実行してください。",L"Folder Size Guard",MB_ICONINFORMATION);return 1;}
#endif
    fsgwin::Handle singleton(CreateMutexW(nullptr,TRUE,L"Local\\FolderSizeGuardStandalone-v0.2"));
    if(!singleton.h||GetLastError()==ERROR_ALREADY_EXISTS){MessageBoxW(nullptr,L"既に起動しています。開いているウィンドウを使用してください。",L"Folder Size Guard",MB_ICONINFORMATION);return 1;}
    SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32|LOAD_LIBRARY_SEARCH_APPLICATION_DIR);
    SetErrorMode(SEM_FAILCRITICALERRORS|SEM_NOOPENFILEERRORBOX);
    WNDCLASSW wc{};wc.hInstance=instance;wc.lpfnWndProc=wndProc;wc.lpszClassName=L"FolderSizeGuardStandalone";
    wc.hCursor=LoadCursorW(nullptr,IDC_ARROW);wc.hbrBackground=reinterpret_cast<HBRUSH>(COLOR_WINDOW+1);
    if(!RegisterClassW(&wc))return 1;
    HWND h=CreateWindowExW(0,wc.lpszClassName,L"Folder Size Guard — Standalone Preview",WS_OVERLAPPED|WS_CAPTION|WS_SYSMENU|WS_MINIMIZEBOX,
        CW_USEDEFAULT,CW_USEDEFAULT,800,610,nullptr,nullptr,instance,nullptr);
    if(!h)return 1;
    ShowWindow(h,show);UpdateWindow(h);
    MSG msg{};while(GetMessageW(&msg,nullptr,0,0)>0){TranslateMessage(&msg);DispatchMessageW(&msg);}
    // Closing this process causes each bridge's owner-process watchdog to
    // disable size callbacks and cancel only its own metadata worker.
    return 0;
}
