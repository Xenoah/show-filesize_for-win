// SPDX-License-Identifier: GPL-3.0-only
#pragma once
#include <string>
namespace fsgwin {
inline std::wstring quoteArgument(const std::wstring& s) {
    std::wstring r=L"\""; size_t slashes=0;
    for(wchar_t c:s) {
        if(c==L'\\') {++slashes; continue;}
        if(c==L'\"') {r.append(slashes*2+1,L'\\'); r+=c;}
        else {r.append(slashes,L'\\'); r+=c;}
        slashes=0;
    }
    r.append(slashes*2,L'\\'); r+=L'\"'; return r;
}
}
