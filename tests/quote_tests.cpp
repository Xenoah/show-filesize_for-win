// SPDX-License-Identifier: GPL-3.0-only
#include "../src/quote_argument.h"
#include <cassert>
#include <iostream>
int main(){
    using fsgwin::quoteArgument;
    assert(quoteArgument(L"")==L"\"\"");
    assert(quoteArgument(L"abc")==L"\"abc\"");
    assert(quoteArgument(L"a b")==L"\"a b\"");
    assert(quoteArgument(L"C:\\")==L"\"C:\\\\\"");
    assert(quoteArgument(L"C:\\data\\file")==L"\"C:\\data\\file\"");
    assert(quoteArgument(L"a\"b")==L"\"a\\\"b\"");
    assert(quoteArgument(L"日本語")==L"\"日本語\"");
    assert(quoteArgument(L"& echo test")==L"\"& echo test\"");
    std::cout<<"8 argument-quoting assertions passed\n";
}
