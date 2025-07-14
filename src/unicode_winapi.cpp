/*
The MIT License (MIT)

Copyright (c) 2020 Trail of Bits, Inc.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

//#include <Windows.h>
#include <string>
#include <codecvt> // For std::codecvt_utf8_utf16 and std::wstring_convert
#include <locale>  // For std::locale

#include "to_string.h"



// Example for std::u16string to std::string (UTF-8)
std::string utf16_to_utf8(const std::u16string& utf16_str) {
    std::wstring_convert<std::codecvt_utf8_utf16<char16_t>, char16_t> converter;
    return converter.to_bytes(utf16_str);
}

// Example for std::wstring (Windows) to std::string (UTF-8)
std::string wstring_to_utf8(const std::wstring& wstr) {
    std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>, wchar_t> converter;
    return converter.to_bytes(wstr);
}

std::wstring char16_to_wchar(const std::u16string& u16str) {
    return std::wstring(reinterpret_cast<const wchar_t*>(u16str.c_str()));
}

namespace peparse {

    //std::string from_utf16(const UCharString& u) 
    std::string from_utf16(const std::u16string& utf16_str)
    {
        std::string result;

        result = utf16_to_utf8(utf16_str);

        //std::string result;
        //std::size_t size = WideCharToMultiByte(CP_UTF8,
        //    0,
        //    u.data(),
        //    static_cast<int>(u.size()),
        //    nullptr,
        //    0,
        //    nullptr,
        //    nullptr);

        //if (size <= 0) {
        //    return result;
        //}

        //result.reserve(size);
        //WideCharToMultiByte(CP_UTF8,
        //    0,
        //    u.data(),
        //    static_cast<int>(u.size()),
        //    &result[0],
        //    static_cast<int>(result.capacity()),
        //    nullptr,
        //    nullptr);

        return result;
    }
} // namespace peparse
