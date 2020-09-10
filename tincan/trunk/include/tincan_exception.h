/*
* EdgeVPNio
* Copyright 2020, University of Florida
*
* Permission is hereby granted, free of charge, to any person obtaining a copy
* of this software and associated documentation files (the "Software"), to deal
* in the Software without restriction, including without limitation the rights
* to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
* copies of the Software, and to permit persons to whom the Software is
* furnished to do so, subject to the following conditions:
*
* The above copyright notice and this permission notice shall be included in
* all copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
* IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
* AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
* LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
* OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
* THE SOFTWARE.
*/
#ifndef TINCAN_EXCEPTION_H_
#define TINCAN_EXCEPTION_H_

#if defined(_TNC_LINUX)
#include "linux/lnx_exception.h"
#elif defined(_TNC_WIN)
#include "windows/win_exception.h"
#endif

namespace tincan {
#if defined(_TNC_LINUX)
#define TCEXCEPT(ExtendedErrorInfo) linux::LNXEXCEPT(ExtendedErrorInfo)
#elif defined(_TNC_WIN)
#define TCEXCEPT(ExtendedErrorInfo) windows::WINEXCEPT(ExtendedErrorInfo)
#endif
} // namespace tincan
#endif  // TINCAN_EXCEPTION_H_
