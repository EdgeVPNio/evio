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
/**************************************************************************
  WinException
  -------------------
  Description : A Win32 specialization of the std::exception.
  Usage: Throw WinEXCEPTION("with your error message"). When caught, ask the
  exception.what() happened to get your error message, source code file and
  line, and the Windows specific error message.
***************************************************************************/

#ifndef TINCAN_WIN_EXCEPTION_H_
#define TINCAN_WIN_EXCEPTION_H_
#if defined(_TNC_WIN)
#include "tincan_base.h"
#include <Winsock2.h>
namespace tincan
{
namespace windows
{
#define WINEXCEPT(ExtendedErrorInfo)\
WinException(ExtendedErrorInfo, __FILE__, __LINE__, GetLastError())
class WinException : virtual public exception
{
private:
  unsigned int mHostErrorCode;
  unsigned int mSourceLine;
  const string mSourceFile;
  const string mExtendedErrorInfo;
  stringstream ss;
protected:
  string mMsg;
  void WinException::TranslateErrorCode() {
    ss << "Exception@ " << mSourceFile << " (" << mSourceLine << ") " << endl
      << mExtendedErrorInfo << endl;
    if(ERROR_SUCCESS != mHostErrorCode)
    {
      LPSTR MsgBuf = NULL;
      DWORD dw = FormatMessageA(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        mHostErrorCode,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), // Default language
        (LPSTR)&MsgBuf,
        12,
        NULL);
      if(dw && MsgBuf) {
        ss << " System error: " << mHostErrorCode << "-" << MsgBuf << endl;
        LocalFree(MsgBuf);
        MsgBuf = NULL;
      }
    }
  }
public:
  WinException(
    const char *const & ExtendedErrorInfo,
    const char *const & SourceFile,
    const unsigned int SourceLine,
    const unsigned int ErrorCode) :
    exception(),
    mHostErrorCode(ErrorCode),
    mSourceLine(SourceLine),
    mSourceFile(SourceFile),
    mExtendedErrorInfo(ExtendedErrorInfo) {
    TranslateErrorCode();
    mMsg = ss.str();
  }

  void AddMessage( string && Msg) {
    ss << Msg << endl;
  }

  const char* WinException::what() const {
    return mMsg.c_str();
  }
}; // WinException
} // windows
} // tincan
#endif // _TNC_WIN
#endif // TINCAN_WIN_EXCEPTION_H_
