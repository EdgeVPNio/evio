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
#ifndef TINCAN_ASYNCIO_H_
#define TINCAN_ASYNCIO_H_
#include "rtc_base/logging.h"
#if defined(_TNC_WIN)
#include <Winsock2.h>
#include <minwinbase.h>
#endif

#include "tincan_base.h"

namespace tincan
{
enum AIO_OP
{
  AIO_READ,
  AIO_WRITE,
  AIO_MAX
};

struct AsyncIo
#if defined(_TNC_WIN)
  : public OVERLAPPED
#endif // defined(_TNC_WIN)
{
  AsyncIo() :
    buffer_to_transfer_(nullptr),
    context_(nullptr),
    bytes_to_transfer_(0),
    bytes_transferred_(0),
    flags_(AIO_READ),
    good_(true)
  {
#if defined(_TNC_WIN)
    ZeroMemory(this, sizeof(OVERLAPPED));
#endif // defined(_TNC_WIN)
  }
  AsyncIo(
    uint8_t* buffer,
    uint32_t bytes_to_transfer,
    void* context,
    AIO_OP flags,
    uint32_t bytes_transferred = 0) :
    buffer_to_transfer_(buffer),
    context_(context),
    bytes_to_transfer_(bytes_to_transfer),
    bytes_transferred_(bytes_transferred),
    flags_(flags),
    good_(true)
  {
#if defined(_TNC_WIN)
    ZeroMemory(this, sizeof(OVERLAPPED));
#endif // defined(_TNC_WIN)
  }
#if !defined(_TNC_WIN)
  virtual ~AsyncIo() = default;
#endif // defined(_TNC_WIN)
  void Initialize(
    uint8_t* buffer_to_transfer,
    uint32_t bytes_to_transfer,
    void* context = nullptr,
    AIO_OP flags = AIO_READ,
    uint32_t bytes_transferred = 0)
  {
    buffer_to_transfer_ = buffer_to_transfer;
    bytes_to_transfer_ = bytes_to_transfer;
    context_ = context;
    flags_ = flags;
    bytes_transferred_ = bytes_transferred;
  }

  void BufferToTransfer(uint8_t* val)
  {
    buffer_to_transfer_ = val;
  }
  uint8_t* BufferToTransfer()
  {
    return buffer_to_transfer_;
  }

  void BytesToTransfer(uint32_t val)
  {
    bytes_to_transfer_ = val;
  }
  uint32_t BytesToTransfer()
  {
    return bytes_to_transfer_;
  }

  void BytesTransferred(uint32_t val)
  {
    bytes_transferred_ = val;
  }
  uint32_t BytesTransferred()
  {
    return bytes_transferred_;
  }

  void Context(void * val)
  {
    context_ = val;
  }
  void * Context()
  {
    return context_;
  }

  bool IsRead()
  {
    return flags_ == AIO_READ;
  }
  void SetReadOp()
  {
    flags_ = AIO_READ;
  }
  bool IsWrite()
  {
    return flags_ == AIO_WRITE;
  }
  void SetWriteOp()
  {
    flags_ = AIO_WRITE;
  }
  bool IsGood()
  {
    return good_;
  }
  uint8_t * buffer_to_transfer_;
  void * context_;
  uint32_t bytes_to_transfer_;
  uint32_t bytes_transferred_;
  AIO_OP flags_;
  bool good_;
};
}
#endif// TINCAN_ASYNCIO_H_
