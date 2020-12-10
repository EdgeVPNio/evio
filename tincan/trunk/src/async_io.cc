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
#include "async_io.h"
#include "tincan_exception.h"
namespace tincan
{

AsyncIo::AsyncIo(AsyncIo & rhs)
{
  *this = rhs;
}

AsyncIo &
AsyncIo::operator= (const AsyncIo & rhs)
{
  if (&rhs != this){
    this->buffer_to_transfer_ = rhs.buffer_to_transfer_;
    this->context_ = rhs.context_;
    this->bytes_to_transfer_ = rhs.bytes_to_transfer_;
    this->bytes_transferred_ = rhs.bytes_transferred_;
    this->flags_ = rhs.flags_;
    this->good_ = rhs.good_;
  }
  return *this;
}

bool
AsyncIo::operator==(
  const AsyncIo & rhs) const
{
  return (
    this == &rhs ||
    this->buffer_to_transfer_ == rhs.buffer_to_transfer_ ||
    this->context_ == rhs.context_ ||
    this->bytes_to_transfer_ == rhs.bytes_to_transfer_ ||
    this->bytes_transferred_ == rhs.bytes_transferred_ ||
    this->flags_ == rhs.flags_ ||
    this->good_ == rhs.good_);
}

bool
AsyncIo::operator!=(
  const AsyncIo & rhs) const
{
  return !(*this == rhs);
}

void
AsyncIo::Initialize(
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

void
AsyncIo::BufferToTransfer(uint8_t* val)
{
  buffer_to_transfer_ = val;
}

uint8_t*
AsyncIo::BufferToTransfer()
{
  return buffer_to_transfer_;
}

void
AsyncIo::BytesToTransfer(uint32_t val)
{
  bytes_to_transfer_ = val;
}

uint32_t
AsyncIo::BytesToTransfer()
{
  return bytes_to_transfer_;
}

void
AsyncIo::BytesTransferred(uint32_t val)
{
  bytes_transferred_ = val;
}

uint32_t
AsyncIo::BytesTransferred()
{
  return bytes_transferred_;
}

void
AsyncIo::Context(void * val)
{
  context_ = val;
}

void *
AsyncIo::Context()
{
  return context_;
}

bool
AsyncIo::IsRead()
{
  return flags_ == AIO_READ;
}

void
AsyncIo::SetReadOp()
{
  flags_ = AIO_READ;
}

bool
AsyncIo::IsWrite()
{
  return flags_ == AIO_WRITE;
}

void
AsyncIo::SetWriteOp()
{
  flags_ = AIO_WRITE;
}

bool
AsyncIo::IsGood()
{
  return good_;
}
} //tincan