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
#include "tap_frame.h"
#include "tincan_exception.h"
namespace tincan
{
TapFrame::TapFrame() :
  AsyncIo(),
  tfb_(nullptr),
  pl_len_(0)
{
    AsyncIo::Initialize(nullptr, 0, this, AIO_READ, 0);
}

TapFrame::TapFrame(const TapFrame & rhs) :
  AsyncIo(),
  tfb_(nullptr),
  pl_len_(rhs.pl_len_)
{
  if(rhs.tfb_)
  {
    tfb_ = new TapFrameBuffer;
    memcpy(tfb_->data(), rhs.tfb_->data(), rhs.tfb_->size());
    AsyncIo::Initialize(tfb_->data(), rhs.bytes_to_transfer_, this,
      rhs.flags_, rhs.bytes_transferred_);
  }
}

TapFrame::TapFrame(TapFrame && rhs) :
  AsyncIo(),
  tfb_(rhs.tfb_),
  pl_len_(rhs.pl_len_)
{
  rhs.tfb_ = nullptr;
  AsyncIo::Initialize(tfb_->data(), rhs.bytes_to_transfer_, this,
    rhs.flags_, rhs.bytes_transferred_);
}

/*
Copies the specifed amount of data into the TFB, starting at begin(). It also
sets up the frame for write IO.
*/
TapFrame::TapFrame(
  uint8_t * in_buf,
  uint32_t buf_len) :
  pl_len_(buf_len - tp.kTapHeaderSize)
{
  if(buf_len > tp.kTapBufferSize)
    throw TCEXCEPT("Input data is larger than the maximum allowed");
  tfb_ = new TapFrameBuffer;
  memcpy(tfb_->data(), in_buf, buf_len);
  AsyncIo::Initialize(tfb_->data(), buf_len, this, AIO_WRITE, buf_len);
}

TapFrame::~TapFrame()
{
  delete tfb_;
}

TapFrame &
TapFrame::operator= (TapFrame & rhs)
{
  if(!tfb_)
    tfb_ = new TapFrameBuffer;
  memcpy(tfb_->data(),rhs.tfb_->data(), rhs.tfb_->size());

  AsyncIo::Initialize(tfb_->data(), rhs.bytes_to_transfer_, this,
    rhs.flags_, rhs.bytes_transferred_);
  pl_len_ = rhs.pl_len_;
  return *this;
}

TapFrame &
TapFrame::operator= (TapFrame && rhs)
{
  if(this->tfb_) delete this->tfb_;
  this->tfb_ = rhs.tfb_;

  AsyncIo::Initialize(tfb_->data(), rhs.bytes_to_transfer_, this,
    rhs.flags_, rhs.bytes_transferred_);
  pl_len_ = rhs.pl_len_;

  rhs.tfb_ = nullptr;
  rhs.buffer_to_transfer_ = nullptr;
  rhs.context_ = nullptr;
  rhs.bytes_transferred_ = 0;
  rhs.bytes_to_transfer_ = 0;
  rhs.flags_ = AIO_WRITE;
  rhs.pl_len_ = 0;
  return *this;
}

bool
TapFrame::operator==(
  const TapFrame & rhs) const
{
  return (tfb_ == rhs.tfb_);
}

bool
TapFrame::operator!=(
  const TapFrame & rhs) const
{
  return !(*this == rhs);
}

bool
TapFrame::operator !() const
{
  return tfb_ == nullptr;
}

uint8_t &
TapFrame::operator [](
  uint32_t index)
{
  if(!tfb_ || index >= tfb_->size())
    throw TCEXCEPT("TapFrameBuffer index out of bounds");
  return (*tfb_)[index];
}

const uint8_t &
TapFrame::operator [](
  const uint32_t index) const
{
  if(!tfb_ || index >= tfb_->size())
    throw TCEXCEPT("TapFrameBuffer index out of bounds");
  return (*tfb_)[index];
}

TapFrame & TapFrame::Initialize()
{
  pl_len_ = 0;
  if(!tfb_)
  {
    tfb_ = new TapFrameBuffer;
  }
  AsyncIo::Initialize(tfb_->data(), tp.kTapBufferSize, this, AIO_READ, 0);
  return *this;
}

TapFrame & TapFrame::Initialize(
  uint8_t* buffer_to_transfer,
  uint32_t bytes_to_transfer,
  AIO_OP flags,
  uint32_t bytes_transferred)
{
  pl_len_ = 0;
  AsyncIo::Initialize(buffer_to_transfer, bytes_to_transfer, this, flags,
    bytes_transferred);
  return *this;
}

void TapFrame::Header(uint16_t val)
{
  *((uint16_t*)tfb_->data()) = val;
}

uint8_t * TapFrame::Begin()
{
  if(!tfb_)
    return nullptr;
  return tfb_->data();
}

uint8_t * TapFrame::End()
{
  if(!tfb_)
    return nullptr;
  return tfb_->data() + tfb_->size(); //one after last valid byte

}

uint32_t TapFrame::Length()
{
  return tp.kTapHeaderSize + PayloadLength();
}

uint32_t TapFrame::PayloadLength()
{
  if(!tfb_ || AsyncIo::BytesTransferred() <= tp.kTapHeaderSize)
    return 0;
  return pl_len_;
}

void TapFrame::PayloadLength(uint32_t length)
{
  pl_len_ = length;
}

uint32_t TapFrame::PayloadCapacity()
{
  if(!tfb_)
    return 0;
  return tp.kEthernetSize;
}

uint8_t * TapFrame::Payload()
{
  if(!tfb_)
    return nullptr;
  return &tfb_->data()[tp.kTapHeaderSize];
}

uint8_t * TapFrame::PayloadEnd()
{
  return Payload() + PayloadLength();
}

uint32_t TapFrame::Capacity() const
{
  if(!tfb_)
    return 0;
  return (uint32_t)tfb_->size();
}

void TapFrame::Dump(const string & label)
{
  if(RTC_LOG_CHECK_LEVEL(LS_VERBOSE))
  {
    ostringstream oss;
    RTC_LOG(LS_VERBOSE) << label << " header=" <<
      ByteArrayToString(Begin(), Payload(), 0, false) << "\n" <<
      ByteArrayToString(Payload(), PayloadEnd(), 16, true);
  }
}

void IccMessage::Message(
  uint8_t * in_buf,
  uint32_t buf_len)
{
  if(buf_len > tp.kEthernetSize)
    throw TCEXCEPT("Input data is larger than the maximum allowed");

  if(!tfb_)
    tfb_ = new TapFrameBuffer;
  pl_len_ = buf_len;
  uint32_t nb = pl_len_ + tp.kTapHeaderSize;
  AsyncIo::Initialize(tfb_->data(), nb, this, AIO_WRITE, nb);
  uint16_t magic = tp.kIccMagic;
  memmove(Begin(), &magic, tp.kTapHeaderSize);
  memmove(Payload(), in_buf, buf_len);
}

void DtfMessage::Message(
  uint8_t * in_buf,
  uint32_t buf_len)
{
  if(buf_len > tp.kEthernetSize)
    throw TCEXCEPT("Input data is larger than the maximum allowed");

  if(!tfb_)
    tfb_ = new TapFrameBuffer;
  pl_len_ = buf_len;
  uint32_t nb = pl_len_ + tp.kTapHeaderSize;
  AsyncIo::Initialize(tfb_->data(), nb, this, AIO_WRITE, nb);
  uint16_t magic = tp.kDtfMagic;
  memmove(Begin(), &magic, tp.kTapHeaderSize);
  memmove(Payload(), in_buf, buf_len);

}

void FwdMessage::Message(
  uint8_t * in_buf,
  uint32_t buf_len)
{
  if(buf_len > tp.kEthernetSize)
    throw TCEXCEPT("Input data is larger than the maximum allowed");
  if(!tfb_)
    tfb_ = new TapFrameBuffer;
  pl_len_ = buf_len;
  uint32_t nb = pl_len_ + tp.kTapHeaderSize;
  AsyncIo::Initialize(tfb_->data(), nb, this, AIO_WRITE, nb);
  uint16_t magic = tp.kFwdMagic;
  memmove(Begin(), &magic, tp.kTapHeaderSize);
  memmove(Payload(), in_buf, buf_len);

}

} //tincan
