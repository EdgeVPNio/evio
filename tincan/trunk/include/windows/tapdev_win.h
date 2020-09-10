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

#ifndef TINCAN_TAPDEV_WIN_H_
#define TINCAN_TAPDEV_WIN_H_
#if defined(_TNC_WIN)
#include "tincan_base.h"
#include "rtc_base/logging.h"
#include "rtc_base/third_party/sigslot/sigslot.h"
#include <Winsock2.h>
#include "async_io.h"
#include "tapdev_inf.h"

namespace tincan
{
namespace windows
{
/*
NOTE: A TapDev object cannot be reused, ie.,
  TapDev::Open(); TapDev::Close(); TapDev::Open();
It must be deleted after it is closed and a new instance create.
*/
class TapDevWin :
  public TapDevInf,
  public MessageHandler
{
public:
  struct IoThreadDescriptor
  {
    HANDLE handle_; //thread join needs this to be first member
    HANDLE exit_ev_;
    HANDLE cmpl_prt_hdl_;
    DWORD id_;
    uint16_t num_;
    IoThreadDescriptor() :
      handle_(INVALID_HANDLE_VALUE),
      cmpl_prt_hdl_(0),
      id_(0), num_(0)
    {
      exit_ev_ = CreateEvent(NULL, FALSE, FALSE, NULL);
    }
    ~IoThreadDescriptor()
    {
      CloseHandle(exit_ev_);
      CloseHandle(handle_);
    }
    static DWORD __stdcall IoCompletionThread(void * param);
  };

  struct IoThreadPool
  {
    IoThreadPool(uint8_t max_threads = 1) :
      ref_(0),
      num_threads_(0),
      max_threads_(max_threads), is_alloc(false)
    {}
    ~IoThreadPool()
    {
      if(is_alloc)
        Free();
    }
    bool Alloc()
    {
      io_threads_ = new IoThreadDescriptor[max_threads_];
      for(uint16_t i = 0; i < max_threads_; i++)
      {
        io_threads_[i].num_ = i;
        io_threads_[i].handle_ = CreateThread(0, 0,
          IoThreadDescriptor::IoCompletionThread, (void *)&io_threads_[i],
          CREATE_SUSPENDED, &io_threads_[i].id_);
        ++num_threads_;
      }
      is_alloc = true;
      return is_alloc;
    }
    void Free()
    {
      for(uint16_t i = 0; i < max_threads_; i++)
      {
        SetEvent(io_threads_[i].exit_ev_);
        PostQueuedCompletionStatus(io_threads_[i].cmpl_prt_hdl_, 0,
          (DWORD)NULL, NULL);
        ResumeThread(io_threads_[i].handle_);
      }
      //wait for io threads to terminate, 10 seconds or bust
      WaitForMultipleObjects(num_threads_, (const HANDLE*)io_threads_,
        TRUE, 10000);
      delete[]io_threads_;
      is_alloc = false;
    }
    void Attach(HANDLE completion_port_handle)
    {
      lock_guard<mutex> lg(iot_mutex_);
      if(0 == ref_++)
      {
        for(uint16_t i = 0; i < max_threads_; i++)
        {
          io_threads_[i].cmpl_prt_hdl_ = completion_port_handle;
          ResumeThread(io_threads_[i].handle_);
        }
      }
    }
    void Release()
    {
      lock_guard<mutex> lg(iot_mutex_);
      if(0 == --ref_)
      {
        for(uint16_t i = 0; i < max_threads_; i++)
        {
          SuspendThread(io_threads_[i].handle_);
          io_threads_[i].cmpl_prt_hdl_ = 0;
        }
      }
    }
    IoThreadDescriptor* io_threads_;
    uint16_t ref_;
    uint16_t num_threads_;
    uint16_t max_threads_;
    mutex iot_mutex_;
    bool is_alloc;
  };

  TapDevWin();

  virtual ~TapDevWin();

  void Open(
    const TapDescriptor & tap_desc) override;

  void Close() override;

  void Up() override;

  void Down() override;

  uint32_t Read(
    AsyncIo & aio_rd) override;

  uint32_t Write(
    AsyncIo & aio_wr) override;

  MacAddressType MacAddress() override;

  IP4AddressType Ip4() override;

  uint16_t Mtu() override;
  //
  //IO Completion Port
  void CompletionPortHandle(HANDLE handle)
  {
    cmpl_prt_handle_ = handle;
  }
  HANDLE CompletionPortHandle()
  {
    return cmpl_prt_handle_;
  }
  HANDLE DeviceHandle()
  {
    return dev_handle_;
  }

  uint32_t MediaStatus();

  sigslot::signal1<AsyncIo *> read_completion_;
  sigslot::signal1<AsyncIo *> write_completion_;
protected:
  void NetDeviceNameToGuid(
    const string & name,
    string & guid);
  void GetMacAddress();
  void OnMessage(
    Message * msg) override;

  static const char * const NETWORK_PATH_;
  static const char * const USER_MODE_DEVICE_DIR_;
  static const char * const TAP_SUFFIX_;
  MacAddressType mac_address_;
  DWORD mac_len_;
  string tap_name_;
  HANDLE cmpl_prt_handle_;
  HANDLE dev_handle_;
  mutex rw_mutex_;
  IoThreadPool io_thread_pool_;
  DWORD media_status_;
  IP4AddressType ip4_;
  rtc::Thread writer_;
};
}  // namespace win
}  // namespace tincan
#endif  // _TNC_WIN
#endif  // TINCAN_TAPDEV_WIN_H_
