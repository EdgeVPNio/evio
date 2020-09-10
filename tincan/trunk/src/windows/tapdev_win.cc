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

#if defined(_TNC_WIN)
#include "windows/tapdev_win.h"
#include <iphlpapi.h>
#include <mstcpip.h>
#include <wchar.h>
#include <winioctl.h>
#include "windows/win_exception.h"
namespace tincan
{
namespace windows
{
const char * const TapDevWin::NETWORK_PATH_ =
"SYSTEM\\CurrentControlSet\\Control\\Network\\"
"{4D36E972-E325-11CE-BFC1-08002BE10318}"; //registry path to network class guid
const char * const TapDevWin::USER_MODE_DEVICE_DIR_ = "\\\\.\\Global\\";
const char * const TapDevWin::TAP_SUFFIX_ = ".tap";

#define TAP_CONTROL_CODE(request,method) \
  CTL_CODE (FILE_DEVICE_UNKNOWN, request, method, FILE_ANY_ACCESS)

#define TAP_IOCTL_GET_MAC               TAP_CONTROL_CODE (1, METHOD_BUFFERED)
#define TAP_IOCTL_GET_VERSION           TAP_CONTROL_CODE (2, METHOD_BUFFERED)
#define TAP_IOCTL_GET_MTU               TAP_CONTROL_CODE (3, METHOD_BUFFERED)
#define TAP_IOCTL_GET_INFO              TAP_CONTROL_CODE (4, METHOD_BUFFERED)
#define TAP_IOCTL_CONFIG_POINT_TO_POINT TAP_CONTROL_CODE (5, METHOD_BUFFERED)
#define TAP_IOCTL_SET_MEDIA_STATUS      TAP_CONTROL_CODE (6, METHOD_BUFFERED)
#define TAP_IOCTL_CONFIG_DHCP_MASQ      TAP_CONTROL_CODE (7, METHOD_BUFFERED)
#define TAP_IOCTL_GET_LOG_LINE          TAP_CONTROL_CODE (8, METHOD_BUFFERED)
#define TAP_IOCTL_CONFIG_DHCP_SET_OPT   TAP_CONTROL_CODE (9, METHOD_BUFFERED)
/* obsoletes TAP_WIN_IOCTL_CONFIG_POINT_TO_POINT */
#define TAP_WIN_IOCTL_CONFIG_TUN        TAP_WIN_CONTROL_CODE (10, METHOD_BUFFERED)

DWORD __stdcall
TapDevWin::IoThreadDescriptor::IoCompletionThread(void * param)
{
  DWORD rv = ERROR_SUCCESS;
  IoThreadDescriptor * ioth = (IoThreadDescriptor*)param;
  while(WAIT_OBJECT_0 != WaitForSingleObject(ioth->exit_ev_, 0))
  {
    DWORD bytes_transfered = 0;
    TapDevWin *tap_dev = NULL;
    OVERLAPPED *overlap = NULL;
    rv = ERROR_SUCCESS;
    if(!GetQueuedCompletionStatus(
      ioth->cmpl_prt_hdl_,
      &bytes_transfered,
      (PULONG_PTR)&tap_dev, &overlap, INFINITE))
    {
      rv = GetLastError();
    }
    if(NULL == tap_dev || NULL == overlap)//shutting down
      break;
    else if(ERROR_SUCCESS != rv)
    {//completion packet for a failed IO
      RTC_LOG(LS_WARNING) << "Received a completion packet for a failed IO, error: " << rv;
      //indicate failure and deliver
      AsyncIo * aio = (AsyncIo*)overlap;
      aio->BytesTransferred(0);
      aio->good_ = false;
      aio->IsWrite() ? tap_dev->write_completion_(aio) :
        tap_dev->read_completion_(aio);
    }
    else
    {//success call the completion function 
      AsyncIo * aio = (AsyncIo*)overlap;
      aio->BytesTransferred(bytes_transfered);
      aio->IsWrite() ? tap_dev->write_completion_(aio) :
        tap_dev->read_completion_(aio);
    }
  }
  return rv;
}

TapDevWin::TapDevWin() :
  cmpl_prt_handle_(0),
  dev_handle_(INVALID_HANDLE_VALUE),
  media_status_(0),
  io_thread_pool_()
{}

TapDevWin::~TapDevWin()
{}

void
TapDevWin::Open(
  const TapDescriptor & tap_desc)
{
  lock_guard<mutex> lg(rw_mutex_);
  tap_name_ = tap_desc.name;
  string device_guid;
  try
  {
    const char *term;
    struct in_addr vip4_addr;
    if(0 == RtlIpv4StringToAddress(tap_desc.ip4.c_str(), TRUE,
      &term, &vip4_addr))
    {
      memmove(ip4_.data(), &vip4_addr.S_un.S_addr, sizeof(ip4_));
    }
    else
      RTC_LOG(WARNING) << "Failed to convert IP4 string in Tap Descriptor="
      << tap_desc.ip4 << " for TAP device " + tap_name_;

    NetDeviceNameToGuid(tap_name_, device_guid);
    string device_path(USER_MODE_DEVICE_DIR_);
    device_path.append(device_guid).append(TAP_SUFFIX_);
    dev_handle_ = CreateFile(device_path.c_str(),
      GENERIC_READ | GENERIC_WRITE, 0, 0, OPEN_EXISTING,
      FILE_ATTRIBUTE_SYSTEM | FILE_FLAG_OVERLAPPED, 0);
    if(INVALID_HANDLE_VALUE == dev_handle_)
    {
      const string emsg("Failed to open TAP device " + tap_name_ + ".");
      throw WINEXCEPT(emsg.c_str());
    }
    cmpl_prt_handle_ = CreateIoCompletionPort(DeviceHandle(),
      CompletionPortHandle(), (ULONG_PTR)this, 0);
    if(!cmpl_prt_handle_)
    {
      string emsg("The TAP IO completion thread failed to create an IO "
        "completion port for device " + tap_name_ + ".");
      throw WINEXCEPT(emsg.c_str());
    }
    io_thread_pool_.Alloc();
  } catch(exception & e)
  {
    CloseHandle(dev_handle_);
    CloseHandle(cmpl_prt_handle_);
    e.what();
    throw;
  }
}

void TapDevWin::Close()
{
  lock_guard<mutex> lg(rw_mutex_);
  io_thread_pool_.Free();
  CloseHandle(cmpl_prt_handle_);
  CloseHandle(dev_handle_);
}


uint32_t
TapDevWin::Read(
  AsyncIo & aio_rd)
{
  lock_guard<mutex> lg(rw_mutex_);
  ReadFile(dev_handle_,
    aio_rd.BufferToTransfer(),
    (unsigned long)aio_rd.BytesToTransfer(),
    NULL,
    (LPOVERLAPPED)&aio_rd);
  DWORD rv = GetLastError();
  if(rv != ERROR_IO_PENDING && rv != ERROR_SUCCESS)
  {
    RTC_LOG(LS_ERROR) << "The TAP device read request operation failed for device "
      << tap_name_ << ", error: " << rv << ".";
    return rv;
  }
  return 0;
}

uint32_t
TapDevWin::Write(
  AsyncIo & aio_wr)
{
  TapMessageData *tp = new TapMessageData;
  tp->aio_ = &aio_wr;
  writer_.Post(RTC_FROM_HERE, this, MSGID_WRITE, tp);
  return 0;
}

void
TapDevWin::NetDeviceNameToGuid(
  const string & name,
  string & guid)
{
  DWORD i_0 = 0;
  bool is_found = false;
  DWORD guid_buf_len = 256, name_buf_len = 256;
  HKEY key_0 = 0, key_1 = 0;
  char guid_buf[256], name_buf[256];
  string full_path;
  try
  {
/* Open up Networking in the registry */
    if(ERROR_SUCCESS != RegOpenKeyEx(HKEY_LOCAL_MACHINE, NETWORK_PATH_, 0,
      KEY_READ, &key_0))
    {
      string emsg("Failed to open registry key");
      emsg.append(NETWORK_PATH_);
      throw WINEXCEPT(emsg.c_str());
    }
    while(!is_found)
    {
/* Enumerate through the different keys under Network\{4D36E972-E325-11CE-BFC1-08002BE10318} */
      guid_buf_len = 256;
      DWORD rv = RegEnumKeyEx(key_0, i_0++, guid_buf, &guid_buf_len,
        NULL, NULL, NULL, NULL);
      if(rv == ERROR_NO_MORE_ITEMS)
        throw WINEXCEPT("Failed to resolve EVIO TAP GUID in system registry");
      if(rv != ERROR_SUCCESS)
        continue;
      full_path.assign(NETWORK_PATH_).append("\\")
        .append(guid_buf).append("\\Connection");
      if(ERROR_SUCCESS != RegOpenKeyEx(HKEY_LOCAL_MACHINE, full_path.c_str(),
        0, KEY_READ, &key_1))
        continue;
      name_buf_len = 256;
      if(ERROR_SUCCESS != RegQueryValueEx(key_1, "Name", NULL, NULL,
        (LPBYTE)name_buf, &name_buf_len))
      {
        RegCloseKey(key_1);
        key_1 = nullptr;
        continue;
      }
      /* Check if the name matches */
      if(name.compare(name_buf) == 0)
      {
        guid.assign(guid_buf, guid_buf_len);
        is_found = true;
      }
      RegCloseKey(key_1);
      key_1 = nullptr;
    }
    RegCloseKey(key_0);
  } catch(exception & e)
  {
    RegCloseKey(key_1);
    RegCloseKey(key_0);
    e.what();
    throw;
  }
  return;
}

uint32_t TapDevWin::MediaStatus()
{
  lock_guard<mutex> lg(rw_mutex_);
  return media_status_;
}

MacAddressType
TapDevWin::MacAddress()
{
  lock_guard<mutex> lg(rw_mutex_);
  GetMacAddress();
  return mac_address_;
}

void
TapDevWin::GetMacAddress()
{
  if (!DeviceIoControl(dev_handle_, TAP_IOCTL_GET_MAC, &mac_address_,
    sizeof(mac_address_), &mac_address_.front(),
    (DWORD)mac_address_.max_size(), &mac_len_, NULL))
  {
    string emsg("Failed to query TAP device for MAC address of " + tap_name_);
    throw WINEXCEPT(emsg.c_str());
  }
}

void
TapDevWin::OnMessage(
  Message * msg)
{
  switch(msg->message_id)
  {
  case MSGID_WRITE:
  {
    AsyncIo* aio_wr = ((TapMessageData*)msg->pdata)->aio_;
    lock_guard<mutex> lg(rw_mutex_);
    WriteFile(dev_handle_, aio_wr->BufferToTransfer(),
      (unsigned long)aio_wr->BytesToTransfer(), NULL, (LPOVERLAPPED)aio_wr);
    DWORD rv = GetLastError();
    if(rv != ERROR_IO_PENDING && rv != ERROR_SUCCESS)
    {
      RTC_LOG(LS_WARNING) << "The TAP device write request operation failed for device "
        << tap_name_ << ", error: " << rv << ".";
      delete static_cast<TapFrame*>(aio_wr->context_);
    }
  }
  break;
  default:
    RTC_LOG(LS_WARNING) << "An invalid TAP Message ID was specified for device " << tap_name_ << ".";
    break;
  }
  delete (TapMessageData*)msg->pdata;
}

void
TapDevWin::Up()
{
  lock_guard<mutex> lg(rw_mutex_);
  DWORD len = 0;
  media_status_ = 1;
  //Set interface as enabled
  if (!DeviceIoControl(dev_handle_, TAP_IOCTL_SET_MEDIA_STATUS,
    &media_status_, sizeof(media_status_), &media_status_,
    sizeof(media_status_), (LPDWORD)&len, NULL))
  {
    const string emsg("Device IO control to TAP failed to enable EVIO TAP device " + tap_name_);
    throw WINEXCEPT(emsg.c_str());
  }
  //Get drivers version
  ULONG info[3];
  memset(info, 0, sizeof(info));
  if(DeviceIoControl(dev_handle_, TAP_IOCTL_GET_VERSION, &info,
    sizeof(info), &info, sizeof(info), &len, NULL))
  {
    RTC_LOG(LS_INFO) << "TAP Driver Version " << (int)info[0] <<
      (int)info[1] << (info[2] ? "(DEBUG)" : "");
  }
  uint16_t mtu = Mtu();
  writer_.Start();
  io_thread_pool_.Attach(cmpl_prt_handle_);
  RTC_LOG(LS_INFO) << "TAP device MTU " << mtu;
}

void
TapDevWin::Down()
{
  lock_guard<mutex> lg(rw_mutex_);
  DWORD len = 0;
  media_status_ = 0;
  io_thread_pool_.Release();
  writer_.Quit();
  if (!DeviceIoControl(dev_handle_, TAP_IOCTL_SET_MEDIA_STATUS, &media_status_,
    sizeof(media_status_), &media_status_, sizeof(media_status_),
    (LPDWORD)&len, NULL))
  {
    const string emsg("Device IO control failed to disable EVIO TAP device " + tap_name_);
    throw WINEXCEPT(emsg.c_str());
  }
}

//void
//TapDevWin::Mtu(
//  uint16_t mtu)
//{//TODO: implement MTU
//  mtu;
//}

uint16_t TapDevWin::Mtu()
{
  //get driver MTU
  DWORD len = 0;
  ULONG mtu;
  if(!DeviceIoControl(dev_handle_, TAP_IOCTL_GET_MTU, &mtu, sizeof(mtu),
    &mtu, sizeof(mtu), &len, NULL))
  {
    RTC_LOG(LS_ERROR) << "The ioctl failed to query the TAP device MTU for device "
      << tap_name_ << ".";
  }
  return (uint16_t)mtu;
}

IP4AddressType
TapDevWin::Ip4()
{
  return ip4_;
}
}  // namespace win
}  // namespace tincan
#endif// _TNC_WIN
