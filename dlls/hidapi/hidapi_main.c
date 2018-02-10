/*
* Wrapper for HIDAPI
*
* Copyright 2018 John Eric Martin <john.eric.martin@gmail.com>
*
* This library is free software; you can redistribute it and/or
* modify it under the terms of the GNU Lesser General Public
* License as published by the Free Software Foundation; either
* version 2.1 of the License, or (at your option) any later version.
*
* This library is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
* Lesser General Public License for more details.
*
* You should have received a copy of the GNU Lesser General Public
* License along with this library; if not, write to the Free Software
* Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
*/

#include "config.h"
#include <stdarg.h>

#include "windef.h"
#include "winbase.h"
#include "winerror.h"
#include "wine/debug.h"

// Standard C Includes
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <wchar.h>

// Linux Includes
#include <dlfcn.h>
#include <hidapi/hidapi.h>

WINE_DEFAULT_DEBUG_CHANNEL(hidapi);

////////////////////////////////////////////////////////////////////////////////
// Macros
////////////////////////////////////////////////////////////////////////////////

//#define SO_FILE_NAME "libhidapi-hidraw.so"
//#define SO_FILE_NAME "libhidapi-libusb.so"
//#define SO_FILE_NAME "/usr/lib/i386-linux-gnu/libhidapi-hidraw.so.0"
#define SO_FILE_NAME "/usr/lib/i386-linux-gnu/libhidapi-libusb.so.0"

#ifdef HID_API_EXPORT
#undef HID_API_EXPORT
#endif // HID_API_EXPORT

#ifdef HID_API_CALL
#undef HID_API_CALL
#endif // HID_API_CALL

#ifdef HID_API_EXPORT_CALL
#undef HID_API_EXPORT_CALL
#endif // HID_API_EXPORT_CALL

#define HID_API_EXPORT
#define HID_API_CALL __cdecl
#define HID_API_EXPORT_CALL HID_API_EXPORT HID_API_CALL

////////////////////////////////////////////////////////////////////////////////
// Function Prototypes
////////////////////////////////////////////////////////////////////////////////

BOOL WINAPI DllMain(
    HINSTANCE hinstDLL,
    DWORD     fdwReason,
    LPVOID    lpvReserved);
BOOL DllEntry(HINSTANCE hinstDLL);
BOOL DllExit(HINSTANCE hinstDLL);
void LogTimestamp(void);
const char* wchar2char(const wchar_t *szIn);
const char* wchar2char_ex(const wchar_t *szIn, size_t len);
void LockLog(void);
void UnlockLog(void);

////////////////////////////////////////////////////////////////////////////////
// Global Variables
////////////////////////////////////////////////////////////////////////////////

static const wchar_t *CHANNEL1 = L"PFxCh1";
static const wchar_t *CHANNEL2 = L"PFxCh2";

BOOL gInitialized = FALSE;
BOOL gLoaded = FALSE;
FILE *gLogFile = NULL;
HMODULE gLibrary = NULL;
HANDLE gMutex = NULL;

int (*gHIDAPI_hid_init)(void);
int (*gHIDAPI_hid_exit)(void);
struct hid_device_info* (*gHIDAPI_hid_enumerate)(
    unsigned short vendor_id, unsigned short product_id);
void (*gHIDAPI_hid_free_enumeration)(struct hid_device_info *devs);
hid_device* (*gHIDAPI_hid_open)(unsigned short vendor_id,
    unsigned short product_id, const wchar_t *serial_number);
hid_device* (*gHIDAPI_hid_open_path)(const char *path);
int (*gHIDAPI_hid_write)(hid_device *device,
    const unsigned char *data, size_t length);
int (*gHIDAPI_hid_read_timeout)(hid_device *device,
    unsigned char *data, size_t length, int milliseconds);
int (*gHIDAPI_hid_read)(hid_device *device,
    unsigned char *data, size_t length);
int (*gHIDAPI_hid_set_nonblocking)(hid_device *device, int nonblock);
int (*gHIDAPI_hid_send_feature_report)(hid_device *device,
    const unsigned char *data, size_t length);
int (*gHIDAPI_hid_get_feature_report)(hid_device *device,
    unsigned char *data, size_t length);
void (*gHIDAPI_hid_close)(hid_device *device);
int (*gHIDAPI_hid_get_manufacturer_string)(hid_device *device,
    wchar_t *string, size_t maxlen);
int (*gHIDAPI_hid_get_product_string)(hid_device *device,
    wchar_t *string, size_t maxlen);
int (*gHIDAPI_hid_get_serial_number_string)(hid_device *device,
    wchar_t *string, size_t maxlen);
int (*gHIDAPI_hid_get_indexed_string)(hid_device *device,
    int string_index, wchar_t *string, size_t maxlen);
const wchar_t* (*gHIDAPI_hid_error)(hid_device *device);

////////////////////////////////////////////////////////////////////////////////
// Function Implementations
////////////////////////////////////////////////////////////////////////////////

BOOL WINAPI DllMain(
    HINSTANCE hinstDLL,
    DWORD     fdwReason,
    LPVOID    lpvReserved)
{
    switch(fdwReason)
    {
        case DLL_PROCESS_ATTACH:
        {
            if(!gLoaded)
            {
                BOOL result = DllEntry(hinstDLL);
                gLoaded = result;

                return result;
            }
        }
        case DLL_PROCESS_DETACH:
        {
            return DllExit(hinstDLL);
        }
        case DLL_THREAD_ATTACH:
        {
            if(!gLoaded)
            {
                BOOL result = DllEntry(hinstDLL);
                gLoaded = result;

                return result;
            }
        }
        case DLL_THREAD_DETACH:
            break;
        default:
            break;
    }

    return TRUE;
}

BOOL DllEntry(HINSTANCE hinstDLL)
{
    //
    // Open the log file.
    //
    gMutex = CreateMutexA(NULL, FALSE, NULL);

    if(NULL == gMutex)
    {
        return FALSE;
    }

    LockLog();
    gLogFile = fopen("/home/erikku/PFx/hidapi_wrapper.log", "w");
    UnlockLog();

    if(NULL == gLogFile)
    {
        return FALSE;
    }

    //
    // Load the original hidapi DLL.
    //
    LockLog();
    LogTimestamp();
    TRACE("Loading original library '" SO_FILE_NAME "'.\n");
    fprintf(gLogFile, "Loading original library '" SO_FILE_NAME "'.\n");
    UnlockLog();

    gLibrary = dlopen(SO_FILE_NAME, RTLD_NOW);

    if(NULL == gLibrary)
    {
        LockLog();
        LogTimestamp();
        TRACE("Failed to load original library '"
            SO_FILE_NAME "'.\n");
        fprintf(gLogFile, "Failed to load original library '"
            SO_FILE_NAME "'.\n");
        LogTimestamp();
        TRACE("ERROR: %s\n", dlerror());
        fprintf(gLogFile, "ERROR: %s\n", dlerror());
        UnlockLog();

        return FALSE;
    }

    //
    // Now save out all the functions so we may wrap them.
    //
    gHIDAPI_hid_init = (int (*)(void))dlsym(gLibrary, "hid_init");
    gHIDAPI_hid_exit = (int (*)(void))dlsym(gLibrary, "hid_exit");
    gHIDAPI_hid_enumerate = (struct hid_device_info* (*)(unsigned short,
        unsigned short))dlsym(gLibrary, "hid_enumerate");
    gHIDAPI_hid_free_enumeration = (void (*)(struct hid_device_info*
        ))dlsym(gLibrary, "hid_free_enumeration");
    gHIDAPI_hid_open = (hid_device* (*)(unsigned short, unsigned short,
        const wchar_t*))dlsym(gLibrary, "hid_open");
    gHIDAPI_hid_open_path = (hid_device* (*)(const char*))dlsym(
        gLibrary, "hid_open_path");
    gHIDAPI_hid_write = (int (*)(hid_device*, const unsigned char*,
        size_t))dlsym(gLibrary, "hid_write");
    gHIDAPI_hid_read_timeout = (int (*)(hid_device*, unsigned char*, size_t,
        int))dlsym(gLibrary, "hid_read_timeout");
    gHIDAPI_hid_read = (int (*)(hid_device*, unsigned char*,
        size_t))dlsym(gLibrary, "hid_read");
    gHIDAPI_hid_set_nonblocking = (int (*)(hid_device*,
        int))dlsym(gLibrary, "hid_set_nonblocking");
    gHIDAPI_hid_send_feature_report = (int (*)(hid_device*,
        const unsigned char*, size_t))dlsym(gLibrary,
        "hid_send_feature_report");
    gHIDAPI_hid_get_feature_report = (int (*)(hid_device*, unsigned char*,
        size_t))dlsym(gLibrary, "hid_get_feature_report");
    gHIDAPI_hid_close = (void (*)(hid_device*))dlsym(
        gLibrary, "hid_close");
    gHIDAPI_hid_get_manufacturer_string = (int (*)(hid_device*,
        wchar_t*, size_t))dlsym(gLibrary,
        "hid_get_manufacturer_string");
    gHIDAPI_hid_get_product_string = (int (*)(hid_device*,
        wchar_t*, size_t))dlsym(gLibrary,
        "hid_get_product_string");
    gHIDAPI_hid_get_serial_number_string = (int (*)(hid_device*,
        wchar_t*, size_t))dlsym(gLibrary,
        "hid_get_serial_number_string");
    gHIDAPI_hid_get_indexed_string = (int (*)(hid_device*,
        int, wchar_t*, size_t))dlsym(gLibrary,
        "hid_get_indexed_string");
    gHIDAPI_hid_error = (const wchar_t* (*)(hid_device*))dlsym(
        gLibrary, "hid_error");

    // Check that all the functions were found.
    if(NULL == gHIDAPI_hid_init ||
        NULL == gHIDAPI_hid_exit ||
        NULL == gHIDAPI_hid_enumerate ||
        NULL == gHIDAPI_hid_free_enumeration ||
        NULL == gHIDAPI_hid_open ||
        NULL == gHIDAPI_hid_open_path ||
        NULL == gHIDAPI_hid_write ||
        NULL == gHIDAPI_hid_read_timeout ||
        NULL == gHIDAPI_hid_read ||
        NULL == gHIDAPI_hid_set_nonblocking ||
        NULL == gHIDAPI_hid_send_feature_report ||
        NULL == gHIDAPI_hid_get_feature_report ||
        NULL == gHIDAPI_hid_close ||
        NULL == gHIDAPI_hid_get_manufacturer_string ||
        NULL == gHIDAPI_hid_get_product_string ||
        NULL == gHIDAPI_hid_get_serial_number_string ||
        NULL == gHIDAPI_hid_get_indexed_string ||
        NULL == gHIDAPI_hid_error)
    {
        return FALSE;
    }

    return TRUE;
}

BOOL DllExit(HINSTANCE hinstDLL)
{
    // Free any temp string.
    (void)wchar2char(NULL);

    if(NULL != gLibrary)
    {
        LockLog();
        LogTimestamp();
        TRACE("Unloading the original library.\n");
        fprintf(gLogFile, "Unloading the original library.\n");
        UnlockLog();

        if(!FreeLibrary(gLibrary))
        {
            LockLog();
            LogTimestamp();
            TRACE("Failed to free the original library.\n");
            fprintf(gLogFile, "Failed to free the original library.\n");
            UnlockLog();
        }
    }

    if(NULL != gLogFile)
    {
        LockLog();
        fclose(gLogFile);
        gLogFile = NULL;
        UnlockLog();
    }

    CloseHandle(gMutex);
    gMutex = NULL;

    return TRUE;
}

void LogTimestamp(void)
{
    time_t localTime = time(NULL);

    char *szTimestamp = asctime(localtime(&localTime));
    szTimestamp[strlen(szTimestamp) - 1] = '\0';

    fprintf(gLogFile, "%s:  ", szTimestamp);
}

const char* wchar2char_ex(const wchar_t *szIn, size_t len)
{
    static char *szOut = NULL;

    if(NULL != szOut)
    {
        free(szOut);
        szOut = NULL;
    }

    if(NULL != szIn && 0 != len)
    {
        szOut = (char*)malloc(len + 1);
        memset(szOut, 0, len + 1);
        wcstombs(szOut, szIn, len);
    }

    return szOut;
}

const char* wchar2char(const wchar_t *szIn)
{
    if(NULL != szIn)
    {
        size_t len = wcslen(szIn);

        return wchar2char_ex(szIn, len);
    }
    else
    {
        return wchar2char_ex(szIn, 0);
    }
}

void LockLog(void)
{
    (void)WaitForSingleObject(gMutex, INFINITE);
}

void UnlockLog(void)
{
    fflush(gLogFile);
    ReleaseMutex(gMutex);
}

int HID_API_EXPORT_CALL hid_init(void)
{
    int returnValue = gHIDAPI_hid_init();

    if(0 == returnValue)
    {
        gInitialized = TRUE;
    }

    LockLog();
    LogTimestamp();
    fprintf(gLogFile, "hid_init() = %d\n", returnValue);
    UnlockLog();

    return returnValue;
}

int HID_API_EXPORT_CALL hid_exit(void)
{
    int returnValue = gHIDAPI_hid_exit();

    if(0 == returnValue)
    {
        gInitialized = FALSE;
    }

    LockLog();
    LogTimestamp();
    fprintf(gLogFile, "hid_exit() = %d\n", returnValue);
    UnlockLog();

    return returnValue;
}

struct hid_device_info HID_API_EXPORT *HID_API_CALL hid_enumerate(
    unsigned short vendor_id, unsigned short product_id)
{
    int i;
    struct hid_device_info *pNext;
    struct hid_device_info *pDevices = gHIDAPI_hid_enumerate(
        vendor_id, product_id);

    LockLog();
    LogTimestamp();
    fprintf(gLogFile, "hid_enumerate(0x%04x, 0x%04x) = 0x%p\n",
        vendor_id & 0xFFFF, product_id & 0xFFFF, pDevices);

    //
    // Log the devices.
    //
    pNext = pDevices;
    i = 0;

    while(NULL != pNext)
    {
        // Modify the enumeration of the PFx Brick to match Windows.
        switch(pNext->interface_number)
        {
            case 0:
            {
                free(pNext->product_string);
                pNext->product_string = wcsdup(CHANNEL1);
                pNext->usage_page = 0xff00;
                pNext->usage = 0x0001;
                break;
            }
            case 1:
            {
                free(pNext->product_string);
                pNext->product_string = wcsdup(CHANNEL2);
                pNext->usage_page = 0xff00;
                pNext->usage = 0x0002;
                break;
            }
            default:
            {
                break;
            }
        }

        LogTimestamp();
        fprintf(gLogFile, "  device %d\n", i++);
        LogTimestamp();
        fprintf(gLogFile, "    path=%s\n", pNext->path);
        LogTimestamp();
        fprintf(gLogFile, "    vendor_id=0x%04x\n",
            pNext->vendor_id & 0xFFFF);
        LogTimestamp();
        fprintf(gLogFile, "    product_id=0x%04x\n",
            pNext->product_id & 0xFFFF);
        LogTimestamp();
        fprintf(gLogFile, "    serial_number=%s\n",
            wchar2char(pNext->serial_number));
        LogTimestamp();
        fprintf(gLogFile, "    release_number=0x%04x\n",
            pNext->release_number & 0xFFFF);
        LogTimestamp();
        fprintf(gLogFile, "    manufacturer_string=%s\n",
            wchar2char(pNext->manufacturer_string));
        LogTimestamp();
        fprintf(gLogFile, "    product_string=%s\n",
            wchar2char(pNext->product_string));
        LogTimestamp();
        fprintf(gLogFile, "    usage_page=0x%04x\n",
            pNext->usage_page & 0xFFFF);
        LogTimestamp();
        fprintf(gLogFile, "    usage=0x%04x\n",
            pNext->usage & 0xFFFF);
        LogTimestamp();
        fprintf(gLogFile, "    interface_number=%d\n",
            pNext->interface_number);

        pNext = pNext->next;
    }

    UnlockLog();

    return pDevices;
}

void HID_API_EXPORT_CALL hid_free_enumeration(
    struct hid_device_info *devs)
{
    gHIDAPI_hid_free_enumeration(devs);

    LockLog();
    LogTimestamp();
    fprintf(gLogFile, "hid_free_enumeration(0x%p)\n", devs);
    UnlockLog();
}

HID_API_EXPORT hid_device *HID_API_CALL hid_open(unsigned short vendor_id,
    unsigned short product_id, const wchar_t *serial_number)
{
    hid_device *pDevice = gHIDAPI_hid_open(vendor_id, product_id,
        serial_number);

    LockLog();
    LogTimestamp();
    fprintf(gLogFile, "hid_open(0x%04x, 0x%04x, %s) = 0x%p\n",
        vendor_id & 0xFFFF, product_id & 0xFFFF,
        wchar2char(serial_number), pDevice);
    UnlockLog();

    return pDevice;
}

HID_API_EXPORT hid_device *HID_API_CALL hid_open_path(const char *path)
{
    hid_device *pDevice = gHIDAPI_hid_open_path(path);

    LockLog();
    LogTimestamp();
    fprintf(gLogFile, "hid_open_path(%s) = 0x%p\n", path, pDevice);
    UnlockLog();

    return pDevice;
}

int HID_API_EXPORT_CALL hid_write(hid_device *device,
    const unsigned char *data, size_t length)
{
    int returnValue = gHIDAPI_hid_write(device, data, length);

    LockLog();
    LogTimestamp();
    fprintf(gLogFile, "hid_write(0x%p, 0x%p, %d) = %d", device, data,
        (int)length, returnValue);

    if(0 < length)
    {
        fprintf(gLogFile, "\n");
        LogTimestamp();
        fprintf(gLogFile, " ");
    }

    while(0 < length--)
    {
        fprintf(gLogFile, " 0x%02X", (int)data[0] & 0xFF);

        data++;
    }

    fprintf(gLogFile, "\n");
    UnlockLog();

    return returnValue;
}

int HID_API_EXPORT_CALL hid_read_timeout(hid_device *device,
    unsigned char *data, size_t length, int milliseconds)
{
    int read;
    int returnValue = gHIDAPI_hid_read_timeout(device, data,
        length, milliseconds);

    LockLog();
    LogTimestamp();
    fprintf(gLogFile, "hid_read_timeout(0x%p, 0x%p, %d, %d) = %d", device,
        data, (int)length, milliseconds, returnValue);

    read = returnValue;

    if(0 < read)
    {
        fprintf(gLogFile, "\n");
        LogTimestamp();
        fprintf(gLogFile, " ");
    }

    while(0 < read--)
    {
        fprintf(gLogFile, " 0x%02X", (int)data[0] & 0xFF);

        data++;
    }

    fprintf(gLogFile, "\n");
    UnlockLog();

    return returnValue;
}

int HID_API_EXPORT_CALL hid_read(hid_device *device,
    unsigned char *data, size_t length)
{
    int read;
    int returnValue = gHIDAPI_hid_read(device, data, length);

    LockLog();
    LogTimestamp();
    fprintf(gLogFile, "hid_read(0x%p, 0x%p, %d) = %d", device, data,
        (int)length, returnValue);

    read = returnValue;

    if(0 < read)
    {
        fprintf(gLogFile, "\n");
        LogTimestamp();
        fprintf(gLogFile, " ");
    }

    while(0 < read--)
    {
        fprintf(gLogFile, " 0x%02X", (int)data[0] & 0xFF);

        data++;
    }

    fprintf(gLogFile, "\n");
    UnlockLog();

    return returnValue;
}

int HID_API_EXPORT_CALL hid_set_nonblocking(
    hid_device *device, int nonblock)
{
    int returnValue = gHIDAPI_hid_set_nonblocking(device, nonblock);

    LockLog();
    LogTimestamp();
    fprintf(gLogFile, "hid_set_nonblocking(0x%p, %d) = %d\n", device,
        nonblock, returnValue);
    UnlockLog();

    return returnValue;
}

int HID_API_EXPORT_CALL hid_send_feature_report(hid_device *device,
    const unsigned char *data, size_t length)
{
    int returnValue = gHIDAPI_hid_send_feature_report(device, data, length);

    LockLog();
    LogTimestamp();
    fprintf(gLogFile, "hid_send_feature_report(0x%p, 0x%p, %d) = %d",
        device, data, (int)length, returnValue);

    if(0 < length)
    {
        fprintf(gLogFile, "\n");
        LogTimestamp();
        fprintf(gLogFile, " ");
    }

    while(0 < length--)
    {
        fprintf(gLogFile, " 0x%02X", (int)data[0] & 0xFF);

        data++;
    }

    fprintf(gLogFile, "\n");
    UnlockLog();

    return returnValue;
}

int HID_API_EXPORT_CALL hid_get_feature_report(hid_device *device,
    unsigned char *data, size_t length)
{
    int read;
    int returnValue = gHIDAPI_hid_get_feature_report(device, data, length);

    LockLog();
    LogTimestamp();
    fprintf(gLogFile, "hid_get_feature_report(0x%p, 0x%p, %d) = %d",
        device, data, (int)length, returnValue);

    read = returnValue;

    if(0 < read)
    {
        fprintf(gLogFile, "\n");
        LogTimestamp();
        fprintf(gLogFile, " ");
    }

    while(0 < read--)
    {
        fprintf(gLogFile, " 0x%02X", (int)data[0] & 0xFF);

        data++;
    }

    fprintf(gLogFile, "\n");
    UnlockLog();

    return returnValue;
}

void HID_API_EXPORT_CALL hid_close(hid_device *device)
{
    // On Linux if you attempt to close a device after calling hid_exit
    // it will hang forever. Prevent this.
    if(gInitialized)
    {
        gHIDAPI_hid_close(device);
    }

    LockLog();
    LogTimestamp();
    fprintf(gLogFile, "hid_close(0x%p)\n", device);
    UnlockLog();
}

int HID_API_EXPORT_CALL hid_get_manufacturer_string(hid_device *device,
    wchar_t *string, size_t maxlen)
{
    int returnValue = gHIDAPI_hid_get_manufacturer_string(device,
        string, maxlen);

    LockLog();
    LogTimestamp();
    fprintf(gLogFile, "hid_get_manufacturer_string(0x%p, %s, %d) = %d\n",
        device, wchar2char(string), (int)maxlen, returnValue);
    UnlockLog();

    return returnValue;
}

int HID_API_EXPORT_CALL hid_get_product_string(hid_device *device,
    wchar_t *string, size_t maxlen)
{
    int returnValue = gHIDAPI_hid_get_product_string(device,
        string, maxlen);

    LockLog();
    LogTimestamp();
    fprintf(gLogFile, "hid_get_product_string(0x%p, %s, %d) = %d\n",
        device, wchar2char(string), (int)maxlen, returnValue);
    UnlockLog();

    return returnValue;
}

int HID_API_EXPORT_CALL hid_get_serial_number_string(hid_device *device,
    wchar_t *string, size_t maxlen)
{
    int returnValue = gHIDAPI_hid_get_serial_number_string(device,
        string, maxlen);

    LockLog();
    LogTimestamp();
    fprintf(gLogFile, "hid_get_serial_number_string(0x%p, %s, %d) = %d\n",
        device, wchar2char(string), (int)maxlen, returnValue);
    UnlockLog();

    return returnValue;
}

int HID_API_EXPORT_CALL hid_get_indexed_string(hid_device *device,
    int string_index, wchar_t *string, size_t maxlen)
{
    int returnValue = gHIDAPI_hid_get_indexed_string(device,
        string_index, string, maxlen);

    LockLog();
    LogTimestamp();
    fprintf(gLogFile, "hid_get_indexed_string(0x%p, %d, %s, %d) = %d\n",
        device, string_index, wchar2char(string), (int)maxlen, returnValue);
    UnlockLog();

    return returnValue;
}

HID_API_EXPORT const wchar_t *HID_API_CALL hid_error(hid_device *device)
{
    const wchar_t *szReturnValue = gHIDAPI_hid_error(device);

    LockLog();
    LogTimestamp();
    fprintf(gLogFile, "hid_error(0x%p) = %s\n", device,
        wchar2char(szReturnValue));
    UnlockLog();

    return szReturnValue;
}
