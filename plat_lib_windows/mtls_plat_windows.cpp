#include "precomp.h"
#include <windows.h>
#include <intsafe.h>
#include "MungeTLS.h"
#include "mtls_plat_windows.h"

namespace MungeTLS
{

HRESULT EpochTimeFromSystemTime(const SYSTEMTIME* pST, ULONG* pTime);

MTERR
GetCurrentGMTTime(
    MT_UINT32* pTime
)
{
    MTERR mr = MT_S_OK;
    HRESULT hr = S_OK;

    SYSTEMTIME st = {0};
    ULONG t = 0;

    GetSystemTime(&st);

    CHKWINOKM(EpochTimeFromSystemTime(&st, &t));

    // TODO: replace cast with function
    *pTime = static_cast<MT_UINT32>(t);

done:
    return mr;

error:
    goto done;
} // end function GetCurrentGMTTime

/*
** translates a SYSTEMTIME object into a 32-bit time value representing seconds
** since midnight on Jan 1 1970 GMT, which is suitable for inclusion in the
** "gmt_unix_time" field in the TLS RFC.
*/
HRESULT
EpochTimeFromSystemTime(
    const SYSTEMTIME* pST,
    ULONG* pTime
)
{
    HRESULT hr = S_OK;
    ULARGE_INTEGER li = {0};

    const SYSTEMTIME st1Jan1970 =
    {
        1970, // year
        1,    // month
        0,    // day of week
        1,    // day
        0,    // hour
        0,    // min
        0,    // sec
        0     // ms
    };

    FILETIME ft = {0};
    FILETIME ft1Jan1970 = {0};
    ULARGE_INTEGER li1Jan1970 = {0};

    // convert system time object into a large integer
    CHKWIN(SystemTimeToFileTime(pST, &ft));

    li.LowPart = ft.dwLowDateTime;
    li.HighPart = ft.dwHighDateTime;

    // convert Jan 1 1970 into a large integer
    CHKWIN(SystemTimeToFileTime(&st1Jan1970, &ft1Jan1970));

    li1Jan1970.LowPart = ft1Jan1970.dwLowDateTime;
    li1Jan1970.HighPart = ft1Jan1970.dwHighDateTime;

    // subtract specified time object from Jan 1 1970 to get elapsed time
    CHKWINOK(ULongLongSub(li.QuadPart, li1Jan1970.QuadPart, &li.QuadPart));

    // convert from 100 ns to ms
    li.QuadPart /= 10000000ULL;

    CHKWINOK(ULongLongToULong(li.QuadPart, pTime));

done:
    return hr;

error:
    goto done;
} // end function EpochTimeFromSystemTime

MTERR
HR2MR(
    HRESULT hr
)
{
    return hr;
} // end function HR2MR

HRESULT
MR2HR(
    MTERR mr
)
{
    return mr;
} // end function MR2HR

MTERR
MT_SizeTToByte(
    size_t s,
    MT_BYTE* pb
)
{
    return HR2MR(SizeTToByte(s, pb));
} // end function MT_SizeTToByte

MTERR
MT_SizeTSub(
    size_t l,
    size_t r,
    size_t* pOut
)
{
    return HR2MR(SizeTSub(l, r, pOut));
} // end function MT_SizeTSub

}
