#ifndef MTLS_INC_MTLS_HELPER_INL_HPP
#define MTLS_INC_MTLS_HELPER_INL_HPP
#include <vector>
#include "MungeTLS.h"

namespace MungeTLS
{

using namespace std;

// reads an integer value in network byte order
template <typename N>
MTERR
ReadNetworkLong(
    const MT_BYTE* pv,
    size_t cb,
    size_t cbToRead,
    N* pResult
)
{
    MTERR mr = MT_S_OK;

    if (cbToRead > sizeof(N))
    {
        mr = MT_E_INSUFFICIENT_BUFFER;
        goto error;
    }

    *pResult = 0;

    while (cbToRead > 0)
    {
        if (cb == 0)
        {
            mr = MT_E_INCOMPLETE_MESSAGE;
            goto error;
        }

        (*pResult) <<= 8;
        *pResult |= *pv;

        pv++;
        cb--;
        cbToRead--;
    }

done:
    return mr;

error:
    goto done;
} // end function ReadNetworkLong

template <typename I>
MTERR
WriteNetworkLong(
    I toWrite,
    size_t cbToWrite,
    MT_BYTE* pv,
    size_t cb
)
{
    MTERR mr = MT_S_OK;

    if (cbToWrite > sizeof(I))
    {
        mr = MT_E_INSUFFICIENT_BUFFER;
        goto error;
    }

    if (cbToWrite > cb)
    {
        mr = MT_E_INSUFFICIENT_BUFFER;
        goto error;
    }

    while (cbToWrite > 0)
    {
        pv[cbToWrite - 1] = (toWrite & 0xFF);

        toWrite >>= 8;
        cbToWrite--;
    }

done:
    return mr;

error:
    goto done;
} // end function WriteNetworkLong

template <typename T>
void
ResizeVector<T>(
    vector<T>* pv,
    typename vector<T>::size_type siz
)
{
    pv->resize(siz);
} // end function ResizeVector<T>

}
#endif
