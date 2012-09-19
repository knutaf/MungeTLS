#include "precomp.h"
#include <windows.h>
#include "MungeTLS.h"

namespace MungeTLS
{

MTERR HR2MR(HRESULT hr)
{
    return hr;
} // end function HR2MR

HRESULT MR2HR(MTERR mr)
{
    return mr;
} // end function MR2HR

}
