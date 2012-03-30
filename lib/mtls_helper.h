#pragma once
#include <intsafe.h>

#define SAFE_SUB(h, l, r)              \
{                                      \
    (h) = SizeTSub((l), (r), &(l));    \
    if ((h) != S_OK) { goto error; }   \
}                                      \

#define ADVANCE_PARSE()                \
{                                      \
    pv += cbField;                     \
    SAFE_SUB(hr, cb, cbField);         \
}                                      \

