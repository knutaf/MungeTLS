TARGET=MungeTLS

C_FILES=\
    main.cpp \

H_FILES=\
    $(H_FILES) \
    main.h \

LIBS=\
    shlwapi.lib \
    shell32.lib \
    ws2_32.lib \
    crypt32.lib \
    advapi32.lib \
    $(MY_LIBS) \

MY_LIBS=\
    ..\lib\MungeTLS.lib \
    ..\plat_lib_windows\MTLS_Windows.lib \

INCLUDES=\
    $(INCLUDES) \
    -I..\plat_lib_windows \

LINK_FLAGS=

#
# detect if Netmon is installed and try to build in Netmon logging support
# you still need to have nmapi.h in your INCLUDES path and nmapi.lib in your
# lib or libpath
#
!if [where NMAPI.dll] == 0
# the NDIS define is needed for ntddndis.h in NetmonLogger.cpp
C_DEFINES=$(C_DEFINES) -DWITH_NETMON -DUM_NDIS630=1

# delayimp.lib is required for /delayload functionality
LIBS=\
    $(LIBS) \
    nmapi.lib \
    Delayimp.lib \

C_FILES=\
    $(C_FILES) \
    NetmonLogger.cpp \

H_FILES=\
    $(H_FILES) \
    NetmonLogger.h \

# this prevents the absence of netmon.dll from stopping the app from launching
LINK_FLAGS=\
    $(LINK_FLAGS) \
    /delayload:nmapi.dll
!endif

SOURCES=$(C_FILES) $(H_FILES)

$(TARGET).exe: $(SOURCES) $(MY_LIBS)
	cl /Fe$(TARGET).exe $(C_FLAGS) $(C_DEFINES) $(INCLUDES) /EHsc /Zi /W4 /Ycprecomp.h $(C_FILES) /link $(LIBS) $(LINK_FLAGS)

clean:
	del *.exe *.obj *.pdb *.ilk *.pch
