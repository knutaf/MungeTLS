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

SOURCES=$(C_FILES) $(H_FILES)

$(TARGET).exe: $(SOURCES) $(MY_LIBS)
	cl /Fe$(TARGET).exe $(C_DEFINES) $(INCLUDES) /EHsc /Zi /W4 /Ycprecomp.h $(C_FILES) /link $(LIBS)

clean:
	del *.exe *.obj *.pdb *.ilk *.pch
