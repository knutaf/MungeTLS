TARGET=MungeTLS
C_DEFINES=/DUNICODE

C_FILES=\
    main.cpp \

H_FILES=\

LIBS=\
    shlwapi.lib \
    shell32.lib \
    ws2_32.lib \
    crypt32.lib \
    $(MY_LIBS) \

MY_LIBS=\
    ..\lib\MungeTLS.lib \

SOURCES=$(C_FILES) $(H_FILES)

$(TARGET).exe: $(SOURCES) $(MY_LIBS)
	cl /Fe$(TARGET).exe $(C_DEFINES) -I..\inc /EHsc /Zi /W4 /Ycprecomp.h $(C_FILES) /link $(LIBS)

clean:
	del *.exe *.obj *.pdb *.ilk *.pch

cleanup:
	del *.obj *.pdb *.ilk *.pch
