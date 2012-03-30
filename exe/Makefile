TARGET=MungeTLS
C_DEFINES=/DUNICODE

C_FILES=\
    main.cpp \

H_FILES=\

LIBS=\
    ..\lib\MungeTLS.lib \

SOURCES=$(C_FILES) $(H_FILES)

$(TARGET).exe: $(SOURCES) $(LIBS)
	cl /Fe$(TARGET).exe $(C_DEFINES) -I..\inc /EHsc /Zi /W4 /Ycprecomp.h $(C_FILES) /link shlwapi.lib shell32.lib ws2_32.lib $(LIBS)

clean:
	del *.exe *.obj *.pdb *.ilk *.pch

cleanup:
	del *.obj *.pdb *.ilk *.pch
