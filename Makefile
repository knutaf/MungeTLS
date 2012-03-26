TARGET=MungeTLS
C_DEFINES=/DUNICODE

C_FILES=\
    main.cpp \
    MungeTLS.cpp \

H_FILES=\
    MungeTLS.h \

SOURCES=$(C_FILES) $(H_FILES)

$(TARGET).exe: $(SOURCES)
	cl /Fe$(TARGET).exe $(C_DEFINES) /EHsc /Zi /W4 /Ycprecomp.h $(C_FILES) /link shlwapi.lib shell32.lib ws2_32.lib

clean:
	del *.exe *.obj *.pdb *.ilk *.pch

cleanup:
	del *.obj *.pdb *.ilk
