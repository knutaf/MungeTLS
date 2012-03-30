TARGET=MungeTLS
C_DEFINES=/DUNICODE

C_FILES=\
    MungeTLS.cpp \

O_FILES=\
    MungeTLS.obj\

H_FILES=\
    MungeTLS.h \

SOURCES=$(C_FILES) $(H_FILES)

$(TARGET).lib: $(O_FILES)
	lib /out:$(TARGET).lib $(O_FILES)

MungeTLS.obj: MungeTLS.cpp ..\inc\MungeTLS.h
	cl /c $(C_DEFINES) -I..\inc /EHsc /Zi /W4 /Ycprecomp.h MungeTLS.cpp

clean:
	del *.exe *.obj *.pdb *.ilk *.pch *.lib

cleanup:
	del *.obj *.pdb *.ilk *.pch
