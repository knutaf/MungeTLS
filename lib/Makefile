TARGET=MungeTLS
C_DEFINES=/DUNICODE

C_FILES=\
    MungeTLS.cpp \
    MungeCrypto.cpp \
    WindowsCrypto.cpp \

O_FILES=\
    MungeTLS.obj \
    MungeCrypto.obj \
    WindowsCrypto.obj \

H_FILES=\
    ..\inc\MungeTLS.h \
    ..\inc\MungeCrypto.h \
    mtls_helper.h  \
    precomp.h  \

SOURCES=$(C_FILES) $(H_FILES)

$(TARGET).lib: $(O_FILES)
	lib /out:$(TARGET).lib $(O_FILES)

$(O_FILES): $(H_FILES) $(C_FILES)

.cpp.obj:
	cl /c $(C_DEFINES) -I..\inc /EHsc /Zi /W4 /Ycprecomp.h $<

clean:
	del *.exe *.obj *.pdb *.ilk *.pch *.lib

cleanup:
	del *.obj *.pdb *.ilk *.pch
