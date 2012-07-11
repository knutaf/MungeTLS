TARGET=MTLS_WinCrypt
C_DEFINES=/DUNICODE

C_FILES=\
    WindowsCrypto.cpp \

O_FILES=\
    WindowsCrypto.obj \

H_FILES=\
    $(H_FILES) \
    wincrypt_help.h  \
    precomp.h  \

SOURCES=$(C_FILES) $(H_FILES)

$(TARGET).lib: $(O_FILES)
	lib /out:$(TARGET).lib $(O_FILES)

$(O_FILES): $(H_FILES) $(C_FILES)

.cpp.obj:
	cl /c $(C_DEFINES) $(INCLUDES) /EHsc /Zi /W4 /Ycprecomp.h $<

clean:
	del *.exe *.obj *.pdb *.ilk *.pch *.lib

cleanup:
	del *.obj *.pdb *.ilk *.pch
