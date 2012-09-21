TARGET=MTLS_Windows

C_FILES=\
    WindowsCrypto.cpp \
    mtls_plat_windows.cpp \

O_FILES=\
    WindowsCrypto.obj \
    mtls_plat_windows.obj \

H_FILES=\
    $(H_FILES) \
    mtls_plat_windows.h  \
    precomp.h  \

SOURCES=$(C_FILES) $(H_FILES)

$(TARGET).lib: $(O_FILES)
	lib /out:$(TARGET).lib $(O_FILES)

$(O_FILES): $(H_FILES) $(C_FILES)

.cpp.obj:
	cl /c $(C_FLAGS) $(C_DEFINES) $(INCLUDES) /EHsc /Zi /W4 /Ycprecomp.h $<

clean:
	del *.exe *.obj *.pdb *.ilk *.pch *.lib
