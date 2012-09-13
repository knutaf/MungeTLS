H_FILES=\
    ..\inc\mtls_defs.h \
    ..\inc\MungeTLS.h \
    ..\inc\MungeCrypto.h \

INCLUDES=\
    -I..\inc \

all:
	set H_FILES=$(H_FILES)
	set INCLUDES=$(INCLUDES)
	cd lib
	$(MAKE)
	cd ..
	cd plat_lib_windows
	$(MAKE)
	cd ..
	cd exe
	$(MAKE)
	cd ..

clean:
	set H_FILES=$(H_FILES)
	set INCLUDES=$(INCLUDES)
	cd exe
	$(MAKE) clean
	cd ..
	cd plat_lib_windows
	$(MAKE) clean
	cd ..
	cd lib
	$(MAKE) clean
	cd ..

cleanup:
	del /s *.ilk vc11* *.obj *.pch
