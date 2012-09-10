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
	cd wincrypt_lib
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
	cd wincrypt_lib
	$(MAKE) clean
	cd ..
	cd lib
	$(MAKE) clean
	cd ..

cleanup:
	del /s *.ilk vc11* *.obj *.pch
