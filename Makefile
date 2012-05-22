H_FILES=\
    ..\inc\mtls_defs.h \
    ..\inc\MungeTLS.h \
    ..\inc\MungeCrypto.h \

all:
	set H_FILES=$(H_FILES)
	cd lib
	$(MAKE)
	cd ..
	cd exe
	$(MAKE)
	cd ..

clean:
	set H_FILES=$(H_FILES)
	cd exe
	$(MAKE) clean
	cd ..
	cd lib
	$(MAKE) clean
	cd ..

cleanup:
	set H_FILES=$(H_FILES)
	cd exe
	$(MAKE) cleanup
	cd ..
	cd lib
	$(MAKE) cleanup
	cd ..
