all: exe\MungeTLS.exe

exe\MungeTLS.exe: lib\MungeTLS.lib
	cd exe
	$(MAKE)
	cd ..

lib\MungeTLS.lib:
	cd lib
	$(MAKE)
	cd ..

clean:
	cd exe
	$(MAKE) clean
	cd ..
	cd lib
	$(MAKE) clean
	cd ..

cleanup:
	cd exe
	$(MAKE) cleanup
	cd ..
	cd lib
	$(MAKE) cleanup
	cd ..
