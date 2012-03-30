all:
	cd lib
	$(MAKE)
	cd ..
	cd exe
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
