TARGET=urldownloadtofile
$(TARGET).exe: main.cpp
	cl /Fe$(TARGET).exe /EHsc /Zi /W4 main.cpp /link shlwapi.lib urlmon.lib

clean:
	del *.exe *.obj *.pdb *.ilk

cleanup:
	del *.obj *.pdb *.ilk
