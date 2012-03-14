TARGET=certenc

$(TARGET).exe: main.cpp
	cl /Fe$(TARGET).exe /EHsc /Zi /W4 main.cpp /link shlwapi.lib crypt32.lib advapi32.lib

clean:
	del *.exe *.obj *.pdb *.ilk

cleanup:
	del *.obj *.pdb *.ilk
