TARGET=symenc2

$(TARGET).exe: main.cpp ..\plat_lib_windows\MTLS_Windows.lib
	cl /Fe$(TARGET).exe /EHsc /Zi /W4 /I..\plat_lib_windows /I..\inc main.cpp /link shlwapi.lib crypt32.lib advapi32.lib ..\plat_lib_windows\MTLS_Windows.lib ..\lib\mungetls.lib

clean:
	del *.exe *.obj *.pdb *.ilk

cleanup:
	del *.obj *.pdb *.ilk
