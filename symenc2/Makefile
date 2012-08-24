TARGET=symenc2

$(TARGET).exe: main.cpp ..\wincrypt_lib\MTLS_WinCrypt.lib
	cl /Fe$(TARGET).exe /EHsc /Zi /W4 /I..\wincrypt_lib /I..\inc main.cpp /link shlwapi.lib crypt32.lib advapi32.lib ..\wincrypt_lib\MTLS_WinCrypt.lib ..\lib\mungetls.lib

clean:
	del *.exe *.obj *.pdb *.ilk

cleanup:
	del *.obj *.pdb *.ilk
