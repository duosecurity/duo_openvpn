set PREFIX=E:\\workspace\\duo_openvpn\\

cl.exe /D_MSVC /DPREFIX=%PREFIX% /D_USRDLL /D_WINDLL duo_openvpn.c duo_openvpn.obj /link /DLL /OUT:duo_openvpn.dll