#ifndef LOGICAL_HPP
#define LOGICAL_HPP

#include <iostream>
#include <comdef.h>
#include <Wbemidl.h>
#include <wincred.h>
#include <strsafe.h>
#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "credui.lib")
#pragma comment(lib, "comsuppw.lib")

#define _WIN32_DCOM
#define UNICODE

int InitCom();
int	SetLevelSecurity();
int	CreateWMILocator();
int	ConnectToWMI();
int ConnectToNamespace(LPCWSTR name_space);
int	CreateCoauth();
int	SetProxySecurity();
int	TakeData(LPCSTR selectfrom);
int GetData(LPCWSTR lname);
void CleanAll();
#endif // LOGICAL_HPP