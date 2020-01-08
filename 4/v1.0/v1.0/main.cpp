#include "Logical.hpp"
#include "Interface.hpp"


int __cdecl main(int argc, char **argv) {
	InitCom();
	SetLevelSecurity();
	CreateWMILocator();
	ConnectToWMI();
	while (1)
	{
		LPCWSTR lname;
		LPCSTR selectfrom;
		LPCWSTR name_space;
		if (ChooseRequest(lname, selectfrom, name_space) == 0)
		{
			ConnectToNamespace(name_space);
			CreateCoauth();
			SetProxySecurity();
			TakeData(selectfrom);
			GetData(lname);
			std::cout << "\n-----------------------------\n";
		}
		else
		{
			CleanAll();
			break;
		}
	}
}

