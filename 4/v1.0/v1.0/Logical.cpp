#include "Logical.hpp"

using namespace std;
///////////////////////////////////////////////////////////////////
HRESULT hres;
IWbemServices *pSvc = nullptr;
IWbemLocator *pLoc = nullptr;
IEnumWbemClassObject* pEnumerator = nullptr;
IWbemClassObject *pclsObj = nullptr;


CREDUI_INFO cui;

wchar_t pszName[CREDUI_MAX_USERNAME_LENGTH + 1] = { 0 };
wchar_t pszPwd[CREDUI_MAX_PASSWORD_LENGTH + 1] = { 0 };
wchar_t pszDomain[CREDUI_MAX_USERNAME_LENGTH + 1];
wchar_t pszUserName[CREDUI_MAX_USERNAME_LENGTH + 1];
wchar_t pszAuthority[CREDUI_MAX_USERNAME_LENGTH + 1];

COAUTHIDENTITY *userAcct = NULL;
COAUTHIDENTITY authIdent;

bool useToken = false;
bool useNTLM = true;
BOOL fSave;
DWORD dwErr;
////////////////////////////////////////////////////////////////////

// Инициализация COM.
int InitCom()
{
	hres = CoInitializeEx(0, COINIT_MULTITHREADED);
	if (FAILED(hres)) {
		cout << "Failed to initialize COM library. Error code = 0x" << hex << hres << endl;
		return 1;
	}
	return 0;
}

// Установка уровней безопасности COM
int SetLevelSecurity()
{
	hres = CoInitializeSecurity(
		NULL,
		-1,
		NULL,
		NULL,
		RPC_C_AUTHN_LEVEL_DEFAULT,
		RPC_C_IMP_LEVEL_IDENTIFY,
		NULL,
		EOAC_NONE, NULL);

	if (FAILED(hres)) {
		cout << "Failed to initialize security. Error code = 0x" << hex << hres << endl;
		CoUninitialize();
		return 1;
	}
	return 0;
}

// Создание локатора WMI
int CreateWMILocator()
{
	//IWbemLocator *pLoc = NULL;
	hres = CoCreateInstance(
		CLSID_WbemLocator,
		0,
		CLSCTX_INPROC_SERVER,
		IID_IWbemLocator,
		(LPVOID *)& pLoc);
	if (FAILED(hres))
	{
		cout << "Failed to create IWbemLocator object." << " Err code = 0x" << hex << hres << endl;
		CoUninitialize();
		return 1;
	}
	return 0;
}

// Подключение к WMI через IWbemLocator::ConnectServer
int ConnectToWMI()
{
	memset(&cui, 0, sizeof(CREDUI_INFO));
	cui.cbSize = sizeof(CREDUI_INFO);
	cui.hwndParent = NULL;
	cui.pszMessageText = TEXT("Press cancel to use process token");
	cui.pszCaptionText = TEXT("Enter Account Information");
	cui.hbmBanner = NULL;
	fSave = FALSE;

	dwErr = CredUIPromptForCredentials(
		&cui,
		TEXT(""),
		NULL,
		0,
		pszName,
		CREDUI_MAX_USERNAME_LENGTH + 1,
		pszPwd,
		CREDUI_MAX_PASSWORD_LENGTH + 1,
		&fSave,
		CREDUI_FLAGS_GENERIC_CREDENTIALS |
		CREDUI_FLAGS_ALWAYS_SHOW_UI |
		CREDUI_FLAGS_DO_NOT_PERSIST);

	if (dwErr == ERROR_CANCELLED)
	{
		useToken = true;
	}
	else if (dwErr) {
		cout << "Did not get credentials " << dwErr << endl;
		//pLoc->Release();
		//CoUninitialize();
		return 1;
	}
}
int ConnectToNamespace(LPCWSTR name_space)
{
	// Подключение к пространству имен root\cimv2
	hres = pLoc->ConnectServer(
		_bstr_t(name_space),
		_bstr_t(useToken ? NULL : pszName),
		_bstr_t(useToken ? NULL : pszPwd),
		NULL,
		NULL,
		_bstr_t(useNTLM ? NULL : pszAuthority),
		NULL,
		&pSvc
	);
	if (FAILED(hres))
	{
		cout << "Could not connect. Error code = 0x"
			<< hex << hres << endl;
		pLoc->Release();
		CoUninitialize();
		return 1;
	}
}

// Создание структуры COAUTHIDENTITY
int CreateCoauth()
{
	if (!useToken) {
		memset(&authIdent, 0, sizeof(COAUTHIDENTITY));
		authIdent.PasswordLength = wcslen(pszPwd);
		authIdent.Password = (USHORT *)pszPwd;

		LPWSTR slash = wcschr(pszName, L'\\');
		if (slash == NULL) {
			cout << "Could not create Auth identity. No domain specified\n";
			pSvc->Release();
			pLoc->Release();
			CoUninitialize();
			return 1;
		}

		StringCchCopy(pszUserName, CREDUI_MAX_USERNAME_LENGTH + 1, slash + 1);
		authIdent.User = (USHORT *)pszUserName;
		authIdent.UserLength = wcslen(pszUserName);

		StringCchCopyN(pszDomain, CREDUI_MAX_USERNAME_LENGTH + 1, pszName, slash - pszName);

		authIdent.Domain = (USHORT *)pszDomain;
		authIdent.DomainLength = slash - pszName;
		authIdent.Flags = SEC_WINNT_AUTH_IDENTITY_UNICODE;

		userAcct = &authIdent;

	}
}

// Установка защиты прокси сервера ------------------
int SetProxySecurity()
{
	hres = CoSetProxyBlanket(
		pSvc, 
		RPC_C_AUTHN_DEFAULT, 
		RPC_C_AUTHZ_DEFAULT, 
		COLE_DEFAULT_PRINCIPAL,
		RPC_C_AUTHN_LEVEL_PKT_PRIVACY, 
		RPC_C_IMP_LEVEL_IMPERSONATE, 
		userAcct, 
		EOAC_NONE);

	if (FAILED(hres)) {
		cout << "Could not set proxy blanket. Error code = 0x" << hex << hres << endl;
		pSvc->Release();
		pLoc->Release();
		CoUninitialize();
		return 1;
	}
}

// Получение данных через WMI ----
int TakeData(LPCSTR selectfrom)
{
	hres = pSvc->ExecQuery(
		bstr_t("WQL"),
		bstr_t(selectfrom),
		WBEM_FLAG_FORWARD_ONLY |
		WBEM_FLAG_RETURN_IMMEDIATELY,
		NULL,
		&pEnumerator);
	if (FAILED(hres))
	{
		cout << "Query for operating system name failed."
			<< " Error code = 0x"
			<< hex << hres << endl;
		pSvc->Release();
		pLoc->Release();
		CoUninitialize();
		return 1;
	}

	hres = CoSetProxyBlanket(
		pEnumerator,
		RPC_C_AUTHN_DEFAULT,
		RPC_C_AUTHZ_DEFAULT,
		COLE_DEFAULT_PRINCIPAL,
		RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
		RPC_C_IMP_LEVEL_IMPERSONATE,
		userAcct,
		EOAC_NONE);

	if (FAILED(hres)) {
		cout << "Could not set proxy blanket on enumerator. Error code = 0x"
			<< hex
			<< hres
			<< endl;
		return 1;
	}
}
		// Получение данных из запроса в шаге 7 -------------------
int GetData(LPCWSTR lname)
{
		ULONG uReturn = 0;
		while (pEnumerator)
		{
			HRESULT hr = pEnumerator->Next(
				WBEM_INFINITE,
				1,
				&pclsObj,
				&uReturn);

			if (0 == uReturn)
			{
				break;
			}

			VARIANT vtProp;

			// Выбираем поле Name
			hr = pclsObj->Get(
				lname,
				0,
				&vtProp,
				0,
				0);
			wcout << vtProp.bstrVal << endl;

			VariantClear(&vtProp);

			pclsObj->Release();
			pclsObj = NULL;
		}
	return 0;
}
void CleanAll()
{
	//Очистка========
	SecureZeroMemory(pszName, sizeof(pszName));
	SecureZeroMemory(pszPwd, sizeof(pszPwd));
	SecureZeroMemory(pszUserName, sizeof(pszUserName));
	SecureZeroMemory(pszDomain, sizeof(pszDomain));

}