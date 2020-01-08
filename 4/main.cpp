#include <comdef.h>
#include <Wbemidl.h>
#include <wincred.h>
#include <strsafe.h>

#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "credui.lib")
#pragma comment(lib, "comsuppw.lib")

#define _WIN32_DCOM
#define UNICODE

using namespace std;


int __cdecl main(int argc, char **argv) {
    HRESULT hres;

    // Шаг 1: --------------------------------------------------
    // Инициализация COM. ------------------------------------------

    hres = CoInitializeEx(0, COINIT_MULTITHREADED);
    if (FAILED(hres)) {
        cout << "Failed to initialize COM library. Error code = 0x" << hex << hres << endl;
        return 1;
    }

    // Шаг 2: --------------------------------------------------
    // Установка уровней безопасности COM --------------------------

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
    // Шаг 3: ---------------------------------------------------
    // Создание локатора WMI -------------------------

    IWbemLocator *pLoc = NULL;
    hres = CoCreateInstance(
            CLSID_WbemLocator,
            0,
            CLSCTX_INPROC_SERVER,
            IID_IWbemLocator,
            (LPVOID * ) & pLoc);
    if (FAILED(hres))
    {
        cout << "Failed to create IWbemLocator object." << " Err code = 0x" << hex << hres << endl;
        CoUninitialize();
        return 1;
    }

    // Шаг 4: -----------------------------------------------------
    // Подключение к WMI через IWbemLocator::ConnectServer

    IWbemServices *pSvc = NULL;

    // Получение реквизитов доступа к удаленному компьютеру
    CREDUI_INFO cui;
    bool useToken = false;
    bool useNTLM = true;
    wchar_t pszName[CREDUI_MAX_USERNAME_LENGTH+1] = {0};
    wchar_t pszPwd[CREDUI_MAX_PASSWORD_LENGTH+1] = {0};
    wchar_t pszDomain[CREDUI_MAX_USERNAME_LENGTH+1];
    wchar_t pszUserName[CREDUI_MAX_USERNAME_LENGTH+1];
    wchar_t pszAuthority[CREDUI_MAX_USERNAME_LENGTH+1];
    BOOL fSave;
    DWORD dwErr;

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
        pLoc->Release();
        CoUninitialize();
        return 1;
    }

    // change the computerName strings below to the full computer name
    // of the remote computer
    if(!useNTLM)
    {
        StringCchPrintf(pszAuthority, CREDUI_MAX_USERNAME_LENGTH+1, L"kERBEROS:%s", L"COMPUTERNAME");
    }

    // Подключение к пространству имен root\cimv2
    // ---------------------------------------------------------
    hres = pLoc->ConnectServer(
            _bstr_t(L"\\\\COMPUTERNAME\\root\\cimv2"),
            _bstr_t(useToken?NULL:pszName),
            _bstr_t(useToken?NULL:pszPwd),
            NULL,
            NULL,
            _bstr_t(useNTLM?NULL:pszAuthority),
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

    cout << "Connected to ROOT\\CIMV2 WMI namespace" << endl;


    // Шаг 5: --------------------------------------------------
    // Создание структуры COAUTHIDENTITY

    COAUTHIDENTITY *userAcct = NULL;
    COAUTHIDENTITY authIdent;

    if (!useToken) {
        memset(&authIdent, 0, sizeof(COAUTHIDENTITY));
        authIdent.PasswordLength = wcslen(pszPwd);
        authIdent.Password = (USHORT *) pszPwd;

        LPWSTR slash = wcschr(pszName, L'\\');
        if (slash == NULL) {
            cout << "Could not create Auth identity. No domain specified\n";
            pSvc->Release();
            pLoc->Release();
            CoUninitialize();
            return 1;
        }

        StringCchCopy(pszUserName, CREDUI_MAX_USERNAME_LENGTH + 1, slash + 1);
        authIdent.User = (USHORT *) pszUserName;
        authIdent.UserLength = wcslen(pszUserName);

        StringCchCopyN(pszDomain, CREDUI_MAX_USERNAME_LENGTH + 1, pszName, slash - pszName);
        40

        authIdent.Domain = (USHORT *) pszDomain;
        authIdent.DomainLength = slash - pszName;
        authIdent.Flags = SEC_WINNT_AUTH_IDENTITY_UNICODE;

        userAcct = &authIdent;

    }

    // Шаг 6: --------------------------------------------------
    // Установка защиты прокси сервера ------------------

    hres = CoSetProxyBlanket(pSvc, RPC_C_AUTHN_DEFAULT, RPC_C_AUTHZ_DEFAULT, COLE_DEFAULT_PRINCIPAL,
                             RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_IMP_LEVEL_IMPERSONATE, userAcct, EOAC_NONE);

    if (FAILED(hres)) {
        cout << "Could not set proxy blanket. Error code = 0x" << hex << hres << endl;
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return 1;
    }

    // Шаг 7: --------------------------------------------------
    // Получение данных через WMI ----

    // Например, получим имя ОС
    IEnumWbemClassObject* pEnumerator = NULL;
    hres = pSvc->ExecQuery(
            bstr_t("WQL"),
            bstr_t("Select * from Win32_OperatingSystem"),
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
        cout << "Could not set proxy blanket on enumerator. Error code = 0x" << hex << hres << endl;
        pEnumerator->Release();
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return 1;
    }

    SecureZeroMemory(pszName, sizeof(pszName));
    SecureZeroMemory(pszPwd, sizeof(pszPwd));
    SecureZeroMemory(pszUserName, sizeof(pszUserName));
    SecureZeroMemory(pszDomain, sizeof(pszDomain));


    // Шаг 9: -------------------------------------------------
    // Получение данных из запроса в шаге 7 -------------------
    IWbemClassObject *pclsObj = NULL;
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
    hr = pclsObj->Get(L"Name", 0, &vtProp, 0, 0);
    wcout << " OS Name : " << vtProp.bstrVal << endl;

    // Выбираем поле свободной памяти
    hr = pclsObj->Get(
            L"FreePhysicalMemory",
            0,
            &vtProp,
            0,
            0);
    wcout << " Free physical memory (in kilobytes): "
        << vtProp.uintVal << endl;
    VariantClear(&vtProp);

    pclsObj->Release();
    pclsObj = NULL;
}

// Очистка
// ========
pSvc->Release();
    pLoc->Release();
    pEnumerator->Release();
    if( pclsObj )
    {
        pclsObj->Release();
    }
CoUninitialize();

return 0;
}

