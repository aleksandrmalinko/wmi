#include "Interface.hpp"


int ChooseRequest(LPCWSTR &lname, LPCSTR &selectfrom , LPCWSTR &name_space)
{
	setlocale(LC_ALL, "Russian");

	std::cout << "Avaible request: \n";
	std::cout <<
		"applications\n"
		"antivirus\n"
		"firewall\n"
		"antispy\n"
		"memory\n"
		"OS\n"
		"font\n"
		"protocol\n"
		"users\n"
		"serial\n"
		"exit\n";

	std::string full_request;
	std::cout << "#";
	std::cin >> full_request;

	if (full_request == "applications")
	{
		std::cout << "������ ������������� ����������: ";
		name_space = L"\\\\WIN-8HVGEBLO3PI\\root\\cimv2";
		selectfrom = "Select * from Win32_Product";
		lname = L"Name";
		return 0;
	}

	if (full_request == "antivirus")
	{
		std::cout << "������ ������������� �����������: ";
		name_space = L"\\\\WIN-8HVGEBLO3PI\\root\\SecurityCenter2";
		selectfrom = "Select * from AntivirusProduct";
		lname = L"displayName";
		return 0;
	}

	if (full_request == "firewall")
	{
		std::cout << "������ ������������� firewall: ";
		name_space = L"\\\\WIN-8HVGEBLO3PI\\root\\SecurityCenter2";
		selectfrom = "Select * from FirewallProduct";
		lname = L"displayName";
		return 0;
	}

	if (full_request == "antispy")
	{
		std::cout << "������ �������������� ����������������� ��: ";
		name_space = L"\\\\WIN-8HVGEBLO3PI\\root\\SecurityCenter2";
		selectfrom = "Select * from AntiSpywareProduct";
		lname = L"displayName";
		return 0;
	}

	if (full_request == "memory")
	{
		std::cout << "����� ��������� ����������� ������ (��): ";
		name_space = L"\\\\WIN-8HVGEBLO3PI\\root\\cimv2";
		selectfrom = "Select * from Win32_OperatingSystem";
		lname = L"FreePhysicalMemory";
		return 0;
	}

	if (full_request == "OS")
	{
		std::cout << "������������ �������: ";
		name_space = L"\\\\WIN-8HVGEBLO3PI\\root\\cimv2";
		selectfrom = "Select * from Win32_OperatingSystem";
		lname = L"Name";
		return 0;
	}

	if (full_request == "font")
	{
		std::cout << "������: ";
		name_space = L"\\\\WIN-8HVGEBLO3PI\\root\\cimv2";
		selectfrom = "Select * from Win32_Desktop";
		lname = L"IconTitleFaceName";
		return 0;
	}

	if (full_request == "protocol")
	{
		std::cout << "������ ����������: ";
		name_space = L"\\\\WIN-8HVGEBLO3PI\\root\\cimv2";
		selectfrom = "Select * from Win32_NetworkProtocol";
		lname = L"Name";
		return 0;
	}

	if (full_request == "users")
	{
		std::cout << "������ �������������: ";
		name_space = L"\\\\WIN-8HVGEBLO3PI\\root\\cimv2";
		selectfrom = "Select * from Win32_Account";
		lname = L"Name";
		return 0;
	}

	if (full_request == "serial")
	{
		std::cout << "�������� �����: ";
		name_space = L"\\\\WIN-8HVGEBLO3PI\\root\\cimv2";
		selectfrom = "Select * from Win32_OperatingSystem";
		lname = L"SerialNumber";
		return 0;
	}
	if (full_request == "exit")
	{
		return 1;
	}
	else
	{
		std::cout << "Incorrect command\n";
		return 1;
	}
}