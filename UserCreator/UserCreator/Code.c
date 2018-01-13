#include <Windows.h>
#include <tchar.h>
#include <wchar.h>
#include <LM.h>
#include <sddl.h>

#pragma comment(lib, "Netapi32.lib")
#define MAX_NAME 256

typedef enum
{
	AdminUser		= 0,
	StandardUser	= 1

}TYPE_OF_USER;

VOID ShowHelp()
{
	wprintf(L"\nUser Creator Tool\n"
			L"Copyright (C) 2018 Sergio Calderon\n"
			L"Checho's Blog - http://geeks.ms/checho\n"
			L"\nUsage:\n"
			L"\t\nUserCreator.exe UserName Password [Privilege]\n"
			L"\n[Privilege]:\n"
			L"\n--user\n\n"
			L"--admin\n"
			L"\nExample:\n"
			L"\nUserCreator Andy P@ssw0rd --admin\n");
}

VOID ShowError(DWORD errorCode)
{
	//FormatMessageW
	DWORD flags = FORMAT_MESSAGE_ALLOCATE_BUFFER |
		FORMAT_MESSAGE_FROM_SYSTEM |
		FORMAT_MESSAGE_IGNORE_INSERTS;
	LPWSTR errorMessage;
	DWORD size = 0;

	if (!FormatMessageW(flags, NULL, errorCode, 0, (LPWSTR)&errorMessage, size, NULL))
	{
		fwprintf(stderr, L"Could not get the format message, error code: %u\n", GetLastError());
		exit(1);
	}

	wprintf(L"\n%s", errorMessage);

	LocalFree(errorMessage);
}

VOID ConfigUser(LPWSTR serverName, LPWSTR userName, TYPE_OF_USER typeOfUser)
{	

	//LocalAlloc
	UINT memAttributes = LMEM_FIXED;
	DWORD sidSize = SECURITY_MAX_SID_SIZE;

	//CreateWellKnownSid
	WELL_KNOWN_SID_TYPE sidType;
	PSID groupSID;

	if (typeOfUser == AdminUser)
	{
		sidType = WinBuiltinUsersSid;
	}
	else if (typeOfUser == StandardUser)
	{
		sidType = WinBuiltinAdministratorsSid;
	}	

	//Let's allocate memory for the SID
	if (!(groupSID = LocalAlloc(memAttributes, sidSize)))	//if fails
	{
		ShowError(GetLastError());
		exit(1);

	}

	//Let's create a SID for Users group
	if (!CreateWellKnownSid(sidType, NULL, groupSID, &sidSize))
	{
		ShowError(GetLastError());
		exit(1);
	}
	else
	{

		//LookupAccountSid
		WCHAR name[MAX_NAME];
		DWORD nameSize = MAX_NAME;
		WCHAR domainName[MAX_NAME];
		DWORD domainNameSize = MAX_NAME;
		SID_NAME_USE accountType;

		if (!LookupAccountSidW(serverName, groupSID, name, &nameSize,
			domainName, &domainNameSize, &accountType))
		{
			ShowError(GetLastError());
			exit(1);

		}

		//LookupAccountName
		PSID theSID;		
		DWORD cbSid = 0;
		SID_NAME_USE typeOfAccount;
		DWORD cchRefDomain = 0;

		if (!LookupAccountNameW(serverName, userName, NULL, &cbSid, NULL, &cchRefDomain, &typeOfAccount))
		{
			/*ShowError(GetLastError());*/
		}

		LPWSTR refDomainName = (LPWSTR)malloc(cchRefDomain * sizeof(WCHAR));

		if (!(theSID = LocalAlloc(memAttributes, cbSid)))
		{
			ShowError(GetLastError());
			exit(1);
		}

		if (refDomainName == NULL)
		{
			fwprintf(stderr, L"Error allocating memory. \n");
			exit(1);
		}

		//Here we go again! 
		if (!LookupAccountNameW(serverName, userName, theSID, &cbSid,
			refDomainName, &cchRefDomain, &typeOfAccount))
		{
			ShowError(GetLastError());
			exit(1);

		}

		//NetLocalGroupAddMembers
		NET_API_STATUS localGroupAdd;
		DWORD levelOfData = 0;	//LOCALGROUP_MEMBERS_INFO_0
		LOCALGROUP_MEMBERS_INFO_0 localMembers;
		DWORD totalEntries = 1;


		//Here I should be able to use NetLocalGroupAddMembers
		//to add the user passed as argument to the Users group. 
		localMembers.lgrmi0_sid = theSID;

		localGroupAdd = NetLocalGroupAddMembers(serverName, name, levelOfData, (LPBYTE)&localMembers, totalEntries);

		if (localGroupAdd != NERR_Success)
		{
			ShowError(localGroupAdd);
			exit(1);
		}
		else
		{

			ShowError(localGroupAdd);

		}

		LocalFree(theSID);
		free(refDomainName);

	}

	LocalFree(groupSID);

}


int wmain(int argc, WCHAR **argv)
{

	if (argc != 4)
	{
		ShowHelp();
		return 1;

	}

	if ((_wcsicmp(argv[3], L"--user") !=0) && 
		(_wcsicmp(argv[3], L"--admin") != 0))
	{
		ShowHelp();
		return 1;
	}

	//NetUserAdd function
	NET_API_STATUS addUser;
	DWORD infoLevel = 1;		//USER_INFO_1
	USER_INFO_1 userData;
	DWORD paramError;

	//Set up USER_INFO_1 structure
	userData.usri1_name = argv[1];
	userData.usri1_password = argv[2];
	userData.usri1_priv = USER_PRIV_USER;
	userData.usri1_home_dir = NULL;
	userData.usri1_comment = NULL;
	userData.usri1_flags = UF_SCRIPT;
	userData.usri1_script_path = NULL;

	addUser = NetUserAdd(NULL, infoLevel, (LPBYTE)&userData, &paramError);

	if (addUser != NERR_Success)
	{
		ShowError(addUser);
		return 1;
	}
	else
	{
		//Globaly used
		LPWSTR serverName = NULL;
		

		if (_wcsicmp(argv[3], L"--user") == 0)
		{
			
			ConfigUser(serverName, argv[1], StandardUser);

		}
		else if (_wcsicmp(argv[3], L"--admin") == 0)
		{
			/*We need to add the users to both
			Administrators group and Users group, so
			we call this function twice*/
			ConfigUser(serverName, argv[1], StandardUser);
			ConfigUser(serverName, argv[1], AdminUser);
		}
		else
		{
			fwprintf(stderr, L"\nWrong arguments.\n");
			ShowHelp();
		}	
		
	}

	return 0;
}