#include <windows.h>
#include "beacon.h"
#include "bofdefs.h"
#include "base.c"

#define REG_RENAME_KEY 1
#define REG_RENAME_VALUE 0

static const char * find_last_char(const char * s, char c)
{
	const char * last = NULL;
	if(!s) return NULL;
	while(*s)
	{
		if(*s == c)
		{
			last = s;
		}
		s++;
	}
	return last;
}

static int trim_trailing_slashes(char * str)
{
	if(!str) return 0;
	int len = MSVCRT$strlen(str);
	while(len > 0 && (str[len - 1] == '\\' || str[len - 1] == '/'))
	{
		str[len - 1] = '\0';
		len--;
	}
	return len;
}

DWORD rename_reg(const char * hostname, HKEY hive, const char * path, const char * oldname, const char * newname, int iskey)
{
	DWORD dwresult = ERROR_SUCCESS;
	HKEY rootkey = NULL;
	HKEY RemoteKey = NULL;
	HKEY targetkey = NULL;
	HKEY parentkey = NULL;
	wchar_t * wpath = NULL;
	wchar_t * wnewname = NULL;
	char * clean_path = NULL;

	if(hostname == NULL)
	{
		REGSAM samDesired = iskey ? KEY_WRITE : (KEY_READ | KEY_SET_VALUE);
		dwresult = (hive == HKCU_LOCAL_IMP) ? ADVAPI32$RegOpenCurrentUser(samDesired, &rootkey) : ADVAPI32$RegOpenKeyExA(hive, NULL, 0, samDesired, &rootkey);
		if(ERROR_SUCCESS != dwresult)
		{
			internal_printf("%s failed (%lX)\n", (hive == HKCU_LOCAL_IMP) ? "RegOpenCurrentUser" : "RegOpenKeyExA", dwresult); 
			goto rename_reg_end;
		}
	}
	else
	{
		dwresult = ADVAPI32$RegConnectRegistryA(hostname, hive, &RemoteKey);
		if(ERROR_SUCCESS != dwresult)
		{
			internal_printf("RegConnectRegistryA failed (%lX)\n", dwresult); 
			goto rename_reg_end;
		}

		REGSAM samDesired = iskey ? KEY_WRITE : (KEY_READ | KEY_SET_VALUE);
		dwresult = ADVAPI32$RegOpenKeyExA(RemoteKey, NULL, 0, samDesired, &rootkey);
		if(ERROR_SUCCESS != dwresult)
		{
			internal_printf("RegOpenKeyExA failed (%lX)\n", dwresult); 
			goto rename_reg_end;
		}
	}

	if(iskey)
	{
		if(path == NULL || *path == 0)
		{
			internal_printf("Cannot rename root registry hive\n");
			dwresult = ERROR_INVALID_PARAMETER;
			goto rename_reg_end;
		}
		if(newname == NULL || *newname == 0)
		{
			internal_printf("New key name cannot be empty\n");
			dwresult = ERROR_INVALID_PARAMETER;
			goto rename_reg_end;
		}

		int pathlen = MSVCRT$strlen(path);
		clean_path = (char *)intAlloc(pathlen + 1);
		if(!clean_path)
		{
			dwresult = ERROR_NOT_ENOUGH_MEMORY;
			goto rename_reg_end;
		}
		MSVCRT$memcpy(clean_path, path, pathlen + 1);
		pathlen = trim_trailing_slashes(clean_path);
		if(pathlen == 0)
		{
			internal_printf("Cannot rename root registry hive\n");
			dwresult = ERROR_INVALID_PARAMETER;
			goto rename_reg_end;
		}

		// Extract leaf name if user provided a path in newname
		const char * leaf_newname = newname;
		const char * p1 = find_last_char(newname, '\\');
		const char * p2 = find_last_char(newname, '/');
		if(p1 && p1 >= leaf_newname) leaf_newname = p1 + 1;
		if(p2 && p2 >= leaf_newname) leaf_newname = p2 + 1;
		if(*leaf_newname == 0)
		{
			internal_printf("Invalid new name\n");
			dwresult = ERROR_INVALID_PARAMETER;
			goto rename_reg_end;
		}

		wpath = Utf8ToUtf16(clean_path);
		wnewname = Utf8ToUtf16(leaf_newname);
		if(!wpath || !wnewname)
		{
			internal_printf("Failed to convert strings to UTF-16\n");
			dwresult = ERROR_NOT_ENOUGH_MEMORY;
			goto rename_reg_end;
		}

		dwresult = ADVAPI32$RegRenameKey(rootkey, wpath, wnewname);
		if(ERROR_SUCCESS != dwresult)
		{
			// Fallback: If clean_path contains subkeys, try opening parent key directly
			char * last_slash = (char *)find_last_char(clean_path, '\\');
			if(!last_slash)
			{
				last_slash = (char *)find_last_char(clean_path, '/');
			}
			if(last_slash)
			{
				*last_slash = '\0';
				char * parent_path = clean_path;
				char * old_sub_name = last_slash + 1;
				wchar_t * woldsub = Utf8ToUtf16(old_sub_name);

				if(woldsub)
				{
					DWORD dwParentRes = ADVAPI32$RegOpenKeyExA(rootkey, parent_path, 0, KEY_WRITE, &parentkey);
					if(ERROR_SUCCESS == dwParentRes)
					{
						dwresult = ADVAPI32$RegRenameKey(parentkey, woldsub, wnewname);
						ADVAPI32$RegCloseKey(parentkey);
						parentkey = NULL;
					}
					intFree(woldsub);
				}
			}
		}

		if(ERROR_SUCCESS != dwresult)
		{
			internal_printf("RegRenameKey failed (%lX)\n", dwresult);
			goto rename_reg_end;
		}

		internal_printf("Successfully renamed registry key '%s' to '%s'\n", path, leaf_newname);
	}
	else
	{
		if(oldname == NULL || *oldname == 0)
		{
			internal_printf("Old value name cannot be empty\n");
			dwresult = ERROR_INVALID_PARAMETER;
			goto rename_reg_end;
		}
		if(newname == NULL || *newname == 0)
		{
			internal_printf("New value name cannot be empty\n");
			dwresult = ERROR_INVALID_PARAMETER;
			goto rename_reg_end;
		}

		dwresult = ADVAPI32$RegOpenKeyExA(rootkey, path, 0, KEY_QUERY_VALUE | KEY_SET_VALUE, &targetkey);
		if(ERROR_SUCCESS != dwresult)
		{
			internal_printf("RegOpenKeyExA failed (%lX)\n", dwresult);
			goto rename_reg_end;
		}

		DWORD dwType = 0;
		DWORD cbData = 0;
		dwresult = ADVAPI32$RegQueryValueExA(targetkey, oldname, NULL, &dwType, NULL, &cbData);
		if(ERROR_SUCCESS != dwresult)
		{
			internal_printf("RegQueryValueExA failed (%lX)\n", dwresult);
			goto rename_reg_end;
		}

		BYTE * valData = NULL;
		if(cbData > 0)
		{
			valData = (BYTE *)intAlloc(cbData);
			if(!valData)
			{
				dwresult = ERROR_NOT_ENOUGH_MEMORY;
				goto rename_reg_end;
			}

			dwresult = ADVAPI32$RegQueryValueExA(targetkey, oldname, NULL, &dwType, valData, &cbData);
			if(ERROR_SUCCESS != dwresult)
			{
				internal_printf("RegQueryValueExA (data) failed (%lX)\n", dwresult);
				intFree(valData);
				goto rename_reg_end;
			}
		}

		dwresult = ADVAPI32$RegSetValueExA(targetkey, newname, 0, dwType, valData, cbData);
		if(ERROR_SUCCESS != dwresult)
		{
			internal_printf("RegSetValueExA failed (%lX)\n", dwresult);
			if(valData) intFree(valData);
			goto rename_reg_end;
		}

		dwresult = ADVAPI32$RegDeleteValueA(targetkey, oldname);
		if(valData) intFree(valData);
		if(ERROR_SUCCESS != dwresult)
		{
			internal_printf("RegDeleteValueA (old value) failed (%lX)\n", dwresult);
			goto rename_reg_end;
		}

		internal_printf("Successfully renamed registry value '%s' to '%s'\n", oldname, newname);
	}

rename_reg_end:
	if(clean_path)
	{
		intFree(clean_path);
		clean_path = NULL;
	}
	if(wpath)
	{
		intFree(wpath);
		wpath = NULL;
	}
	if(wnewname)
	{
		intFree(wnewname);
		wnewname = NULL;
	}
	if(parentkey)
	{
		ADVAPI32$RegCloseKey(parentkey);
		parentkey = NULL;
	}
	if(targetkey)
	{
		ADVAPI32$RegCloseKey(targetkey);
		targetkey = NULL;
	}
	if(rootkey)
	{
		ADVAPI32$RegCloseKey(rootkey);
		rootkey = NULL;
	}
	if(RemoteKey)
	{
		ADVAPI32$RegCloseKey(RemoteKey);
		RemoteKey = NULL;
	}

	return dwresult;
}

#ifdef BOF
VOID go( 
	IN PCHAR Buffer, 
	IN ULONG Length 
) 
{
	DWORD dwErrorCode = ERROR_SUCCESS;
	datap parser = {0};
	const char * hostname = NULL;
	HKEY hive = (HKEY)0x80000000;
	const char * path = NULL;
	const char * oldname = NULL;
	const char * newname = NULL;
	int t = 0;
	int iskey = 1;

	BeaconDataParse(&parser, Buffer, Length);
	hostname = BeaconDataExtract(&parser, NULL);
	t = BeaconDataInt(&parser);
	#pragma GCC diagnostic ignored "-Wint-to-pointer-cast"
	#pragma GCC diagnostic ignored "-Wpointer-to-int-cast"
	hive = ((HKEY)t == HKCU_LOCAL_IMP) ? HKCU_LOCAL_IMP :(HKEY)((DWORD) hive + (DWORD)t);
	#pragma GCC diagnostic pop
	path = BeaconDataExtract(&parser, NULL);
	oldname = BeaconDataExtract(&parser, NULL);
	newname = BeaconDataExtract(&parser, NULL);
	iskey = BeaconDataInt(&parser);

	//correct hostname param
	if(hostname && *hostname == 0)
	{
		hostname = NULL;
	}
	if(oldname && *oldname == 0)
	{
		oldname = NULL;
	}

	if(!bofstart())
	{
		return;
	}

	if(hostname != NULL && hive == HKCU_LOCAL_IMP)
	{
		BeaconPrintf(CALLBACK_ERROR, "Refusing to use HKCU_LOCAL_IMP with a remote host");
		goto go_end;
	}

	if(iskey)
	{
		internal_printf("Renaming registry key %s\\%p\\%s to %s\n", ((hostname == NULL)?"\\\\.":hostname), hive, path, newname);
	}
	else
	{
		internal_printf("Renaming registry value %s\\%p\\%s\\%s to %s\n", ((hostname == NULL)?"\\\\.":hostname), hive, path, (oldname ? oldname : "(default)"), newname);
	}

	dwErrorCode = rename_reg(hostname, hive, path, oldname, newname, iskey);
	if(ERROR_SUCCESS != dwErrorCode)
	{
		BeaconPrintf(CALLBACK_ERROR, "rename_reg failed: %lX\n", dwErrorCode);
		goto go_end;
	}

	internal_printf("SUCCESS.\n");

go_end:
	printoutput(TRUE);
	bofstop();
};
#else
#define TEST_HOSTNAME ""
#define TEST_REG_HIVE HKEY_CURRENT_USER
#define TEST_REG_PATH "Software\\BOF_TEST"
#define TEST_REG_OLDNAME "BOF_OLD"
#define TEST_REG_NEWNAME "BOF_NEW"
#define TEST_IS_KEY 1
int main(int argc, char ** argv)
{
	DWORD dwErrorCode = ERROR_SUCCESS;
	LPCSTR lpszHostName = TEST_HOSTNAME;
	HKEY hkRootKey = TEST_REG_HIVE;
	LPCSTR lpszRegPathName = TEST_REG_PATH;
	LPCSTR lpszOldName = TEST_REG_OLDNAME;
	LPCSTR lpszNewName = TEST_REG_NEWNAME;
	int iskey = TEST_IS_KEY;

	if(*lpszHostName == 0)
	{
		lpszHostName = NULL;
	}
	if(*lpszOldName == 0)
	{
		lpszOldName = NULL;
	}

	if(iskey)
	{
		internal_printf("Renaming registry key %s\\%p\\%s to %s\n", ((lpszHostName == NULL)?"\\\\.":lpszHostName), hkRootKey, lpszRegPathName, lpszNewName);
	}
	else
	{
		internal_printf("Renaming registry value %s\\%p\\%s\\%s to %s\n", ((lpszHostName == NULL)?"\\\\.":lpszHostName), hkRootKey, lpszRegPathName, (lpszOldName ? lpszOldName : "(default)"), lpszNewName);
	}

	dwErrorCode = rename_reg(lpszHostName, hkRootKey, lpszRegPathName, lpszOldName, lpszNewName, iskey);
	if ( ERROR_SUCCESS != dwErrorCode )
	{
		BeaconPrintf(CALLBACK_ERROR, "rename_reg failed: %lX\n", dwErrorCode);
		goto main_end;
	}

	internal_printf("SUCCESS.\n");

main_end:
	return dwErrorCode;
}
#endif
