#include <Windows.h>

DWORD GetProcAddressRemote(HANDLE hProc, const char *moduleName, const char *exportName)
{
    DWORD res = 0;

    DWORD modulesCount = 0;
    HMODULE hModules[1024] = { 0 };

    BOOL istatus = K32EnumProcessModulesEx(hProc, hModules, sizeof hModules, &modulesCount, LIST_MODULES_ALL);

    if (!istatus)
    {
        return 0;
    }

    for (const auto &hModule : hModules)
    {
        char modulepath[MAX_PATH] = { 0 };
        K32GetModuleFileNameExA(hProc, hModule, modulepath, sizeof modulepath);
        if (strcmp(modulepath + strlen(modulepath) - strlen(moduleName), moduleName))
        {
            continue;
        }

#if _DEBUG
        printf("Module path: %s\n", modulepath);
#endif

        MODULEINFO moduleInfo = { 0 };
        K32GetModuleInformation(hProc, hModule, &moduleInfo, sizeof moduleInfo);

#if _DEBUG
        printf("Image base: %X\n", moduleInfo.lpBaseOfDll);
#endif

        char *image = new char[moduleInfo.SizeOfImage];

        SIZE_T bytesRead = 0;
        ReadProcessMemory(hProc, moduleInfo.lpBaseOfDll, image, moduleInfo.SizeOfImage, &bytesRead);

        PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)image;
        PIMAGE_NT_HEADERS32 pNtHeaders = (PIMAGE_NT_HEADERS32)(image + pDosHeader->e_lfanew);

        IMAGE_DATA_DIRECTORY exportsDataDirectory = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        if (exportsDataDirectory.Size <= 0)
        {
            return 0;
        }

        PIMAGE_EXPORT_DIRECTORY exportsTable = (PIMAGE_EXPORT_DIRECTORY)(image + exportsDataDirectory.VirtualAddress);

        auto pNameOffset = (DWORD *)(image + exportsTable->AddressOfNames);
        for (DWORD i = 0; i < exportsTable->NumberOfNames; ++i, ++pNameOffset)
        {
            auto szName = (char *)(image + *pNameOffset);
            
            if (strcmp(szName, exportName))
            {
                continue;
            }

            auto pNameOrdinal = (WORD *)(image + exportsTable->AddressOfNameOrdinals) + i;
            res = *((DWORD *)(image + exportsTable->AddressOfFunctions) + *pNameOrdinal);
            res += (DWORD)moduleInfo.lpBaseOfDll;

#if _DEBUG
            printf("[%lu] %s\n", i, szName);
#endif
            
            break;
        }

        delete[] image;
    }

    CloseHandle(hProc);
    return res;
}
