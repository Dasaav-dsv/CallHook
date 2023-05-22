#pragma once

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <Psapi.h>
#include "Logger.h"

namespace CallHook {
	// Tries to allocate the specified amount of bytes within a MAX_INT range from a module.
	// If the module name is left unspecified, the main module is chosen by default.
	// Big thanks to LukeYui for providing the code I based this on.
	void* moduleAlloc(std::size_t cb, LPCSTR lpModuleName = NULL) {
		auto& logger = Logger::get();
		std::string moduleName;
		// Get the name of the base module if a module name wasn't already provided.
		if (lpModuleName == NULL) {
			auto moduleNameShort = std::make_unique<char[]>(MAX_PATH);
			moduleName = Logger::getCurrentModuleName<true>();
			if (errno_t error = _splitpath_s(moduleName.c_str(), NULL, 0, NULL, 0, moduleNameShort.get(), MAX_PATH, NULL, 0)) {
				logger.log("Failed to allocate memory: unable to get main module name; error %d", error);
				return nullptr;
			}
			else {
				moduleName = std::string(moduleNameShort.get()) + ".exe";
			}
		}
		else {
			moduleName = std::string(lpModuleName);
		}
		logger.log("Allocating %d bytes near module %s", cb, moduleName);
		MODULEINFO modInfo{};
		MEMORY_BASIC_INFORMATION memInfo{};
		if (HMODULE hModule = GetModuleHandleA(moduleName.c_str())) {
			if (!GetModuleInformation(GetCurrentProcess(), hModule, &modInfo, sizeof(MODULEINFO))) {
				logger.log("Failed to allocate memory: unable to get module information; error %d", GetLastError());
				return nullptr;
			}
		}
		else {
			logger.log("Failed to allocate memory: unable to get module handle; error %d", GetLastError());
			return nullptr;
		}
		uintptr_t moduleStart = reinterpret_cast<uintptr_t>(modInfo.lpBaseOfDll);
		uintptr_t moduleEnd = moduleStart + modInfo.SizeOfImage;
		// Establish the base address to search for suitable memory from, it must be within an INT_MAX range from any point in the module.
		memInfo.BaseAddress = reinterpret_cast<void*>(moduleEnd + cb - INT_MAX);
		memInfo.RegionSize = 0;
		// Search for a free memory region of our size.
		while (VirtualQuery(reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(memInfo.BaseAddress) + memInfo.RegionSize), &memInfo, sizeof(MEMORY_BASIC_INFORMATION))) {
			// Check if region is free and large enough.
			if (!(memInfo.State & MEM_FREE)) continue;
			if (cb > memInfo.RegionSize) continue;
			uintptr_t begin = reinterpret_cast<uintptr_t>(memInfo.BaseAddress);
			uintptr_t end = begin + memInfo.RegionSize;
			// Check if region is within INT_MAX bounds.
			if (end <= moduleStart && cb + moduleEnd - end > INT_MAX) continue;
			if (begin >= moduleEnd && cb + begin - moduleStart > INT_MAX) continue;
			// Found a suitable region.
			void* alloc = reinterpret_cast<void*>(end <= moduleStart ? end - cb : begin);
			alloc = VirtualAlloc(alloc, cb, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
			if (alloc) {
				logger.log("Allocated %d bytes at %p", cb, alloc);
				return alloc;
			}
		}
		// Completing the loop means a suitable memory region was not found withing INT_MAX range of the module.
		logger.log("Failed to allocate memory, size %d: no suitable memory region found", cb);
		return nullptr;
	}
}