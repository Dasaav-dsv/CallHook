#pragma once

#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <winnt.h>
#include <vector>

#include "Logger.h"

namespace CallHook {
	// A singleton class for patching calls and jumps.
	class CallPatcher {
		struct PatchJob {
			void* callAddress;
			int tgtDisp;
			bool isJmp;
		};

	public:
		static CallPatcher& get() noexcept {
			static CallPatcher s;
			return s;
		}

		// Patch a call or jmp instruction at a specified address in memory.
		bool patchCall(void* callAddress, void* tgtAddress, bool isJmp = false) {
			int64_t disp = reinterpret_cast<uintptr_t>(tgtAddress) - reinterpret_cast<uintptr_t>(callAddress) - 5;
			// To encode the new call target, its displacement must fit in a signed 32 bit integer.
			if (std::abs(disp) > INT_MAX) {
				Logger::get().log("Error when patching call at %p, target address %p is out of range", callAddress, tgtAddress);
				return false;
			}
			CallPatcher::jobs.emplace_back(PatchJob{ callAddress, static_cast<int>(disp), isJmp });
			// Prepare the VEH and place a software breakpoint on the first byte of the call.
			// This is important because the 32 bit integer displacement encoded in the call may not be 
			// aligned on a 4 byte boundary. This means writes to that memory may not be atomic.
			void* handler = AddVectoredExceptionHandler(true, CallPatcherVEH);
			if (!CallPatcher::write(callAddress, static_cast<uint8_t>(0xCC))) {
				Logger::get().log("Error when patching call at %p, memory is inaccessible", callAddress);
				if (handler) RemoveVectoredExceptionHandler(handler);
				return false;
			};
			// No matter if the breakpoint was hit and the address has already been patched,
			// patch it again. If it has not been patched by the VEH before, it will be patched now,
			// if it was already patched by the VEH, nothing will happen.
			CallPatcher::write(reinterpret_cast<uint8_t*>(callAddress) + 1, static_cast<int>(disp));
			CallPatcher::write(callAddress, static_cast<uint8_t>(0xE8 | isJmp));
			FlushInstructionCache(GetCurrentProcess(), NULL, 0);
			// Remove the job.
			for (auto iter = CallPatcher::jobs.begin(); iter != CallPatcher::jobs.end(); ++iter) {
				if (callAddress != reinterpret_cast<uint8_t*>(iter->callAddress)) continue;
				CallPatcher::jobs.erase(iter);
				break;
			}
			return true;
		}

		// As CallPatcher is a singleton, the assignment and copy operators are deleted.
		CallPatcher(const CallPatcher&) = delete;
		CallPatcher& operator = (const CallPatcher&) = delete;
	private:
		CallPatcher() {}
		~CallPatcher() {}

		// A "safe" write to memory that resets memory protection flags.
		template <typename T1, typename T2> static bool write(T1* address, T2 value) {
			DWORD oldProtect;
			if (!VirtualProtect(reinterpret_cast<void*>(address), sizeof(T2), PAGE_EXECUTE_READWRITE, &oldProtect)) return false;
			_mm_mfence();
			*reinterpret_cast<T2*>(address) = value;
			return VirtualProtect(reinterpret_cast<void*>(address), sizeof(T2), oldProtect, &oldProtect);
		}

		// A vectored exception handler that handles patching the call in case the breakpoint is hit.
		static LONG WINAPI CallPatcherVEH(EXCEPTION_POINTERS* exInfo) {
			// If it's not a breakpoint exception, do not handle it.
			if (exInfo->ExceptionRecord->ExceptionCode != EXCEPTION_BREAKPOINT) {
				return EXCEPTION_CONTINUE_SEARCH;
			}
			// Check every job for an address that matches the exception address.
			// If none are found, do not handle the exception.
			uint8_t* exAddress = reinterpret_cast<uint8_t*>(exInfo->ExceptionRecord->ExceptionAddress) - 1;
			for (auto& job : CallPatcher::jobs) {
				if (exAddress != reinterpret_cast<uint8_t*>(job.callAddress)) continue;
				// Write the displacement and restore the call/jmp byte.
				CallPatcher::write(exAddress + 1, job.tgtDisp);
				CallPatcher::write(exAddress, static_cast<uint8_t>(0xE8 | job.isJmp));
				FlushInstructionCache(GetCurrentProcess(), NULL, 0);
				return EXCEPTION_CONTINUE_EXECUTION;
			}
			return EXCEPTION_CONTINUE_SEARCH;
		}

		static inline std::vector<PatchJob> jobs;
	};
}