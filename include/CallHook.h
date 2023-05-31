#pragma once

#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#include <map>
#include <unordered_map>

#include <mutex>
#include <vector>
#include <memory>
#include <immintrin.h>
#include <profileapi.h>

#include "PE.h"
#include "Alloc.h"
#include "Logger.h"
#include "Decoder.h"
#include "HookTemplates.h"
#include "CallPatcherVEH.h"

// A managed hook template.
// The assembly can be modified without hurting functionality or compatibility
// with other CallHookTemplate instances, so long as the data section layout is preserved.
// Any additional data, structs or class instances can be referenced by the "extra" pointer.
// Without modification to the assembly, all function arguments passed to the original function
// will be preserved when calling the hook function, besides those directly passed on the stack.
// Calling delete on a hook instance automatically unhooks it.
template <typename HookType> class CallHookTemplate {
public:
	// Redirects a call to point to a hook function template.
	template <typename F> CallHookTemplate(void* callAddress, F* function) {
		hook(callAddress, function);
	}

	// Unhooks a function, restoring the original function pointer while preserving the hook chain (if it exists)
	virtual ~CallHookTemplate() {
		HookType* hook = reinterpret_cast<HookType*>(allocationBase);
		if (!hook) {
			CallHook::Logger::get().log("Error: unable to unhook call, it has no associated memory");
			return;
		}
		else {
			CallHook::Logger::get().log("Unhooking call at %p", reinterpret_cast<void*>(hook->hookData.previous));
		}

		// Find the topmost in the chain hook.
		HookType* topHook = hook;
		while (reinterpret_cast<HookType*>(topHook->hookData.previous)->hookData.magic == hook->hookData.magic) {
			topHook = reinterpret_cast<HookType*>(topHook->hookData.previous);
		}

		{
			// Lock top hook's mutex when hooking and unhooking.
			std::scoped_lock lock(*topHook->hookData.mutex);

			// The hook data is above the actual hook function pointed at.
			HookType* nextHook = reinterpret_cast<HookType*>(reinterpret_cast<uintptr_t>(hook->hookData.fnHooked) - sizeof(HookBase));
			HookType* prevHook = reinterpret_cast<HookType*>(hook->hookData.previous);

			// If the hook to be removed is in a chain, the reference to it is removed from the chain.
			if (hook->hookData.magic == nextHook->hookData.magic) {
				CallHookTemplate::rdataWrite(&nextHook->hookData.previous, prevHook);
			}

			// If the previous function is a hook, replace the function it hooks (the current hook) 
			// with the function the current hook hooked. If it's not a hook, try to unhook the call.
			if (hook->hookData.magic == prevHook->hookData.magic) {
				CallHookTemplate::rdataWrite(&prevHook->hookData.fnHooked, hook->hookData.fnHooked);
			}
			else {
				uint8_t callType = *reinterpret_cast<uint8_t*>(prevHook) ^ 0xE8;
				if (callType <= 1) {
					CallHook::CallPatcher::get().patchCall(prevHook, hook->hookData.fnHooked, callType);
				}
				else {
					CallHook::Logger::get().log("Error: unable to unhook call - unrecognized hooking template");
				}
			}
			CallHook::Logger::get().log("Successfully unhooked call at %p", reinterpret_cast<void*>(prevHook));
		}

		// Destroy the hook and free the memory.
		hook->~HookType();
		VirtualFree(this->allocationBase, NULL, MEM_RELEASE);
	}

	// Write a pointer to potentially read-only memory, restoring the protection flags afterwards.
	template <typename T1, typename T2> static bool rdataWrite(T1* pAddress, T2* pointer) {
		DWORD oldProtect;
		if (!VirtualProtect(reinterpret_cast<void*>(pAddress), sizeof(uintptr_t), PAGE_EXECUTE_READWRITE, &oldProtect)) return false;
		_mm_mfence();
		*reinterpret_cast<uintptr_t*>(pAddress) = reinterpret_cast<uintptr_t>(pointer);
		return VirtualProtect(reinterpret_cast<void*>(pAddress), sizeof(uintptr_t), oldProtect, &oldProtect);
	}

private:
	template <typename F> void hook(void* callAddress, F* function) {
		auto& logger = CallHook::Logger::get();
		logger.log("Hooking call at %p - allocating hook memory", callAddress);
		// Allocate executable memory for the hook
		void* allocationBase = CallHook::moduleAlloc(sizeof(HookType));
		if (!allocationBase) {
			logger.log("Error: failed to hook call at %p - unable to allocate memory", callAddress);
			return;
		}

		this->allocationBase = allocationBase;
		HookType* hook = new(allocationBase) HookType{};

		uint8_t callType = *reinterpret_cast<uint8_t*>(callAddress) ^ 0xE8u;
		if (callType > 1) return;

		void* hooked = getFunctionFromCall(callAddress);

		// Set up new hook data
		hook->hookData.mutex.reset(new std::mutex);
		hook->hookData.fnHooked = hooked;
		hook->hookData.previous = callAddress;
		hook->hookData.fnNew = reinterpret_cast<void*>(function);

		CallHook::CallPatcher& patcher = CallHook::CallPatcher::get();

		// Get and check for any previously placed hooks, which will need to be chained together.
		// The hook data is above the actual hook function pointed to.
		HookType* prevHook = reinterpret_cast<HookType*>(reinterpret_cast<uintptr_t>(hook->hookData.fnHooked) - sizeof(HookBase));
		if (hook->hookData.magic == prevHook->hookData.magic) {
			// Lock top hook's mutex when hooking and unhooking.
			std::scoped_lock lock(*prevHook->hookData.mutex);

			// Update hook pointers.
			_mm_mfence();
			if (hook->hookData.fnHooked != hooked) {
				hook->hookData.fnHooked = hooked;
				prevHook = reinterpret_cast<HookType*>(reinterpret_cast<uintptr_t>(hook->hookData.fnHooked) - sizeof(HookBase));
			}
			CallHookTemplate::rdataWrite(&prevHook->hookData.previous, hook);
			// Write the displacement of the hook to the call that is being hooked.
			patcher.patchCall(callAddress, reinterpret_cast<uint8_t*>(hook) + sizeof(HookBase), callType);
		}
		else {
			_mm_mfence();
			if (hook->hookData.fnHooked != hooked) hook->hookData.fnHooked = hooked;

			// Write the displacement of the hook to the call that is being hooked.
			patcher.patchCall(callAddress, reinterpret_cast<uint8_t*>(hook) + sizeof(HookBase), callType);
		}
		logger.log("Successfully hooked call at %p", callAddress);
	}

	// Retrieve the function address from the 32-bit displacement in the instruction encoding.
	static void* getFunctionFromCall(void* callAddress) {
		uint8_t* callAddress_u8 = reinterpret_cast<uint8_t*>(callAddress);
		return callAddress_u8 + *reinterpret_cast<int*>(callAddress_u8 + 1) + 5;
	}

	void* allocationBase = nullptr;
};

namespace CallHook {
	// A class encapsulating all non-virtual function calls within a module.
	// The underlying memory allocation will stay as long as the CallMap object is in scope.
	// Uses Zydis to disassemble all instructions in all .text sections of a module.
	// The target module is specified by the PEParser. It can be initialized with CallHook::initialize,
	// which must be called prior to creating CallMap instances.
	class CallMap {
		struct PdataEntry {
			PEParser::ibo32 start;
			PEParser::ibo32 end;
			PEParser::ibo32 unwind;
		};
	public:
		CallMap() {
			auto& logger = CallHook::Logger::get();
			// Get the .text sections to scan for non-virtual function calls.
			if (auto sections = PEParser::getSectionsWithName(".pdata")) {
				// A map to store function address/incoming call pairs.
				// It is temporary and does not use a continuous memory allocation. 
				std::map<PEParser::ibo32, std::vector<PEParser::ibo32>> rawCalls;
				// Call count, which determines the size of the continuous memory to be allocated later.
				int callCount = 0;
				// Perf counter for logging.
				uint64_t perfCounter1;
				QueryPerformanceCounter(reinterpret_cast<LARGE_INTEGER*>(&perfCounter1));
				// The decoder's constructor may throw if it fails to initialize the decoder.
				std::unique_ptr<CallHook::Decoder> decoder;
				try {
					decoder = std::make_unique<CallHook::Decoder>();
				}
				catch (const std::runtime_error&) {
					logger.log("Error: unable to initialize Zydis instruction decoder.");
					return;
				}
				// A module may have multiple sections of the same name. Iterate over all of them.
				for (auto& section : *sections) {
					auto cur = section->start.as<PdataEntry*>();
					auto end = section->end.as<PdataEntry*>();
					while (cur < end) {
						auto fnCur = cur->start.as<uint8_t*>();
						auto fnEnd = cur->end.as<uint8_t*>();
						if (PEParser::isAddressInSection(fnCur, ".text") && PEParser::isAddressInSection(fnEnd, ".text") && fnCur < fnEnd) {
							while (fnCur < fnEnd) {
								ZydisDecodedInstruction inst;
								if (decoder->decodeInstruction(fnCur, inst)) {
									// 0xE8 and 0xE9 - 32-bit relative call and jump.
									if ((inst.opcode & 0xFE) == 0xE8 && inst.length == 5) {
										PEParser::ibo32 callTarget = PEParser::ibo32(fnCur + *reinterpret_cast<int*>(fnCur + 1) + 5);
										if (!(callTarget & 0x0F)) {
											// We only want to hook in-module calls, or calls hooked by other CallHook instances.
											if (!PEParser::isIbo32InSection(callTarget, ".text")) {
												HookBase* hookBase = reinterpret_cast<HookBase*>(callTarget.as<uint8_t*>() - sizeof(HookBase));
												MEMORY_BASIC_INFORMATION mbi;
												// Check if memory is accessible.
												if (!VirtualQueryEx((HANDLE)-1, (LPVOID)hookBase, &mbi, sizeof(mbi)) || (mbi.Protect & PAGE_NOACCESS) == 1) {
													fnCur += 5;
													continue;
												}
												// magic: "UniHook\0"
												if (hookBase->magic != 0x6B6F6F48696E55ull) {
													fnCur += 5;
													continue;
												}
											}
											// If a found call targets a function that already exists in the map,
											// add its address to the vector. If a function address is not yet in the map,
											// add it to the map. Increment the call count used for allocating memory later.
											auto iter = rawCalls.find(callTarget);
											if (iter != rawCalls.end()) {
												iter->second.push_back(PEParser::ibo32(fnCur));
												++callCount;
											}
											else {
												rawCalls[callTarget] = std::vector<PEParser::ibo32>{ PEParser::ibo32(fnCur) };
												++callCount;
											}
										}
									}
									fnCur += inst.length;
								}
								else {
									// If an instruction fails to disassemble,
									// increment the pointer to traverse memory byte by byte.
									++fnCur;
								}
							}
						}
						++cur;
					}
				}
				// Insert the section ends to the back of the map.
				for (auto& section : *sections) {
					rawCalls.insert({ section->end, std::vector<PEParser::ibo32>{} });
				}
				// Perf counter for logging.
				uint64_t perfCounter2;
				QueryPerformanceCounter(reinterpret_cast<LARGE_INTEGER*>(&perfCounter2));
				uint64_t perfFrequency;
				QueryPerformanceFrequency(reinterpret_cast<LARGE_INTEGER*>(&perfFrequency));
				logger.log("Found a total of %d functions and %d calls in %fs", rawCalls.size(), callCount, static_cast<float>(perfCounter2 - perfCounter1) / static_cast<float>(perfFrequency));
				// Allocate memory for each call in the vector.
				// The key-value address/vector pairs will be moved to a map and a continous vector.
				this->underlying.reserve(callCount);
				// The map stores pointers to the beginning of each vector segment containing calls to the corresponding function.
				// Since the map is ordered, we can get the span of elements of a single segment 
				// by subtracting the current pointer from the pointer of the next map entry.
				for (auto& keyval : rawCalls) {
					auto& function = keyval.first;
					auto& calls = keyval.second;
					// Add call addresses to the vector, in the order they are in memory (since the map we use is ordered).
					for (auto& call : calls) {
						// It is important not to add more elements to the vector than memory that has been reserved.
						// Accidentally doing so would cause a reallocation and invalidate any pointers to the underlying memory.
						if (--callCount >= 0) {
							this->underlying.push_back(call);
						}
					}
					// Add a key-value pair of a function address and a pointer to the position
					// inside the vector that holds the incoming function calls.
					if (callCount >= 0) this->map[function] = &*std::next(this->underlying.rbegin(), std::max(calls.size() - 1, 0ull));
				}
				// After populating the map and the underlying memory vector, the call count should be back at zero.
				// A negative call count would mean calls were not able to be added because doing so would cause a relocation.
				// A positive call count would mean more calls were expected to be added than were actually found.
				if (callCount != 0) {
					logger.log("Error: total count of calls found did not match the expected amount. Expected call count %d off by %d. Not all calls have been added to the call map.", this->underlying.capacity(), std::abs(callCount));
				}
			}
			else {
				logger.log("Error: unable to locate .text section of the module. Make sure CallHook::initialize has been called");
			}
		}

		// Retrieve a vector of void* call addresses from the map.
		// The address can either be an exact function address or an address inside the function.
		auto getCalls(void* address) {
			return getCallsImpl(address);
		}

		// Retrieve a vector of void* call addresses from the map.
		// The address can either be an exact function address or an address inside the function.
		// The ibo32 represents the offset from image base of the module.
		auto getCalls(PEParser::ibo32 offsetFromBase) {
			return getCallsImpl(offsetFromBase.as<void*>());
		}

		// Retrieve a vector of void* call addresses from the map.
		// The address can either be an exact function address or an address inside the function.
		// The integer offset represents the offset from image base of the module.
		auto getCalls(int offsetFromBase) {
			return getCallsImpl(PEParser::ibo32(offsetFromBase).as<void*>());
		}

		void dbgPrint() {
			CallHook::Logger::get().log("\nMap address: %p\nTotal entries in map: %d\nMap size (MB): %d\nTotal calls: %d\nUnderlying memory address: %p\nTotal size of underlying memory (MB): %d",
				reinterpret_cast<void*>(&*this->map.begin()),
				map.size(),
				map.size() * sizeof(std::pair<PEParser::ibo32, PEParser::ibo32*>) / 1024 / 1024,
				underlying.size(),
				reinterpret_cast<void*>(underlying.data()),
				(map.size() * sizeof(std::pair<PEParser::ibo32, PEParser::ibo32*>) + underlying.size() * sizeof(PEParser::ibo32)) / 1024 / 1024);
		}

		// CallMap is not copy-constructible or assignable.
		// These operations would invalidate the mapped pointers.
		CallMap(const CallMap&) = delete;
		CallMap& operator = (const CallMap&) = delete;

	private:
		// Constructs and returns a vector of void pointers to all incoming calls for a function.
		// The function address can either be an exact function address or an address inside the function.
		std::vector<void*> getCallsImpl(void* address) {
			// Match the function address or an address of the first function above it.
			// This is possible as the map is ordered.
			auto prev = this->map.lower_bound(PEParser::ibo32(address));
			// The address wasn't possible to match, return an empty vector.
			if (prev == this->map.end() || std::next(prev) == this->map.end()) return std::vector<void*>{};
			// Since the map is ordered, we can get the span of elements of a single segment 
			// by subtracting the current pointer from the pointer of the next map entry.
			auto next = std::next(prev);
			if (!prev->second || !next->second) return std::vector<void*>{};
			std::vector<void*> result;
			result.reserve((next->second - prev->second) / sizeof(PEParser::ibo32));
			// Iterate over pointers between the start position of the current entry and the start of the next entry.
			for (PEParser::ibo32* start = prev->second; start != next->second; ++start) {
				result.push_back(start->as<void*>());
			}
			return result;
		}

		std::map<PEParser::ibo32, PEParser::ibo32*> map{};
		std::vector<PEParser::ibo32> underlying{};
	};

	// Initializes CallHook.
	// Supports passing custom process info to the PEParser.
	bool initialize(PEParser::ProcessInfo* pInfo = nullptr) {
		auto& logger = Logger::get();
		static PEParser parser(pInfo);
		if (!parser.parse(pInfo)) {
			auto modulePath = std::make_unique<char[]>(MAX_PATH);
			auto moduleNameShort = std::make_unique<char[]>(MAX_PATH);
			GetModuleFileNameA(parser.getProcessInfo()->hProcessModule, modulePath.get(), MAX_PATH);
			// Shorten the full module path to just its name, naming it "unkModule" if any of the steps fail.
			logger.log("Failed to parse PE headers of %s", _splitpath_s(modulePath.get(), NULL, 0, NULL, 0, moduleNameShort.get(), MAX_PATH, NULL, 0)
				|| !strnlen_s(modulePath.get(), MAX_PATH) ? "unkModule" : moduleNameShort.get());
			return false;
		}
		else {
			logger.log("Successfully initialized CallHook");
		}
	}

	template <typename T> using FunctionHooks = std::vector<CallHookTemplate<T>*>;

	// Hook a vector of void pointers to function calls with the function in the second argument.
	// Create a CallHook::CallMap to get the function call addresses easily. 
	// CallHook::initialize must be called prior to creating any CallMap instances
	template <typename T, typename F> FunctionHooks<T> hookFunction(std::vector<void*> calls, F* function) {
		FunctionHooks<T> hooks{};
		for (auto call : calls) {
			hooks.push_back(new CallHookTemplate<T>(call, function));
		}
		return hooks;
	}

	// Undo a vector of function hooks returned by CallHook::hookFunction.
	template <typename T> void unhookFunction(FunctionHooks<T>& hooks) {
		for (auto hook : hooks) {
			delete hook;
		}
	}
}