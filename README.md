# CallHook
## An x86-64 function call hooking library.
CallHook is a simple to include and use C++17 function and function call hooking library, designed for non-invasive hooking by redirecting existing calls. Uses [Zydis](https://github.com/zyantific/zydis) for disassembly.

## How and why?
CallHook aims to make hooking functions less invasive by redirecting existing function calls - meaning it targets incoming call instructions instead of the function prologue.
This approach has several advantages over injecting trampolines:
1. No instructions are injected - the program code is unchanged besides call targets.
2. Resistant to race conditions - CallHook is designed to prevent race conditions while hooking and unhooking, including interactions between threads and modules.
3. Hook templates - hook before and after a function call, override the return value, the function call or capture the entire context as if using breakpoints (no actual debugger needed!)
4. Choose where you hook - hooking individual calls allows for greater control over the control flow of the program. 
5. Every call is a goal (almost) - use calls as safe injection points, you might not even need the function you hook, but its location in the surrounding code.

## How to use:
Include CallHook.h (if not using MSVC, you must statically link the two Zydis libraries found in thirdparty/Zydis to your project)

## Examples:
(all examples are taken from the example dll)
Single call hook:
```cpp
    // Initialize CallHook. Make sure initialization succeeds before proceeding.
    // You can pass in a different PEParser::ProcessInfo struct if you are looking to hook functions outside of the main module.
    if (!CallHook::initialize()) return;
    // Hook a specific call (by providing its address/offset from image base)
    // This does not hook an entire function, but only a single time this function is called from a specific location.
    auto hook2 = new CallHookTemplate<EntryHook>(reinterpret_cast<uint8_t*>(PEParser::getProcessInfo()->mInfo->lpBaseOfDll) + IBO_PLAYER_BLOCK_HOOK_POINT, applyShield);
```
A function hook:
```cpp
    // Initialize CallHook. Make sure initialization succeeds before proceeding.
    // You can pass in a different PEParser::ProcessInfo struct if you are looking to hook functions outside of the main module.
    if (!CallHook::initialize()) return;
    // Create a call map of the target module.
    // This disassembles all of the module's code (.text sections) and maps non-virtual call and function addresses it finds.
    CallHook::CallMap callMap{};
    // Get all calls to a function at a particular address/offset from image base.
    // The address does not have to match the beginning of the function, it can be inside the function too.
    // (This is useful for pattern matching instructions inside some function, ignoring the prologue.)
    // IBO_GET_SPEFFECTPARAM_FN is defined in static.h and represents the offset of this function from image base.
    auto calls = callMap.getCalls(IBO_GET_SPEFFECTPARAM_FN);
    // Hook a function (by hooking the calls returned by CallMap::getCalls).
    // You can also use a vector of void pointers to function addresses you get yourself.
    // The template argument represents the type of hook you want to place (more templates are in HookTemplates.h).
    auto hook1 = CallHook::hookFunction<ReturnHook>(calls, spEffectParamHook);
```
