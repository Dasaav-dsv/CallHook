// This is an example dll mod for Elden Ring that uses CallHook.
// It hooks the Special Effect param lookup function to implement a new SpEffect id.
// It also applies this new speffect to any blocking player.

#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#include <cstdint>

// The main CallHook header:
// defines all CallHook functions and classes.
#include "../include/CallHook.h"

// Helper headers.
#include "static.h"
#include "PointerChain.h"
#include "speffect/example.h"

// An example special effect param entry id we'll add without editing regulation.bin.
// This is possible by hooking the function which retrieves pointers to speffect param entries
// and handling our own ids separately. As a bonus, we get to know if our new id overlaps ids
// added by other mods. (And act accordingly, but this example will only log an error)
#define EXAMPLE_SPEFFECT_ID 11113507

// The hook for the speffect id lookup function.
// It relies on the fact speffect lookup will return a nullptr inside the output struct
// if a particular id has not been found. We can put a pointer to our own special effect entry
// into the output, effectively adding a new id without editing the regulation file.
void spEffectParamHook(SpEffectOut& out, int paramId) {
    static bool overlapErr = false;
    // Implement your own id lookup here, for example using a hashmap (e.g. std::unordered_map). 
    if (paramId != EXAMPLE_SPEFFECT_ID) return;
    // Check if the game's param id lookup already retrieved something.
    // Normally, this field will be empty, since the id we are trying to use should not already exist.
    // If it does, we have an id overlap we need to log (only once).
    if (out.paramEntry != nullptr && overlapErr == false) {
        // Get the logger instance (singleton).
        // CallHook comes with a logger class that saves the logs in logs\CallHook inside the main module's (process's) directory.
        // So, \ELDEN RING\Game\logs\CallHook\callhookexample.log for this example. 
        // Also, it prints to console (and allocates one if building in debug mode).
        CallHook::Logger& logger = CallHook::Logger::get();
        logger.log("Error: SpEffect %d overlaps another one with the same id. This means another mod has already added this SpEffect entry", paramId);
        overlapErr = true;
    }
    // Replace the return value in the output struct with our custom special effect.
    // This is all that is needed from this hook, really.
    out.paramEntry = exampleSpEffect;
}

void applyShield(uintptr_t** CSChrAiModule) {
    // Get the character instance pointer, which is at offset 0x8 of the CSChrAiModule.
    uintptr_t* ChrIns = CSChrAiModule[1];
    // Check that the character instance is a player by matching the handle.
    // (Player handles will be in the range 0xFFFFFFFF15A00000ull to 0xFFFFFFFF15A00005ull 
    // for normal gameplay and up to 0xFFFFFFFF15A0007Full for Seamless Co-op.)
    if ((ChrIns[1] ^ 0xFFFFFFFF15A00000ull) > 127) return;
    // Get the block flag: it is the 6th bit at offset 0x40 in the CSChrActionFlagModule 
    // (offset 0x8 of the ChrModules struct, which is 0x190 bytes away from ChrIns) 
    bool isPlayerBlocking = (*PointerChain::make<uint8_t>(ChrIns, 0x190, 0x8, 0x40) >> 5) & 1;
    // If a player is blocking, apply the shield effect, else remove it.
    if (isPlayerBlocking) {
        // Get the function pointer for the apply speffect function.
        FnApplyEffect applyEffect = reinterpret_cast<FnApplyEffect>(reinterpret_cast<uint8_t*>(PEParser::getProcessInfo()->mInfo->lpBaseOfDll) + IBO_APPLYEFFECT_FN);
        // We can apply our custom effect since we hooked the id lookup function.
        applyEffect(ChrIns, EXAMPLE_SPEFFECT_ID);
    }
    else {
        // Get the function pointer for the erase speffect function.
        FnEraseEffect eraseEffect = reinterpret_cast<FnApplyEffect>(reinterpret_cast<uint8_t*>(PEParser::getProcessInfo()->mInfo->lpBaseOfDll) + IBO_ERASEEFFECT_FN);
        // Erase the speffect (a pointer to the CS::SpecialEffect section of the ChrIns is needed (0x178)).
        eraseEffect(*PointerChain::make<void*>(ChrIns, 0x178u), EXAMPLE_SPEFFECT_ID);
    }
}

// A function that sets up the hooks in this example.
// It is called from dllmain.
void setupHooks() {
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
    // Hook a specific call (by providing its address/offset from image base)
    // This does not hook an entire function, but only a single time this function is called from a specific location.
    auto hook2 = new CallHookTemplate<EntryHook>(reinterpret_cast<uint8_t*>(PEParser::getProcessInfo()->mInfo->lpBaseOfDll) + IBO_PLAYER_BLOCK_HOOK_POINT, applyShield);
    // We won't be unhooking, however here is how to do it.
    if (false) {
        // A function unhooking example.
        CallHook::unhookFunction(hook1);
        // Individual call unhooking.
        delete hook2;
    }
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     ){
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        setupHooks();
        break;
    case DLL_THREAD_ATTACH:
        break;
    case DLL_THREAD_DETACH:
        break;
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

