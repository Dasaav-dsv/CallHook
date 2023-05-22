// A list of static offsets in the executable memory of eldenring.exe.
// Updated to game version 1.09.1 (these change every game version).

// The image base offset (offset from the beginning of the eldenring.exe module in bytes) of the getSpeffectParam function we hook.
#define IBO_GET_SPEFFECTPARAM_FN 0xD19B30
// The output struct of the getSpeffectParam function.
struct SpEffectOut {
	void* paramEntry;
	int spEffectId;
	int : 4;
};
// The signature of the getSpeffectParam function.
using FnGetSpEffectParam = void (*)(SpEffectOut& out, int paramId);

// A call hook location that will be called to check if the player is blocking.
// We don't need the function we are hooking, but it also conveniently returns the current character instance.
// Also, the position of this specific call is passed when the player blocks.
#define IBO_PLAYER_BLOCK_HOOK_POINT 0x432A93

// The apply speffect function IBO.
#define IBO_APPLYEFFECT_FN 0x3E66F0
// The signature of the function.
using FnApplyEffect = void (*)(void* ChrIns, int spEffectId);

// The erase speffect function IBO.
#define IBO_ERASEEFFECT_FN 0x4F3070
// The signature of the function.
using FnEraseEffect = void (*)(void* CSSpecialEffect, int spEffectId);
