#pragma once

#include <stdexcept>

#define ZYDIS_STATIC_BUILD
#define ZYDIS_DISABLE_ENCODER
#define ZYDIS_DISABLE_SEGMENT
#define ZYDIS_DISABLE_FORMATTER
#include "../thirdparty/zydis/include/Zydis/Zydis.h"

#include "Logger.h"

namespace CallHook {
	class Decoder {
	public:
		// Initializes the Zydis decoder with default parameters.
		// Will throw on failure to do so.
		Decoder() {
			if (!Decoder::decoder) {
				Decoder::decoder = new ZydisDecoder{};
				ZyanStatus status = ZydisDecoderInit(Decoder::decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
				if (ZYAN_FAILED(status)) {
					Logger::get().log("Failed to initialize Zydis instruction decoder; error %X", status);
					Decoder::decoder = nullptr;
					throw std::runtime_error("Failed to initialize Zydis instruction decoder.");
				}
				else {
					ZydisDecoderEnableMode(Decoder::decoder, ZYDIS_DECODER_MODE_MINIMAL, true);
				}
			}
		}

		// Check decoder status.
		static bool isDecoderInitialized() noexcept {
			return Decoder::decoder;
		}

		// Modify the decoder machine mode and stack width default values.
		bool setDecoderEnvironment(ZydisMachineMode machineMode = ZYDIS_MACHINE_MODE_LONG_64, ZydisStackWidth stackWidth = ZYDIS_STACK_WIDTH_64) noexcept {
			if (!Decoder::isDecoderInitialized()) return false;
			decoder->machine_mode = machineMode;
			decoder->stack_width = stackWidth;
			return true;
		}

		// Attempt to decode a single instruction at an address.
		bool decodeInstruction(uint8_t* address, ZydisDecodedInstruction& instruction) noexcept {
			ZyanStatus status = ZydisDecoderDecodeInstruction(Decoder::decoder, nullptr, address, 15, &instruction);
			return ZYAN_SUCCESS(status);
		}

	private:
		static inline ZydisDecoder* decoder = nullptr;
	};
}