#pragma once

#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <iostream>
#include <cstdarg>
#include <string>
#include <memory>

namespace CallHook {
	// A singleton logger class for CallHook.
	class Logger {
	public:
		static Logger& get() noexcept {
			static Logger s;
			return s;
		}

		// Log the specified string with printf formatting options in the log file and console.
		void log(std::string log, ...) noexcept {
			va_list extra_args;
			va_start(extra_args, log);
			std::string fullLog = this->moduleName + "\\" + loggerDir;
			fullLog.back() = *":";
			fullLog += " " + log + "\n";
			if (Logger::logFile) {
				vfprintf(Logger::logFile, fullLog.c_str(), extra_args);
				fflush(Logger::logFile);
			}
			vprintf(fullLog.c_str(), extra_args);
			va_end(extra_args);
		}

		// Retrieves the full path of the current module or the current main module.
		template <bool getMainModule = false> static std::string getCurrentModuleName() {
			auto modulePath = std::make_unique<char[]>(MAX_PATH);
			// GetModuleHandleExA returns the handle to the current module from an address within its memory.
			// If the handle itself is NULL, the call to GetModuleFileName will return the filename of the main module.
			HINSTANCE hinstDLL;
			if constexpr (getMainModule) {
				hinstDLL = NULL;
			}
			else {
				GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT | GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, reinterpret_cast<LPCSTR>(Logger::getCurrentModuleName<>), &hinstDLL);
			}
			// Get and return the full module path, or an empty string on failure.
			if (!GetModuleFileNameA(hinstDLL, modulePath.get(), MAX_PATH)) {
				return "";
			}
			return std::string(modulePath.get());
		}

		// As Logger is a singleton, the assignment and copy operators are deleted.
		Logger(const Logger&) = delete;
		Logger& operator = (const Logger&) = delete;

	private:
		Logger() {
			// Allocate console and redirect output on a debug build.
#ifndef NDEBUG
			AllocConsole();
			FILE* out;
			freopen_s(&out, "CON", "w", stdout);
#endif
			this->moduleName = Logger::getCurrentModuleName();
			auto moduleNameShort = std::make_unique<char[]>(MAX_PATH);
			// Shorten the full module path to just its name, naming it "unkModule" if any of the steps fail.
			this->moduleName = _splitpath_s(this->moduleName.c_str(), NULL, 0, NULL, 0, moduleNameShort.get(), MAX_PATH, NULL, 0)
				|| !this->moduleName.length() ? "unkModule" : std::string(moduleNameShort.get());
			this->moduleName.shrink_to_fit();
			// Get the full path of the main module - the process itself.
			std::string processPath = Logger::getCurrentModuleName<true>();
			char loggerDir[MAX_PATH];
			// Attempt to get the path of the current module.
			// Append the logger directory on to it on success or to the current directory on failure.
			if (_splitpath_s(processPath.c_str(), NULL, 0, loggerDir, MAX_PATH, NULL, 0, NULL, 0)) {
				strcpy_s(loggerDir, this->loggerDir);
			}
			else {
				strcat_s(loggerDir, this->loggerDir);
			}
			CreateDirectoryA("log", NULL);
			CreateDirectoryA(loggerDir, NULL);
			// Append the full log path.
			// Attempt to open or create a log file.
			// If the file fails to open, it's likely a log of the same name is already used.
			for (int i = 0; i < 4; i++) {
				auto logFileAttempt = [&](int attempt)->bool {
					char loggerDirAttempt[MAX_PATH];
					strcpy_s(loggerDirAttempt, loggerDir);
					if (attempt != 0) {
						// Append the repeat attempt number to the log.
						// In this (unlikely) case, try three more times.
						this->moduleName.back() = std::to_string(attempt).back();
					}
					strcat_s(loggerDirAttempt, this->moduleName.c_str());
					strcat_s(loggerDirAttempt, ".log");
					return fopen_s(&Logger::logFile, loggerDirAttempt, "w");
				};
				if (!logFileAttempt(i)) break;
				this->moduleName += "0";
			}
		}

		~Logger() {}
		
		static inline FILE* logFile{};
		std::string moduleName;
		static constexpr const char* loggerDir = "log\\CallHook\\";
	};
}
