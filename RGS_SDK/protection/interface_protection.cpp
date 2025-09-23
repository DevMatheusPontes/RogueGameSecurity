#include "interface_protection.hpp"
#include <psapi.h>
#include <algorithm>
#include <cmath>
#include <numeric>

namespace rgs::sdk::protection {

    // Static instance for hook procedures
    InterfaceProtection* InterfaceProtection::s_instance = nullptr;

    InterfaceProtection::InterfaceProtection() {
        s_instance = this;
    }

    InterfaceProtection::~InterfaceProtection() {
        shutdown();
        s_instance = nullptr;
    }

    bool InterfaceProtection::initialize() {
        if (m_initialized) {
            return true;
        }

        m_initialized = true;
        return true;
    }

    void InterfaceProtection::shutdown() {
        if (!m_initialized) {
            return;
        }

        disableWindowProtection();
        disableInputMonitoring();

        m_knownWindows.clear();
        m_windowProcessMap.clear();
        m_inputHistory.clear();
        m_detectedThreats.clear();

        m_initialized = false;
    }

    bool InterfaceProtection::enableWindowProtection() {
        if (m_windowProtectionEnabled) {
            return true;
        }

        // Initialize window tracking
        EnumWindows(enumWindowsProc, reinterpret_cast<LPARAM>(this));

        m_windowProtectionEnabled = true;
        return true;
    }

    void InterfaceProtection::disableWindowProtection() {
        if (!m_windowProtectionEnabled) {
            return;
        }

        m_windowProtectionEnabled = false;
    }

    std::vector<WindowThreatDetection> InterfaceProtection::scanForWindowThreats() {
        std::vector<WindowThreatDetection> threats;

        if (!m_windowProtectionEnabled) {
            return threats;
        }

        // Enumerate all windows and check for threats
        EnumWindows(enumWindowsProc, reinterpret_cast<LPARAM>(this));

        // Check for overlays
        if (m_overlayDetectionEnabled && detectOverlays()) {
            WindowThreatDetection threat;
            threat.type = InterfaceThreat::OverlayAttack;
            threat.targetWindow = GetForegroundWindow();
            threat.description = "Suspicious overlay detected";
            threats.push_back(threat);
        }

        // Check for window manipulation
        if (detectWindowManipulation()) {
            WindowThreatDetection threat;
            threat.type = InterfaceThreat::WindowManipulation;
            threat.targetWindow = GetForegroundWindow();
            threat.description = "Window manipulation detected";
            threats.push_back(threat);
        }

        return threats;
    }

    bool InterfaceProtection::enableInputMonitoring() {
        if (m_inputMonitoringEnabled) {
            return true;
        }

        // Install low-level keyboard hook
        m_keyboardHook = SetWindowsHookExW(WH_KEYBOARD_LL, lowLevelKeyboardProc, 
                                          GetModuleHandle(NULL), 0);
        if (!m_keyboardHook) {
            return false;
        }

        // Install low-level mouse hook
        m_mouseHook = SetWindowsHookExW(WH_MOUSE_LL, lowLevelMouseProc, 
                                       GetModuleHandle(NULL), 0);
        if (!m_mouseHook) {
            UnhookWindowsHookEx(m_keyboardHook);
            m_keyboardHook = NULL;
            return false;
        }

        m_inputMonitoringEnabled = true;
        return true;
    }

    void InterfaceProtection::disableInputMonitoring() {
        if (!m_inputMonitoringEnabled) {
            return;
        }

        if (m_keyboardHook) {
            UnhookWindowsHookEx(m_keyboardHook);
            m_keyboardHook = NULL;
        }

        if (m_mouseHook) {
            UnhookWindowsHookEx(m_mouseHook);
            m_mouseHook = NULL;
        }

        m_inputMonitoringEnabled = false;
    }

    bool InterfaceProtection::validateInput() {
        if (!m_inputMonitoringEnabled) {
            return true;
        }

        // Analyze recent input patterns
        auto patterns = analyzeInputPatterns();
        
        for (const auto& pattern : patterns) {
            if (pattern.isAutomated) {
                WindowThreatDetection threat;
                threat.type = InterfaceThreat::InputAutomation;
                threat.targetWindow = GetForegroundWindow();
                threat.description = "Automated input pattern detected";
                m_detectedThreats.push_back(threat);
                return false;
            }
        }

        return true;
    }

    bool InterfaceProtection::detectMacros() {
        if (!m_macroDetectionEnabled) {
            return false;
        }

        auto patterns = analyzeInputPatterns();
        
        for (const auto& pattern : patterns) {
            if (pattern.isAutomated && detectRepeatingPattern(pattern.events)) {
                WindowThreatDetection threat;
                threat.type = InterfaceThreat::MacroDetection;
                threat.targetWindow = GetForegroundWindow();
                threat.description = "Macro execution detected";
                m_detectedThreats.push_back(threat);
                return true;
            }
        }

        return false;
    }

    bool InterfaceProtection::detectAutomation() {
        if (m_inputHistory.size() < 10) {
            return false; // Not enough data
        }

        return isInputPatternAutomated(m_inputHistory);
    }

    std::vector<InputPattern> InterfaceProtection::analyzeInputPatterns() {
        std::vector<InputPattern> patterns;
        
        if (m_inputHistory.size() < 5) {
            return patterns; // Not enough data
        }

        // Group events into patterns (sliding window)
        const size_t windowSize = 10;
        for (size_t i = 0; i <= m_inputHistory.size() - windowSize; i++) {
            InputPattern pattern;
            pattern.events.assign(m_inputHistory.begin() + i, 
                                 m_inputHistory.begin() + i + windowSize);
            
            if (!pattern.events.empty()) {
                pattern.totalDuration = pattern.events.back().timestamp - pattern.events.front().timestamp;
                pattern.averageInterval = static_cast<double>(pattern.totalDuration) / (pattern.events.size() - 1);
                pattern.isAutomated = isInputPatternAutomated(pattern.events);
                patterns.push_back(pattern);
            }
        }

        return patterns;
    }

    bool InterfaceProtection::detectOverlays() {
        return checkWindowLayering() || detectTransparentOverlays();
    }

    bool InterfaceProtection::detectWindowInjection() {
        return scanForInjectedWindows();
    }

    bool InterfaceProtection::detectInputHooks() {
        return detectKeyboardHooks() || detectMouseHooks();
    }

    bool InterfaceProtection::detectKeyboardHooks() {
        // Check for keyboard hooks in the system
        return checkSetWindowsHookEx();
    }

    bool InterfaceProtection::detectMouseHooks() {
        // Check for mouse hooks in the system
        return checkSetWindowsHookEx();
    }

    bool InterfaceProtection::detectWindowManipulation() {
        return detectForegroundChanges();
    }

    bool InterfaceProtection::detectForegroundChanges() {
        static HWND lastForeground = NULL;
        static DWORD lastChangeTime = 0;
        
        HWND currentForeground = GetForegroundWindow();
        DWORD currentTime = GetTickCount();
        
        if (currentForeground != lastForeground) {
            if (currentTime - lastChangeTime < 100) { // Very rapid changes
                return true;
            }
            lastForeground = currentForeground;
            lastChangeTime = currentTime;
        }
        
        return false;
    }

    void InterfaceProtection::setInputSensitivity(float sensitivity) {
        m_inputSensitivity = std::max(0.0f, std::min(1.0f, sensitivity));
    }

    float InterfaceProtection::getInputSensitivity() const {
        return m_inputSensitivity;
    }

    void InterfaceProtection::setMacroDetectionEnabled(bool enabled) {
        m_macroDetectionEnabled = enabled;
    }

    void InterfaceProtection::setOverlayDetectionEnabled(bool enabled) {
        m_overlayDetectionEnabled = enabled;
    }

    void InterfaceProtection::setHookDetectionEnabled(bool enabled) {
        m_hookDetectionEnabled = enabled;
    }

    void InterfaceProtection::setThreatCallback(ThreatCallback callback) {
        m_threatCallback = callback;
    }

    // Private helper methods

    BOOL CALLBACK InterfaceProtection::enumWindowsProc(HWND hwnd, LPARAM lParam) {
        InterfaceProtection* instance = reinterpret_cast<InterfaceProtection*>(lParam);
        if (instance) {
            instance->analyzeWindow(hwnd);
        }
        return TRUE;
    }

    bool InterfaceProtection::analyzeWindow(HWND hwnd) {
        if (!IsWindow(hwnd) || !IsWindowVisible(hwnd)) {
            return false;
        }

        // Add to known windows
        m_knownWindows.insert(hwnd);

        // Get process information
        DWORD processId;
        GetWindowThreadProcessId(hwnd, &processId);
        std::string processName = getWindowProcessName(hwnd);
        m_windowProcessMap[hwnd] = processName;

        // Check if window is suspicious
        if (isWindowSuspicious(hwnd)) {
            WindowThreatDetection threat;
            threat.type = InterfaceThreat::WindowManipulation;
            threat.targetWindow = hwnd;
            threat.processId = processId;
            threat.processName = processName;
            threat.description = "Suspicious window detected: " + processName;
            m_detectedThreats.push_back(threat);

            if (m_threatCallback) {
                m_threatCallback(threat);
            }
            return true;
        }

        return false;
    }

    bool InterfaceProtection::isWindowSuspicious(HWND hwnd) {
        // Check window class name
        char className[256];
        GetClassNameA(hwnd, className, sizeof(className));
        std::string classNameStr = className;
        
        // Suspicious class names
        std::vector<std::string> suspiciousClasses = {
            "CheatEngine", "Cheat Engine", "CE", "OllyDbg", "x64dbg",
            "IDA", "WinAPIOverride", "API Monitor", "Process Hacker"
        };

        for (const auto& suspicious : suspiciousClasses) {
            if (classNameStr.find(suspicious) != std::string::npos) {
                return true;
            }
        }

        // Check window title
        char windowTitle[256];
        GetWindowTextA(hwnd, windowTitle, sizeof(windowTitle));
        std::string titleStr = windowTitle;
        
        std::vector<std::string> suspiciousTitles = {
            "cheat", "hack", "trainer", "mod", "inject", "debug",
            "memory", "process", "hook", "bot", "macro"
        };

        std::transform(titleStr.begin(), titleStr.end(), titleStr.begin(), ::tolower);
        for (const auto& suspicious : suspiciousTitles) {
            if (titleStr.find(suspicious) != std::string::npos) {
                return true;
            }
        }

        return false;
    }

    std::string InterfaceProtection::getWindowProcessName(HWND hwnd) {
        DWORD processId;
        GetWindowThreadProcessId(hwnd, &processId);
        
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
        if (hProcess) {
            char processName[MAX_PATH];
            if (GetModuleBaseNameA(hProcess, NULL, processName, sizeof(processName))) {
                CloseHandle(hProcess);
                return std::string(processName);
            }
            CloseHandle(hProcess);
        }
        
        return "Unknown";
    }

    LRESULT CALLBACK InterfaceProtection::lowLevelKeyboardProc(int nCode, WPARAM wParam, LPARAM lParam) {
        if (nCode >= 0 && s_instance && s_instance->m_inputMonitoringEnabled) {
            KBDLLHOOKSTRUCT* pkbhs = (KBDLLHOOKSTRUCT*)lParam;
            
            InputEvent event;
            event.timestamp = GetTickCount();
            event.position = {0, 0}; // Keyboard doesn't have position
            event.inputType = 1; // Keyboard
            event.data.resize(sizeof(KBDLLHOOKSTRUCT));
            memcpy(event.data.data(), pkbhs, sizeof(KBDLLHOOKSTRUCT));
            
            s_instance->recordInputEvent(1, (BYTE*)pkbhs, sizeof(KBDLLHOOKSTRUCT));
        }
        
        return CallNextHookEx(s_instance ? s_instance->m_keyboardHook : NULL, nCode, wParam, lParam);
    }

    LRESULT CALLBACK InterfaceProtection::lowLevelMouseProc(int nCode, WPARAM wParam, LPARAM lParam) {
        if (nCode >= 0 && s_instance && s_instance->m_inputMonitoringEnabled) {
            MSLLHOOKSTRUCT* pmshs = (MSLLHOOKSTRUCT*)lParam;
            
            InputEvent event;
            event.timestamp = GetTickCount();
            event.position = pmshs->pt;
            event.inputType = 2; // Mouse
            event.data.resize(sizeof(MSLLHOOKSTRUCT));
            memcpy(event.data.data(), pmshs, sizeof(MSLLHOOKSTRUCT));
            
            s_instance->recordInputEvent(2, (BYTE*)pmshs, sizeof(MSLLHOOKSTRUCT));
        }
        
        return CallNextHookEx(s_instance ? s_instance->m_mouseHook : NULL, nCode, wParam, lParam);
    }

    void InterfaceProtection::recordInputEvent(DWORD inputType, const BYTE* data, size_t dataSize) {
        InputEvent event;
        event.timestamp = GetTickCount();
        event.inputType = inputType;
        
        if (inputType == 2 && dataSize >= sizeof(MSLLHOOKSTRUCT)) { // Mouse
            MSLLHOOKSTRUCT* mouseData = (MSLLHOOKSTRUCT*)data;
            event.position = mouseData->pt;
        } else {
            event.position = {0, 0};
        }
        
        event.data.resize(dataSize);
        memcpy(event.data.data(), data, dataSize);
        
        m_inputHistory.push_back(event);
        
        // Limit history size
        if (m_inputHistory.size() > m_maxInputHistorySize) {
            m_inputHistory.erase(m_inputHistory.begin(), 
                                m_inputHistory.begin() + (m_inputHistory.size() - m_maxInputHistorySize));
        }
    }

    bool InterfaceProtection::isInputPatternAutomated(const std::vector<InputEvent>& events) {
        if (events.size() < 5) {
            return false;
        }

        // Calculate entropy of input timing
        double entropy = calculateInputEntropy(events);
        
        // Low entropy indicates automation
        double threshold = 1.0 - m_inputSensitivity; // Higher sensitivity = lower threshold
        
        return entropy < threshold || analyzeTimingPatterns(events);
    }

    double InterfaceProtection::calculateInputEntropy(const std::vector<InputEvent>& events) {
        if (events.size() < 2) {
            return 1.0; // Maximum entropy for insufficient data
        }

        std::vector<DWORD> intervals;
        for (size_t i = 1; i < events.size(); i++) {
            intervals.push_back(events[i].timestamp - events[i-1].timestamp);
        }

        // Group intervals into buckets (10ms precision)
        std::unordered_map<DWORD, int> buckets;
        for (DWORD interval : intervals) {
            DWORD bucket = (interval / 10) * 10; // Round to nearest 10ms
            buckets[bucket]++;
        }

        // Calculate Shannon entropy
        double entropy = 0.0;
        size_t totalIntervals = intervals.size();
        
        for (const auto& [bucket, count] : buckets) {
            double probability = static_cast<double>(count) / totalIntervals;
            if (probability > 0) {
                entropy -= probability * log2(probability);
            }
        }

        // Normalize entropy (0-1 scale)
        double maxEntropy = log2(static_cast<double>(buckets.size()));
        return maxEntropy > 0 ? entropy / maxEntropy : 0.0;
    }

    bool InterfaceProtection::detectRepeatingPattern(const std::vector<InputEvent>& events) {
        if (events.size() < 6) {
            return false;
        }

        // Look for repeating timing patterns
        for (size_t patternLen = 2; patternLen <= events.size() / 3; patternLen++) {
            std::vector<DWORD> pattern;
            
            // Extract timing pattern
            for (size_t i = 1; i <= patternLen && i < events.size(); i++) {
                pattern.push_back(events[i].timestamp - events[i-1].timestamp);
            }

            // Check if this pattern repeats
            int repetitions = 0;
            for (size_t i = patternLen; i + patternLen < events.size(); i += patternLen) {
                bool matches = true;
                for (size_t j = 0; j < patternLen - 1 && i + j + 1 < events.size(); j++) {
                    DWORD currentInterval = events[i + j + 1].timestamp - events[i + j].timestamp;
                    DWORD patternInterval = pattern[j];
                    
                    // Allow 5ms tolerance
                    if (abs(static_cast<int>(currentInterval - patternInterval)) > 5) {
                        matches = false;
                        break;
                    }
                }
                
                if (matches) {
                    repetitions++;
                } else {
                    break;
                }
            }

            // If pattern repeats at least 2 times, it's likely automated
            if (repetitions >= 2) {
                return true;
            }
        }

        return false;
    }

    bool InterfaceProtection::analyzeTimingPatterns(const std::vector<InputEvent>& events) {
        if (events.size() < 10) {
            return false;
        }

        std::vector<DWORD> intervals;
        for (size_t i = 1; i < events.size(); i++) {
            intervals.push_back(events[i].timestamp - events[i-1].timestamp);
        }

        // Calculate standard deviation of intervals
        double mean = std::accumulate(intervals.begin(), intervals.end(), 0.0) / intervals.size();
        double variance = 0.0;
        
        for (DWORD interval : intervals) {
            variance += (interval - mean) * (interval - mean);
        }
        variance /= intervals.size();
        
        double stdDev = sqrt(variance);
        
        // Very low standard deviation indicates automation (too consistent)
        return stdDev < 5.0; // Less than 5ms variation
    }

    bool InterfaceProtection::checkSetWindowsHookEx() {
        // This is simplified - a real implementation would need to inspect
        // the hook chain or use more advanced techniques
        HHOOK testHook = SetWindowsHookExW(WH_KEYBOARD_LL, 
                                          [](int code, WPARAM w, LPARAM l) -> LRESULT {
                                              return CallNextHookEx(NULL, code, w, l);
                                          }, 
                                          GetModuleHandle(NULL), 0);
        if (testHook) {
            UnhookWindowsHookEx(testHook);
            return false; // No interference detected
        }
        
        return true; // Hook installation failed, might indicate existing hooks
    }

    bool InterfaceProtection::checkWindowLayering() {
        HWND foreground = GetForegroundWindow();
        if (!foreground) return false;

        // Check if there are windows above the foreground window
        HWND topWindow = GetTopWindow(NULL);
        while (topWindow) {
            if (topWindow != foreground && IsWindowVisible(topWindow)) {
                // Check if this window overlaps with foreground
                RECT foregroundRect, topRect;
                if (GetWindowRect(foreground, &foregroundRect) && 
                    GetWindowRect(topWindow, &topRect)) {
                    
                    // Check for overlap
                    if (!(topRect.right < foregroundRect.left || 
                          topRect.left > foregroundRect.right ||
                          topRect.bottom < foregroundRect.top || 
                          topRect.top > foregroundRect.bottom)) {
                        return true; // Overlapping window found
                    }
                }
            }
            topWindow = GetNextWindow(topWindow, GW_HWNDNEXT);
        }

        return false;
    }

    bool InterfaceProtection::detectTransparentOverlays() {
        // Check for windows with transparency that might be overlays
        HWND foreground = GetForegroundWindow();
        if (!foreground) return false;

        HWND window = GetTopWindow(NULL);
        while (window) {
            if (window != foreground && IsWindowVisible(window)) {
                // Check window attributes for transparency
                LONG exStyle = GetWindowLongA(window, GWL_EXSTYLE);
                if (exStyle & WS_EX_LAYERED) {
                    BYTE alpha;
                    COLORREF colorKey;
                    DWORD flags;
                    
                    if (GetLayeredWindowAttributes(window, &colorKey, &alpha, &flags)) {
                        if (alpha < 255 || (flags & LWA_COLORKEY)) {
                            return true; // Transparent overlay detected
                        }
                    }
                }
            }
            window = GetNextWindow(window, GW_HWNDNEXT);
        }

        return false;
    }

    bool InterfaceProtection::scanForInjectedWindows() {
        // This would require more advanced techniques to detect injected windows
        // For now, we'll check for windows from suspicious processes
        return false;
    }

} // namespace rgs::sdk::protection