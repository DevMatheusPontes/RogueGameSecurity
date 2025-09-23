#pragma once

#include <windows.h>
#include <vector>
#include <string>
#include <optional>
#include <unordered_set>
#include <unordered_map>
#include <functional>

namespace rgs::sdk::protection {

    enum class InterfaceThreat {
        Unknown,
        WindowManipulation,
        InputAutomation,
        MacroDetection,
        OverlayAttack,
        ClickBot,
        KeyboardHook,
        MouseHook
    };

    struct InputEvent {
        DWORD timestamp;
        POINT position;
        DWORD inputType; // Mouse, keyboard, etc.
        std::vector<BYTE> data;
    };

    struct WindowThreatDetection {
        InterfaceThreat type;
        HWND targetWindow;
        std::string description;
        std::string processName;
        DWORD processId;
    };

    struct InputPattern {
        std::vector<InputEvent> events;
        DWORD totalDuration;
        double averageInterval;
        bool isAutomated;
    };

    class InterfaceProtection {
    public:
        InterfaceProtection();
        ~InterfaceProtection();

        // Initialize interface protection
        bool initialize();
        void shutdown();

        // Window protection
        bool enableWindowProtection();
        void disableWindowProtection();
        std::vector<WindowThreatDetection> scanForWindowThreats();
        
        // Input validation and monitoring
        bool enableInputMonitoring();
        void disableInputMonitoring();
        bool validateInput();
        
        // Macro and automation detection
        bool detectMacros();
        bool detectAutomation();
        std::vector<InputPattern> analyzeInputPatterns();
        
        // Overlay and injection protection
        bool detectOverlays();
        bool detectWindowInjection();
        
        // Hook detection
        bool detectInputHooks();
        bool detectKeyboardHooks();
        bool detectMouseHooks();
        
        // Window manipulation detection
        bool detectWindowManipulation();
        bool detectForegroundChanges();
        
        // Configuration
        void setInputSensitivity(float sensitivity); // 0.0 - 1.0
        float getInputSensitivity() const;
        void setMacroDetectionEnabled(bool enabled);
        void setOverlayDetectionEnabled(bool enabled);
        void setHookDetectionEnabled(bool enabled);

        // Callbacks for custom threat handling
        using ThreatCallback = std::function<void(const WindowThreatDetection&)>;
        void setThreatCallback(ThreatCallback callback);

    private:
        // Window enumeration and analysis
        static BOOL CALLBACK enumWindowsProc(HWND hwnd, LPARAM lParam);
        bool analyzeWindow(HWND hwnd);
        bool isWindowSuspicious(HWND hwnd);
        std::string getWindowProcessName(HWND hwnd);
        
        // Input monitoring helpers
        static LRESULT CALLBACK lowLevelKeyboardProc(int nCode, WPARAM wParam, LPARAM lParam);
        static LRESULT CALLBACK lowLevelMouseProc(int nCode, WPARAM wParam, LPARAM lParam);
        void recordInputEvent(DWORD inputType, const BYTE* data, size_t dataSize);
        
        // Pattern analysis
        bool isInputPatternAutomated(const std::vector<InputEvent>& events);
        double calculateInputEntropy(const std::vector<InputEvent>& events);
        bool detectRepeatingPattern(const std::vector<InputEvent>& events);
        bool analyzeTimingPatterns(const std::vector<InputEvent>& events);
        
        // Hook detection helpers
        bool checkSetWindowsHookEx();
        bool scanForHookChains();
        bool detectInlineInputHooks();
        
        // Overlay detection helpers
        bool checkWindowLayering();
        bool detectTransparentOverlays();
        bool scanForInjectedWindows();
        
        // Window manipulation helpers
        bool monitorWindowChanges();
        bool detectWindowClassChanges();
        bool checkWindowProperties();

        // State management
        bool m_initialized = false;
        bool m_windowProtectionEnabled = false;
        bool m_inputMonitoringEnabled = false;
        bool m_macroDetectionEnabled = true;
        bool m_overlayDetectionEnabled = true;
        bool m_hookDetectionEnabled = true;
        
        // Configuration
        float m_inputSensitivity = 0.7f;
        
        // Hooks
        HHOOK m_keyboardHook = NULL;
        HHOOK m_mouseHook = NULL;
        
        // Input tracking
        std::vector<InputEvent> m_inputHistory;
        DWORD m_maxInputHistorySize = 1000;
        
        // Window tracking
        std::unordered_set<HWND> m_knownWindows;
        std::unordered_map<HWND, std::string> m_windowProcessMap;
        
        // Threat detection
        std::vector<WindowThreatDetection> m_detectedThreats;
        ThreatCallback m_threatCallback;
        
        // Static instance for hook procedures
        static InterfaceProtection* s_instance;
    };

} // namespace rgs::sdk::protection