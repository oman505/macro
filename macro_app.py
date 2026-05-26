import time
import threading
import ctypes
import json
import customtkinter as ctk
from pynput import mouse, keyboard
from tkinter import filedialog, messagebox
import queue

# Set window default theme
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

# --- NATIVE WINDOWS API FOR EXE DETECTION ---
GetForegroundWindow = ctypes.windll.user32.GetForegroundWindow
GetWindowThreadProcessId = ctypes.windll.user32.GetWindowThreadProcessId
OpenProcess = ctypes.windll.kernel32.OpenProcess
CloseHandle = ctypes.windll.kernel32.CloseHandle
QueryFullProcessImageNameW = ctypes.windll.kernel32.QueryFullProcessImageNameW
EnumWindows = ctypes.windll.user32.EnumWindows
IsWindowVisible = ctypes.windll.user32.IsWindowVisible
GetWindowTextW = ctypes.windll.user32.GetWindowTextW

PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010

def get_exe_from_hwnd(hwnd):
    """Helper to look up an executable name given a window handle."""
    pid = ctypes.c_ulong()
    GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
    process_handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid.value)
    if not process_handle:
        return ""
    buf = ctypes.create_unicode_buffer(1024)
    size = ctypes.c_ulong(1024)
    success = QueryFullProcessImageNameW(process_handle, 0, buf, ctypes.byref(size))
    CloseHandle(process_handle)
    if success:
        return buf.value.split('\\')[-1].split('/')[-1].lower()
    return ""

def get_active_window_exe():
    """Returns the lower-case executable name of the current foreground window."""
    hwnd = GetForegroundWindow()
    if not hwnd:
        return ""
    return get_exe_from_hwnd(hwnd)

def get_all_visible_window_exes():
    """Scans open windows on screen and extracts unique executable targets."""
    exes = set()
    
    # Callback logic for window enumeration
    def enum_windows_callback(hwnd, lParam):
        if IsWindowVisible(hwnd):
            text_buf = ctypes.create_unicode_buffer(512)
            GetWindowTextW(hwnd, text_buf, 512)
            # Only track windows with actual descriptive window titles
            if text_buf.value.strip():
                exe_name = get_exe_from_hwnd(hwnd)
                if exe_name and not exe_name.startswith("macro_app"):
                    exes.add(exe_name)
        return True
        
    WNDENUMPROC = ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_long, ctypes.c_long)
    EnumWindows(WNDENUMPROC(enum_windows_callback), 0)
    
    sorted_list = sorted(list(exes))
    return sorted_list if sorted_list else ["notepad.exe"]


# --- NATIVE DIRECTINPUT HARDWARE EMULATION SETUP ---
SendInput = ctypes.windll.user32.SendInput
PUL = ctypes.POINTER(ctypes.c_ulong)

class KeyBdInput(ctypes.Structure):
    _fields_ = [
        ("wVk", ctypes.c_ushort),
        ("wScan", ctypes.c_ushort),
        ("dwFlags", ctypes.c_ulong),
        ("time", ctypes.c_ulong),
        ("dwExtraInfo", PUL)
    ]

class HardwareInput(ctypes.Structure):
    _fields_ = [("uMsg", ctypes.c_ulong), ("wParamL", ctypes.c_short), ("wParamH", ctypes.c_ushort)]

class MouseInput(ctypes.Structure):
    _fields_ = [
        ("dx", ctypes.c_long),
        ("dy", ctypes.c_long),
        ("mouseData", ctypes.c_ulong),
        ("dwFlags", ctypes.c_ulong),
        ("time", ctypes.c_ulong),
        ("dwExtraInfo", PUL)
    ]

class Input_I(ctypes.Union):
    _fields_ = [("ki", KeyBdInput), ("mi", MouseInput), ("hi", HardwareInput)]

class Input(ctypes.Structure):
    _fields_ = [("type", ctypes.c_ulong), ("ii", Input_I)]

# COMPREHENSIVE SCANCODE MATRIX
VK_TO_SCAN = {
    0x41: 0x1E, 0x42: 0x30, 0x43: 0x2E, 0x44: 0x20, 0x45: 0x12, 0x46: 0x21, 0x47: 0x22,
    0x48: 0x23, 0x49: 0x17, 0x4A: 0x24, 0x4B: 0x25, 0x4C: 0x26, 0x4D: 0x32, 0x4E: 0x31,
    0x4F: 0x18, 0x50: 0x19, 0x51: 0x10, 0x52: 0x13, 0x53: 0x1F, 0x54: 0x14, 0x55: 0x16,
    0x56: 0x2F, 0x57: 0x11, 0x58: 0x2D, 0x59: 0x15, 0x5A: 0x2C,
    0x61: 0x1E, 0x62: 0x30, 0x63: 0x2E, 0x64: 0x20, 0x65: 0x12, 0x66: 0x21, 0x67: 0x22,
    0x68: 0x23, 0x69: 0x17, 0x6A: 0x24, 0x6B: 0x25, 0x6C: 0x26, 0x6D: 0x32, 0x6E: 0x31,
    0x6F: 0x18, 0x70: 0x19, 0x71: 0x10, 0x72: 0x13, 0x73: 0x1F, 0x74: 0x14, 0x75: 0x16,
    0x76: 0x2F, 0x77: 0x11, 0x78: 0x2D, 0x79: 0x15, 0x7A: 0x2C,
    0x30: 0x0B, 0x31: 0x02, 0x32: 0x03, 0x33: 0x04, 0x34: 0x05, 0x35: 0x06, 0x36: 0x07, 0x37: 0x08, 0x38: 0x09, 0x39: 0x0A,
    0x60: 0x52, 0x61: 0x4F, 0x62: 0x50, 0x63: 0x51, 0x64: 0x4B, 0x65: 0x4C, 0x66: 0x4D, 0x67: 0x47, 0x68: 0x48, 0x69: 0x49,
    0x6A: 0x37, 0x6B: 0x4E, 0x6D: 0x4A, 0x6E: 0x53, 0x6F: 0x35,
    0x20: 0x39, 0x0D: 0x1C, 0x10: 0x2A, 0xA0: 0x2A, 0xA1: 0x36, 0x11: 0x1D, 0xA2: 0x1D, 0xA3: 0x1D,
    0x12: 0x38, 0xA4: 0x38, 0xA5: 0x38, 0x14: 0x3A, 0x09: 0x0F, 0x08: 0x0E, 0x1B: 0x01,
    0x25: 0x4B, 0x26: 0x48, 0x27: 0x4D, 0x28: 0x50, 0x24: 0x47, 0x21: 0x49, 0x22: 0x51, 0x23: 0x4F,
    0x2D: 0x52, 0x2E: 0x53, 0xBA: 0x27, 0xBB: 0x0D, 0xBC: 0x33, 0xBD: 0x0C, 0xBE: 0x34, 0xBF: 0x35,
    0xC0: 0x29, 0xDB: 0x1A, 0xDC: 0x2B, 0xDD: 0x1B, 0xDE: 0x28
}

EXTENDED_KEYS = {0x25, 0x26, 0x27, 0x28, 0x0D, 0x24, 0x21, 0x22, 0x23, 0x2E, 0xA3, 0xA5, 0x6F}

SCAN_TO_NAME = {
    0x39: "SPACE", 0x1C: "ENTER", 0x2A: "SHIFT", 0x36: "R_SHIFT", 0x1D: "CTRL", 0x38: "ALT",
    0x3A: "CAPS LOCK", 0x0F: "TAB", 0x0E: "BACKSPACE", 0x01: "ESC",
    0x4B: "LEFT ARROW", 0x48: "UP ARROW", 0x4D: "RIGHT ARROW", 0x50: "DOWN ARROW",
    0x47: "HOME", 0x49: "PAGE_UP", 0x51: "PAGE_DOWN", 0x4F: "END",
    0x1E: "A", 0x30: "B", 0x2E: "C", 0x20: "D", 0x12: "E", 0x21: "F", 0x22: "G",
    0x23: "H", 0x17: "I", 0x24: "J", 0x25: "K", 0x26: "L", 0x32: "M", 0x31: "N",
    0x18: "O", 0x19: "P", 0x10: "Q", 0x13: "R", 0x1F: "S", 0x14: "T", 0x16: "U",
    0x2F: "V", 0x11: "W", 0x2D: "X", 0x15: "Y", 0x2C: "Z",
    0x02: "1", 0x03: "2", 0x04: "3", 0x05: "4", 0x06: "5", 0x07: "6", 0x08: "7", 0x09: "8", 0x0A: "9", 0x0B: "0"
}

def send_hardware_input(vk_code, is_release=False):
    scan_code = VK_TO_SCAN.get(vk_code, 0)
    if scan_code == 0: return False
    flags = 0x0008  
    if vk_code in EXTENDED_KEYS: flags |= 0x0001  
    if is_release: flags |= 0x0002  
    extra = ctypes.c_ulong(0)
    ii_ = Input_I()
    ii_.ki = KeyBdInput(0, scan_code, flags, 0, ctypes.pointer(extra))
    command = Input(ctypes.c_ulong(1), ii_)
    SendInput(1, ctypes.pointer(command), ctypes.sizeof(command))
    return True

class MacroApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Python Macro Editor Pro")
        self.geometry("860x810")  
        self.resizable(False, False)

        self.macro_actions = []  
        self.is_recording = False
        self.is_playing = False
        self.start_time = 0
        
        self.selected_record_hotkey = "HOME"
        self.selected_play_hotkey = "PAGE_UP"
        self.listening_for_new_hotkey = None 
        self.loop_mode = "One Time"

        self.currently_pressed_keys = set()
        self.mouse_listener = None
        self.keyboard_listener = None
        self.global_hotkey_listener = None

        self.ui_queue = queue.Queue()
        self.action_ui_buttons = []
        self.selected_action_index = None

        self.create_widgets()
        self.start_global_hotkey_listeners()
        self.check_ui_queue()

    def create_widgets(self):
        self.left_panel = ctk.CTkFrame(self, width=390)
        self.left_panel.pack(side="left", fill="y", padx=15, pady=15)
        self.left_panel.pack_propagate(False)

        self.title_label = ctk.CTkLabel(self.left_panel, text="Macro Controls", font=ctk.CTkFont(family="Arial", size=22, weight="bold"))
        self.title_label.pack(pady=10)

        self.config_frame = ctk.CTkFrame(self.left_panel)
        self.config_frame.pack(pady=5, fill="x", padx=15)

        self.rec_label = ctk.CTkLabel(self.config_frame, text="Record/Stop Hotkey:", font=ctk.CTkFont(size=12))
        self.rec_label.grid(row=0, column=0, padx=10, pady=8, sticky="w")
        
        self.rec_hk_btn = ctk.CTkButton(self.config_frame, text=self.selected_record_hotkey, width=120, fg_color="#333333", hover_color="#444444", command=lambda: self.start_listening_for_hotkey('record'))
        self.rec_hk_btn.grid(row=0, column=1, padx=10, pady=8, sticky="e")

        self.play_label = ctk.CTkLabel(self.config_frame, text="Play/Stop Hotkey:", font=ctk.CTkFont(size=12))
        self.play_label.grid(row=1, column=0, padx=10, pady=8, sticky="w")
        
        self.play_hk_btn = ctk.CTkButton(self.config_frame, text=self.selected_play_hotkey, width=120, fg_color="#333333", hover_color="#444444", command=lambda: self.start_listening_for_hotkey('play'))
        self.play_hk_btn.grid(row=1, column=1, padx=10, pady=8, sticky="e")

        self.loop_label = ctk.CTkLabel(self.config_frame, text="Playback Mode:", font=ctk.CTkFont(size=12, weight="bold"))
        self.loop_label.grid(row=2, column=0, padx=10, pady=6, sticky="w")

        self.loop_var = ctk.StringVar(value="One Time")
        
        self.radio_one_time = ctk.CTkRadioButton(self.config_frame, text="One Time", variable=self.loop_var, value="One Time", command=self.change_loop_mode, radiobutton_width=16, radiobutton_height=16)
        self.radio_one_time.grid(row=2, column=1, padx=10, pady=3, sticky="w")
        
        self.radio_loop = ctk.CTkRadioButton(self.config_frame, text="Infinite Loop", variable=self.loop_var, value="Loop", command=self.change_loop_mode, radiobutton_width=16, radiobutton_height=16)
        self.radio_loop.grid(row=3, column=1, padx=10, pady=3, sticky="w")
        
        self.radio_count = ctk.CTkRadioButton(self.config_frame, text="Loop Count", variable=self.loop_var, value="Count", command=self.change_loop_mode, radiobutton_width=16, radiobutton_height=16)
        self.radio_count.grid(row=4, column=1, padx=10, pady=3, sticky="w")

        self.count_input_frame = ctk.CTkFrame(self.config_frame, fg_color="transparent")
        self.count_label = ctk.CTkLabel(self.count_input_frame, text="Iterations:", font=ctk.CTkFont(size=11))
        self.count_label.pack(side="left", padx=5)
        self.count_entry = ctk.CTkEntry(self.count_input_frame, width=60, height=22)
        self.count_entry.insert(0, "5")
        self.count_entry.pack(side="left", padx=5)

        self.delay_input_frame = ctk.CTkFrame(self.config_frame, fg_color="transparent")
        self.delay_label = ctk.CTkLabel(self.delay_input_frame, text="Loop Interval (s):", font=ctk.CTkFont(size=11))
        self.delay_label.pack(side="left", padx=5)
        self.delay_entry = ctk.CTkEntry(self.delay_input_frame, width=60, height=22)
        self.delay_entry.insert(0, "0.5")  
        self.delay_entry.pack(side="left", padx=5)

        self.config_frame.columnconfigure(0, weight=1)
        self.config_frame.columnconfigure(1, weight=1)

        self.status_label = ctk.CTkLabel(self.left_panel, text="Status: Idle", font=ctk.CTkFont(family="Arial", size=14, slant="italic"), text_color="gray")
        self.status_label.pack(pady=10)

        self.record_btn = ctk.CTkButton(self.left_panel, text=f"🔴 Start Record ({self.selected_record_hotkey})", fg_color="#d32f2f", hover_color="#b71c1c", font=ctk.CTkFont(size=13, weight="bold"), command=self.toggle_recording)
        self.record_btn.pack(pady=5, fill="x", padx=20)

        self.play_btn = ctk.CTkButton(self.left_panel, text=f"▶️ Play Macro ({self.selected_play_hotkey})", fg_color="#388e3c", hover_color="#1b5e20", font=ctk.CTkFont(size=13, weight="bold"), command=self.toggle_playback)
        self.play_btn.pack(pady=5, fill="x", padx=20)

        self.clear_btn = ctk.CTkButton(self.left_panel, text="🗑️ Clear Macro Sequence", fg_color="#757575", hover_color="#616161", command=self.clear_macro)
        self.clear_btn.pack(pady=5, fill="x", padx=20)

        self.file_frame = ctk.CTkFrame(self.left_panel, fg_color="transparent")
        self.file_frame.pack(pady=10, fill="x", padx=20)

        self.export_btn = ctk.CTkButton(self.file_frame, text="💾 Export Macro", fg_color="#0288d1", hover_color="#01579b", command=self.export_macro, width=150)
        self.export_btn.pack(side="left", expand=True, padx=5)

        self.import_btn = ctk.CTkButton(self.file_frame, text="📂 Import Macro", fg_color="#f57c00", hover_color="#e65100", command=self.import_macro, width=150)
        self.import_btn.pack(side="right", expand=True, padx=5)

        # --- DYNAMIC OPEN WINDOWS DROP DOWN TARGET SECTION ---
        self.exe_lock_frame = ctk.CTkFrame(self.left_panel)
        self.exe_lock_frame.pack(fill="x", padx=20, pady=10)
        
        self.exe_section_title = ctk.CTkLabel(self.exe_lock_frame, text="EXE Window Lock Target", font=ctk.CTkFont(size=12, weight="bold"), text_color=("#1f538d", "#a9c6e2"))
        self.exe_section_title.pack(anchor="w", padx=15, pady=(8, 2))

        self.exe_switch_var = ctk.StringVar(value="off")
        self.exe_toggle = ctk.CTkSwitch(self.exe_lock_frame, text="Lock Playback to EXE", variable=self.exe_switch_var, onvalue="on", offvalue="off", command=self.toggle_exe_lock)
        self.exe_toggle.pack(anchor="w", padx=15, pady=5)
        
        self.exe_entry_frame = ctk.CTkFrame(self.exe_lock_frame, fg_color="transparent")
        self.exe_entry_frame.pack(fill="x", padx=15, pady=(5, 10))
        
        self.exe_label_text = ctk.CTkLabel(self.exe_entry_frame, text="Target:", font=ctk.CTkFont(size=11))
        self.exe_label_text.pack(side="left", padx=2)
        
        # CHANGED: Replaced entry box with a dynamic ComboBox dropdown
        initial_detected_list = get_all_visible_window_exes()
        self.exe_name_entry = ctk.CTkComboBox(self.exe_entry_frame, values=initial_detected_list, height=26)
        self.exe_name_entry.set(initial_detected_list[0] if initial_detected_list else "notepad.exe")
        self.exe_name_entry.pack(side="left", fill="x", expand=True, padx=5)
        
        # CHANGED: Capture now behaves as an instant list refresher!
        self.exe_detect_btn = ctk.CTkButton(self.exe_entry_frame, text="🔄 Refresh", width=65, height=26, fg_color="#2e7d32", hover_color="#1b5e20", command=self.refresh_running_exes_list)
        self.exe_detect_btn.pack(side="right", padx=2)

        # Theme Switcher
        self.theme_frame = ctk.CTkFrame(self.left_panel, fg_color="transparent")
        self.theme_frame.pack(side="bottom", fill="x", padx=20, pady=15)
        
        self.theme_label = ctk.CTkLabel(self.theme_frame, text="App Theme Mode:", font=ctk.CTkFont(size=12))
        self.theme_label.pack(side="left", padx=5)
        
        self.theme_menu = ctk.CTkOptionMenu(self.theme_frame, values=["Dark", "Light", "System"], command=self.change_theme_mode, width=120)
        self.theme_menu.set("Dark")
        self.theme_menu.pack(side="right", padx=5)

        # Right Panel Widgets (Action Logs)
        self.right_panel = ctk.CTkFrame(self)
        self.right_panel.pack(side="right", fill="both", expand=True, padx=15, pady=15)

        self.timeline_label = ctk.CTkLabel(self.right_panel, text="Action Timeline (Click to Edit)", font=ctk.CTkFont(family="Arial", size=16, weight="bold"))
        self.timeline_label.pack(pady=10)

        self.timeline_scroll = ctk.CTkScrollableFrame(self.right_panel, fg_color=("#e2e2e2", "#1d1e22"))
        self.timeline_scroll.pack(fill="both", expand=True, padx=10, pady=5)

        self.edit_tools_frame = ctk.CTkFrame(self.right_panel, fg_color="transparent")
        self.edit_tools_frame.pack(fill="x", pady=10, padx=10)

        self.move_up_btn = ctk.CTkButton(self.edit_tools_frame, text="▲ Move Up", width=90, command=lambda: self.move_action(-1))
        self.move_up_btn.pack(side="left", padx=5)

        self.move_down_btn = ctk.CTkButton(self.edit_tools_frame, text="▼ Move Down", width=90, command=lambda: self.move_action(1))
        self.move_down_btn.pack(side="left", padx=5)

        self.delete_btn = ctk.CTkButton(self.edit_tools_frame, text="❌ Delete", fg_color="#c62828", hover_color="#b71c1c", width=80, command=self.delete_action)
        self.delete_btn.pack(side="right", padx=5)

        self.info_label = ctk.CTkLabel(self.left_panel, text="Actions Logged: 0", font=ctk.CTkFont(size=12))
        self.info_label.pack(side="bottom", pady=5)

        # Initializing interface state logic
        self.exe_name_entry.configure(state="disabled")
        self.exe_detect_btn.configure(state="disabled")

    def toggle_exe_lock(self):
        if self.exe_switch_var.get() == "on":
            self.exe_name_entry.configure(state="readonly")
            self.exe_detect_btn.configure(state="normal")
            self.refresh_running_exes_list()
        else:
            self.exe_name_entry.configure(state="disabled")
            self.exe_detect_btn.configure(state="disabled")

    def refresh_running_exes_list(self):
        """Finds open window EXEs on screen and feeds them into the dropdown options dynamically."""
        updated_list = get_all_visible_window_exes()
        self.exe_name_entry.configure(values=updated_list)
        if updated_list:
            # Keep previous selection if it's still running, otherwise pick the first item
            current_val = self.exe_name_entry.get()
            if current_val in updated_list:
                self.exe_name_entry.set(current_val)
            else:
                self.exe_name_entry.set(updated_list[0])

    def change_theme_mode(self, choice):
        ctk.set_appearance_mode(choice)

    def check_ui_queue(self):
        try:
            while True:
                msg = self.ui_queue.get_nowait()
                if msg == "STOP_PLAYBACK":
                    self.stop_playback_ui_reset()
        except queue.Empty:
            pass
        self.after(100, self.check_ui_queue)

    def start_listening_for_hotkey(self, target):
        if self.is_recording or self.is_playing: return
        self.listening_for_new_hotkey = target
        if target == 'record':
            self.rec_hk_btn.configure(text="Press Any Key...", fg_color="#b71c1c")
        elif target == 'play':
            self.play_hk_btn.configure(text="Press Any Key...", fg_color="#1b5e20")

    def change_loop_mode(self):
        self.loop_mode = self.loop_var.get()
        self.count_input_frame.grid_forget()
        self.delay_input_frame.grid_forget()

        if self.loop_mode == "Count":
            self.count_input_frame.grid(row=5, column=1, padx=10, pady=4, sticky="w")
            self.delay_input_frame.grid(row=6, column=1, padx=10, pady=4, sticky="w")
        elif self.loop_mode == "Loop":
            self.delay_input_frame.grid(row=5, column=1, padx=10, pady=4, sticky="w")

    def refresh_timeline_ui(self):
        for btn in self.action_ui_buttons: btn.destroy()
        self.action_ui_buttons.clear()

        for idx, action in enumerate(self.macro_actions):
            delay_str = f"{action['delay']:.2f}s wait"
            if action['type'] == 'mouse':
                btn_name = str(action['details'][2]).split('.')[-1].upper()
                text_summary = f"[{idx+1}] 🖱️ MOUSE CLICK ({btn_name}) at X:{action['details'][0]}, Y:{action['details'][1]}  ⏱️ {delay_str}"
            else:
                key_name = action.get('name', 'UNKNOWN')
                state = "PRESS DOWN" if not action.get('is_release') else "RELEASE UP"
                text_summary = f"[{idx+1}] ⌨️ {state} [{key_name}]  ⏱️ {delay_str}"

            item_btn = ctk.CTkButton(self.timeline_scroll, text=text_summary, anchor="w", fg_color=("#cfcfcf", "#2b2b2b"), hover_color=("#bebebe", "#404040"), text_color=("black", "white"), command=lambda i=idx: self.select_timeline_item(i))
            item_btn.pack(fill="x", pady=2, padx=5)
            self.action_ui_buttons.append(item_btn)
        self.info_label.configure(text=f"Actions Logged: {len(self.macro_actions)}")

    def select_timeline_item(self, index):
        self.selected_action_index = index
        for idx, btn in enumerate(self.action_ui_buttons):
            btn.configure(fg_color="#1f538d" if idx == index else ("#cfcfcf", "#2b2b2b"), text_color="white" if idx == index else ("black", "white"))

    def move_action(self, direction):
        if self.selected_action_index is None: return
        old_idx = self.selected_action_index
        new_idx = old_idx + direction
        if 0 <= new_idx < len(self.macro_actions):
            self.macro_actions[old_idx], self.macro_actions[new_idx] = self.macro_actions[new_idx], self.macro_actions[old_idx]
            self.refresh_timeline_ui()
            self.select_timeline_item(new_idx)

    def delete_action(self):
        if self.selected_action_index is None: return
        self.macro_actions.pop(self.selected_action_index)
        self.selected_action_index = None
        self.refresh_timeline_ui()

    def export_macro(self):
        if not self.macro_actions: return
        file_path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON Macro Files", "*.json")])
        if file_path:
            serializable_list = []
            for act in self.macro_actions:
                if act['type'] == 'mouse':
                    serializable_list.append({'type': 'mouse', 'x': act['details'][0], 'y': act['details'][1], 'button': str(act['details'][2]).split('.')[-1], 'delay': act['delay']})
                elif act['type'] == 'keyboard':
                    serializable_list.append({'type': 'keyboard', 'vk': act.get('vk'), 'name': act.get('name', 'UNKNOWN'), 'is_release': act.get('is_release', False), 'delay': act['delay']})
            with open(file_path, 'w') as f: json.dump(serializable_list, f, indent=4)

    def import_macro(self):
        if self.is_playing or self.is_recording: return
        file_path = filedialog.askopenfilename(filetypes=[("JSON Macro Files", "*.json")])
        if file_path:
            try:
                with open(file_path, 'r') as f: loaded_data = json.load(f)
                self.macro_actions.clear()
                for item in loaded_data:
                    if item['type'] == 'mouse':
                        btn_attr = getattr(mouse.Button, item['button'].lower(), mouse.Button.left)
                        self.macro_actions.append({'type': 'mouse', 'details': (item['x'], item['y'], btn_attr), 'delay': item['delay']})
                    elif item['type'] == 'keyboard':
                        self.macro_actions.append({'type': 'keyboard', 'details': None, 'vk': item.get('vk'), 'name': item.get('name'), 'is_release': item.get('is_release', False), 'delay': item['delay']})
                self.refresh_timeline_ui()
            except Exception: pass

    def start_global_hotkey_listeners(self):
        def global_press(key):
            try:
                key_name = ""
                if hasattr(key, 'name'): key_name = key.name.upper()
                elif hasattr(key, 'char') and key.char: key_name = key.char.upper()
                if key == keyboard.Key.space: key_name = "SPACE"
                if key == keyboard.Key.scroll_lock: key_name = "SCROLL LOCK"
                if key == keyboard.Key.pause: key_name = "PAUSE"
                if key == keyboard.Key.num_lock: key_name = "NUM LOCK"
                if key == keyboard.Key.home: key_name = "HOME"
                if key == keyboard.Key.page_up: key_name = "PAGE_UP"
                if key == keyboard.Key.page_down: key_name = "PAGE_DOWN"

                if key == keyboard.Key.esc:
                    if self.is_playing:
                        self.is_playing = False
                        return

                if self.listening_for_new_hotkey is not None:
                    target = self.listening_for_new_hotkey
                    self.listening_for_new_hotkey = None
                    if target == 'record':
                        self.selected_record_hotkey = key_name
                        self.after(0, lambda: self.rec_hk_btn.configure(text=self.selected_record_hotkey, fg_color="#333333"))
                        self.after(0, lambda: self.record_btn.configure(text=f"🔴 Start Record ({self.selected_record_hotkey})"))
                    elif target == 'play':
                        self.selected_play_hotkey = key_name
                        self.after(0, lambda: self.play_hk_btn.configure(text=self.selected_play_hotkey, fg_color="#333333"))
                        self.after(0, lambda: self.play_btn.configure(text=f"▶️ Play Macro ({self.selected_play_hotkey})"))
                    return

                if key_name == self.selected_record_hotkey.upper(): self.after(0, self.toggle_recording)
                elif key_name == self.selected_play_hotkey.upper(): self.after(0, self.toggle_playback)
            except Exception: pass
        self.global_hotkey_listener = keyboard.Listener(on_press=global_press)
        self.global_hotkey_listener.start()

    def toggle_recording(self):
        if self.is_playing or self.listening_for_new_hotkey: return
        if not self.is_recording:
            self.is_recording = True
            self.macro_actions.clear()
            self.currently_pressed_keys.clear()
            self.start_time = time.time()
            self.record_btn.configure(text=f"⏹️ Stop Record ({self.selected_record_hotkey})")
            self.status_label.configure(text="Status: Recording...", text_color="#d32f2f")
            
            self.mouse_listener = mouse.Listener(on_click=self.on_click)
            self.keyboard_listener = keyboard.Listener(on_press=self.on_press, on_release=self.on_release)
            self.mouse_listener.start()
            self.keyboard_listener.start()
            self.refresh_timeline_ui()
        else:
            self.is_recording = False
            self.record_btn.configure(text=f"🔴 Start Record ({self.selected_record_hotkey})")
            self.status_label.configure(text="Status: Idle", text_color="gray")
            if self.mouse_listener: self.mouse_listener.stop()
            if self.keyboard_listener: self.keyboard_listener.stop()
            
            while self.macro_actions and self.macro_actions[-1].get('name') == self.selected_record_hotkey.upper():
                self.macro_actions.pop()
            self.refresh_timeline_ui()

    def on_click(self, x, y, button, pressed):
        if pressed and self.is_recording:
            delay = time.time() - self.start_time
            self.start_time = time.time()
            self.macro_actions.append({'type': 'mouse', 'details': (x, y, button), 'delay': delay})
            self.after(0, self.refresh_timeline_ui)

    def _extract_key_info(self, key):
        vk, name = None, "UNKNOWN"
        if hasattr(key, 'vk') and key.vk is not None: 
            vk = key.vk
        elif hasattr(key, 'char') and key.char: 
            vk = ord(key.char.upper())
        elif hasattr(key, 'value') and hasattr(key, 'name'):
            if hasattr(key, '_value_'): vk = key._value_.vk
            
        if key == keyboard.Key.space:
            vk = 0x20
            name = "SPACE"
        elif key == keyboard.Key.enter:
            vk = 0x0D
            name = "ENTER"
        elif key == keyboard.Key.shift or key == keyboard.Key.shift_l:
            vk = 0xA0
            name = "SHIFT"
        elif key == keyboard.Key.shift_r:
            vk = 0xA1
            name = "R_SHIFT"
        elif key == keyboard.Key.ctrl or key == keyboard.Key.ctrl_l:
            vk = 0xA2
            name = "CTRL"
        elif key == keyboard.Key.ctrl_r:
            vk = 0xA3
            name = "R_CTRL"
        elif key == keyboard.Key.alt or key == keyboard.Key.alt_l:
            vk = 0xA4
            name = "ALT"
        elif key == keyboard.Key.alt_r:
            vk = 0xA5
            name = "R_ALT"
        elif key == keyboard.Key.caps_lock:
            vk = 0x14
            name = "CAPS LOCK"
        elif key == keyboard.Key.tab:
            vk = 0x09
            name = "TAB"
        elif key == keyboard.Key.backspace:
            vk = 0x08
            name = "BACKSPACE"
        elif key == keyboard.Key.esc:
            vk = 0x1B
            name = "ESC"
        elif hasattr(key, 'name'): 
            name = key.name.upper()
            if name == "UP": vk = 0x26
            elif name == "DOWN": vk = 0x28
            elif name == "LEFT": vk = 0x25
            elif name == "RIGHT": vk = 0x27
            elif name == "HOME": vk = 0x24
            elif name == "PAGE_UP": vk = 0x21
            elif name == "PAGE_DOWN": vk = 0x22
            elif name == "END": vk = 0x23
            elif name == "INSERT": vk = 0x2D
            elif name == "DELETE": vk = 0x2E

        if vk and vk in VK_TO_SCAN and name == "UNKNOWN":
            name = SCAN_TO_NAME.get(VK_TO_SCAN[vk], str(key)).upper()
            
        return vk, name

    def on_press(self, key):
        if self.is_recording:
            vk, name = self._extract_key_info(key)
            if name in self.currently_pressed_keys: return
            self.currently_pressed_keys.add(name)
            delay = time.time() - self.start_time
            self.start_time = time.time()
            self.macro_actions.append({'type': 'keyboard', 'details': key, 'vk': vk, 'name': name, 'is_release': False, 'delay': delay})
            self.after(0, self.refresh_timeline_ui)

    def on_release(self, key):
        if self.is_recording:
            vk, name = self._extract_key_info(key)
            if name in self.currently_pressed_keys: self.currently_pressed_keys.remove(name)
            delay = time.time() - self.start_time
            self.start_time = time.time()
            self.macro_actions.append({'type': 'keyboard', 'details': key, 'vk': vk, 'name': name, 'is_release': True, 'delay': delay})
            self.after(0, self.refresh_timeline_ui)

    def clear_macro(self):
        if self.is_playing or self.is_recording: return
        self.macro_actions.clear()
        self.selected_action_index = None
        self.refresh_timeline_ui()

    def toggle_playback(self):
        if self.is_recording or self.listening_for_new_hotkey: return
        if not self.is_playing:
            if not self.macro_actions: return
            self.is_playing = True
            self.play_btn.configure(text=f"⏹️ Stop Play ({self.selected_play_hotkey})", fg_color="#1565c0", hover_color="#0d47a1")
            self.status_label.configure(text="Status: Playing...", text_color="#388e3c")
            threading.Thread(target=self.play_macro, daemon=True).start()
        else:
            self.is_playing = False

    def play_macro(self):
        mouse_controller = mouse.Controller()
        active_hardware_keys = set()
        
        cleaned_actions = list(self.macro_actions)
        while cleaned_actions and cleaned_actions[-1].get('type') == 'keyboard':
            last_key_name = cleaned_actions[-1].get('name', '').upper()
            if last_key_name in [self.selected_record_hotkey.upper(), self.selected_play_hotkey.upper()]:
                cleaned_actions.pop()
            else:
                break

        if not cleaned_actions:
            self.ui_queue.put("STOP_PLAYBACK")
            return

        max_loops = 1
        if self.loop_mode == "Loop": 
            max_loops = 99999999
        elif self.loop_mode == "Count":
            try:
                max_loops = int(self.count_entry.get())
                if max_loops <= 0: max_loops = 1
            except ValueError: 
                max_loops = 1

        custom_loop_delay = 0.05
        if self.loop_mode in ["Loop", "Count"]:
            try:
                custom_loop_delay = float(self.delay_entry.get())
                if custom_loop_delay < 0: custom_loop_delay = 0.0
            except ValueError:
                custom_loop_delay = 0.05

        loop_count = 0
        while self.is_playing and loop_count < max_loops:
            for action in cleaned_actions:
                if not self.is_playing: break
                
                if self.exe_switch_var.get() == "on":
                    target_exe_name = self.exe_name_entry.get().strip().lower()
                    if target_exe_name:
                        while self.is_playing and get_active_window_exe() != target_exe_name:
                            time.sleep(0.1)

                if not self.is_playing: break

                if action['delay'] > 0:
                    remaining_delay = action['delay']
                    while remaining_delay > 0 and self.is_playing:
                        if self.exe_switch_var.get() == "on" and target_exe_name and get_active_window_exe() != target_exe_name:
                            break
                        sleep_slice = min(0.02, remaining_delay)
                        time.sleep(sleep_slice)
                        remaining_delay -= sleep_slice
                
                if not self.is_playing: break

                if action['type'] == 'mouse':
                    x, y, button = action['details']
                    mouse_controller.position = (x, y)
                    mouse_controller.click(button)
                
                elif action['type'] == 'keyboard':
                    vk_code = action.get('vk')
                    is_release = action.get('is_release', False)
                    
                    if vk_code and vk_code in VK_TO_SCAN:
                        if not is_release:
                            active_hardware_keys.add(vk_code)
                            send_hardware_input(vk_code, is_release=False)
                        else:
                            if vk_code in active_hardware_keys: active_hardware_keys.remove(vk_code)
                            send_hardware_input(vk_code, is_release=True)
                            
            loop_count += 1
            if self.loop_mode == "One Time": break
            
            if self.is_playing and custom_loop_delay > 0:
                remaining_interval = custom_loop_delay
                while remaining_interval > 0 and self.is_playing:
                    if self.exe_switch_var.get() == "on" and target_exe_name and get_active_window_exe() != target_exe_name:
                        break
                    interval_slice = min(0.02, remaining_interval)
                    time.sleep(interval_slice)
                    remaining_interval -= interval_slice

        for vk in list(active_hardware_keys): send_hardware_input(vk, is_release=True)
        for action in cleaned_actions:
            if action['type'] == 'keyboard' and action.get('vk') in VK_TO_SCAN:
                send_hardware_input(action['vk'], is_release=True)

        self.ui_queue.put("STOP_PLAYBACK")

    def stop_playback_ui_reset(self):
        self.is_playing = False
        self.play_btn.configure(text=f"▶️ Play Macro ({self.selected_play_hotkey})", fg_color="#388e3c", hover_color="#1b5e20")
        self.status_label.configure(text="Status: Idle", text_color="gray")

if __name__ == "__main__":
    app = MacroApp()
    app.mainloop()