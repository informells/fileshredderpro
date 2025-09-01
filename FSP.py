import os
import sys
import threading
import hashlib
import json
import time
from datetime import datetime
from pathlib import Path
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
from tkinter import BooleanVar, StringVar, DoubleVar, IntVar
import shutil
import secrets
import platform
import getpass

# ------------------------------
# Configuration & Constants
# ------------------------------

APP_NAME = "File Shredder Pro X"
VERSION = "2.0"
LOG_DIR = "logs"
REPORTS_DIR = "reports"
TEMP_DIR = "temp"
SHRED_LOG = os.path.join(LOG_DIR, f"shred_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")

os.makedirs(LOG_DIR, exist_ok=True)
os.makedirs(REPORTS_DIR, exist_ok=True)
os.makedirs(TEMP_DIR, exist_ok=True)

# Shredding methods with detailed descriptions
SHRED_METHODS = {
    "Quick Erase": {
        "passes": 1,
        "pattern": [b"\x00"],
        "description": "Single pass with zeros - Fast but less secure",
        "security": "Low",
        "time_estimate": "Seconds"
    },
    "DoD 5220.22-M": {
        "passes": 3,
        "pattern": [b"\x00", b"\xFF", None],
        "description": "US DoD standard - Zero, One, Random",
        "security": "High",
        "time_estimate": "Minutes"
    },
    "Gutmann Method": {
        "passes": 35,
        "pattern": [
            b"\x55", b"\xAA", b"\x92\x49\x24", b"\x49\x24\x92",
            b"\x24\x92\x49", b"\x00", b"\x11", b"\x22", b"\x33",
            b"\x44", b"\x55", b"\x66", b"\x77", b"\x88", b"\x99",
            b"\xAA", b"\xBB", b"\xCC", b"\xDD", b"\xEE", b"\xFF",
            None, None, None, None, None, None, None, None,
            None, None, None, None, None, None
        ],
        "description": "Maximum security - 35-pass pattern sequence",
        "security": "Maximum",
        "time_estimate": "Hours"
    },
    "British HMG IS5": {
        "passes": 3,
        "pattern": [b"\x00", b"\xFF", None],
        "description": "UK government standard - Zero, One, Random",
        "security": "High",
        "time_estimate": "Minutes"
    },
    "Russian GOST P50739-95": {
        "passes": 2,
        "pattern": [b"\x00", None],
        "description": "Russian standard - Zero, Random",
        "security": "Medium",
        "time_estimate": "Minutes"
    },
    "Custom Pattern": {
        "passes": 5,
        "pattern": [b"\x00", b"\xFF", b"\x55", b"\xAA", None],
        "description": "User-defined 5-pass pattern",
        "security": "High",
        "time_estimate": "Minutes"
    }
}

# System information
SYSTEM_INFO = {
    "os": platform.system(),
    "release": platform.release(),
    "machine": platform.machine(),
    "processor": platform.processor(),
    "user": getpass.getuser(),
    "python_version": platform.python_version()
}

# ------------------------------
# Secure File Shredding Engine
# ------------------------------

class FileShredderX:
    def __init__(self, log_callback, progress_callback, status_callback):
        self.log = log_callback
        self.update_progress = progress_callback
        self.update_status = status_callback
        self.cancelled = False
        self.shred_log = []
        self.total_operations = 0
        self.completed_operations = 0

    def cancel(self):
        self.cancelled = True

    def generate_pattern(self, pattern_type, size):
        """Generate byte pattern for overwriting"""
        if pattern_type is None:  # Random data
            return secrets.token_bytes(size)
        elif isinstance(pattern_type, bytes):
            # Repeat pattern to fill size
            return (pattern_type * ((size // len(pattern_type)) + 1))[:size]
        else:
            return b"\x00" * size  # Default to zeros

    def calculate_file_hash(self, filepath):
        """Calculate SHA-256 hash of file before shredding"""
        hash_sha256 = hashlib.sha256()
        try:
            with open(filepath, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_sha256.update(chunk)
            return hash_sha256.hexdigest()
        except Exception as e:
            self.log(f"[HASH ERROR] {e}")
            return "N/A"

    def shred_file(self, filepath, method_name, verify=True):
        """Securely delete a single file"""
        try:
            filepath = Path(filepath)
            if not filepath.exists():
                self.log(f"[ERROR] File not found: {filepath.name}")
                return False

            method = SHRED_METHODS[method_name]
            file_size = filepath.stat().st_size
            passes = method["passes"]
            patterns = method["pattern"]
            
            # Calculate initial hash
            initial_hash = self.calculate_file_hash(filepath)
            
            self.update_status(f"Shredding: {filepath.name}")
            self.log(f"[START] Shredding {filepath.name} ({file_size} bytes) with {method_name} ({passes} passes)")

            # Open file for writing
            with open(filepath, "r+b") as f:
                for i, pattern_type in enumerate(patterns, 1):
                    if self.cancelled:
                        self.log("[CANCELLED] Shredding operation cancelled")
                        return False

                    # Generate pattern
                    pattern = self.generate_pattern(pattern_type, file_size)
                    
                    # Write pattern
                    f.seek(0)
                    f.write(pattern)
                    f.flush()
                    os.fsync(f.fileno())  # Force write to disk
                    
                    # Update progress
                    progress = (i / passes) * 100
                    self.update_progress(progress)
                    
                    self.log(f"  Pass {i}/{passes} completed")

            # Verification step
            if verify:
                self.update_status(f"Verifying: {filepath.name}")
                with open(filepath, "rb") as f:
                    data = f.read()
                    # Check if all bytes are the last pattern (or zeros if last was random)
                    expected = self.generate_pattern(patterns[-1], file_size)
                    if data != expected:
                        self.log(f"[VERIFY FAIL] Verification failed for {filepath.name}")
                        return False
                self.log(f"[VERIFY OK] File verified successfully")

            # Rename file multiple times to hide name
            parent = filepath.parent
            name = filepath.name
            temp_names = []
            for i in range(10):
                temp_name = secrets.token_hex(8) + Path(name).suffix
                temp_path = parent / temp_name
                temp_names.append(temp_name)
                try:
                    filepath.rename(temp_path)
                    filepath = temp_path
                except Exception as e:
                    self.log(f"[RENAME ERROR] {e}")
                    break

            # Delete file
            filepath.unlink()
            self.log(f"[SUCCESS] File securely deleted: {name}")
            
            # Log to shred log
            self.shred_log.append({
                "timestamp": datetime.now().isoformat(),
                "filename": name,
                "method": method_name,
                "size": file_size,
                "initial_hash": initial_hash,
                "temp_names": temp_names,
                "status": "success"
            })
            
            return True

        except Exception as e:
            self.log(f"[ERROR] Failed to shred {filepath.name}: {str(e)}")
            self.shred_log.append({
                "timestamp": datetime.now().isoformat(),
                "filename": filepath.name,
                "method": method_name,
                "size": filepath.stat().st_size if filepath.exists() else 0,
                "initial_hash": "N/A",
                "status": "failed",
                "error": str(e)
            })
            return False

    def shred_folder(self, folderpath, method_name, recursive=True, verify=True):
        """Securely delete all files in a folder"""
        try:
            folderpath = Path(folderpath)
            if not folderpath.exists() or not folderpath.is_dir():
                self.log(f"[ERROR] Folder not found: {folderpath}")
                return False

            self.update_status(f"Scanning folder: {folderpath.name}")
            files_to_shred = []
            
            if recursive:
                for root, dirs, files in os.walk(folderpath):
                    for file in files:
                        files_to_shred.append(Path(root) / file)
            else:
                for item in folderpath.iterdir():
                    if item.is_file():
                        files_to_shred.append(item)

            total_files = len(files_to_shred)
            self.log(f"[INFO] Found {total_files} files to shred")

            for i, filepath in enumerate(files_to_shred, 1):
                if self.cancelled:
                    self.log("[CANCELLED] Shredding operation cancelled")
                    return False

                success = self.shred_file(filepath, method_name, verify)
                self.completed_operations += 1
                progress = (self.completed_operations / self.total_operations) * 100
                self.update_progress(progress)
                self.update_status(f"Shredded {i}/{total_files} files")

            # Try to remove empty directory
            try:
                folderpath.rmdir()
                self.log(f"[SUCCESS] Folder removed: {folderpath.name}")
            except Exception as e:
                self.log(f"[INFO] Could not remove folder (may not be empty): {e}")

            return True

        except Exception as e:
            self.log(f"[ERROR] Failed to process folder {folderpath}: {str(e)}")
            return False

    def save_log(self):
        """Save shredding log to JSON file"""
        try:
            # Add system info to log
            log_data = {
                "session_info": {
                    "app_name": APP_NAME,
                    "version": VERSION,
                    "timestamp": datetime.now().isoformat(),
                    "system": SYSTEM_INFO
                },
                "operations": self.shred_log
            }
            
            with open(SHRED_LOG, 'w') as f:
                json.dump(log_data, f, indent=2)
            self.log(f"[LOG] Shred log saved to: {SHRED_LOG}")
        except Exception as e:
            self.log(f"[ERROR] Failed to save log: {e}")

# ------------------------------
# GUI Application
# ------------------------------

class FileShredderProX:
    def __init__(self, root):
        self.root = root
        self.root.title(f"{APP_NAME} v{VERSION}")
        self.root.geometry("1100x800")
        self.root.minsize(900, 700)
        self.root.configure(bg="#0F0F0F")

        self.shredder = None
        self.file_list = []
        self.folder_list = []
        self.schedule_job = None

        self.setup_styles()
        self.create_widgets()
        self.update_counts()
        self.update_system_info()

    def setup_styles(self):
        style = ttk.Style()
        style.theme_use('clam')

        # Custom dark theme colors
        self.colors = {
            "bg_dark": "#0F0F0F",
            "bg_medium": "#1A1A1A",
            "bg_light": "#2D2D2D",
            "fg_text": "#E0E0E0",
            "fg_highlight": "#4FC3F7",
            "accent": "#00BFA5",
            "warning": "#FFB74D",
            "error": "#F44336",
            "success": "#4CAF50"
        }

        # Configure widget styles
        style.configure("TFrame", background=self.colors["bg_dark"])
        style.configure("TLabelframe", background=self.colors["bg_dark"], relief="flat")
        style.configure("TLabelframe.Label", background=self.colors["bg_dark"], foreground=self.colors["fg_text"], font=("Segoe UI", 10, "bold"))
        style.configure("TLabel", background=self.colors["bg_dark"], foreground=self.colors["fg_text"], font=("Segoe UI", 10))
        style.configure("Header.TLabel", font=("Segoe UI", 18, "bold"), foreground=self.colors["accent"])
        style.configure("Subheader.TLabel", font=("Segoe UI", 10), foreground=self.colors["fg_text"])
        style.configure("TButton", font=("Segoe UI", 9), padding=6, background=self.colors["bg_light"], foreground=self.colors["fg_text"])
        style.map("TButton", background=[("active", "#3A3A3A")])
        style.configure("Accent.TButton", font=("Segoe UI", 9, "bold"), padding=6, background=self.colors["accent"], foreground="black")
        style.map("Accent.TButton", background=[("active", "#009688")])
        style.configure("Danger.TButton", font=("Segoe UI", 9, "bold"), padding=6, background=self.colors["error"], foreground="white")
        style.map("Danger.TButton", background=[("active", "#D32F2F")])
        style.configure("TCheckbutton", background=self.colors["bg_dark"], foreground=self.colors["fg_text"], font=("Segoe UI", 9))
        style.configure("TRadiobutton", background=self.colors["bg_dark"], foreground=self.colors["fg_text"], font=("Segoe UI", 9))
        style.configure("TCombobox", fieldbackground=self.colors["bg_light"], background=self.colors["bg_light"], foreground=self.colors["fg_text"])
        style.configure("TProgressbar", thickness=15, background=self.colors["accent"], troughcolor=self.colors["bg_light"])
        style.configure("Custom.TEntry", fieldbackground=self.colors["bg_light"], foreground=self.colors["fg_text"], insertbackground=self.colors["fg_text"])

    def create_widgets(self):
        # === Header ===
        header_frame = tk.Frame(self.root, bg=self.colors["bg_dark"], padx=20, pady=15)
        header_frame.pack(fill='x')

        title_frame = tk.Frame(header_frame, bg=self.colors["bg_dark"])
        title_frame.pack(fill='x')

        title_label = ttk.Label(title_frame, text=f"🔒 {APP_NAME}", style="Header.TLabel")
        title_label.pack(side='left')

        version_label = ttk.Label(title_frame, text=f"v{VERSION}", style="Subheader.TLabel")
        version_label.pack(side='right')

        subtitle_label = ttk.Label(header_frame, text="Enterprise-Grade Secure File Deletion", style="Subheader.TLabel")
        subtitle_label.pack(pady=(5, 0))

        # === Main Content Frame ===
        main_frame = tk.Frame(self.root, bg=self.colors["bg_dark"])
        main_frame.pack(fill='both', expand=True, padx=20, pady=10)

        # Left panel - File/Folder selection
        left_frame = tk.Frame(main_frame, bg=self.colors["bg_dark"])
        left_frame.pack(side='left', fill='both', expand=True, padx=(0, 10))

        # File selection
        file_frame = ttk.LabelFrame(left_frame, text="Files to Shred", padding=10)
        file_frame.pack(fill='both', expand=True, pady=(0, 10))

        file_btn_frame = tk.Frame(file_frame, bg=self.colors["bg_medium"])
        file_btn_frame.pack(fill='x', pady=(0, 10))

        ttk.Button(file_btn_frame, text="📁 Add Files", command=self.browse_files).pack(side='left', padx=5)
        ttk.Button(file_btn_frame, text="🗑️ Remove", command=self.remove_files).pack(side='left', padx=5)
        ttk.Button(file_btn_frame, text="🧹 Clear All", command=self.clear_files).pack(side='left', padx=5)

        self.file_listbox = tk.Listbox(file_frame, bg=self.colors["bg_light"], fg=self.colors["fg_text"], 
                                       font=("Consolas", 9), selectbackground="#007ACC", selectforeground="white", 
                                       highlightthickness=0, bd=0, height=8)
        self.file_listbox.pack(fill='both', expand=True)

        file_scroll = ttk.Scrollbar(file_frame, orient='vertical', command=self.file_listbox.yview)
        file_scroll.pack(side='right', fill='y')
        self.file_listbox.config(yscrollcommand=file_scroll.set)

        # Folder selection
        folder_frame = ttk.LabelFrame(left_frame, text="Folders to Shred", padding=10)
        folder_frame.pack(fill='both', expand=True)

        folder_btn_frame = tk.Frame(folder_frame, bg=self.colors["bg_medium"])
        folder_btn_frame.pack(fill='x', pady=(0, 10))

        ttk.Button(folder_btn_frame, text="📁 Add Folder", command=self.browse_folder).pack(side='left', padx=5)
        ttk.Button(folder_btn_frame, text="🗑️ Remove", command=self.remove_folders).pack(side='left', padx=5)
        ttk.Button(folder_btn_frame, text="🧹 Clear All", command=self.clear_folders).pack(side='left', padx=5)

        self.folder_listbox = tk.Listbox(folder_frame, bg=self.colors["bg_light"], fg=self.colors["fg_text"], 
                                         font=("Consolas", 9), selectbackground="#007ACC", selectforeground="white", 
                                         highlightthickness=0, bd=0, height=8)
        self.folder_listbox.pack(fill='both', expand=True)

        folder_scroll = ttk.Scrollbar(folder_frame, orient='vertical', command=self.folder_listbox.yview)
        folder_scroll.pack(side='right', fill='y')
        self.folder_listbox.config(yscrollcommand=folder_scroll.set)

        # Right panel - Settings and info
        right_frame = tk.Frame(main_frame, bg=self.colors["bg_dark"], width=300)
        right_frame.pack(side='right', fill='y')
        right_frame.pack_propagate(False)

        # Method selection
        method_frame = ttk.LabelFrame(right_frame, text="Shredding Method", padding=10)
        method_frame.pack(fill='x', pady=(0, 10))

        self.method_var = StringVar(value="DoD 5220.22-M")
        method_combo = ttk.Combobox(method_frame, textvariable=self.method_var, 
                                    values=list(SHRED_METHODS.keys()), state="readonly", width=25)
        method_combo.pack(pady=5)
        method_combo.bind("<<ComboboxSelected>>", self.on_method_change)

        # Method details
        self.method_details = tk.Text(method_frame, bg=self.colors["bg_light"], fg=self.colors["fg_text"], 
                                      font=("Segoe UI", 9), height=6, wrap='word', bd=0, padx=10, pady=10)
        self.method_details.pack(fill='x', pady=(10, 0))
        self.method_details.config(state='disabled')
        self.update_method_details()

        # Options
        options_frame = ttk.LabelFrame(right_frame, text="Options", padding=10)
        options_frame.pack(fill='x', pady=(0, 10))

        self.var_recursive = BooleanVar(value=True)
        self.var_verify = BooleanVar(value=True)
        self.var_schedule = BooleanVar(value=False)
        
        ttk.Checkbutton(options_frame, text="🔁 Recursive Folder Shred", variable=self.var_recursive).pack(anchor='w', pady=2)
        ttk.Checkbutton(options_frame, text="✅ Verify After Shred", variable=self.var_verify).pack(anchor='w', pady=2)
        ttk.Checkbutton(options_frame, text="⏰ Schedule Shredding", variable=self.var_schedule, command=self.toggle_schedule).pack(anchor='w', pady=2)

        # Schedule frame (hidden by default)
        self.schedule_frame = ttk.Frame(options_frame)
        self.schedule_frame.pack(fill='x', pady=(10, 0))
        self.schedule_frame.pack_forget()

        ttk.Label(self.schedule_frame, text="Delay (minutes):").pack(anchor='w')
        self.schedule_delay = IntVar(value=5)
        delay_spin = ttk.Spinbox(self.schedule_frame, from_=1, to=1440, textvariable=self.schedule_delay, width=10)
        delay_spin.pack(anchor='w', pady=5)

        # System info
        sysinfo_frame = ttk.LabelFrame(right_frame, text="System Information", padding=10)
        sysinfo_frame.pack(fill='x', pady=(0, 10))

        self.sysinfo_text = tk.Text(sysinfo_frame, bg=self.colors["bg_light"], fg=self.colors["fg_text"], 
                                    font=("Consolas", 8), height=6, wrap='word', bd=0)
        self.sysinfo_text.pack(fill='x')
        self.sysinfo_text.config(state='disabled')

        # Counts
        counts_frame = tk.Frame(right_frame, bg=self.colors["bg_dark"])
        counts_frame.pack(fill='x', pady=(0, 10))

        self.counts_var = StringVar(value="Files: 0 | Folders: 0")
        self.counts_label = ttk.Label(counts_frame, textvariable=self.counts_var, font=("Segoe UI", 10, "bold"))
        self.counts_label.pack()

        # === Progress Section ===
        progress_frame = tk.Frame(self.root, bg=self.colors["bg_dark"], padx=20, pady=10)
        progress_frame.pack(fill='x')

        progress_label = ttk.Label(progress_frame, text="Progress:", font=("Segoe UI", 10, "bold"))
        progress_label.pack(anchor='w')

        self.progress_var = DoubleVar()
        self.progress_bar = ttk.Progressbar(progress_frame, variable=self.progress_var, maximum=100, style="TProgressbar")
        self.progress_bar.pack(fill='x', pady=(5, 0))

        progress_bottom_frame = tk.Frame(progress_frame, bg=self.colors["bg_dark"])
        progress_bottom_frame.pack(fill='x', pady=(5, 0))

        self.progress_label = ttk.Label(progress_bottom_frame, text="0%", width=6)
        self.progress_label.pack(side='right')

        self.status_var = StringVar(value="Ready. Add files or folders to shred.")
        self.status_label = ttk.Label(progress_bottom_frame, textvariable=self.status_var, font=("Segoe UI", 9))
        self.status_label.pack(side='left')

        # === Controls ===
        ctrl_frame = tk.Frame(self.root, bg=self.colors["bg_dark"], padx=20, pady=10)
        ctrl_frame.pack(fill='x')

        self.start_btn = ttk.Button(ctrl_frame, text="🔥 START SHREDDING", command=self.start_shredding, style="Accent.TButton")
        self.start_btn.pack(side='left', padx=5)

        self.cancel_btn = ttk.Button(ctrl_frame, text="⏹️ CANCEL", command=self.cancel_shredding, state='disabled', style="Danger.TButton")
        self.cancel_btn.pack(side='left', padx=5)

        ttk.Button(ctrl_frame, text="📤 Export Log", command=self.export_log).pack(side='right', padx=5)
        ttk.Button(ctrl_frame, text="📋 Save Report", command=self.save_report).pack(side='right', padx=5)

        # === Log Section ===
        log_frame = tk.Frame(self.root, bg=self.colors["bg_dark"], padx=20, pady=10)
        log_frame.pack(fill='both', expand=True)

        log_label = ttk.Label(log_frame, text="Activity Log", font=("Segoe UI", 10, "bold"))
        log_label.pack(anchor='w')

        self.log_text = scrolledtext.ScrolledText(log_frame, wrap='word', bg=self.colors["bg_light"], fg=self.colors["fg_text"], 
                                                  font=("Consolas", 9), height=10)
        self.log_text.pack(fill='both', expand=True, pady=(5, 0))

        # Status bar
        self.status_bar_var = StringVar(value=f"{APP_NAME} v{VERSION} | Ready")
        self.status_bar = ttk.Label(self.root, textvariable=self.status_bar_var, relief='sunken', anchor='w', 
                                    font=("Consolas", 8), background=self.colors["bg_medium"], foreground=self.colors["fg_text"])
        self.status_bar.pack(side='bottom', fill='x', padx=20, pady=5)

        self.log("✅ File Shredder Pro X initialized. Add files or folders to begin.")

    def update_system_info(self):
        """Update system information display"""
        info_text = f"OS: {SYSTEM_INFO['os']} {SYSTEM_INFO['release']}\n"
        info_text += f"Machine: {SYSTEM_INFO['machine']}\n"
        info_text += f"User: {SYSTEM_INFO['user']}\n"
        info_text += f"Python: {SYSTEM_INFO['python_version']}\n"
        info_text += f"CPU: {SYSTEM_INFO['processor'][:30]}..." if len(SYSTEM_INFO['processor']) > 30 else f"CPU: {SYSTEM_INFO['processor']}"
        
        self.sysinfo_text.config(state='normal')
        self.sysinfo_text.delete(1.0, tk.END)
        self.sysinfo_text.insert(tk.END, info_text)
        self.sysinfo_text.config(state='disabled')

    def on_method_change(self, event=None):
        """Update method details when selection changes"""
        self.update_method_details()

    def update_method_details(self):
        """Update the method details text area"""
        method = self.method_var.get()
        if method in SHRED_METHODS:
            details = SHRED_METHODS[method]
            info = f"Description: {details['description']}\n"
            info += f"Security Level: {details['security']}\n"
            info += f"Passes: {details['passes']}\n"
            info += f"Time Estimate: {details['time_estimate']}"
            
            self.method_details.config(state='normal')
            self.method_details.delete(1.0, tk.END)
            self.method_details.insert(tk.END, info)
            self.method_details.config(state='disabled')

    def toggle_schedule(self):
        """Toggle schedule options visibility"""
        if self.var_schedule.get():
            self.schedule_frame.pack(fill='x', pady=(10, 0))
        else:
            self.schedule_frame.pack_forget()

    def browse_files(self):
        files = filedialog.askopenfilenames(title="Select files to shred")
        if files:
            for file in files:
                if file not in self.file_list:
                    self.file_list.append(file)
            self.update_file_listbox()
            self.update_counts()

    def browse_folder(self):
        folder = filedialog.askdirectory(title="Select folder to shred")
        if folder:
            if folder not in self.folder_list:
                self.folder_list.append(folder)
            self.update_folder_listbox()
            self.update_counts()

    def remove_files(self):
        selected = self.file_listbox.curselection()
        if not selected:
            messagebox.showinfo("Info", "Please select files to remove.")
            return
        
        # Remove in reverse order to maintain indices
        for i in reversed(selected):
            del self.file_list[i]
        
        self.update_file_listbox()
        self.update_counts()

    def remove_folders(self):
        selected = self.folder_listbox.curselection()
        if not selected:
            messagebox.showinfo("Info", "Please select folders to remove.")
            return
        
        # Remove in reverse order to maintain indices
        for i in reversed(selected):
            del self.folder_list[i]
        
        self.update_folder_listbox()
        self.update_counts()

    def clear_files(self):
        self.file_list.clear()
        self.update_file_listbox()
        self.update_counts()

    def clear_folders(self):
        self.folder_list.clear()
        self.update_folder_listbox()
        self.update_counts()

    def update_file_listbox(self):
        self.file_listbox.delete(0, tk.END)
        for f in self.file_list:
            self.file_listbox.insert(tk.END, f"  {Path(f).name}")

    def update_folder_listbox(self):
        self.folder_listbox.delete(0, tk.END)
        for f in self.folder_list:
            self.folder_listbox.insert(tk.END, f"  {Path(f).name}/")

    def update_counts(self):
        self.counts_var.set(f"Files: {len(self.file_list)} | Folders: {len(self.folder_list)}")

    def log(self, msg):
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log_text.insert(tk.END, f"[{timestamp}] {msg}\n")
        self.log_text.see(tk.END)
        self.log_text.update_idletasks()

    def update_progress(self, value):
        self.progress_var.set(value)
        self.progress_label.config(text=f"{value:.1f}%")
        self.root.update_idletasks()

    def update_status(self, msg):
        self.status_var.set(msg)
        self.status_bar_var.set(f"{APP_NAME} v{VERSION} | {msg}")
        self.root.update_idletasks()

    def start_shredding(self):
        if not self.file_list and not self.folder_list:
            messagebox.showwarning("No Items", "Please add files or folders to shred.")
            return

        method = self.method_var.get()
        if method not in SHRED_METHODS:
            messagebox.showerror("Error", "Invalid shredding method selected.")
            return

        # If scheduling is enabled
        if self.var_schedule.get():
            delay = self.schedule_delay.get()
            self.schedule_job = self.root.after(delay * 60 * 1000, self._execute_shredding)
            self.update_status(f"Scheduled to start in {delay} minutes...")
            self.start_btn.config(state='disabled', text="⏰ SCHEDULED")
            self.log(f"[SCHEDULE] Shredding scheduled to start in {delay} minutes")
            return

        # Confirm action
        count = len(self.file_list) + len(self.folder_list)
        method_info = SHRED_METHODS[method]
        confirm = messagebox.askyesno(
            "Confirm Shredding",
            f"Permanently delete {count} items using {method}?\n\n"
            f"Security Level: {method_info['security']}\n"
            f"Passes: {method_info['passes']}\n"
            f"Time Estimate: {method_info['time_estimate']}\n\n"
            "This action cannot be undone!",
            icon='warning'
        )
        if not confirm:
            return

        self._execute_shredding()

    def _execute_shredding(self):
        # Disable buttons during operation
        self.start_btn.config(state='disabled')
        self.cancel_btn.config(state='normal')
        
        # Calculate total operations
        total_files = len(self.file_list)
        total_folders = len(self.folder_list)
        self.shredder = FileShredderX(
            log_callback=self.log,
            progress_callback=self.update_progress,
            status_callback=self.update_status
        )
        self.shredder.total_operations = total_files + (total_folders if self.var_recursive.get() else 0)
        
        # Start shredding in background thread
        thread = threading.Thread(
            target=self._shred_worker,
            args=(self.method_var.get(), self.var_recursive.get(), self.var_verify.get()),
            daemon=True
        )
        thread.start()

    def _shred_worker(self, method, recursive, verify):
        try:
            # Process files
            for filepath in self.file_list:
                if self.shredder.cancelled:
                    break
                self.shredder.shred_file(filepath, method, verify)
                self.shredder.completed_operations += 1
                progress = (self.shredder.completed_operations / self.shredder.total_operations) * 100
                self.update_progress(progress)
            
            # Process folders
            for folderpath in self.folder_list:
                if self.shredder.cancelled:
                    break
                self.shredder.shred_folder(folderpath, method, recursive, verify)
            
            # Save log
            self.shredder.save_log()
            
            # Final status
            if not self.shredder.cancelled:
                self.log("[COMPLETE] Shredding operation finished!")
                self.update_status("Shredding completed successfully.")
                messagebox.showinfo("Complete", "File shredding completed successfully!")
            else:
                self.update_status("Shredding cancelled by user.")
                
        except Exception as e:
            self.log(f"[ERROR] Unexpected error: {e}")
        finally:
            # Re-enable buttons
            self.start_btn.config(state='normal', text="🔥 START SHREDDING")
            self.cancel_btn.config(state='disabled')
            self.update_progress(0)
            self.schedule_job = None

    def cancel_shredding(self):
        if self.schedule_job:
            self.root.after_cancel(self.schedule_job)
            self.schedule_job = None
            self.start_btn.config(state='normal', text="🔥 START SHREDDING")
            self.update_status("Scheduled shredding cancelled.")
            self.log("[CANCEL] Scheduled shredding cancelled by user.")
        elif self.shredder:
            self.shredder.cancel()
            self.log("[CANCEL] User requested cancellation...")

    def export_log(self):
        content = self.log_text.get(1.0, tk.END)
        if not content.strip():
            messagebox.showinfo("Empty", "Log is empty.")
            return
            
        file_path = filedialog.asksaveasfilename(
            defaultextension=".log",
            filetypes=[("Log Files", "*.log"), ("Text Files", "*.txt"), ("All Files", "*.*")],
            title="Export Log File"
        )
        if file_path:
            try:
                with open(file_path, 'w') as f:
                    f.write(content)
                messagebox.showinfo("Saved", f"Log exported to:\n{file_path}")
            except Exception as e:
                messagebox.showerror("Error", f"Could not save file:\n{e}")

    def save_report(self):
        if not self.shredder or not self.shredder.shred_log:
            messagebox.showinfo("No Data", "No shredding operations to report.")
            return
            
        file_path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON Files", "*.json"), ("All Files", "*.*")],
            title="Save Shredding Report"
        )
        if file_path:
            try:
                # Add system info to report
                report_data = {
                    "session_info": {
                        "app_name": APP_NAME,
                        "version": VERSION,
                        "timestamp": datetime.now().isoformat(),
                        "system": SYSTEM_INFO
                    },
                    "operations": self.shredder.shred_log
                }
                
                with open(file_path, 'w') as f:
                    json.dump(report_data, f, indent=2)
                messagebox.showinfo("Saved", f"Report saved to:\n{file_path}")
            except Exception as e:
                messagebox.showerror("Error", f"Could not save report:\n{e}")

# ------------------------------
# Run Application
# ------------------------------

if __name__ == "__main__":
    # For Windows DPI awareness
    try:
        from ctypes import windll
        windll.shcore.SetProcessDpiAwareness(1)
    except:
        pass

    root = tk.Tk()
    app = FileShredderProX(root)
    root.mainloop()