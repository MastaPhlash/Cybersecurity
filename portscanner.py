import socket
import tkinter as tk
from tkinter import scrolledtext
from ipaddress import ip_address
import threading
from tkinter import filedialog
from tkinter import ttk
import json
import os
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from tkinter import messagebox
from typing import Optional, List, Dict, Any
import configparser
import time
import logging

stop_event = threading.Event()

# Common port to service mapping
PORT_SERVICES: Dict[int, str] = {
    21: 'FTP',
    22: 'SSH',
    23: 'Telnet',
    25: 'SMTP',
    53: 'DNS',
    80: 'HTTP',
    110: 'POP3',
    143: 'IMAP',
    443: 'HTTPS',
    3306: 'MySQL',
    3389: 'RDP',
    5900: 'VNC',
    8080: 'HTTP-Alt',
    # Add more as needed
}

PROFILE_FILE: str = "scan_profiles.json"

CONFIG_FILE = 'portscanner.cfg'
config = configparser.ConfigParser()

scan_history: List[str] = []

logging.basicConfig(filename='portscanner.log', level=logging.INFO, format='%(asctime)s %(levelname)s: %(message)s')

# --- Input validation helpers ---
def validate_ip(ip_str: str) -> bool:
    try:
        ip_address(ip_str)
        return True
    except ValueError:
        return False

def validate_port(port_str: str) -> bool:
    try:
        port = int(port_str)
        return 1 <= port <= 65535
    except ValueError:
        return False

# --- Highlight invalid fields ---
def highlight_entry(entry: tk.Entry, valid: bool) -> None:
    if valid:
        entry.config(bg='white')
    else:
        entry.config(bg='#ffcccc')

# --- Progress estimation ---
def update_progress_label(scanned: int, total: int) -> None:
    percent = (scanned / total) * 100 if total else 0
    progress_var.set(f"Progress: {scanned}/{total} ({percent:.1f}%)")

def set_thread_count(count: int) -> None:
    thread_count.set(count)
    set_status(f"Thread count set to {count}")

def is_host_alive(ip: str) -> bool:
    try:
        # Use -c 1 for Linux, -n 1 for Windows
        param = '-c' if os.name != 'nt' else '-n'
        result = subprocess.run(['ping', param, '1', str(ip)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return result.returncode == 0
    except Exception:
        return False

def grab_banner(ip: str, port: int, timeout: float) -> Optional[str]:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((str(ip), port))
            try:
                banner = s.recv(1024)
                return banner.decode(errors='ignore').strip()
            except Exception:
                return None
    except Exception:
        return None

def resolve_hostname(ip: str) -> Optional[str]:
    try:
        # Only resolve if not already a hostname
        if not any(c.isalpha() for c in str(ip)):
            return socket.gethostbyaddr(str(ip))[0]
    except Exception:
        pass
    return None

def insert_and_scroll(widget: tk.Text, text: str) -> None:
    widget.insert(tk.END, text)
    widget.see(tk.END)

# --- Color coding for output box ---
def color_insert(widget: tk.Text, text: str, tag: Optional[str] = None) -> None:
    widget.insert(tk.END, text, tag)
    widget.see(tk.END)

# --- Tooltip helper ---
class ToolTip:
    def __init__(self, widget, text):
        self.widget = widget
        self.text = text
        self.tipwindow = None
        widget.bind("<Enter>", self.show_tip)
        widget.bind("<Leave>", self.hide_tip)
    def show_tip(self, event=None):
        if self.tipwindow or not self.text:
            return
        x, y, _, cy = self.widget.bbox("insert") if hasattr(self.widget, 'bbox') else (0,0,0,0)
        x = x + self.widget.winfo_rootx() + 25
        y = y + cy + self.widget.winfo_rooty() + 20
        self.tipwindow = tw = tk.Toplevel(self.widget)
        tw.wm_overrideredirect(True)
        tw.wm_geometry(f"+{x}+{y}")
        label = tk.Label(tw, text=self.text, justify=tk.LEFT, background="#ffffe0", relief=tk.SOLID, borderwidth=1, font=("tahoma", "8", "normal"))
        label.pack(ipadx=1)
    def hide_tip(self, event=None):
        tw = self.tipwindow
        self.tipwindow = None
        if tw:
            tw.destroy()

# Unified port scan worker
def port_scan_worker(ip: str, port: int, timeout: float, udp_scan: bool, output_widget: tk.Text, open_ports: List[str], show_closed: bool = False) -> None:
    if stop_event.is_set():
        return
    if udp_scan:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            try:
                s.sendto(b"", (str(ip), port))
                s.recvfrom(1024)
            except socket.timeout:
                root.after(0, color_insert, output_widget, f"UDP Port {port}: OPEN or FILTERED\n", 'filtered')
                open_ports.append(f"{port} (UDP)")
            except Exception:
                if show_closed:
                    root.after(0, color_insert, output_widget, f"UDP Port {port}: CLOSED\n", 'closed')
    else:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((str(ip), port))
            if result == 0:
                service = PORT_SERVICES.get(port, "Unknown")
                banner = grab_banner(ip, port, timeout)
                banner_str = f" | Banner: {banner}" if banner else ""
                root.after(0, color_insert, output_widget, f"Port {port}: OPEN ({service}){banner_str}\n", 'open')
                open_ports.append(f"{port} ({service}){banner_str}")
            elif show_closed:
                root.after(0, color_insert, output_widget, f"Port {port}: CLOSED\n", 'closed')

def scan_ip_range(start_ip: str, end_ip: str, start_port: int, end_port: int, output_widget: tk.Text, timeout: float) -> None:
    output_widget.delete(1.0, tk.END)
    scan_summary = f"Scan: {start_ip} - {end_ip}, Ports: {start_port}-{end_port}, Timeout: {timeout}s\n"
    scan_result = ""
    start_time = time.time()
    try:
        current_ip = ip_address(start_ip)
        last_ip = ip_address(end_ip)
    except ValueError:
        root.after(0, insert_and_scroll, output_widget, "Invalid IP address format.\n")
        set_status("Error: Invalid IP address format.")
        logging.error("Invalid IP address format: %s - %s", start_ip, end_ip)
        return
    total_ips = int(last_ip) - int(current_ip) + 1
    progress['maximum'] = total_ips
    scanned_ips = 0
    update_progress_label(scanned_ips, total_ips)
    udp_scan = udp_scan_var.get() if 'udp_scan_var' in globals() else False
    show_closed = show_closed_var.get()
    hosts_scanned = 0
    open_ports_count = 0
    while current_ip <= last_ip:
        if stop_event.is_set():
            root.after(0, insert_and_scroll, output_widget, "\nScan stopped by user.\n")
            progress['value'] = 0
            set_status("Scan stopped.")
            update_progress_label(0, total_ips)
            logging.info("Scan stopped by user.")
            return
        hostname = resolve_hostname(current_ip)
        if hostname:
            root.after(0, insert_and_scroll, output_widget, f"Resolved hostname for {current_ip}: {hostname}\n")
        if ping_before_scan.get():
            root.after(0, insert_and_scroll, output_widget, f"Pinging {current_ip}... ")
            if not is_host_alive(current_ip):
                root.after(0, insert_and_scroll, output_widget, "No response. Skipping.\n")
                scan_result += f"{current_ip}: No ping response. Skipped.\n"
                scanned_ips += 1
                progress['value'] = scanned_ips
                update_progress_label(scanned_ips, total_ips)
                output_widget.update_idletasks()
                progress.update_idletasks()
                current_ip += 1
                continue
            else:
                root.after(0, insert_and_scroll, output_widget, "Alive. Scanning...\n")
        root.after(0, insert_and_scroll, output_widget, f"\nScanning {current_ip} from port {start_port} to {end_port}...\n")
        scan_result += f"\nScanning {current_ip} from port {start_port} to {end_port}...\n"
        open_ports = []
        with ThreadPoolExecutor(max_workers=thread_count.get()) as executor:
            futures = [executor.submit(port_scan_worker, current_ip, port, timeout, udp_scan, output_widget, open_ports, show_closed)
                       for port in range(start_port, end_port + 1)]
            for _ in as_completed(futures):
                pass
        host_reachable = bool(open_ports)
        if not host_reachable:
            root.after(0, insert_and_scroll, output_widget, f"Host {current_ip} appears unreachable (no open ports in range).\n")
            scan_result += f"Host {current_ip} appears unreachable (no open ports in range).\n"
        else:
            root.after(0, insert_and_scroll, output_widget, f"Open ports for {current_ip}: {open_ports}\n")
            scan_result += f"Open ports for {current_ip}: {open_ports}\n"
            open_ports_count += len(open_ports)
        scanned_ips += 1
        hosts_scanned += 1
        progress['value'] = scanned_ips
        update_progress_label(scanned_ips, total_ips)
        output_widget.update_idletasks()
        progress.update_idletasks()
        current_ip += 1
    progress['value'] = 0
    update_progress_label(0, total_ips)
    duration = time.time() - start_time
    summary = f"\n--- Scan Summary ---\nHosts scanned: {hosts_scanned}\nTotal open ports: {open_ports_count}\nDuration: {duration:.2f} seconds\n"
    root.after(0, insert_and_scroll, output_widget, summary)
    scan_history.append(scan_summary + scan_result + summary)
    set_status("Scan complete.")
    logging.info("Scan complete: %s - %s, Ports: %d-%d, Open ports: %d, Duration: %.2fs", start_ip, end_ip, start_port, end_port, open_ports_count, duration)

def threaded_scan() -> None:
    start_ip = entry_start_ip.get()
    end_ip = entry_end_ip.get()
    valid_start_ip = validate_ip(start_ip)
    valid_end_ip = validate_ip(end_ip)
    valid_start_port = validate_port(entry_start.get())
    valid_end_port = validate_port(entry_end.get())
    highlight_entry(entry_start_ip, valid_start_ip)
    highlight_entry(entry_end_ip, valid_end_ip)
    highlight_entry(entry_start, valid_start_port)
    highlight_entry(entry_end, valid_end_port)
    if not (valid_start_ip and valid_end_ip):
        insert_and_scroll(output, "Please enter valid IP addresses.\n")
        set_status("Error: Invalid IP addresses.")
        return
    if not (valid_start_port and valid_end_port):
        insert_and_scroll(output, "Port numbers must be between 1 and 65535, and start <= end.\n")
        set_status("Error: Invalid port numbers.")
        return
    try:
        start_port = int(entry_start.get())
        end_port = int(entry_end.get())
        if not (start_port <= end_port):
            insert_and_scroll(output, "Port numbers must be between 1 and 65535, and start <= end.\n")
            set_status("Error: Invalid port numbers.")
            return
        timeout = float(entry_timeout.get()) if entry_timeout.get() else 0.2
        if timeout <= 0:
            insert_and_scroll(output, "Timeout must be a positive number.\n")
            set_status("Error: Invalid timeout.")
            return
        scan_ip_range(start_ip, end_ip, start_port, end_port, output, timeout)
    except ValueError:
        insert_and_scroll(output, "Please enter valid port numbers and timeout.\n")
        set_status("Error: Invalid port numbers or timeout.")

def start_scan() -> None:
    stop_event.clear()
    set_status("Scanning in progress...")
    t = threading.Thread(target=threaded_scan)
    t.daemon = True
    t.start()

def stop_scan() -> None:
    stop_event.set()
    set_status("Scan stopped.")

def export_results() -> None:
    file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
    if file_path:
        with open(file_path, 'w') as f:
            f.write(output.get(1.0, tk.END))
        set_status("Results exported.")

def export_results_csv() -> None:
    file_path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files", "*.csv"), ("All files", "*.*")])
    if file_path:
        with open(file_path, 'w') as f:
            f.write("IP,Port,Service,Banner\n")
            # Parse the output for CSV export
            lines = output.get(1.0, tk.END).splitlines()
            current_ip = None
            for line in lines:
                if line.startswith("Scanning "):
                    # Example: Scanning 192.168.1.1 from port 1 to 1023...
                    parts = line.split()
                    if len(parts) > 1:
                        current_ip = parts[1]
                elif line.startswith("Port ") and current_ip:
                    # Example: Port 22: OPEN (SSH) | Banner: ...
                    port_part = line.split(":")[0].replace("Port ", "").strip()
                    service = ""
                    banner = ""
                    if "OPEN (" in line:
                        service_start = line.find("(") + 1
                        service_end = line.find(")")
                        service = line[service_start:service_end]
                    if "| Banner: " in line:
                        banner = line.split("| Banner: ", 1)[1].strip()
                    f.write(f'{current_ip},{port_part},{service},"{banner}"\n')
        set_status("Results exported as CSV.")

def export_results_html() -> None:
    file_path = filedialog.asksaveasfilename(defaultextension=".html", filetypes=[("HTML files", "*.html"), ("All files", "*.*")])
    if file_path:
        html = ["<html><head><title>Port Scan Results</title></head><body>"]
        html.append(f"<h2>Port Scan Results</h2><pre>{output.get(1.0, tk.END)}</pre>")
        html.append("</body></html>")
        with open(file_path, 'w') as f:
            f.write('\n'.join(html))
        set_status("Results exported as HTML.")

def export_results_json() -> None:
    file_path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON files", "*.json"), ("All files", "*.*")])
    if file_path:
        # Parse the output for JSON export
        lines = output.get(1.0, tk.END).splitlines()
        results: List[Dict[str, Any]] = []
        current_ip = None
        for line in lines:
            if line.startswith("Scanning "):
                parts = line.split()
                if len(parts) > 1:
                    current_ip = parts[1]
            elif line.startswith("Port ") and current_ip:
                port_part = line.split(":")[0].replace("Port ", "").strip()
                service = ""
                banner = ""
                if "OPEN (" in line:
                    service_start = line.find("(") + 1
                    service_end = line.find(")")
                    service = line[service_start:service_end]
                if "| Banner: " in line:
                    banner = line.split("| Banner: ", 1)[1].strip()
                results.append({
                    "ip": current_ip,
                    "port": port_part,
                    "service": service,
                    "banner": banner
                })
        with open(file_path, 'w') as f:
            json.dump(results, f, indent=2)
        set_status("Results exported as JSON.")

def save_scan_results() -> None:
    file_path = filedialog.asksaveasfilename(defaultextension=".scan", filetypes=[("Scan files", "*.scan"), ("All files", "*.*")])
    if file_path:
        with open(file_path, 'w') as f:
            f.write(output.get(1.0, tk.END))
        set_status("Full scan results saved.")

def load_scan_results() -> None:
    file_path = filedialog.askopenfilename(defaultextension=".scan", filetypes=[("Scan files", "*.scan"), ("All files", "*.*")])
    if file_path:
        with open(file_path, 'r') as f:
            data = f.read()
        output.delete(1.0, tk.END)
        output.insert(tk.END, data)
        set_status("Scan results loaded.")

def show_history() -> None:
    if not scan_history:
        output.delete(1.0, tk.END)
        insert_and_scroll(output, "No scan history yet.\n")
        set_status("No scan history.")
        return
    output.delete(1.0, tk.END)
    for i, entry in enumerate(scan_history, 1):
        insert_and_scroll(output, f"--- Scan #{i} ---\n{entry}\n\n")
    set_status("History displayed.")

def save_profile() -> None:
    profile: Dict[str, str] = {
        "start_ip": entry_start_ip.get(),
        "end_ip": entry_end_ip.get(),
        "start_port": entry_start.get(),
        "end_port": entry_end.get(),
        "timeout": entry_timeout.get()
    }
    if os.path.exists(PROFILE_FILE):
        with open(PROFILE_FILE, 'r') as f:
            profiles = json.load(f)
    else:
        profiles = []
    profiles.append(profile)
    with open(PROFILE_FILE, 'w') as f:
        json.dump(profiles, f, indent=2)
    insert_and_scroll(output, "Profile saved.\n")
    set_status("Profile saved.")

def load_profile() -> None:
    if not os.path.exists(PROFILE_FILE):
        insert_and_scroll(output, "No profiles saved yet.\n")
        set_status("No profiles found.")
        return
    with open(PROFILE_FILE, 'r') as f:
        profiles = json.load(f)
    if not profiles:
        insert_and_scroll(output, "No profiles found.\n")
        set_status("No profiles found.")
        return
    # Load the last profile
    profile = profiles[-1]
    entry_start_ip.delete(0, tk.END)
    entry_start_ip.insert(0, profile["start_ip"])
    entry_end_ip.delete(0, tk.END)
    entry_end_ip.insert(0, profile["end_ip"])
    entry_start.delete(0, tk.END)
    entry_start.insert(0, profile["start_port"])
    entry_end.delete(0, tk.END)
    entry_end.insert(0, profile["end_port"])
    entry_timeout.delete(0, tk.END)
    entry_timeout.insert(0, profile["timeout"])
    insert_and_scroll(output, "Profile loaded.\n")
    set_status("Profile loaded.")

def load_theme():
    if os.path.exists(CONFIG_FILE):
        config.read(CONFIG_FILE)
        return config.get('theme', 'mode', fallback='light')
    return 'light'

def save_theme(mode: str):
    if not config.has_section('theme'):
        config.add_section('theme')
    config.set('theme', 'mode', mode)
    with open(CONFIG_FILE, 'w') as f:
        config.write(f)

def toggle_dark_mode() -> None:
    dark_bg = '#2e2e2e'
    dark_fg = '#ffffff'
    light_bg = '#f0f0f0'
    light_fg = '#000000'
    if root['bg'] == dark_bg:
        # Switch to light mode
        root.configure(bg=light_bg)
        for widget in root.winfo_children():
            if isinstance(widget, (tk.Label, tk.Entry, tk.Button, scrolledtext.ScrolledText)):
                widget.configure(bg=light_bg, fg=light_fg)
            if isinstance(widget, scrolledtext.ScrolledText):
                widget.configure(insertbackground=light_fg)
        set_status("Light mode activated.")
        save_theme('light')
    else:
        # Switch to dark mode
        root.configure(bg=dark_bg)
        for widget in root.winfo_children():
            if isinstance(widget, (tk.Label, tk.Entry, tk.Button, scrolledtext.ScrolledText)):
                widget.configure(bg=dark_bg, fg=dark_fg)
            if isinstance(widget, scrolledtext.ScrolledText):
                widget.configure(insertbackground=dark_fg)
        set_status("Dark mode activated.")
        save_theme('dark')

# Apply theme at startup
if load_theme() == 'dark':
    toggle_dark_mode()

def clear_output() -> None:
    output.delete(1.0, tk.END)
    set_status("Output cleared.")

def copy_output_to_clipboard() -> None:
    root.clipboard_clear()
    root.clipboard_append(output.get(1.0, tk.END))
    set_status("Output copied to clipboard.")

def set_preset_ports(preset: str) -> None:
    if preset == "Well-known":
        entry_start.delete(0, tk.END)
        entry_start.insert(0, "1")
        entry_end.delete(0, tk.END)
        entry_end.insert(0, "1023")
        set_status("Preset: Well-known ports (1-1023)")
    elif preset == "Common":
        entry_start.delete(0, tk.END)
        entry_start.insert(0, "1")
        entry_end.delete(0, tk.END)
        entry_end.insert(0, "49151")
        set_status("Preset: Common ports (1-49151)")
    elif preset == "All":
        entry_start.delete(0, tk.END)
        entry_start.insert(0, "1")
        entry_end.delete(0, tk.END)
        entry_end.insert(0, "65535")
        set_status("Preset: All ports (1-65535)")

# GUI setup
root = tk.Tk()
root.title("Python Port Scanner")

# Add a user warning about legal/ethical use
messagebox.showinfo(
    "Notice",
    "This tool is for authorized network scanning only. Scanning networks you do not own or have permission to scan may be illegal. Use responsibly."
)

thread_count = tk.IntVar(value=20)

tk.Label(root, text="Start IP:").grid(row=0, column=0, padx=5, pady=5, sticky="e")
entry_start_ip = tk.Entry(root, width=20)
entry_start_ip.grid(row=0, column=1, padx=5, pady=5, sticky='ew')

tk.Label(root, text="End IP:").grid(row=1, column=0, padx=5, pady=5, sticky="e")
entry_end_ip = tk.Entry(root, width=20)
entry_end_ip.grid(row=1, column=1, padx=5, pady=5, sticky='ew')

tk.Label(root, text="Start Port:").grid(row=2, column=0, padx=5, pady=5, sticky="e")
entry_start = tk.Entry(root, width=10)
entry_start.grid(row=2, column=1, padx=5, pady=5, sticky='ew')

tk.Label(root, text="End Port:").grid(row=3, column=0, padx=5, pady=5, sticky="e")
entry_end = tk.Entry(root, width=10)
entry_end.grid(row=3, column=1, padx=5, pady=5, sticky='ew')

tk.Label(root, text="Timeout (s):").grid(row=4, column=0, padx=5, pady=5, sticky="e")
entry_timeout = tk.Entry(root, width=10)
entry_timeout.insert(0, "0.2")
entry_timeout.grid(row=4, column=1, padx=5, pady=5, sticky='ew')

ping_before_scan = tk.BooleanVar(value=False)
ping_checkbox = tk.Checkbutton(root, text="Ping hosts before scanning", variable=ping_before_scan)
ping_checkbox.grid(row=5, column=2, columnspan=2, padx=5, pady=5, sticky="w")

udp_scan_var = tk.BooleanVar(value=False)
udp_checkbox = tk.Checkbutton(root, text="UDP Scan (experimental)", variable=udp_scan_var)
udp_checkbox.grid(row=6, column=2, columnspan=2, padx=5, pady=5, sticky="w")

show_closed_var = tk.BooleanVar(value=False)
show_closed_checkbox = tk.Checkbutton(root, text="Show Closed Ports", variable=show_closed_var)
show_closed_checkbox.grid(row=7, column=2, columnspan=2, padx=5, pady=5, sticky="w")
ToolTip(show_closed_checkbox, "Display closed ports in the output (may be verbose).")

scan_button = tk.Button(root, text="Scan", command=start_scan)
scan_button.grid(row=8, column=0, pady=10)
scan_button.config(underline=0)

stop_button = tk.Button(root, text="Stop", command=stop_scan)
stop_button.grid(row=8, column=1, pady=10)
stop_button.config(underline=0)

output = scrolledtext.ScrolledText(root, width=50, height=15)
output.grid(row=9, column=0, columnspan=7, padx=5, pady=5, sticky="nsew")

# Setup tags for color coding
output.tag_configure('open', foreground='green')
output.tag_configure('filtered', foreground='orange')
output.tag_configure('closed', foreground='red')
output.tag_configure('info', foreground='blue')

# --- Search/filter box above output ---
search_var = tk.StringVar()
def filter_output(*args):
    search = search_var.get().lower()
    output.delete(1.0, tk.END)
    lines = output._all_lines if hasattr(output, '_all_lines') else output.get(1.0, tk.END).splitlines()
    filtered = [line for line in lines if search in line.lower()]
    for line in filtered:
        output.insert(tk.END, line + '\n')
search_entry = tk.Entry(root, textvariable=search_var, width=30)
search_entry.grid(row=8, column=2, columnspan=3, padx=5, pady=5, sticky="ew")
ToolTip(search_entry, "Filter output by IP, port, or service name.")
search_var.trace_add('write', filter_output)
# Patch output widget to keep all lines
old_insert = output.insert
def patched_insert(*args, **kwargs):
    if not hasattr(output, '_all_lines'):
        output._all_lines = []
    if len(args) > 1:
        lines = args[1].splitlines()
        output._all_lines.extend(lines)
    return old_insert(*args, **kwargs)
output.insert = patched_insert

progress = ttk.Progressbar(root, orient="horizontal", length=300, mode="determinate")
progress.grid(row=10, column=0, columnspan=7, padx=5, pady=5, sticky="ew")

progress_var = tk.StringVar()
progress_var.set("")
progress_label = tk.Label(root, textvariable=progress_var, bd=1, relief=tk.SUNKEN, anchor="e")
progress_label.grid(row=11, column=6, sticky="ew")

status_var = tk.StringVar()
status_var.set("Ready.")
status_bar = tk.Label(root, textvariable=status_var, bd=1, relief=tk.SUNKEN, anchor="w")
status_bar.grid(row=11, column=0, columnspan=6, sticky="ew")

def set_status(msg: str) -> None:
    status_var.set(msg)
    status_bar.update_idletasks()

# Add tooltips to input fields and buttons
ToolTip(entry_start_ip, "Enter the starting IP address for the scan range.")
ToolTip(entry_end_ip, "Enter the ending IP address for the scan range.")
ToolTip(entry_start, "Enter the starting port number.")
ToolTip(entry_end, "Enter the ending port number.")
ToolTip(entry_timeout, "Set the timeout (in seconds) for each port scan.")
ToolTip(ping_checkbox, "Ping hosts before scanning to skip unreachable hosts.")
ToolTip(udp_checkbox, "Enable UDP port scanning (experimental).")
ToolTip(show_closed_checkbox, "Display closed ports in the output (may be verbose).")
ToolTip(scan_button, "Start the port scan.")
ToolTip(stop_button, "Stop the current scan.")
ToolTip(output, "Scan results and progress will be displayed here.")

# Add a menu bar with a Tools dropdown
menubar = tk.Menu(root)
tools_menu = tk.Menu(menubar, tearoff=0)
tools_menu.add_command(label="Export Results", command=export_results)
tools_menu.add_command(label="Export as CSV", command=export_results_csv)
tools_menu.add_command(label="Export as HTML", command=export_results_html)
tools_menu.add_command(label="Export as JSON", command=export_results_json)
tools_menu.add_command(label="Save Full Scan Results", command=save_scan_results)
tools_menu.add_command(label="Load Full Scan Results", command=load_scan_results)
tools_menu.add_separator()
tools_menu.add_command(label="Save Scan Results", command=save_scan_results)
tools_menu.add_command(label="Load Scan Results", command=load_scan_results)
tools_menu.add_command(label="Show History", command=show_history)
tools_menu.add_command(label="Clear Output", command=clear_output)
tools_menu.add_command(label="Copy Output to Clipboard", command=copy_output_to_clipboard)
tools_menu.add_separator()
tools_menu.add_command(label="Save Profile", command=save_profile)
tools_menu.add_command(label="Load Profile", command=load_profile)
tools_menu.add_separator()
tools_menu.add_command(label="Toggle Dark Mode", command=toggle_dark_mode)
menubar.add_cascade(label="Tools", menu=tools_menu)

# Add a Presets menu to the menubar
presets_menu = tk.Menu(menubar, tearoff=0)
presets_menu.add_command(label="Well-known ports (1-1023)", command=lambda: set_preset_ports("Well-known"))
presets_menu.add_command(label="Common ports (1-49151)", command=lambda: set_preset_ports("Common"))
presets_menu.add_command(label="All ports (1-65535)", command=lambda: set_preset_ports("All"))
menubar.add_cascade(label="Presets", menu=presets_menu)

# Add a Threads menu to the menubar
threads_menu = tk.Menu(menubar, tearoff=0)
for count in [5, 10, 20, 50, 100]:
    threads_menu.add_radiobutton(label=f"{count} Threads", variable=thread_count, value=count, command=lambda c=count: set_thread_count(c))
menubar.add_cascade(label="Threads", menu=threads_menu)

root.config(menu=menubar)

# --- Keyboard shortcuts ---
root.bind('<Control-s>', lambda e: start_scan())
root.bind('<Control-S>', lambda e: start_scan())
root.bind('<Control-e>', lambda e: export_results())
root.bind('<Control-E>', lambda e: export_results())
root.bind('<Control-q>', lambda e: stop_scan())
root.bind('<Control-Q>', lambda e: stop_scan())

# Make the output box and input fields expand responsively
for i in range(12):
    root.grid_rowconfigure(i, weight=1 if i in [9,10,11] else 0)
for i in range(7):
    root.grid_columnconfigure(i, weight=1)

root.mainloop()