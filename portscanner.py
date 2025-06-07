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
from concurrent.futures import ThreadPoolExecutor

stop_event = threading.Event()

# Common port to service mapping
PORT_SERVICES = {
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

PROFILE_FILE = "scan_profiles.json"

scan_history = []

def set_thread_count(count):
    thread_count.set(count)
    set_status(f"Thread count set to {count}")

def is_host_alive(ip):
    try:
        # Use -c 1 for Linux, -n 1 for Windows
        param = '-c' if os.name != 'nt' else '-n'
        result = subprocess.run(['ping', param, '1', str(ip)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return result.returncode == 0
    except Exception:
        return False

def grab_banner(ip, port, timeout):
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

def resolve_hostname(ip):
    try:
        # Only resolve if not already a hostname
        if not any(c.isalpha() for c in str(ip)):
            return socket.gethostbyaddr(str(ip))[0]
    except Exception:
        pass
    return None

def insert_and_scroll(widget, text):
    widget.insert(tk.END, text)
    widget.see(tk.END)

# Unified port scan worker
def port_scan_worker(ip, port, timeout, udp_scan, output_widget, open_ports):
    if stop_event.is_set():
        return
    if udp_scan:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            try:
                s.sendto(b"", (str(ip), port))
                s.recvfrom(1024)
            except socket.timeout:
                insert_and_scroll(output_widget, f"UDP Port {port}: OPEN or FILTERED\n")
                open_ports.append(f"{port} (UDP)")
            except Exception:
                pass
    else:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((str(ip), port))
            if result == 0:
                service = PORT_SERVICES.get(port, "Unknown")
                banner = grab_banner(ip, port, timeout)
                banner_str = f" | Banner: {banner}" if banner else ""
                insert_and_scroll(output_widget, f"Port {port}: OPEN ({service}){banner_str}\n")
                open_ports.append(f"{port} ({service}){banner_str}")

def scan_ip_range(start_ip, end_ip, start_port, end_port, output_widget, timeout):
    output_widget.delete(1.0, tk.END)
    scan_summary = f"Scan: {start_ip} - {end_ip}, Ports: {start_port}-{end_port}, Timeout: {timeout}s\n"
    scan_result = ""
    try:
        current_ip = ip_address(start_ip)
        last_ip = ip_address(end_ip)
    except ValueError:
        insert_and_scroll(output_widget, "Invalid IP address format.\n")
        set_status("Error: Invalid IP address format.")
        return
    total_ips = int(last_ip) - int(current_ip) + 1
    progress['maximum'] = total_ips
    scanned_ips = 0
    udp_scan = udp_scan_var.get() if 'udp_scan_var' in globals() else False
    while current_ip <= last_ip:
        if stop_event.is_set():
            insert_and_scroll(output_widget, "\nScan stopped by user.\n")
            progress['value'] = 0
            set_status("Scan stopped.")
            return
        hostname = resolve_hostname(current_ip)
        if hostname:
            insert_and_scroll(output_widget, f"Resolved hostname for {current_ip}: {hostname}\n")
        if ping_before_scan.get():
            insert_and_scroll(output_widget, f"Pinging {current_ip}... ")
            if not is_host_alive(current_ip):
                insert_and_scroll(output_widget, "No response. Skipping.\n")
                scan_result += f"{current_ip}: No ping response. Skipped.\n"
                scanned_ips += 1
                progress['value'] = scanned_ips
                output_widget.update_idletasks()
                progress.update_idletasks()
                current_ip += 1
                continue
            else:
                insert_and_scroll(output_widget, "Alive. Scanning...\n")
        insert_and_scroll(output_widget, f"\nScanning {current_ip} from port {start_port} to {end_port}...\n")
        scan_result += f"\nScanning {current_ip} from port {start_port} to {end_port}...\n"
        open_ports = []
        with ThreadPoolExecutor(max_workers=thread_count.get()) as executor:
            futures = [executor.submit(port_scan_worker, current_ip, port, timeout, udp_scan, output_widget, open_ports)
                       for port in range(start_port, end_port + 1)]
            for f in futures:
                f.result()
        host_reachable = bool(open_ports)
        if not host_reachable:
            insert_and_scroll(output_widget, f"Host {current_ip} appears unreachable (no open ports in range).\n")
            scan_result += f"Host {current_ip} appears unreachable (no open ports in range).\n"
        else:
            insert_and_scroll(output_widget, f"Open ports for {current_ip}: {open_ports}\n")
            scan_result += f"Open ports for {current_ip}: {open_ports}\n"
        scanned_ips += 1
        progress['value'] = scanned_ips
        output_widget.update_idletasks()
        progress.update_idletasks()
        current_ip += 1
    progress['value'] = 0
    scan_history.append(scan_summary + scan_result)
    set_status("Scan complete.")

def threaded_scan():
    start_ip = entry_start_ip.get()
    end_ip = entry_end_ip.get()
    try:
        # Validate IP addresses
        ip_address(start_ip)
        ip_address(end_ip)
    except ValueError:
        insert_and_scroll(output, "Please enter valid IP addresses.\n")
        set_status("Error: Invalid IP addresses.")
        return
    try:
        start_port = int(entry_start.get())
        end_port = int(entry_end.get())
        if not (0 < start_port <= 65535 and 0 < end_port <= 65535 and start_port <= end_port):
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

def start_scan():
    stop_event.clear()
    set_status("Scanning in progress...")
    t = threading.Thread(target=threaded_scan)
    t.daemon = True
    t.start()

def stop_scan():
    stop_event.set()
    set_status("Scan stopped.")

def export_results():
    file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
    if file_path:
        with open(file_path, 'w') as f:
            f.write(output.get(1.0, tk.END))
        set_status("Results exported.")

def export_results_csv():
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

def show_history():
    if not scan_history:
        output.delete(1.0, tk.END)
        insert_and_scroll(output, "No scan history yet.\n")
        set_status("No scan history.")
        return
    output.delete(1.0, tk.END)
    for i, entry in enumerate(scan_history, 1):
        insert_and_scroll(output, f"--- Scan #{i} ---\n{entry}\n\n")
    set_status("History displayed.")

def save_profile():
    profile = {
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

def load_profile():
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

def toggle_dark_mode():
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
    else:
        # Switch to dark mode
        root.configure(bg=dark_bg)
        for widget in root.winfo_children():
            if isinstance(widget, (tk.Label, tk.Entry, tk.Button, scrolledtext.ScrolledText)):
                widget.configure(bg=dark_bg, fg=dark_fg)
            if isinstance(widget, scrolledtext.ScrolledText):
                widget.configure(insertbackground=dark_fg)
        set_status("Dark mode activated.")

def clear_output():
    output.delete(1.0, tk.END)
    set_status("Output cleared.")

def copy_output_to_clipboard():
    root.clipboard_clear()
    root.clipboard_append(output.get(1.0, tk.END))
    set_status("Output copied to clipboard.")

def set_preset_ports(preset):
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

thread_count = tk.IntVar(value=20)

tk.Label(root, text="Start IP:").grid(row=0, column=0, padx=5, pady=5, sticky="e")
entry_start_ip = tk.Entry(root, width=20)
entry_start_ip.grid(row=0, column=1, padx=5, pady=5)

tk.Label(root, text="End IP:").grid(row=1, column=0, padx=5, pady=5, sticky="e")
entry_end_ip = tk.Entry(root, width=20)
entry_end_ip.grid(row=1, column=1, padx=5, pady=5)

tk.Label(root, text="Start Port:").grid(row=2, column=0, padx=5, pady=5, sticky="e")
entry_start = tk.Entry(root, width=10)
entry_start.grid(row=2, column=1, padx=5, pady=5, sticky="w")

tk.Label(root, text="End Port:").grid(row=3, column=0, padx=5, pady=5, sticky="e")
entry_end = tk.Entry(root, width=10)
entry_end.grid(row=3, column=1, padx=5, pady=5, sticky="w")

tk.Label(root, text="Timeout (s):").grid(row=4, column=0, padx=5, pady=5, sticky="e")
entry_timeout = tk.Entry(root, width=10)
entry_timeout.insert(0, "0.2")
entry_timeout.grid(row=4, column=1, padx=5, pady=5, sticky="w")

ping_before_scan = tk.BooleanVar(value=False)
ping_checkbox = tk.Checkbutton(root, text="Ping hosts before scanning", variable=ping_before_scan)
ping_checkbox.grid(row=4, column=2, columnspan=2, padx=5, pady=5, sticky="w")

udp_scan_var = tk.BooleanVar(value=False)
udp_checkbox = tk.Checkbutton(root, text="UDP Scan (experimental)", variable=udp_scan_var)
udp_checkbox.grid(row=5, column=2, columnspan=2, padx=5, pady=5, sticky="w")

scan_button = tk.Button(root, text="Scan", command=start_scan)
scan_button.grid(row=6, column=0, pady=10)

stop_button = tk.Button(root, text="Stop", command=stop_scan)
stop_button.grid(row=6, column=1, pady=10)

output = scrolledtext.ScrolledText(root, width=50, height=15)
output.grid(row=7, column=0, columnspan=7, padx=5, pady=5, sticky="nsew")

progress = ttk.Progressbar(root, orient="horizontal", length=300, mode="determinate")
progress.grid(row=8, column=0, columnspan=7, padx=5, pady=5, sticky="ew")

status_var = tk.StringVar()
status_var.set("Ready.")
status_bar = tk.Label(root, textvariable=status_var, bd=1, relief=tk.SUNKEN, anchor="w")
status_bar.grid(row=9, column=0, columnspan=7, sticky="ew")

def set_status(msg):
    status_var.set(msg)
    status_bar.update_idletasks()

# Add a menu bar with a Tools dropdown
menubar = tk.Menu(root)
tools_menu = tk.Menu(menubar, tearoff=0)
tools_menu.add_command(label="Export Results", command=export_results)
tools_menu.add_command(label="Export as CSV", command=export_results_csv)
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

# Make the output box expand with the window
root.grid_rowconfigure(7, weight=1)
root.grid_rowconfigure(8, weight=1)
root.grid_rowconfigure(9, weight=1)
root.grid_columnconfigure(0, weight=1)
root.grid_columnconfigure(1, weight=1)
root.grid_columnconfigure(2, weight=1)
root.grid_columnconfigure(3, weight=1)
root.grid_columnconfigure(4, weight=1)
root.grid_columnconfigure(5, weight=1)
root.grid_columnconfigure(6, weight=1)

root.mainloop()