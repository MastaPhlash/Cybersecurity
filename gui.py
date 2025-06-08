"""
gui.py
Tkinter GUI and event wiring for the Python Port Scanner.
"""
import tkinter as tk
import threading
from tkinter import scrolledtext, filedialog, ttk, messagebox
from typing import List, Dict, Any, Optional
import json
import os
import time
from utils import ToolTip, load_theme, save_theme, show_info_dialog
from scanner import validate_ip, validate_port, is_host_alive, grab_banner, resolve_hostname, parse_ports

# --- Global variables and state ---
stop_event = threading.Event()
scan_history: List[str] = []
PROFILE_FILE: str = "scan_profiles.json"
CONFIG_FILE = 'portscanner.cfg'
PORT_SERVICES: Dict[int, str] = {
    21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS', 80: 'HTTP',
    110: 'POP3', 143: 'IMAP', 443: 'HTTPS', 3306: 'MySQL', 3389: 'RDP',
    5900: 'VNC', 8080: 'HTTP-Alt',
}

# --- GUI setup and event logic ---
def run_gui():
    global stop_event, scan_history
    root = tk.Tk()
    root.title("Python Port Scanner")
    root.geometry("370x480")  # Set a narrower window size

    messagebox.showinfo(
        "Notice",
        "This tool is for authorized network scanning only. Scanning networks you do not own or have permission to scan may be illegal. Use responsibly."
    )

    def show_about():
        show_info_dialog(
            "About Python Port Scanner",
            "Python Port Scanner\n\nA graphical port scanner for cybersecurity professionals and enthusiasts.\n\nFeatures:\n- Scan IP/port ranges or custom lists\n- Banner grabbing\n- Export results\n- Dark/light mode\n- Nmap integration (if installed)\n\nAuthor: Phlash\nLicense: MIT\n\nFor help, see the README or visit the project repository."
        )

    thread_count = tk.IntVar(value=20)

    # --- Option variables (for Options menu) ---
    ping_before_scan = tk.BooleanVar(value=False)
    udp_scan_var = tk.BooleanVar(value=False)
    show_closed_var = tk.BooleanVar(value=False)
    reverse_dns_var = tk.BooleanVar(value=False)
    banner_grab_var = tk.BooleanVar(value=True)
    randomize_ports_var = tk.BooleanVar(value=False)
    retry_on_fail_var = tk.BooleanVar(value=False)
    verbose_var = tk.BooleanVar(value=False)
    export_on_complete_var = tk.BooleanVar(value=False)
    sound_notify_var = tk.BooleanVar(value=False)

    # --- Main input fields ---
    tk.Label(root, text="Target(s):").grid(row=0, column=0, padx=5, pady=5, sticky="e")
    entry_targets = tk.Entry(root, width=14)
    entry_targets.grid(row=0, column=1, padx=5, pady=5, sticky='ew', columnspan=1)
    ToolTip(entry_targets, "Enter a single IP, a range (e.g. 192.168.1.1-192.168.1.10), or a comma-separated list of IPs.")

    tk.Label(root, text="Ports:").grid(row=1, column=0, padx=5, pady=5, sticky="e")
    entry_ports = tk.Entry(root, width=8)
    entry_ports.grid(row=1, column=1, padx=5, pady=5, sticky='ew')
    ToolTip(entry_ports, "Enter ports as a comma-separated list and/or ranges.")

    tk.Label(root, text="Timeout (s):").grid(row=2, column=0, padx=5, pady=5, sticky="e")
    entry_timeout = tk.Entry(root, width=4)
    entry_timeout.insert(0, "0.2")
    entry_timeout.grid(row=2, column=1, padx=5, pady=5, sticky='ew')
    ToolTip(entry_timeout, "Set the timeout (in seconds) for each port scan.")

    thread_count = tk.IntVar(value=20)
    tk.Label(root, text="Threads:").grid(row=3, column=0, padx=5, pady=5, sticky="e")
    thread_spin = tk.Spinbox(root, from_=1, to=100, textvariable=thread_count, width=2)
    thread_spin.grid(row=3, column=1, padx=5, pady=5, sticky='w')
    ToolTip(thread_spin, "Number of threads for parallel scanning.")

    # --- Output area ---
    output = scrolledtext.ScrolledText(root, width=26, height=13)
    output.grid(row=7, column=0, columnspan=3, padx=10, pady=10, sticky="nsew")
    ToolTip(output, "Scan results and progress will be displayed here.")

    # --- Color-coded output and scan summary ---
    output.tag_configure('open', foreground='green')
    output.tag_configure('filtered', foreground='orange')
    output.tag_configure('closed', foreground='red')
    output.tag_configure('info', foreground='blue')

    def color_insert(widget, text, tag=None):
        widget.insert(tk.END, text, tag)
        widget.see(tk.END)

    def scan_summary(hosts_scanned, open_ports_count, duration):
        return f"\n--- Scan Summary ---\nHosts scanned: {hosts_scanned}\nTotal open ports: {open_ports_count}\nDuration: {duration:.2f} seconds\n"

    # --- Progress bar ---
    progress = ttk.Progressbar(root, orient="horizontal", length=180, mode="determinate")
    progress.grid(row=8, column=0, columnspan=3, padx=5, pady=5, sticky="ew")

    # --- Search/filter box ---
    search_var = tk.StringVar()
    def filter_output(*args):
        search = search_var.get().lower()
        output.delete(1.0, tk.END)
        lines = getattr(output, '_all_lines', output.get(1.0, tk.END).splitlines())
        filtered = [line for line in lines if search in line.lower()]
        for line in filtered:
            output.insert(tk.END, line + '\n')
    search_entry = tk.Entry(root, textvariable=search_var, width=18)
    search_entry.grid(row=9, column=0, columnspan=2, padx=5, pady=5, sticky="ew")
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

    # --- Status bar (two lines) ---
    status_var = tk.StringVar()
    status_var.set("Ready.")
    status_bar = tk.Label(root, textvariable=status_var, bd=1, relief=tk.SUNKEN, anchor="w", justify="left")
    status_bar.grid(row=10, column=0, columnspan=3, sticky="ew")
    def set_status_line(ip_port: str = "", percent: float = None, elapsed: float = None, est_left: float = None):
        line1 = ip_port
        if percent is not None:
            line1 += f"   {percent:.1f}%"
        line2 = ""
        if elapsed is not None:
            line2 += f"Elapsed: {elapsed:.1f}s"
        if est_left is not None:
            if line2:
                line2 += "   "
            line2 += f"Est. left: {max(0, est_left):.1f}s"
        status_var.set(f"{line1}\n{line2}" if line2 else line1)
        status_bar.update_idletasks()

    # --- Export menu options ---
    def export_results():
        file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if file_path:
            with open(file_path, 'w') as f:
                f.write(output.get(1.0, tk.END))
            set_status_line("Results exported.")

    def export_results_csv():
        file_path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files", "*.csv"), ("All files", "*.*")])
        if file_path:
            with open(file_path, 'w') as f:
                f.write("IP,Port\n")
                lines = output.get(1.0, tk.END).splitlines()
                current_ip = None
                for line in lines:
                    if line.startswith("Scanning "):
                        parts = line.split()
                        if len(parts) > 1:
                            current_ip = parts[1]
                    elif line.startswith("Port ") and current_ip:
                        port_part = line.split(":")[0].replace("Port ", "").strip()
                        f.write(f'{current_ip},{port_part}\n')
            set_status_line("Results exported as CSV.")

    def export_results_html():
        file_path = filedialog.asksaveasfilename(defaultextension=".html", filetypes=[("HTML files", "*.html"), ("All files", "*.*")])
        if file_path:
            html = ["<html><head><title>Port Scan Results</title></head><body>"]
            html.append(f"<h2>Port Scan Results</h2><pre>{output.get(1.0, tk.END)}</pre>")
            html.append("</body></html>")
            with open(file_path, 'w') as f:
                f.write('\n'.join(html))
            set_status_line("Results exported as HTML.")

    def export_results_json():
        import json
        file_path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON files", "*.json"), ("All files", "*.*")])
        if file_path:
            lines = output.get(1.0, tk.END).splitlines()
            results = []
            current_ip = None
            for line in lines:
                if line.startswith("Scanning "):
                    parts = line.split()
                    if len(parts) > 1:
                        current_ip = parts[1]
                elif line.startswith("Port ") and current_ip:
                    port_part = line.split(":")[0].replace("Port ", "").strip()
                    results.append({"ip": current_ip, "port": port_part})
            with open(file_path, 'w') as f:
                json.dump(results, f, indent=2)
            set_status_line("Results exported as JSON.")

    def export_results_pdf():
        try:
            from reportlab.lib.pagesizes import letter
            from reportlab.pdfgen import canvas
        except ImportError:
            messagebox.showerror("Missing Dependency", "reportlab is required for PDF export. Install with 'pip install reportlab'.")
            return
        file_path = filedialog.asksaveasfilename(defaultextension=".pdf", filetypes=[("PDF files", "*.pdf"), ("All files", "*.*")])
        if file_path:
            c = canvas.Canvas(file_path, pagesize=letter)
            textobject = c.beginText(40, 750)
            for line in output.get(1.0, tk.END).splitlines():
                textobject.textLine(line)
            c.drawText(textobject)
            c.save()
            set_status_line("Results exported as PDF.")

    # --- Scan history feature ---
    scan_history = []
    def show_history():
        if not scan_history:
            output.insert(tk.END, "No scan history yet.\n")
            set_status_line("No scan history.")
            return
        output.delete(1.0, tk.END)
        for i, entry in enumerate(scan_history, 1):
            output.insert(tk.END, f"--- Scan #{i} ---\n{entry}\n\n")
        set_status_line("History displayed.")

    def add_to_history(summary, result):
        scan_history.append(summary + result)

    # --- Profile save/load feature ---
    def save_profile():
        profile = {
            "targets": entry_targets.get(),
            "ports": entry_ports.get(),
            "timeout": entry_timeout.get(),
            "threads": thread_count.get()
        }
        if os.path.exists(PROFILE_FILE):
            with open(PROFILE_FILE, 'r') as f:
                profiles = json.load(f)
        else:
            profiles = []
        profiles.append(profile)
        with open(PROFILE_FILE, 'w') as f:
            json.dump(profiles, f, indent=2)
        set_status_line("Profile saved.")

    def load_profile():
        if not os.path.exists(PROFILE_FILE):
            set_status_line("No profiles found.")
            return
        with open(PROFILE_FILE, 'r') as f:
            profiles = json.load(f)
        if not profiles:
            set_status_line("No profiles found.")
            return
        profile = profiles[-1]
        entry_targets.delete(0, tk.END)
        entry_targets.insert(0, profile["targets"])
        entry_ports.delete(0, tk.END)
        entry_ports.insert(0, profile["ports"])
        entry_timeout.delete(0, tk.END)
        entry_timeout.insert(0, profile["timeout"])
        thread_count.set(profile["threads"])
        set_status_line("Profile loaded.")

    # --- Copy output to clipboard ---
    def copy_output_to_clipboard():
        root.clipboard_clear()
        root.clipboard_append(output.get(1.0, tk.END))
        set_status_line("Output copied to clipboard.")

    # --- Graceful scan stop ---
    def stop_scan():
        stop_event.set()
        set_status_line("Scan stopped.")
        progress['value'] = 0

    root.bind('<Control-q>', lambda e: stop_scan())
    root.bind('<Control-Q>', lambda e: stop_scan())

    # --- Suggestion: Add auto-detect local subnet feature ---
    def suggest_local_subnet():
        import socket
        try:
            hostname = socket.gethostname()
            local_ip = socket.gethostbyname(hostname)
            if local_ip.startswith('127.'):
                # Try to get the first non-loopback address
                # Optional: netifaces is not required for most users. Ignore Pylance warning if missing.
                try:
                    import netifaces  # type: ignore
                except ImportError:
                    netifaces = None
                if netifaces:
                    for iface in netifaces.interfaces():
                        addrs = netifaces.ifaddresses(iface)
                        if netifaces.AF_INET in addrs:
                            for addr in addrs[netifaces.AF_INET]:
                                ip = addr.get('addr')
                                if ip and not ip.startswith('127.'):
                                    local_ip = ip
                                    break
            subnet = '.'.join(local_ip.split('.')[:3]) + '.0/24'
            entry_targets.delete(0, tk.END)
            entry_targets.insert(0, subnet.replace('/24','1') + '-' + subnet.replace('/24','254'))
            set_status_line(f"Suggested local subnet: {subnet}")
        except Exception as e:
            set_status_line(f"Could not detect local subnet: {e}")

    # --- Real scan logic ---
    import threading, time
    from scanner import parse_ports, validate_ip, is_host_alive, grab_banner, resolve_hostname

    def parse_targets(target_input: str):
        """Parse a single IP, a range (192.168.1.1-192.168.1.10), or comma-separated IPs into a list."""
        from ipaddress import ip_address
        targets = set()
        for part in target_input.split(','):
            part = part.strip()
            if '-' in part:
                start_ip, end_ip = part.split('-')
                try:
                    start = ip_address(start_ip.strip())
                    end = ip_address(end_ip.strip())
                    if int(end) < int(start):
                        continue
                    for i in range(int(start), int(end)+1):
                        targets.add(str(ip_address(i)))
                except Exception:
                    continue
            elif part:
                try:
                    ip_address(part)
                    targets.add(part)
                except Exception:
                    continue
        return sorted(targets)

    def threaded_scan():
        stop_event.clear()
        target_input = entry_targets.get()
        targets = parse_targets(target_input)
        port_input = entry_ports.get()
        ports = parse_ports(port_input)
        timeout = float(entry_timeout.get()) if entry_timeout.get() else 0.2
        udp_scan = udp_scan_var.get()
        show_closed = show_closed_var.get()
        reverse_dns = reverse_dns_var.get()
        banner_grab = banner_grab_var.get()
        randomize_ports = randomize_ports_var.get()
        retry_on_fail = retry_on_fail_var.get()
        verbose = verbose_var.get()
        export_on_complete = export_on_complete_var.get()
        sound_notify = sound_notify_var.get()
        # Optionally randomize port order
        if randomize_ports:
            import random
            random.shuffle(ports)
        hosts_scanned = 0
        open_ports_count = 0
        if not targets:
            color_insert(output, "Invalid or empty target(s) input.\n", 'closed')
            set_status_line("Error: Invalid or empty target(s) input.")
            return
        total_ips = len(targets)
        progress['maximum'] = total_ips
        scanned_ips = 0
        t0 = time.time()
        for current_ip in targets:
            if stop_event.is_set():
                color_insert(output, "\nScan stopped by user.\n", 'info')
                progress['value'] = 0
                set_status_line("Scan stopped.")
                return
            if ping_before_scan.get() and not is_host_alive(str(current_ip)):
                color_insert(output, f"{current_ip}: No ping response. Skipped.\n", 'filtered')
                scanned_ips += 1
                progress['value'] = scanned_ips
                continue
            # Reverse DNS lookup if enabled
            if reverse_dns:
                try:
                    hostname = resolve_hostname(str(current_ip))
                    color_insert(output, f"{current_ip} ({hostname})\n", 'info')
                except Exception:
                    color_insert(output, f"{current_ip} (unresolved)\n", 'info')
            else:
                color_insert(output, f"\nScanning {current_ip}...\n", 'info')
            open_ports = []
            open_port_details = []
            ip_start_time = time.time()
            for idx, port in enumerate(ports):
                if stop_event.is_set():
                    color_insert(output, "\nScan stopped by user.\n", 'info')
                    progress['value'] = 0
                    set_status_line("Scan stopped.")
                    return
                try:
                    if udp_scan:
                        # UDP scan logic placeholder
                        pass
                    else:
                        import socket
                        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                            s.settimeout(timeout)
                            result = s.connect_ex((str(current_ip), port))
                            if result == 0:
                                banner = grab_banner(str(current_ip), port, timeout) if banner_grab else None
                                banner_str = f" | Banner: {banner}" if banner else ""
                                color_insert(output, f"Port {port}: OPEN{banner_str}\n", 'open')
                                open_ports.append(port)
                                open_port_details.append(f"{port}{banner_str}")
                                open_ports_count += 1
                            elif show_closed:
                                color_insert(output, f"Port {port}: CLOSED\n", 'closed')
                            # Retry on failure (placeholder, not implemented)
                            # if retry_on_fail and result != 0:
                            #     ...
                    # Progress and status update for each port
                    percent = ((scanned_ips + (idx+1)/len(ports)) / total_ips) * 100
                    elapsed = time.time() - t0
                    est_total = (elapsed / (scanned_ips + (idx+1)/len(ports))) * total_ips if (scanned_ips + (idx+1)/len(ports)) > 0 else 0
                    est_left = est_total - elapsed
                    set_status_line(f"{current_ip}:{port}", percent, elapsed, est_left)
                    progress['value'] = scanned_ips + (idx+1)/len(ports)
                    progress.update_idletasks()
                except Exception as e:
                    if verbose:
                        color_insert(output, f"Port {port}: ERROR ({e})\n", 'closed')
            if open_ports:
                color_insert(output, f"Open ports for {current_ip}: {open_port_details}\n", 'info')
            else:
                color_insert(output, f"No open ports found for {current_ip}.\n", 'filtered')
            hosts_scanned += 1
            scanned_ips += 1
            output.update_idletasks()
        progress['value'] = 0
        duration = time.time() - t0
        summary = scan_summary(hosts_scanned, open_ports_count, duration)
        color_insert(output, summary, 'info')
        add_to_history(f"Scan: {target_input}, Ports: {port_input}, Timeout: {timeout}s\n", output.get(1.0, tk.END))
        set_status_line("Scan complete.")
        # Export on completion
        if export_on_complete:
            export_results()
        # Sound notification
        if sound_notify:
            try:
                root.bell()
            except Exception:
                pass

    def start_scan():
        port_input = entry_ports.get()
        ports = parse_ports(port_input)
        if not ports:
            set_status_line("Invalid port input.")
            color_insert(output, "Invalid port input.\n", 'closed')
            return
        target_input = entry_targets.get()
        targets = parse_targets(target_input)
        if not targets:
            set_status_line("Invalid or empty target(s) input.")
            color_insert(output, "Invalid or empty target(s) input.\n", 'closed')
            return
        output.delete(1.0, tk.END)
        progress['value'] = 0
        set_status_line("Scanning...")
        import threading
        t = threading.Thread(target=threaded_scan)
        t.daemon = True
        t.start()

    scan_button = tk.Button(root, text="Scan", command=start_scan, width=8)
    scan_button.grid(row=11, column=0, pady=5, padx=(10,2), sticky="ew")
    ToolTip(scan_button, "Start the port scan with the specified options.")

    stop_button = tk.Button(root, text="Stop", command=stop_scan, width=8)
    stop_button.grid(row=11, column=1, pady=5, padx=(2,10), sticky="ew")
    ToolTip(stop_button, "Stop the current scan.")

    # --- Menu bar with all options (moved here so all functions are defined) ---
    menubar = tk.Menu(root)

    # Tools menu
    tools_menu = tk.Menu(menubar, tearoff=0)
    tools_menu.add_command(label="Export Results", command=export_results)
    tools_menu.add_command(label="View History", command=show_history)
    # Manage Profiles submenu
    profiles_menu = tk.Menu(tools_menu, tearoff=0)
    profiles_menu.add_command(label="Save Profile", command=save_profile)
    profiles_menu.add_command(label="Load Profile", command=load_profile)
    tools_menu.add_cascade(label="Manage Profiles", menu=profiles_menu)
    menubar.add_cascade(label="Tools", menu=tools_menu)

    # Presets menu
    presets_menu = tk.Menu(menubar, tearoff=0)
    presets_menu.add_command(label="Common Ports", command=lambda: entry_ports.delete(0, tk.END) or entry_ports.insert(0, "20,21,22,23,25,53,80,110,139,143,443,445,3389,8080,3306,5900,123,161,389,636,993,995,1723,5432,1521,5060,69,137,138,139,445"))
    presets_menu.add_command(label="Well-known Ports (0-1023)", command=lambda: entry_ports.delete(0, tk.END) or entry_ports.insert(0, "0-1023"))
    presets_menu.add_command(label="Registered Ports (1024-49151)", command=lambda: entry_ports.delete(0, tk.END) or entry_ports.insert(0, "1024-49151"))
    presets_menu.add_command(label="Private Ports (49152-65535)", command=lambda: entry_ports.delete(0, tk.END) or entry_ports.insert(0, "49152-65535"))
    presets_menu.add_command(label="All Ports (0-65535)", command=lambda: entry_ports.delete(0, tk.END) or entry_ports.insert(0, "0-65535"))
    menubar.add_cascade(label="Presets", menu=presets_menu)

    # Options menu (for checkboxes)
    options_menu = tk.Menu(menubar, tearoff=0)
    options_menu.add_checkbutton(label="Ping hosts before scanning", variable=ping_before_scan)
    options_menu.add_checkbutton(label="UDP Scan (experimental)", variable=udp_scan_var)
    options_menu.add_checkbutton(label="Show Closed Ports", variable=show_closed_var)
    options_menu.add_separator()
    options_menu.add_checkbutton(label="Reverse DNS Lookup", variable=reverse_dns_var)
    options_menu.add_checkbutton(label="Banner Grabbing", variable=banner_grab_var)
    options_menu.add_checkbutton(label="Randomize Port Order", variable=randomize_ports_var)
    options_menu.add_checkbutton(label="Retry on Failure", variable=retry_on_fail_var)
    options_menu.add_checkbutton(label="Verbose Output", variable=verbose_var)
    options_menu.add_separator()
    options_menu.add_checkbutton(label="Export on Completion", variable=export_on_complete_var)
    options_menu.add_checkbutton(label="Sound Notification", variable=sound_notify_var)
    menubar.add_cascade(label="Options", menu=options_menu)

    # Demo Mode menu (dropdown, off by default)
    demo_mode_var = tk.BooleanVar(value=False)
    def toggle_demo_mode():
        demo_mode_var.set(not demo_mode_var.get())
    demo_menu = tk.Menu(menubar, tearoff=0)
    def set_demo_mode_on():
        demo_mode_var.set(True)
    def set_demo_mode_off():
        demo_mode_var.set(False)
    demo_menu.add_radiobutton(label="Off", variable=demo_mode_var, value=False, command=set_demo_mode_off)
    demo_menu.add_radiobutton(label="On", variable=demo_mode_var, value=True, command=set_demo_mode_on)
    menubar.add_cascade(label="Demo Mode", menu=demo_menu)

    # Help menu
    help_menu = tk.Menu(menubar, tearoff=0)
    help_menu.add_command(label="About / Help", command=show_about)
    menubar.add_cascade(label="Help", menu=help_menu)

    root.config(menu=menubar)

    # --- Make grid responsive ---
    for i in range(12):
        root.grid_rowconfigure(i, weight=1 if i in [7, 8] else 0)
    for i in range(3):
        root.grid_columnconfigure(i, weight=1)

    root.mainloop()

# Entry point for launching the GUI
if __name__ == "__main__":
    run_gui()
