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

    menubar = tk.Menu(root)
    help_menu = tk.Menu(menubar, tearoff=0)
    help_menu.add_command(label="About / Help", command=show_about)
    menubar.add_cascade(label="Help", menu=help_menu)
    root.config(menu=menubar)

    # --- Main input fields ---
    tk.Label(root, text="Target(s):").grid(row=0, column=0, padx=5, pady=5, sticky="e")
    entry_targets = tk.Entry(root, width=40)
    entry_targets.grid(row=0, column=1, padx=5, pady=5, sticky='ew', columnspan=2)
    ToolTip(entry_targets, "Enter a single IP, a range (e.g. 192.168.1.1-192.168.1.10), or a comma-separated list of IPs.")

    tk.Label(root, text="Ports (e.g. 22,80,443 or 20-25)").grid(row=1, column=0, padx=5, pady=5, sticky="e")
    entry_ports = tk.Entry(root, width=30)
    entry_ports.grid(row=1, column=1, padx=5, pady=5, sticky='ew')
    ToolTip(entry_ports, "Enter ports as a comma-separated list and/or ranges, e.g. 22,80,443 or 20-25,80")

    tk.Label(root, text="Timeout (s):").grid(row=2, column=0, padx=5, pady=5, sticky="e")
    entry_timeout = tk.Entry(root, width=10)
    entry_timeout.insert(0, "0.2")
    entry_timeout.grid(row=2, column=1, padx=5, pady=5, sticky='ew')
    ToolTip(entry_timeout, "Set the timeout (in seconds) for each port scan.")

    thread_count = tk.IntVar(value=20)
    tk.Label(root, text="Threads:").grid(row=3, column=0, padx=5, pady=5, sticky="e")
    thread_spin = tk.Spinbox(root, from_=1, to=100, textvariable=thread_count, width=5)
    thread_spin.grid(row=3, column=1, padx=5, pady=5, sticky='w')
    ToolTip(thread_spin, "Number of threads for parallel scanning.")

    # --- Option checkboxes ---
    ping_before_scan = tk.BooleanVar(value=False)
    ping_checkbox = tk.Checkbutton(root, text="Ping hosts before scanning", variable=ping_before_scan)
    ping_checkbox.grid(row=4, column=0, columnspan=2, padx=5, pady=2, sticky="w")
    ToolTip(ping_checkbox, "Ping hosts before scanning to skip unreachable hosts.")

    udp_scan_var = tk.BooleanVar(value=False)
    udp_checkbox = tk.Checkbutton(root, text="UDP Scan (experimental)", variable=udp_scan_var)
    udp_checkbox.grid(row=5, column=0, columnspan=2, padx=5, pady=2, sticky="w")
    ToolTip(udp_checkbox, "Enable UDP port scanning (experimental).")

    show_closed_var = tk.BooleanVar(value=False)
    show_closed_checkbox = tk.Checkbutton(root, text="Show Closed Ports", variable=show_closed_var)
    show_closed_checkbox.grid(row=6, column=0, columnspan=2, padx=5, pady=2, sticky="w")
    ToolTip(show_closed_checkbox, "Display closed ports in the output (may be verbose).")

    # --- Output area ---
    output = scrolledtext.ScrolledText(root, width=60, height=15)
    output.grid(row=7, column=0, columnspan=7, padx=10, pady=10, sticky="nsew")
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
    progress = ttk.Progressbar(root, orient="horizontal", length=300, mode="determinate")
    progress.grid(row=8, column=0, columnspan=7, padx=5, pady=5, sticky="ew")

    # --- Search/filter box ---
    search_var = tk.StringVar()
    def filter_output(*args):
        search = search_var.get().lower()
        output.delete(1.0, tk.END)
        lines = getattr(output, '_all_lines', output.get(1.0, tk.END).splitlines())
        filtered = [line for line in lines if search in line.lower()]
        for line in filtered:
            output.insert(tk.END, line + '\n')
    search_entry = tk.Entry(root, textvariable=search_var, width=30)
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

    # --- Status bar ---
    status_var = tk.StringVar()
    status_var.set("Ready.")
    status_bar = tk.Label(root, textvariable=status_var, bd=1, relief=tk.SUNKEN, anchor="w")
    status_bar.grid(row=10, column=0, columnspan=6, sticky="ew")
    def set_status(msg: str):
        status_var.set(msg)
        status_bar.update_idletasks()

    # --- Menu bar with all options ---
    menubar = tk.Menu(root)
    help_menu = tk.Menu(menubar, tearoff=0)
    help_menu.add_command(label="About / Help", command=show_about)
    menubar.add_cascade(label="Help", menu=help_menu)

    # --- Export menu options ---
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
            set_status("Results exported as CSV.")

    def export_results_html():
        file_path = filedialog.asksaveasfilename(defaultextension=".html", filetypes=[("HTML files", "*.html"), ("All files", "*.*")])
        if file_path:
            html = ["<html><head><title>Port Scan Results</title></head><body>"]
            html.append(f"<h2>Port Scan Results</h2><pre>{output.get(1.0, tk.END)}</pre>")
            html.append("</body></html>")
            with open(file_path, 'w') as f:
                f.write('\n'.join(html))
            set_status("Results exported as HTML.")

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
            set_status("Results exported as JSON.")

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
            set_status("Results exported as PDF.")

    tools_menu = tk.Menu(menubar, tearoff=0)
    tools_menu.add_command(label="Export Results", command=export_results)
    tools_menu.add_command(label="Export as CSV", command=export_results_csv)
    tools_menu.add_command(label="Export as HTML", command=export_results_html)
    tools_menu.add_command(label="Export as JSON", command=export_results_json)
    tools_menu.add_command(label="Export as PDF", command=export_results_pdf)
    tools_menu.add_separator()

    # --- Scan history feature ---
    scan_history = []
    def show_history():
        if not scan_history:
            output.insert(tk.END, "No scan history yet.\n")
            set_status("No scan history.")
            return
        output.delete(1.0, tk.END)
        for i, entry in enumerate(scan_history, 1):
            output.insert(tk.END, f"--- Scan #{i} ---\n{entry}\n\n")
        set_status("History displayed.")

    def add_to_history(summary, result):
        scan_history.append(summary + result)

    tools_menu.add_command(label="Show History", command=show_history)
    tools_menu.add_command(label="Clear Output", command=lambda: output.delete(1.0, tk.END))

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
        set_status("Profile saved.")

    def load_profile():
        if not os.path.exists(PROFILE_FILE):
            set_status("No profiles found.")
            return
        with open(PROFILE_FILE, 'r') as f:
            profiles = json.load(f)
        if not profiles:
            set_status("No profiles found.")
            return
        profile = profiles[-1]
        entry_targets.delete(0, tk.END)
        entry_targets.insert(0, profile["targets"])
        entry_ports.delete(0, tk.END)
        entry_ports.insert(0, profile["ports"])
        entry_timeout.delete(0, tk.END)
        entry_timeout.insert(0, profile["timeout"])
        thread_count.set(profile["threads"])
        set_status("Profile loaded.")

    tools_menu.add_separator()
    tools_menu.add_command(label="Save Profile", command=save_profile)
    tools_menu.add_command(label="Load Profile", command=load_profile)

    # --- Copy output to clipboard ---
    def copy_output_to_clipboard():
        root.clipboard_clear()
        root.clipboard_append(output.get(1.0, tk.END))
        set_status("Output copied to clipboard.")

    tools_menu.add_command(label="Copy Output to Clipboard", command=copy_output_to_clipboard)

    # --- Graceful scan stop ---
    def stop_scan():
        stop_event.set()
        set_status("Scan stopped by user.")
        progress['value'] = 0

    tools_menu.add_command(label="Stop Scan", command=stop_scan)
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
                import netifaces
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
            set_status(f"Suggested local subnet: {subnet}")
        except Exception as e:
            set_status(f"Could not detect local subnet: {e}")

    tools_menu.add_separator()
    tools_menu.add_command(label="Suggest Local Subnet", command=suggest_local_subnet)

    menubar.add_cascade(label="Tools", menu=tools_menu)

    # --- Presets menu for common ports ---
    def set_preset_ports(preset: str):
        if preset == "Well-known":
            entry_ports.delete(0, tk.END)
            entry_ports.insert(0, "1-1023")
            set_status("Preset: Well-known ports (1-1023)")
        elif preset == "Common":
            entry_ports.delete(0, tk.END)
            entry_ports.insert(0, "1-49151")
            set_status("Preset: Common ports (1-49151)")
        elif preset == "All":
            entry_ports.delete(0, tk.END)
            entry_ports.insert(0, "1-65535")
            set_status("Preset: All ports (1-65535)")

    presets_menu = tk.Menu(menubar, tearoff=0)
    presets_menu.add_command(label="Well-known ports (1-1023)", command=lambda: set_preset_ports("Well-known"))
    presets_menu.add_command(label="Common ports (1-49151)", command=lambda: set_preset_ports("Common"))
    presets_menu.add_command(label="All ports (1-65535)", command=lambda: set_preset_ports("All"))
    menubar.add_cascade(label="Presets", menu=presets_menu)

    root.config(menu=menubar)

    # --- Keyboard shortcuts ---
    root.bind('<Control-s>', lambda e: start_scan())
    root.bind('<Control-S>', lambda e: start_scan())
    root.bind('<Control-e>', lambda e: export_results())
    root.bind('<Control-E>', lambda e: export_results())

    # --- Keyboard shortcut for stop (Ctrl+Q) ---
    root.bind('<Control-q>', lambda e: stop_scan())
    root.bind('<Control-Q>', lambda e: stop_scan())

    # --- Demo mode toggle ---
    demo_mode = tk.BooleanVar(value=True)
    demo_checkbox = tk.Checkbutton(root, text="Demo Mode (show scan input only)", variable=demo_mode)
    demo_checkbox.grid(row=11, column=1, padx=5, pady=5, sticky="w")
    ToolTip(demo_checkbox, "If checked, only shows scan input as a demo. Uncheck to run real scan.")

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
        hosts_scanned = 0
        open_ports_count = 0
        if not targets:
            color_insert(output, "Invalid or empty target(s) input.\n", 'closed')
            set_status("Error: Invalid or empty target(s) input.")
            return
        total_ips = len(targets)
        progress['maximum'] = total_ips
        scanned_ips = 0
        t0 = time.time()
        for current_ip in targets:
            if stop_event.is_set():
                color_insert(output, "\nScan stopped by user.\n", 'info')
                progress['value'] = 0
                set_status("Scan stopped.")
                return
            if ping_before_scan.get() and not is_host_alive(str(current_ip)):
                color_insert(output, f"{current_ip}: No ping response. Skipped.\n", 'filtered')
                scanned_ips += 1
                progress['value'] = scanned_ips
                continue
            color_insert(output, f"\nScanning {current_ip} on ports {ports}...\n", 'info')
            open_ports = []
            for port in ports:
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
                                banner = grab_banner(str(current_ip), port, timeout)
                                banner_str = f" | Banner: {banner}" if banner else ""
                                color_insert(output, f"Port {port}: OPEN{banner_str}\n", 'open')
                                open_ports.append(port)
                            elif show_closed:
                                color_insert(output, f"Port {port}: CLOSED\n", 'closed')
                except Exception as e:
                    color_insert(output, f"Port {port}: ERROR ({e})\n", 'closed')
            if open_ports:
                open_ports_count += len(open_ports)
            hosts_scanned += 1
            scanned_ips += 1
            progress['value'] = scanned_ips
            output.update_idletasks()
            progress.update_idletasks()
        progress['value'] = 0
        duration = time.time() - t0
        summary = scan_summary(hosts_scanned, open_ports_count, duration)
        color_insert(output, summary, 'info')
        add_to_history(f"Scan: {target_input}, Ports: {port_input}, Timeout: {timeout}s\n", output.get(1.0, tk.END))
        set_status("Scan complete.")

    def start_scan():
        port_input = entry_ports.get()
        ports = parse_ports(port_input)
        if not ports:
            set_status("Invalid port input.")
            color_insert(output, "Invalid port input.\n", 'closed')
            return
        target_input = entry_targets.get()
        targets = parse_targets(target_input)
        if not targets:
            set_status("Invalid or empty target(s) input.")
            color_insert(output, "Invalid or empty target(s) input.\n", 'closed')
            return
        output.delete(1.0, tk.END)
        progress['value'] = 0
        set_status("Scanning...")
        import threading
        t = threading.Thread(target=threaded_scan)
        t.daemon = True
        t.start()

    scan_button = tk.Button(root, text="Scan", command=start_scan)
    scan_button.grid(row=11, column=0, pady=5)
    ToolTip(scan_button, "Start the port scan with the specified options.")

    # --- Make grid responsive ---
    for i in range(12):
        root.grid_rowconfigure(i, weight=1 if i in [7, 8] else 0)
    for i in range(7):
        root.grid_columnconfigure(i, weight=1)

    root.mainloop()

# Entry point for launching the GUI
if __name__ == "__main__":
    run_gui()
