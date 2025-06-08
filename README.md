# Python Port Scanner

A graphical port scanner tool built with Python and Tkinter. This application allows you to scan a range of IP addresses and ports, identify open TCP/UDP ports, grab service banners, and export results. It is designed for cybersecurity professionals, network administrators, and enthusiasts.

## Features

- **Scan IP Ranges:** Specify target(s) as a single IP, a range, or a comma-separated list to scan multiple hosts.
- **Port Range Selection:** Choose custom port ranges or use presets (Well-known, Common, All).
- **Threaded Scanning:** Adjustable thread count for faster scans.
- **UDP Scan (Experimental):** Optionally scan UDP ports.
- **Ping Before Scan:** Optionally ping hosts before scanning to skip unreachable hosts.
- **Service Detection:** Maps common ports to service names.
- **Banner Grabbing:** Attempts to retrieve service banners from open ports.
- **Hostname Resolution:** Resolves hostnames for scanned IPs.
- **Flexible Port Input:** Enter ports as a comma-separated list and/or ranges (e.g., `22,80,443` or `20-25,80`).
- **Export Results:** Save scan results as text, CSV, HTML, JSON, or PDF (PDF requires `reportlab`).
- **Scan History:** View previous scan results within the app.
- **Profiles:** Save and load scan profiles for quick reuse.
- **Copy Output:** Copy scan results to clipboard.
- **Responsive GUI:** Output and progress bar update in real time.
- **Search/Filter Output:** Filter scan results in real time.
- **Presets:** Quickly select well-known, common, or all ports.
- **Stop Scan:** Gracefully stop an ongoing scan from the menu or with Ctrl+Q.
- **Auto-Detect Local Subnet:** Suggests your local subnet for quick scanning.
- **Demo Mode:** Toggle to preview scan input without running a real scan.

## Usage

1. **Install Requirements:**  
   This app uses only Python's standard library for core features. For PDF export, install `reportlab`:
   ```sh
   pip install reportlab
   ```
   For advanced local subnet detection, you may also want:
   ```sh
   pip install netifaces
   ```

2. **Run the App:**  
   ```sh
   python portscanner.py
   ```

3. **Configure Scan:**
   - Enter the **Target(s)** as a single IP, a range (e.g. `192.168.1.1-192.168.1.10`), or a comma-separated list (e.g. `192.168.1.1,192.168.1.5`).
   - Set the port range or use the Presets menu.
   - Adjust timeout and thread count as needed.
   - Optionally enable "Ping hosts before scanning" or "UDP Scan".
   - Use the Tools menu for export, history, profiles, and more.
   - Use the Help menu for About/Help.

4. **Start Scan:**  
   Click the **Scan** button. Progress and results will appear in the output box.

5. **Export/Copy Results:**  
   Use the **Tools** menu to export results, copy to clipboard, or manage profiles.

6. **Stop Scan:**  
   Use the **Stop Scan** menu item or Ctrl+Q to halt an ongoing scan.

## Example

```
Scanning 192.168.1.1,192.168.1.5-192.168.1.7 on ports [20, 21, 22, 23, 25]
Port 22: OPEN (SSH) | Banner: OpenSSH_7.6p1 Ubuntu-4ubuntu0.3
Open ports for 192.168.1.1: ['22 (SSH) | Banner: OpenSSH_7.6p1 Ubuntu-4ubuntu0.3']
```

## Notes

- **UDP scanning** is experimental and may produce false positives due to the nature of UDP.
- **Banner grabbing** may not always succeed, depending on the service and firewall settings.
- **Profiles** are saved in `scan_profiles.json` in the app directory.
- **PDF export** requires the `reportlab` package.
- **Local subnet detection** is best with `netifaces` installed, but works for most users without it.

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.