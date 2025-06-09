# Python Port Scanner

A graphical port scanner tool built with Python and Tkinter. This application allows you to scan a range of IP addresses and ports, identify open TCP/UDP ports, grab service banners, and export results. It is designed for cybersecurity professionals, network administrators, and enthusiasts.

## Features

- **Scan IP Ranges:** Specify target(s) as a single IP, a range, or a comma-separated list to scan multiple hosts.
- **Port Range Selection:** Choose custom port ranges or use presets (Common, Well-known, Registered, Private, All).
- **Threaded Scanning:** Adjustable thread count for faster scans (default: 20 threads).
- **Timeout Control:** Adjustable timeout per port (default: 0.2 seconds). Lower values are faster; higher values are more reliable on slow networks.
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
- **Presets:** Quickly select common, well-known, registered, private, or all ports. (All presets start at port 1; port 0 is not scanned.)
- **Stop Scan:** Gracefully stop an ongoing scan from the menu or with Ctrl+Q.
- **Auto-Detect Local Subnet:** Suggests your local subnet for quick scanning.
- **Demo Mode:** Toggle to preview scan input without running a real scan.
- **Advanced Options:** Reverse DNS, Banner Grabbing, Randomize Port Order, Retry on Failure, Verbose Output, Export on Completion, Sound Notification.
- **Scan Settings Dialog:** Timeout and thread count are set via the Tools > Scan Settings... dialog for a clean main UI.

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
   - Set the port range or use the Presets menu. Presets include Common, Well-known (1-1023), Registered (1024-49151), Private (49152-65535), and All (1-65535) ports.
   - Adjust timeout and thread count in Tools > Scan Settings... (default: 0.2s timeout, 20 threads).
   - Optionally enable advanced options in the Options menu (Ping, UDP, Reverse DNS, Banner Grabbing, etc).
   - Use the Tools menu for export, history, profiles, and more.
   - Use the Help menu for About/Help.

4. **Start Scan:**  
   Click the **Scan** button. Progress and results will appear in the output box.

5. **Export/Copy Results:**  
   Use the **Tools** menu to export results, copy to clipboard, or manage profiles.

6. **Stop Scan:**  
   Use the **Stop** button or Ctrl+Q to halt an ongoing scan.

## Example

```
Scanning 192.168.1.1,192.168.1.5-192.168.1.7 on ports [20, 21, 22, 23, 25]
Port 22: OPEN (SSH) | Banner: OpenSSH_7.6p1 Ubuntu-4ubuntu0.3
Open ports for 192.168.1.1: ['22 (SSH) | Banner: OpenSSH_7.6p1 Ubuntu-4ubuntu0.3']
```

## Notes

- **Timeout:** Controls how long to wait for each port. 0.2s is fast for LANs; increase to 0.5–1.0s for slow/remote networks.
- **Threads:** Controls how many ports/hosts are scanned in parallel. 20 is safe for most users; increase for speed on fast systems, decrease if you see errors.
- **UDP scanning** is experimental and may produce false positives due to the nature of UDP.
- **Banner grabbing** may not always succeed, depending on the service and firewall settings.
- **Profiles** are saved in `scan_profiles.json` in the app directory.
- **PDF export** requires the `reportlab` package.
- **Local subnet detection** is best with `netifaces` installed, but works for most users without it.

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.