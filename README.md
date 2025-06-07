# Python Port Scanner

A graphical port scanner tool built with Python and Tkinter. This application allows you to scan a range of IP addresses and ports, identify open TCP/UDP ports, grab service banners, and export results. It is designed for cybersecurity professionals, network administrators, and enthusiasts.

## Features

- **Scan IP Ranges:** Specify start and end IP addresses to scan multiple hosts.
- **Port Range Selection:** Choose custom port ranges or use presets (Well-known, Common, All).
- **Threaded Scanning:** Adjustable thread count for faster scans.
- **UDP Scan (Experimental):** Optionally scan UDP ports.
- **Ping Before Scan:** Optionally ping hosts before scanning to skip unreachable hosts.
- **Service Detection:** Maps common ports to service names.
- **Banner Grabbing:** Attempts to retrieve service banners from open ports.
- **Hostname Resolution:** Resolves hostnames for scanned IPs.
- **Export Results:** Save scan results as text or CSV.
- **Scan History:** View previous scan results within the app.
- **Profiles:** Save and load scan profiles for quick reuse.
- **Dark/Light Mode:** Toggle between dark and light themes.
- **Copy Output:** Copy scan results to clipboard.
- **Responsive GUI:** Output and progress bar update in real time.

## Usage

1. **Install Requirements:**  
   This app uses only Python's standard library. No extra dependencies are required.

2. **Run the App:**  
   ```sh
   python portscanner.py
   ```

3. **Configure Scan:**
   - Enter the start and end IP addresses.
   - Set the port range or use the Presets menu.
   - Adjust timeout and thread count as needed.
   - Optionally enable "Ping hosts before scanning" or "UDP Scan".

4. **Start Scan:**  
   Click the **Scan** button. Progress and results will appear in the output box.

5. **Export/Copy Results:**  
   Use the **Tools** menu to export results, copy to clipboard, or manage profiles.

6. **Stop Scan:**  
   Click the **Stop** button to halt an ongoing scan.

## Example

```
Scanning 192.168.1.1 from port 20 to 25...
Port 22: OPEN (SSH) | Banner: OpenSSH_7.6p1 Ubuntu-4ubuntu0.3
Open ports for 192.168.1.1: ['22 (SSH) | Banner: OpenSSH_7.6p1 Ubuntu-4ubuntu0.3']
```

## Notes

- **UDP scanning** is experimental and may produce false positives due to the nature of UDP.
- **Banner grabbing** may not always succeed, depending on the service and firewall settings.
- **Profiles** are saved in `scan_profiles.json` in the app directory.

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.