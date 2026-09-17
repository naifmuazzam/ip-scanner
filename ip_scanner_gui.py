"""
IP Scanner - Check Available vs Used IPs
Run: python ip_scanner_gui.py
Uses only Python standard library (tkinter, etc.) - no install needed.
"""
import ipaddress
import platform
import socket
import subprocess
import threading
import time
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from concurrent.futures import ThreadPoolExecutor, as_completed


def get_local_network_suggestion():
    """Guess local subnet, e.g. 192.168.1.0/24"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(2)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        # Assume /24
        parts = local_ip.split(".")
        return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24", local_ip
    except Exception:
        return "192.168.1.0/24", "127.0.0.1"


def ping_host(ip_str, timeout_ms=300):
    """Ping once. Returns (is_used: bool, latency_ms: float|None) - optimized for speed."""
    system = platform.system().lower()
    try:
        if "windows" in system:
            cmd = ["ping", "-n", "1", "-w", str(timeout_ms), ip_str]
        else:
            # Linux/Mac: timeout in seconds (min 1s)
            timeout_s = max(1, int(round(timeout_ms / 1000)))
            cmd = ["ping", "-c", "1", "-W", str(timeout_s), ip_str]

        start = time.time()
        kwargs = {"stdout": subprocess.DEVNULL, "stderr": subprocess.DEVNULL,
                  "timeout": (timeout_ms / 1000 + 3)}
        # Avoid console popup & slightly faster on Windows
        if "windows" in system:
            kwargs["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        result = subprocess.run(cmd, **kwargs)
        elapsed = (time.time() - start) * 1000
        if result.returncode == 0:
            return True, round(elapsed, 1)
        return False, None
    except Exception:
        return False, None


def resolve_hostname(ip_str):
    try:
        host, _, _ = socket.gethostbyaddr(ip_str)
        return host
    except Exception:
        return "-"


class IPScannerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("IP Scanner - Available vs Used")
        self.root.geometry("760x600")
        self.root.minsize(680, 520)

        self.stop_event = threading.Event()
        self.scanning = False
        self.results = []  # list of dict(ip, status, hostname, latency)

        self.build_ui()
        suggestion, local_ip = get_local_network_suggestion()
        self.network_var.set(suggestion)
        self.info_var.set(f"Your IP: {local_ip} | Examples: 192.168.1.0/24 or 192.168.1.1-50")

    def build_ui(self):
        # --- Top frame: input ---
        top = ttk.Frame(self.root, padding=10)
        top.pack(fill="x")

        ttk.Label(top, text="Network / Range:").grid(row=0, column=0, sticky="w")
        self.network_var = tk.StringVar()
        self.network_entry = ttk.Entry(top, textvariable=self.network_var, width=28)
        self.network_entry.grid(row=0, column=1, padx=5, sticky="ew")

        ttk.Label(top, text="Timeout (ms):").grid(row=0, column=2, padx=(10, 0))
        self.timeout_var = tk.StringVar(value="300")
        ttk.Entry(top, textvariable=self.timeout_var, width=7).grid(row=0, column=3, padx=5)

        ttk.Label(top, text="Threads:").grid(row=0, column=4)
        self.threads_var = tk.StringVar(value="254")
        ttk.Entry(top, textvariable=self.threads_var, width=6).grid(row=0, column=5, padx=5)

        top.columnconfigure(1, weight=1)

        # --- Speed options ---
        opt_frame = ttk.Frame(self.root, padding=(10, 0, 10, 0))
        opt_frame.pack(fill="x")
        self.resolve_var = tk.BooleanVar(value=False)
        self.fast_state = False
        self.resolve_chk = ttk.Checkbutton(
            opt_frame, text="Resolve Hostname (SLOW - adds 10-20s, Used IPs only)",
            variable=self.resolve_var, command=self.update_mode_indicator)
        self.resolve_chk.pack(side="left")
        self.fast_btn = tk.Button(opt_frame, text="Fast Mode: OFF", command=self.toggle_fast_mode,
                                  relief="raised", bd=1, padx=10, pady=1, cursor="hand2")
        self.fast_btn.pack(side="right")

        # --- Active mode indicators ---
        mode_ind = ttk.Frame(self.root, padding=(10, 2, 10, 0))
        mode_ind.pack(fill="x")
        ttk.Label(mode_ind, text="Active modes:").pack(side="left", padx=(0, 5))
        self.fast_ind = tk.Label(mode_ind, text="Fast Mode: OFF", bg="#d0d0d0", fg="#666666", padx=8, pady=2)
        self.fast_ind.pack(side="left", padx=(0, 5))
        self.resolve_ind = tk.Label(mode_ind, text="Resolve Hostname: OFF", bg="#d0d0d0", fg="#666666", padx=8, pady=2)
        self.resolve_ind.pack(side="left")

        # --- Buttons ---
        btn_frame = ttk.Frame(self.root, padding=(10, 0, 10, 5))
        btn_frame.pack(fill="x")

        self.scan_btn = ttk.Button(btn_frame, text="▶ Start Scan", command=self.start_scan)
        self.scan_btn.pack(side="left", padx=(0, 5))

        self.stop_btn = ttk.Button(btn_frame, text="⏹ Stop", command=self.stop_scan, state="disabled")
        self.stop_btn.pack(side="left", padx=5)

        ttk.Button(btn_frame, text="💾 Save CSV", command=self.save_csv).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="🗑 Clear", command=self.clear_results).pack(side="left", padx=5)

        self.info_var = tk.StringVar()
        ttk.Label(self.root, textvariable=self.info_var, foreground="gray").pack(fill="x", padx=10)

        # --- Summary ---
        summary = ttk.Frame(self.root, padding=(10, 5))
        summary.pack(fill="x")
        self.total_var = tk.StringVar(value="Total: 0")
        self.used_var = tk.StringVar(value="● Used: 0")
        self.free_var = tk.StringVar(value="○ Available: 0")
        ttk.Label(summary, textvariable=self.total_var, font=("Segoe UI", 10, "bold")).pack(side="left", padx=10)
        ttk.Label(summary, textvariable=self.used_var, foreground="green", font=("Segoe UI", 10, "bold")).pack(side="left", padx=10)
        ttk.Label(summary, textvariable=self.free_var, foreground="blue", font=("Segoe UI", 10, "bold")).pack(side="left", padx=10)

        self.progress = ttk.Progressbar(self.root, mode="determinate")
        self.progress.pack(fill="x", padx=10, pady=5)

        self.status_var = tk.StringVar(value="Ready.")
        ttk.Label(self.root, textvariable=self.status_var).pack(fill="x", padx=10)

        # --- Results table ---
        table_frame = ttk.Frame(self.root, padding=10)
        table_frame.pack(fill="both", expand=True)

        cols = ("ip", "status", "hostname", "latency")
        self.tree = ttk.Treeview(table_frame, columns=cols, show="headings")
        self.tree.heading("ip", text="IP Address")
        self.tree.heading("status", text="Status")
        self.tree.heading("hostname", text="Hostname")
        self.tree.heading("latency", text="Response (ms)")
        self.tree.column("ip", width=140, anchor="center")
        self.tree.column("status", width=150, anchor="center")
        self.tree.column("hostname", width=260)
        self.tree.column("latency", width=100, anchor="center")

        self.tree.tag_configure("used", foreground="white", background="#2e7d32")
        self.tree.tag_configure("free", foreground="#555555", background="#e8eaf6")

        vsb = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")

    # ---------- Input parsing ----------
    def parse_targets(self, text):
        """Supported formats: 192.168.1.0/24 or 192.168.1.1-50 or 192.168.1.10"""
        text = text.strip()
        if "/" in text:
            net = ipaddress.ip_network(text, strict=False)
            hosts = list(net.hosts())
            if len(hosts) == 0:  # e.g. /31, /32
                hosts = [ipaddress.ip_address(text.split("/")[0])]
            return [str(h) for h in hosts]
        if "-" in text:
            # format: 192.168.1.10-50 or 192.168.1.10-192.168.1.50
            start_s, end_s = [x.strip() for x in text.split("-", 1)]
            if "." not in end_s:
                # end is only the last octet: 192.168.1.10-50
                base = start_s.rsplit(".", 1)[0]
                start_ip = ipaddress.ip_address(start_s)
                end_ip = ipaddress.ip_address(f"{base}.{end_s}")
            else:
                start_ip = ipaddress.ip_address(start_s)
                end_ip = ipaddress.ip_address(end_s)
            if int(end_ip) < int(start_ip):
                raise ValueError("End IP is smaller than start IP.")
            count = int(end_ip) - int(start_ip) + 1
            if count > 2048:
                raise ValueError(f"Range too large ({count} IPs). Max 2048.")
            return [str(ipaddress.ip_address(int(start_ip) + i)) for i in range(count)]
        # single IP
        return [str(ipaddress.ip_address(text))]

    # ---------- Scan ----------
    def toggle_fast_mode(self):
        """Toggle Fastest preset: low timeout + max threads. Shows clear active/off state."""
        if self.scanning:
            self.status_var.set("Stop the scan before changing mode.")
            return
        self.fast_state = not self.fast_state
        if self.fast_state:
            self.timeout_var.set("250")
            self.threads_var.set("254")
        else:
            self.timeout_var.set("300")
            self.threads_var.set("254")
        self.update_mode_indicator()
        if self.fast_state:
            self.status_var.set("Fast Mode ON: 250ms, 254 threads. Press Start Scan.")
        else:
            self.status_var.set("Fast Mode OFF. Press Start Scan.")

    def update_mode_indicator(self):
        """Refresh the ON/OFF indicator chips and Fast Mode button appearance."""
        if self.fast_state:
            self.fast_btn.config(text="⚡ Fast Mode: ACTIVE", bg="#2e7d32", fg="white", activebackground="#245f28")
            self.fast_ind.config(text="Fast Mode: ON", bg="#2e7d32", fg="white")
        else:
            self.fast_btn.config(text="Fast Mode: OFF", bg="#e0e0e0", fg="#333333", activebackground="#c8c8c8")
            self.fast_ind.config(text="Fast Mode: OFF", bg="#d0d0d0", fg="#666666")
        if self.resolve_var.get():
            self.resolve_ind.config(text="Resolve Hostname: ON", bg="#1565c0", fg="white")
        else:
            self.resolve_ind.config(text="Resolve Hostname: OFF", bg="#d0d0d0", fg="#666666")

    def start_scan(self):
        if self.scanning:
            return
        try:
            targets = self.parse_targets(self.network_var.get())
        except Exception as e:
            messagebox.showerror("Invalid input", f"Cannot parse network/range:\n{e}")
            return
        try:
            timeout_ms = int(self.timeout_var.get())
            n_threads = int(self.threads_var.get())
        except ValueError:
            messagebox.showerror("Invalid input", "Timeout and Threads must be numbers.")
            return
        n_threads = max(1, min(n_threads, 500))
        timeout_ms = max(100, min(timeout_ms, 5000))

        if len(targets) > 1024:
            ok = messagebox.askyesno(
                "Large range",
                f"There are {len(targets)} IPs, scan may take a while. Continue?",
            )
            if not ok:
                return

        self.tree.delete(*self.tree.get_children())
        self.results = []
        self.stop_event.clear()
        self.scanning = True
        self.scan_btn.config(state="disabled")
        self.stop_btn.config(state="normal")
        self.progress.config(maximum=len(targets), value=0)
        self.status_var.set(f"Scanning {len(targets)} IPs...")

        t = threading.Thread(target=self._scan_worker, args=(targets, timeout_ms, n_threads), daemon=True)
        t.start()

    def _scan_worker(self, targets, timeout_ms, n_threads):
        t0 = time.time()
        done = 0
        used = 0
        do_resolve = self.resolve_var.get()
        with ThreadPoolExecutor(max_workers=n_threads) as ex:
            future_to_ip = {ex.submit(ping_host, ip, timeout_ms): ip for ip in targets}
            for fut in as_completed(future_to_ip):
                if self.stop_event.is_set():
                    ex.shutdown(wait=False, cancel_futures=True)
                    break
                ip = future_to_ip[fut]
                try:
                    is_used, latency = fut.result()
                except Exception:
                    is_used, latency = False, None
                # Do NOT resolve hostname here - this is the main slowdown!
                # Set "-" first, resolve later only for Used IPs if the user opts in.
                hostname = "-"
                status = "Used" if is_used else "Available"
                if is_used:
                    used += 1
                self.results.append({"ip": ip, "status": status, "hostname": hostname, "latency": latency})
                done += 1
                # update UI from main thread
                self.root.after(0, self._update_row, ip, status, hostname, latency, done, len(targets), used, t0)

        # After ping completes, resolve hostnames for Used IPs only (parallel, background)
        if do_resolve and not self.stop_event.is_set():
            used_ips = [r["ip"] for r in self.results if "Used" in r["status"]]
            if used_ips:
                self.root.after(0, lambda: self.status_var.set(f"Resolving {len(used_ips)} hostnames..."))
                with ThreadPoolExecutor(max_workers=20) as rex:
                    rmap = {rex.submit(resolve_hostname, ip): ip for ip in used_ips}
                    for rf in as_completed(rmap):
                        if self.stop_event.is_set():
                            break
                        ip = rmap[rf]
                        try:
                            hn = rf.result()
                        except Exception:
                            hn = "-"
                        for r in self.results:
                            if r["ip"] == ip:
                                r["hostname"] = hn
                                break
                        self.root.after(0, self._update_hostname_row, ip, hn)

        self.root.after(0, self._scan_finished, done, len(targets), t0)

    def _update_row(self, ip, status, hostname, latency, done, total, used, t0):
        tag = "used" if "Used" in status else "free"
        lat = f"{latency}" if latency is not None else "-"
        self.tree.insert("", "end", values=(ip, status, hostname, lat), tags=(tag,))
        self.progress.config(value=done)
        self.total_var.set(f"Total: {done}/{total}")
        self.used_var.set(f"● Used: {used}")
        self.free_var.set(f"○ Available: {done - used}")
        el = time.time() - t0
        self.status_var.set(f"Scanning... {done}/{total} ({el:.1f}s)")

    def _update_hostname_row(self, ip, hostname):
        for row in self.tree.get_children():
            vals = self.tree.item(row, "values")
            if vals and vals[0] == ip:
                self.tree.item(row, values=(vals[0], vals[1], hostname, vals[3]))
                break

    def _scan_finished(self, done, total, t0):
        self.scanning = False
        self.scan_btn.config(state="normal")
        self.stop_btn.config(state="disabled")
        if self.stop_event.is_set():
            self.status_var.set(f"Stopped. Finished {done}/{total} IPs in {time.time()-t0:.1f}s.")
        else:
            self.status_var.set(f"Done! Scanned {done} IPs in {time.time()-t0:.1f}s.")
            # sort: Used first, then by IP
            for row in self.tree.get_children():
                self.tree.delete(row)
            sorted_res = sorted(self.results, key=lambda r: (0 if "Used" in r["status"] else 1, ipaddress.ip_address(r["ip"])))
            for r in sorted_res:
                tag = "used" if "Used" in r["status"] else "free"
                lat = f"{r['latency']}" if r["latency"] is not None else "-"
                self.tree.insert("", "end", values=(r["ip"], r["status"], r["hostname"], lat), tags=(tag,))

    def stop_scan(self):
        self.stop_event.set()
        self.status_var.set("Stopping...")

    def clear_results(self):
        if self.scanning:
            messagebox.showwarning("Scan running", "Stop the scan before clearing.")
            return
        self.tree.delete(*self.tree.get_children())
        self.results = []
        self.progress.config(value=0)
        self.total_var.set("Total: 0")
        self.used_var.set("● Used: 0")
        self.free_var.set("○ Available: 0")
        self.status_var.set("Ready.")

    def save_csv(self):
        if not self.results:
            messagebox.showinfo("Empty", "No scan results yet.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV", "*.csv")], initialfile="ip_scan_results.csv")
        if not path:
            return
        try:
            import csv
            sorted_res = sorted(self.results, key=lambda r: ipaddress.ip_address(r["ip"]))
            with open(path, "w", newline="", encoding="utf-8") as f:
                w = csv.DictWriter(f, fieldnames=["ip", "status", "hostname", "latency"])
                w.writeheader()
                w.writerows(sorted_res)
            messagebox.showinfo("Success", f"Saved to:\n{path}")
        except Exception as e:
            messagebox.showerror("Failed", str(e))


if __name__ == "__main__":
    root = tk.Tk()
    app = IPScannerApp(root)
    root.mainloop()
