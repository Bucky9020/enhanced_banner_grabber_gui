#!/usr/bin/env python3
"""
enhanced_banner_grabber_gui.py
Enhanced Banner Grabber + Lightweight Port Scanner with GUI (Tkinter) and CLI.
Features:
 - Smart probes for HTTP/HTTPS/SMTP/FTP/MySQL
 - Per-port probes and retries
 - Timeout, retry, delay, rate limiting, thread control
 - Outputs: CSV, JSON (pretty), summary
 - Simple Tkinter GUI: enter host or upload file, start scan, view table, export results
 - Offline, uses only Python standard library
"""
import argparse
import csv
import html
import json
import os
import re
import socket
import ssl
import sys
import threading
import time
from queue import Queue
try:
    import tkinter as tk
    from tkinter import ttk, filedialog, messagebox
    GUI_AVAILABLE = True
except Exception:
    GUI_AVAILABLE = False

VERSION = "2.0"

COMMON_PORTS = [21,22,23,25,53,80,110,111,135,139,143,443,445,587,993,995,3306,3389,8080]

DEFAULT_PROBES = {
    80: b"GET / HTTP/1.0\r\nHost: %b\r\nUser-Agent: banner-grabber/2.0\r\n\r\n",
    8080: b"GET / HTTP/1.0\r\nHost: %b\r\nUser-Agent: banner-grabber/2.0\r\n\r\n",
    443: b"GET / HTTP/1.0\r\nHost: %b\r\nUser-Agent: banner-grabber/2.0\r\n\r\n",
    25: b"EHLO example.com\r\n",
    587: b"EHLO example.com\r\n",
    21: b"QUIT\r\n",
    110: b"\r\n",
    143: b"\r\n",
}

def parse_ports(ports_arg):
    ports = set()
    if not ports_arg:
        return set(COMMON_PORTS)
    parts = str(ports_arg).split(',')
    for p in parts:
        p = p.strip()
        if not p:
            continue
        if '-' in p:
            try:
                a,b = p.split('-',1)
                a=int(a); b=int(b)
                for i in range(max(1,a), min(65535,b)+1):
                    ports.add(i)
            except ValueError:
                continue
        else:
            try:
                ports.add(int(p))
            except ValueError:
                continue
    return set(sorted(ports))

def _try_recv(sock, num=4096):
    try:
        data = sock.recv(num)
        if not data:
            return b""
        return data
    except socket.timeout:
        return b""
    except Exception:
        return b""

def clean_mysql_banner(raw):
    # Attempt to extract readable ascii and version patterns
    try:
        s = raw.decode(errors='replace')
    except Exception:
        s = repr(raw)
    # common mysql pattern: version number like 5.7.23 or 8.0.XX
    m = re.search(r'(\d+\.\d+\.\d+)', s)
    if m:
        return s[m.start():].splitlines()[0]
    # fallback: strip non-printables
    return ''.join(ch for ch in s if 32 <= ord(ch) <= 126)[:200]

def extract_http_info(text):
    # parse status line and headers, and first <title>
    try:
        s = text if isinstance(text, str) else text.decode(errors='replace')
    except Exception:
        s = str(text)
    headers = {}
    body = ""
    parts = re.split(r'\r\n\r\n', s, maxsplit=1)
    hdr = parts[0]
    hdr_lines = hdr.splitlines()
    status = hdr_lines[0] if hdr_lines else ""
    for ln in hdr_lines[1:]:
        if ':' in ln:
            k,v = ln.split(':',1)
            headers[k.strip()] = v.strip()
    if len(parts) > 1:
        body = parts[1][:8192]  # first 8KB
        # try to find title
        m = re.search(r'<title[^>]*>(.*?)</title>', body, re.IGNORECASE|re.DOTALL)
        title = html.unescape(m.group(1).strip()) if m else ""
    else:
        title = ""
    return status, headers, title

def banner_for_target(host, port, timeout=6, send_bytes=None, use_ssl=False, retries=1):
    try:
        addrinfo = socket.getaddrinfo(host, port, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM)
    except Exception as e:
        return False, f"DNS/resolve error: {e}"
    last_err = None
    for family, socktype, proto, canonname, sockaddr in addrinfo:
        for attempt in range(max(1, retries)):
            s = None
            try:
                s = socket.socket(family, socktype, proto)
                s.settimeout(timeout)
                s.connect(sockaddr)
                need_ssl = use_ssl or port in (443, 8443)
                if need_ssl:
                    try:
                        ctx = ssl.create_default_context()
                        s = ctx.wrap_socket(s, server_hostname=host)
                    except Exception:
                        pass
                data = _try_recv(s, 4096)
                if data:
                    # post-process for some known services
                    if port in (80,8080,443):
                        status, headers, title = extract_http_info(data)
                        banner_text = status + ("\n" + "\n".join(f"{k}: {v}" for k,v in headers.items()) if headers else "") + (("\nTitle: " + title) if title else "")
                        return True, banner_text.strip()
                    if port == 3306:
                        return True, clean_mysql_banner(data)
                    # generic
                    try:
                        return True, data.decode(errors='replace').strip()
                    except Exception:
                        return True, repr(data)
                # no passive data: try probe
                probe = None
                if send_bytes:
                    probe = send_bytes
                else:
                    if port in DEFAULT_PROBES:
                        raw = DEFAULT_PROBES[port]
                        if b"%b" in raw:
                            probe = raw.replace(b"%b", host.encode())
                        else:
                            probe = raw
                if probe:
                    try:
                        s.sendall(probe)
                    except Exception:
                        pass
                    data = _try_recv(s, 8192)
                    if data:
                        if port in (80,8080,443):
                            status, headers, title = extract_http_info(data)
                            banner_text = status + ("\n" + "\n".join(f"{k}: {v}" for k,v in headers.items()) if headers else "") + (("\nTitle: " + title) if title else "")
                            return True, banner_text.strip()
                        if port == 3306:
                            return True, clean_mysql_banner(data)
                        try:
                            return True, data.decode(errors='replace').strip()
                        except Exception:
                            return True, repr(data)
                    else:
                        return True, "<no banner (after probe)>"
                return True, "<no banner>"
            except socket.timeout:
                last_err = "timeout"
                if s:
                    try: s.close()
                    except: pass
                continue
            except ConnectionRefusedError as e:
                last_err = e
                if s:
                    try: s.close()
                    except: pass
                break
            except Exception as e:
                last_err = e
                if s:
                    try: s.close()
                    except: pass
                continue
            finally:
                try:
                    if s:
                        s.close()
                except Exception:
                    pass
    return False, f"connect error: {last_err}"

class ScanWorker(threading.Thread):
    def __init__(self, q, results, args, lock):
        super().__init__(daemon=True)
        self.q = q
        self.results = results
        self.args = args
        self.lock = lock

    def run(self):
        while True:
            try:
                host, port = self.q.get(block=False)
            except Exception:
                return
            try:
                probe = None
                if self.args.probe and self.args.probe.lower() == "http":
                    probe = b"GET / HTTP/1.0\r\nHost: %b\r\n\r\n" % host.encode()
                elif self.args.probe:
                    probe = self.args.probe.encode()
                use_ssl = self.args.ssl or port in (443,8443)
                ok, banner = banner_for_target(host, port, timeout=self.args.timeout, send_bytes=probe, use_ssl=use_ssl, retries=self.args.retry)
                entry = {"host": host, "port": port, "open": bool(ok), "banner": banner}
                with self.lock:
                    self.results.append(entry)
                if self.args.verbose:
                    status = "OPEN" if ok else "CLOSED/ERR"
                    print(f"[{status}] {host}:{port} -> {banner}")
                if self.args.delay:
                    time.sleep(self.args.delay)
            except Exception as e:
                if self.args.verbose:
                    print(f"[ERROR] {host}:{port} -> {e}")
            finally:
                self.q.task_done()

def load_hosts(path):
    hosts = []
    with open(path, "r", encoding="utf-8") as f:
        for ln in f:
            ln = ln.strip()
            if not ln or ln.startswith("#"):
                continue
            hosts.append(ln)
    return hosts

def run_scan(hosts, ports, args):
    q = Queue()
    results = []
    lock = threading.Lock()
    for host in hosts:
        for p in ports:
            q.put((host, p))
    num_threads = max(1, min(args.threads, q.qsize()))
    workers = []
    for _ in range(num_threads):
        w = ScanWorker(q, results, args, lock)
        w.start()
        workers.append(w)
    try:
        q.join()
    except KeyboardInterrupt:
        print("Interrupted by user.")
        time.sleep(0.2)
    return results

def summarize(results):
    summary = {}
    for r in results:
        host = r["host"]
        if host not in summary:
            summary[host] = {"open_ports": [], "count": 0}
        if r.get("open"):
            summary[host]["open_ports"].append(r["port"])
        summary[host]["count"] += 1
    return summary

def save_outputs(results, args):
    if args.json:
        out = args.output if args.output else None
        if out:
            try:
                with open(out, "w", encoding="utf-8") as fh:
                    if args.pretty:
                        json.dump(results, fh, indent=2, ensure_ascii=False)
                    else:
                        json.dump(results, fh, ensure_ascii=False)
                print(f"Saved JSON -> {out}")
            except Exception as e:
                print("Could not write JSON:", e)
        else:
            if args.pretty:
                print(json.dumps(results, indent=2, ensure_ascii=False))
            else:
                print(json.dumps(results, ensure_ascii=False))
    elif args.output:
        try:
            with open(args.output, "w", newline='', encoding="utf-8") as csvfile:
                fieldnames = ["host","port","open","banner"]
                w = csv.DictWriter(csvfile, fieldnames=fieldnames)
                w.writeheader()
                for r in results:
                    w.writerow(r)
            print(f"Saved CSV -> {args.output}")
        except Exception as e:
            print("Could not write CSV:", e)
    else:
        for r in results:
            status = "OPEN" if r.get("open") else "CLOSED/ERR"
            print(f"{status:10s} {r['host']:30s} {r['port']:5d}  -> {r['banner']}")

# ----------------------
# CLI entrypoint
# ----------------------
def cli_main():
    parser = argparse.ArgumentParser(description="Enhanced banner grabber + GUI (offline).")
    parser.add_argument("-t","--target", help="Target host (single)", default=None)
    parser.add_argument("-f","--file", help="File with hosts (one per line)", default=None)
    parser.add_argument("-p","--ports", help="Comma-separated ports or ranges", dest="ports", default=None)
    parser.add_argument("--portrange", help="Deprecated alias for -p", default=None)
    parser.add_argument("-T","--threads", help="Worker threads (default 40)", type=int, default=40)
    parser.add_argument("-o","--output", help="Output CSV/JSON file (optional)", default=None)
    parser.add_argument("--json", help="Output JSON (stdout or file)", action="store_true")
    parser.add_argument("--pretty", help="Pretty-print JSON", action="store_true")
    parser.add_argument("--timeout", help="Timeout seconds (default 6)", type=float, default=6.0)
    parser.add_argument("--retry", help="Retries per address (default 1)", type=int, default=1)
    parser.add_argument("--delay", help="Delay seconds between probes per worker (default 0)", type=float, default=0.0)
    parser.add_argument("--probe", help="Optional probe (http or raw string)", default=None)
    parser.add_argument("--ssl", help="Force SSL/TLS", action="store_true")
    parser.add_argument("--verbose", help="Verbose", action="store_true")
    parser.add_argument("--version", action="store_true")
    args = parser.parse_args()

    if args.version:
        print("enhanced_banner_grabber", VERSION)
        sys.exit(0)

    hosts = []
    if args.target:
        hosts.append(args.target)
    if args.file:
        hosts.extend(load_hosts(args.file))
    if not hosts:
        parser.print_help()
        print("\\nError: specify --target or --file")
        sys.exit(1)

    ports_arg = args.ports if args.ports else args.portrange
    ports = parse_ports(ports_arg)
    if not ports:
        ports = set(COMMON_PORTS)

    results = run_scan(hosts, ports, args)
    s = summarize(results)
    print(f"Done. Scanned {len(hosts)} host(s) * {len(ports)} port(s). Open-ish summary:")
    for h, info in s.items():
        print(f" - {h}: open ports: {sorted(info['open_ports'])} / scanned: {info['count']}")
    save_outputs(results, args)

# ----------------------
# Simple GUI
# ----------------------
class SimpleGUI:
    def __init__(self, root):
        self.root = root
        self.root.title(f"Enhanced Banner Grabber v{VERSION}")
        self.root.geometry("1000x700")
        self._build()

    def _build(self):
        frm_top = ttk.Frame(self.root, padding=6)
        frm_top.pack(fill=tk.X)

        ttk.Label(frm_top, text="Target (host) or choose hosts file:").pack(side=tk.LEFT)
        self.target_var = tk.StringVar()
        ttk.Entry(frm_top, textvariable=self.target_var, width=40).pack(side=tk.LEFT, padx=6)
        ttk.Button(frm_top, text="Load hosts file", command=self.load_hosts_file).pack(side=tk.LEFT)

        ttk.Label(frm_top, text="Ports (e.g. 22,80 or 1-1024)").pack(side=tk.LEFT, padx=6)
        self.ports_var = tk.StringVar(value=",".join(str(x) for x in COMMON_PORTS))
        ttk.Entry(frm_top, textvariable=self.ports_var, width=30).pack(side=tk.LEFT)

        opts = ttk.Frame(self.root, padding=6)
        opts.pack(fill=tk.X)
        self.threads_var = tk.IntVar(value=40)
        ttk.Label(opts, text="Threads:").pack(side=tk.LEFT)
        ttk.Entry(opts, textvariable=self.threads_var, width=6).pack(side=tk.LEFT, padx=4)
        self.timeout_var = tk.DoubleVar(value=6.0)
        ttk.Label(opts, text="Timeout(s):").pack(side=tk.LEFT)
        ttk.Entry(opts, textvariable=self.timeout_var, width=6).pack(side=tk.LEFT, padx=4)
        self.retry_var = tk.IntVar(value=1)
        ttk.Label(opts, text="Retries:").pack(side=tk.LEFT)
        ttk.Entry(opts, textvariable=self.retry_var, width=4).pack(side=tk.LEFT, padx=4)
        self.delay_var = tk.DoubleVar(value=0.0)
        ttk.Label(opts, text="Delay(s):").pack(side=tk.LEFT)
        ttk.Entry(opts, textvariable=self.delay_var, width=6).pack(side=tk.LEFT, padx=4)
        self.probe_var = tk.StringVar(value="")
        ttk.Label(opts, text="Probe:").pack(side=tk.LEFT)
        ttk.Entry(opts, textvariable=self.probe_var, width=20).pack(side=tk.LEFT, padx=4)
        self.ssl_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(opts, text="Force SSL", variable=self.ssl_var).pack(side=tk.LEFT, padx=6)
        self.verbose_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(opts, text="Verbose", variable=self.verbose_var).pack(side=tk.LEFT, padx=6)

        ctrl = ttk.Frame(self.root, padding=6)
        ctrl.pack(fill=tk.X)
        ttk.Button(ctrl, text="Start Scan", command=self.start_scan).pack(side=tk.LEFT, padx=6)
        ttk.Button(ctrl, text="Stop Scan", command=self.stop_scan).pack(side=tk.LEFT, padx=6)
        ttk.Button(ctrl, text="Export CSV", command=self.export_csv).pack(side=tk.LEFT, padx=6)
        ttk.Button(ctrl, text="Export JSON", command=self.export_json).pack(side=tk.LEFT, padx=6)
        ttk.Button(ctrl, text="Clear Results", command=self.clear_results).pack(side=tk.LEFT, padx=6)

        # Results tree
        cols = ("host","port","open","banner")
        self.tree = ttk.Treeview(self.root, columns=cols, show="headings")
        for c in cols:
            self.tree.heading(c, text=c)
            self.tree.column(c, width=200 if c=="banner" else 120, anchor=tk.W)
        self.tree.pack(fill=tk.BOTH, expand=True, padx=6, pady=6)

        # status
        self.status_var = tk.StringVar(value="Ready")
        ttk.Label(self.root, textvariable=self.status_var, relief=tk.SUNKEN).pack(side=tk.BOTTOM, fill=tk.X)

        # internal
        self._scan_thread = None
        self._stop_event = threading.Event()
        self._results = []

    def load_hosts_file(self):
        path = filedialog.askopenfilename(title="Select hosts file", filetypes=[("Text","*.txt"),("All","*.*")])
        if not path:
            return
        hosts = load_hosts(path)
        if hosts:
            messagebox.showinfo("Hosts loaded", f"Loaded {len(hosts)} hosts from {os.path.basename(path)}")
            # place first host in entry; user can run file mode by leaving blank and setting file later
            self.target_var.set(hosts[0])

    def start_scan(self):
        if self._scan_thread and self._scan_thread.is_alive():
            messagebox.showinfo("Scan running", "A scan is already running.")
            return
        target = self.target_var.get().strip()
        file_hosts = None
        if not target:
            # ask to pick file
            file_hosts = filedialog.askopenfilename(title="Select hosts file", filetypes=[("Text","*.txt"),("All","*.*")])
            if not file_hosts:
                messagebox.showinfo("Input required", "Enter a target host or choose a hosts file.")
                return
        ports_arg = self.ports_var.get().strip()
        ports = parse_ports(ports_arg)
        args = argparse.Namespace()
        args.threads = int(self.threads_var.get())
        args.timeout = float(self.timeout_var.get())
        args.retry = int(self.retry_var.get())
        args.delay = float(self.delay_var.get())
        args.probe = self.probe_var.get().strip() or None
        args.ssl = bool(self.ssl_var.get())
        args.verbose = bool(self.verbose_var.get())
        hosts = [target] if target else load_hosts(file_hosts)
        # prepare queue and launch in thread
        self._results = []
        self.tree.delete(*self.tree.get_children())
        self._stop_event.clear()
        self._scan_thread = threading.Thread(target=self._scan_runner, args=(hosts, ports, args), daemon=True)
        self._scan_thread.start()
        self.status_var.set("Scan started...")

    def _scan_runner(self, hosts, ports, args):
        q = Queue()
        lock = threading.Lock()
        for h in hosts:
            for p in ports:
                q.put((h,p))
        num_threads = max(1, min(args.threads, q.qsize()))
        workers = []
        for _ in range(num_threads):
            w = ScanWorker(q, self._results, args, lock)
            w.start()
            workers.append(w)
        try:
            while any(w.is_alive() for w in workers):
                # update tree with new results
                self._update_tree()
                time.sleep(0.5)
                if self._stop_event.is_set():
                    break
            q.join(timeout=0.1)
        except Exception:
            pass
        self._update_tree(final=True)
        s = summarize(self._results)
        summary_lines = []
        for h, info in s.items():
            summary_lines.append(f"{h}: open {sorted(info['open_ports'])} (scanned {info['count']})")
        self.status_var.set("Done. " + " | ".join(summary_lines[:3]))
        return

    def _update_tree(self, final=False):
        # clear and re-add (simple approach)
        self.tree.delete(*self.tree.get_children())
        for r in self._results:
            self.tree.insert("", tk.END, values=(r["host"], r["port"], "OPEN" if r.get("open") else "CLOSED", (r["banner"][:200] + "...") if len(r["banner"])>200 else r["banner"]))
        if final:
            self.tree.yview_moveto(1.0)

    def stop_scan(self):
        if self._scan_thread and self._scan_thread.is_alive():
            self._stop_event.set()
            self.status_var.set("Stop requested. Waiting threads to finish...")
        else:
            messagebox.showinfo("No scan", "No scan is currently running.")

    def export_csv(self):
        if not self._results:
            messagebox.showinfo("No results", "No results to export.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV","*.csv"),("All","*.*")])
        if not path:
            return
        try:
            with open(path, "w", newline='', encoding="utf-8") as fh:
                w = csv.DictWriter(fh, fieldnames=["host","port","open","banner"])
                w.writeheader()
                for r in self._results:
                    w.writerow(r)
            messagebox.showinfo("Saved", f"CSV saved: {path}")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def export_json(self):
        if not self._results:
            messagebox.showinfo("No results", "No results to export.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON","*.json"),("All","*.*")])
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(self._results, fh, indent=2, ensure_ascii=False)
            messagebox.showinfo("Saved", f"JSON saved: {path}")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def clear_results(self):
        self._results = []
        self.tree.delete(*self.tree.get_children())
        self.status_var.set("Cleared.")

def gui_main():
    if not GUI_AVAILABLE:
        print("Tkinter GUI not available on this system.")
        sys.exit(1)
    root = tk.Tk()
    app = SimpleGUI(root)
    root.mainloop()

if __name__ == "__main__":
    # If run with --gui flag, show GUI; else CLI
    if "--gui" in sys.argv or not GUI_AVAILABLE:
        gui_main()
    else:
        cli_main()
