"""Tkinter GUI: live packet table, activity graph, protocol mix and top talkers."""

import tkinter as tk
from collections import OrderedDict
from datetime import datetime
from tkinter import filedialog, messagebox, ttk

from .capture import CaptureEngine, list_interfaces
from .exporter import save_csv, save_pcap
from .parser import PROTOCOLS, PacketRecord
from .stats import TrafficStats, human_bytes

COLORS = {
    "TCP": "#e7e6ff", "HTTP": "#e4ffc7", "HTTPS": "#d4f5e0", "UDP": "#daeeff",
    "DNS": "#fff6c2", "ICMP": "#fce0ff", "ARP": "#fae0d4", "SSH": "#e0f0f0",
    "DHCP": "#e9e9e9", "NTP": "#f0f0d8", "ICMPv6": "#fce0ff", "IPv6": "#e9e9e9",
}
BAR_COLORS = {
    "TCP": "#7b6cf6", "HTTP": "#6cc24a", "HTTPS": "#2fa36b", "UDP": "#3b8de0",
    "DNS": "#e0b400", "ICMP": "#c25bd6", "ARP": "#e07b4a", "SSH": "#3aa0a0",
}
DEFAULT_BAR = "#8a8a8a"

MAX_TABLE_ROWS = 3000     # rows kept in the visible table
MAX_RECORDS = 10000       # packets kept in memory (for save / detail / filter)
MAX_PER_TICK = 400        # packets processed per GUI refresh (keeps UI responsive)
REFRESH_MS = 100


class MonitorApp(tk.Tk):
    def __init__(self, simulate: bool = False, iface: str = "", bpf: str = ""):
        super().__init__()
        self.title("Real-Time Network Traffic Monitor")
        self.geometry("1300x780")
        self.minsize(1000, 600)

        self.engine = None
        self.stats = TrafficStats()
        self.records: "OrderedDict[int, PacketRecord]" = OrderedDict()

        self.var_iface = tk.StringVar(value=iface)
        self.var_bpf = tk.StringVar(value=bpf)
        self.var_sim = tk.BooleanVar(value=simulate)
        self.var_proto = tk.StringVar(value="All")
        self.var_search = tk.StringVar()
        self.var_autoscroll = tk.BooleanVar(value=True)
        self.var_status = tk.StringVar(value="Stopped")

        self._build_ui()
        self.after(REFRESH_MS, self._tick)
        self.after(1000, self._redraw_panels)
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    # ------------------------------------------------------------------- layout
    def _build_ui(self):
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure("Treeview", rowheight=22, font=("Consolas", 10))
        style.configure("Treeview.Heading", font=("Segoe UI", 10, "bold"))
        style.configure("Big.TLabel", font=("Segoe UI", 18, "bold"))

        bar = ttk.Frame(self, padding=6)
        bar.pack(fill="x")
        ttk.Label(bar, text="Interface:").pack(side="left")
        ifaces = [""] + list_interfaces()
        self.cmb_iface = ttk.Combobox(bar, textvariable=self.var_iface, values=ifaces, width=22)
        self.cmb_iface.pack(side="left", padx=(2, 10))
        ttk.Label(bar, text="Capture filter (BPF):").pack(side="left")
        ttk.Entry(bar, textvariable=self.var_bpf, width=20).pack(side="left", padx=(2, 10))
        ttk.Checkbutton(bar, text="Demo mode (simulated traffic)",
                        variable=self.var_sim).pack(side="left", padx=(0, 10))
        self.btn_start = ttk.Button(bar, text="▶ Start", command=self.start_capture)
        self.btn_start.pack(side="left", padx=2)
        self.btn_stop = ttk.Button(bar, text="■ Stop", command=self.stop_capture, state="disabled")
        self.btn_stop.pack(side="left", padx=2)
        ttk.Button(bar, text="Clear", command=self.clear).pack(side="left", padx=2)
        ttk.Button(bar, text="Save CSV", command=self.save_csv).pack(side="left", padx=(12, 2))
        ttk.Button(bar, text="Save PCAP", command=self.save_pcap).pack(side="left", padx=2)

        bar2 = ttk.Frame(self, padding=(6, 0, 6, 6))
        bar2.pack(fill="x")
        ttk.Label(bar2, text="Show protocol:").pack(side="left")
        cmb = ttk.Combobox(bar2, textvariable=self.var_proto, values=["All"] + PROTOCOLS,
                           width=9, state="readonly")
        cmb.pack(side="left", padx=(2, 10))
        cmb.bind("<<ComboboxSelected>>", lambda e: self._refresh_table())
        ttk.Label(bar2, text="Search (IP / text):").pack(side="left")
        ent = ttk.Entry(bar2, textvariable=self.var_search, width=24)
        ent.pack(side="left", padx=(2, 10))
        ent.bind("<KeyRelease>", lambda e: self._refresh_table())
        ttk.Checkbutton(bar2, text="Auto-scroll", variable=self.var_autoscroll).pack(side="left")

        main = ttk.PanedWindow(self, orient="horizontal")
        main.pack(fill="both", expand=True, padx=6)

        # ---- left: packet table + details
        left = ttk.PanedWindow(main, orient="vertical")
        main.add(left, weight=4)

        table_frame = ttk.Frame(left)
        cols = ("no", "time", "src", "dst", "proto", "len", "info")
        self.tree = ttk.Treeview(table_frame, columns=cols, show="headings", selectmode="browse")
        for col, text, width, anchor in [
            ("no", "No.", 60, "e"), ("time", "Time", 100, "w"), ("src", "Source", 150, "w"),
            ("dst", "Destination", 150, "w"), ("proto", "Protocol", 70, "w"),
            ("len", "Length", 65, "e"), ("info", "Info / Activity", 460, "w")]:
            self.tree.heading(col, text=text)
            self.tree.column(col, width=width, anchor=anchor, stretch=(col == "info"))
        for proto, color in COLORS.items():
            self.tree.tag_configure(proto, background=color)
        vsb = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree.yview)
        hsb = ttk.Scrollbar(table_frame, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        table_frame.rowconfigure(0, weight=1)
        table_frame.columnconfigure(0, weight=1)
        left.add(table_frame, weight=3)
        self.tree.bind("<<TreeviewSelect>>", self._show_details)

        detail_frame = ttk.LabelFrame(left, text="Packet details (select a row)")
        self.txt_detail = tk.Text(detail_frame, height=9, font=("Consolas", 9), wrap="none")
        dsb = ttk.Scrollbar(detail_frame, command=self.txt_detail.yview)
        self.txt_detail.configure(yscrollcommand=dsb.set)
        self.txt_detail.pack(side="left", fill="both", expand=True)
        dsb.pack(side="right", fill="y")
        left.add(detail_frame, weight=1)

        # ---- right: statistics
        right = ttk.Frame(main, padding=(8, 0, 0, 0))
        main.add(right, weight=1)

        tiles = ttk.Frame(right)
        tiles.pack(fill="x")
        self.lbl_total = self._tile(tiles, "Packets", 0, 0)
        self.lbl_bytes = self._tile(tiles, "Data", 0, 1)
        self.lbl_pps = self._tile(tiles, "Packets/s", 1, 0)
        self.lbl_bps = self._tile(tiles, "Speed", 1, 1)
        tiles.columnconfigure((0, 1), weight=1)

        ttk.Label(right, text="Packets per second (last 60 s)",
                  font=("Segoe UI", 10, "bold")).pack(anchor="w", pady=(10, 2))
        self.cv_graph = tk.Canvas(right, height=140, bg="white", highlightthickness=1,
                                  highlightbackground="#cccccc")
        self.cv_graph.pack(fill="x")

        ttk.Label(right, text="Protocol distribution",
                  font=("Segoe UI", 10, "bold")).pack(anchor="w", pady=(10, 2))
        self.cv_proto = tk.Canvas(right, height=190, bg="white", highlightthickness=1,
                                  highlightbackground="#cccccc")
        self.cv_proto.pack(fill="x")

        ttk.Label(right, text="Top talkers (by bytes sent)",
                  font=("Segoe UI", 10, "bold")).pack(anchor="w", pady=(10, 2))
        self.lst_talkers = tk.Listbox(right, height=6, font=("Consolas", 9))
        self.lst_talkers.pack(fill="x")

        status = ttk.Frame(self, padding=4)
        status.pack(fill="x", side="bottom")
        ttk.Label(status, textvariable=self.var_status).pack(side="left")
        self.lbl_clock = ttk.Label(status, text="")
        self.lbl_clock.pack(side="right")

    def _tile(self, parent, caption, row, col):
        f = ttk.Frame(parent, padding=6, relief="groove")
        f.grid(row=row, column=col, sticky="nsew", padx=2, pady=2)
        ttk.Label(f, text=caption).pack(anchor="w")
        lbl = ttk.Label(f, text="0", style="Big.TLabel")
        lbl.pack(anchor="w")
        return lbl

    # ------------------------------------------------------------------ control
    def start_capture(self):
        if self.engine and self.engine.running:
            return
        self.engine = CaptureEngine(iface=self.var_iface.get(), bpf=self.var_bpf.get(),
                                    simulate=self.var_sim.get())
        self.engine.reset_counter()
        self.engine.start()
        self.btn_start.config(state="disabled")
        self.btn_stop.config(state="normal")
        mode = "DEMO traffic" if self.var_sim.get() else (self.var_iface.get() or "default interface")
        self.var_status.set(f"Capturing on {mode} ...")

    def stop_capture(self):
        if self.engine:
            self.engine.stop()
        self.btn_start.config(state="normal")
        self.btn_stop.config(state="disabled")
        self.var_status.set(f"Stopped - {self.stats.total_packets} packets captured")

    def clear(self):
        self.tree.delete(*self.tree.get_children())
        self.records.clear()
        self.stats.reset()
        self.txt_detail.delete("1.0", "end")
        if self.engine:
            while not self.engine.packets.empty():
                try:
                    self.engine.packets.get_nowait()
                except Exception:
                    break
            self.engine.reset_counter()
        self._redraw_panels(schedule=False)

    # --------------------------------------------------------------- live update
    def _matches(self, rec: PacketRecord) -> bool:
        proto = self.var_proto.get()
        if proto != "All" and rec.protocol != proto:
            return False
        q = self.var_search.get().strip().lower()
        if q and q not in rec.src.lower() and q not in rec.dst.lower() \
                and q not in rec.info.lower() and q not in rec.protocol.lower():
            return False
        return True

    def _insert_row(self, rec: PacketRecord):
        self.tree.insert("", "end", iid=str(rec.no), tags=(rec.protocol,),
                         values=(rec.no, rec.time_str, rec.src, rec.dst,
                                 rec.protocol, rec.length, rec.info))

    def _tick(self):
        engine = self.engine
        if engine:
            added = False
            for _ in range(MAX_PER_TICK):
                try:
                    rec = engine.packets.get_nowait()
                except Exception:
                    break
                self.stats.add(rec)
                self.records[rec.no] = rec
                if len(self.records) > MAX_RECORDS:
                    self.records.popitem(last=False)
                if self._matches(rec):
                    self._insert_row(rec)
                    added = True
            if added:
                children = self.tree.get_children()
                extra = len(children) - MAX_TABLE_ROWS
                if extra > 0:
                    self.tree.delete(*children[:extra])
                if self.var_autoscroll.get():
                    last = self.tree.get_children()
                    if last:
                        self.tree.see(last[-1])
            try:
                err = engine.errors.get_nowait()
            except Exception:
                err = None
            if err:
                self.stop_capture()
                self.var_status.set("Error - capture stopped")
                messagebox.showerror("Capture error", err + "\n\nTip: tick 'Demo mode' to "
                                     "run the project without administrator rights.")
        self.after(REFRESH_MS, self._tick)

    def _refresh_table(self):
        self.tree.delete(*self.tree.get_children())
        # rebuild in chronological order for the newest MAX_TABLE_ROWS matches
        matches = [r for r in self.records.values() if self._matches(r)][-MAX_TABLE_ROWS:]
        for rec in matches:
            self._insert_row(rec)

    def _show_details(self, _event=None):
        sel = self.tree.selection()
        if not sel:
            return
        rec = self.records.get(int(sel[0]))
        self.txt_detail.delete("1.0", "end")
        if rec is None:
            self.txt_detail.insert("end", "Packet no longer in memory.")
            return
        head = (f"Packet #{rec.no}   {rec.date_time_str}   {rec.length} bytes\n"
                f"{rec.src}{'' if rec.sport is None else ':' + str(rec.sport)}  ->  "
                f"{rec.dst}{'' if rec.dport is None else ':' + str(rec.dport)}   [{rec.protocol}]\n"
                f"{rec.info}\n{'-' * 70}\n")
        self.txt_detail.insert("end", head)
        if rec.raw is not None:
            try:
                self.txt_detail.insert("end", rec.raw.show(dump=True))
            except Exception:
                self.txt_detail.insert("end", rec.raw.summary())

    # --------------------------------------------------------------- side panels
    def _redraw_panels(self, schedule=True):
        self.stats.tick()
        pps, bps = self.stats.current_rate()
        self.lbl_total.config(text=f"{self.stats.total_packets:,}")
        self.lbl_bytes.config(text=human_bytes(self.stats.total_bytes))
        self.lbl_pps.config(text=f"{pps:.0f}")
        self.lbl_bps.config(text=human_bytes(bps) + "/s")
        self.lbl_clock.config(text=datetime.now().strftime("%A %d %b %Y  %H:%M:%S"))
        if self.engine and self.engine.running:
            drop = f"  (dropped {self.engine.dropped})" if self.engine.dropped else ""
            self.var_status.set(f"Capturing... {self.stats.total_packets} packets, "
                                f"{self.stats.elapsed():.0f}s elapsed{drop}")
        self._draw_graph()
        self._draw_protocols()
        self.lst_talkers.delete(0, "end")
        for ip, nbytes in self.stats.top_talkers(6):
            self.lst_talkers.insert("end", f"{ip:<40} {human_bytes(nbytes):>10}")
        if schedule:
            self.after(1000, self._redraw_panels)

    def _draw_graph(self):
        cv = self.cv_graph
        cv.delete("all")
        w = max(cv.winfo_width(), 200)
        h = max(cv.winfo_height(), 100)
        data = self.stats.pps_history()
        peak = max(max(data), 5)
        pad_l, pad_b, pad_t = 34, 14, 8
        gw, gh = w - pad_l - 6, h - pad_b - pad_t
        for frac in (0, 0.5, 1):
            y = pad_t + gh * (1 - frac)
            cv.create_line(pad_l, y, w - 6, y, fill="#e5e5e5")
            cv.create_text(pad_l - 4, y, text=f"{peak * frac:.0f}", anchor="e",
                           font=("Segoe UI", 8), fill="#666")
        step = gw / (len(data) - 1)
        pts = []
        for i, v in enumerate(data):
            pts += [pad_l + i * step, pad_t + gh * (1 - v / peak)]
        cv.create_polygon([pad_l, pad_t + gh] + pts + [pad_l + gw, pad_t + gh],
                          fill="#dbe9fb", outline="")
        cv.create_line(*pts, fill="#2a6fdb", width=2)
        cv.create_text(pad_l, h - 2, text="-60s", anchor="sw", font=("Segoe UI", 8), fill="#666")
        cv.create_text(w - 6, h - 2, text="now", anchor="se", font=("Segoe UI", 8), fill="#666")

    def _draw_protocols(self):
        cv = self.cv_proto
        cv.delete("all")
        w = max(cv.winfo_width(), 200)
        total = max(self.stats.total_packets, 1)
        items = self.stats.protocols.most_common(7)
        if not items:
            cv.create_text(w / 2, 20, text="No packets yet", fill="#888")
            return
        row_h = 24
        for i, (proto, n) in enumerate(items):
            y = 8 + i * row_h
            cv.create_text(6, y + 9, text=proto, anchor="w", font=("Segoe UI", 9))
            bar_w = (w - 150) * n / total
            cv.create_rectangle(64, y, 64 + max(bar_w, 2), y + 18,
                                fill=BAR_COLORS.get(proto, DEFAULT_BAR), outline="")
            cv.create_text(70 + bar_w, y + 9, text=f"{n} ({n * 100 / total:.0f}%)",
                           anchor="w", font=("Segoe UI", 8), fill="#333")

    # ------------------------------------------------------------------- export
    def _snapshot(self):
        return list(self.records.values())

    def save_csv(self):
        recs = self._snapshot()
        if not recs:
            messagebox.showinfo("Nothing to save", "No packets captured yet.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".csv",
                                            initialfile=f"capture_{datetime.now():%Y%m%d_%H%M%S}.csv",
                                            filetypes=[("CSV file", "*.csv")])
        if path:
            n = save_csv(recs, path)
            messagebox.showinfo("Saved", f"{n} packets saved to\n{path}")

    def save_pcap(self):
        recs = self._snapshot()
        if not recs:
            messagebox.showinfo("Nothing to save", "No packets captured yet.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".pcap",
                                            initialfile=f"capture_{datetime.now():%Y%m%d_%H%M%S}.pcap",
                                            filetypes=[("PCAP file", "*.pcap")])
        if path:
            n = save_pcap(recs, path)
            messagebox.showinfo("Saved", f"{n} packets saved to\n{path}\n(open with Wireshark)")

    def _on_close(self):
        if self.engine:
            self.engine.stop(timeout=1.5)
        self.destroy()


def run_gui(simulate=False, iface="", bpf=""):
    app = MonitorApp(simulate=simulate, iface=iface, bpf=bpf)
    app.mainloop()
