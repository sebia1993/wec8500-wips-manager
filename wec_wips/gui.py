"""Tkinter UI. All widgets are accessed only from the main thread."""
from __future__ import annotations

import csv
import copy
import math
import os
import time
import io
import queue
import threading
import tkinter as tk
import webbrowser
from datetime import datetime
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from . import __version__


SYNTAX = {
    "NAT 포함 · 삼성 문서 형식": "with_nat",
    "NAT 생략 · 해당 장비 문법 확인 필요": "without_nat",
}
NAT = {"기존 값 유지": "keep", "1 · NAT 사용 안 함": "1", "2 · NAT 사용": "2"}


def csv_ap_entries(content: str) -> tuple[list[str], dict[str, str]]:
    """Import only explicit AP IP/name columns, never credential columns."""
    try:
        reader = csv.reader(io.StringIO(content.lstrip("\ufeff")))
        header = next(reader)
        columns = [i for i, title in enumerate(header)
                   if title.strip().lower().replace(" ", "").replace("_", "") in ("ip", "apip")]
        if len(columns) != 1:
            raise ValueError("CSV에 ap_ip, IP 또는 AP IP 열을 하나만 넣어 주세요.")
        index = columns[0]
        name_columns = [i for i, title in enumerate(header)
                        if title.strip().lower().replace(' ', '').replace('_', '')
                        in ('hostname', 'aphostname', 'apname', '호스트명')]
        if len(name_columns) > 1:
            raise ValueError('CSV에 hostname, ap_hostname, AP Name 또는 호스트명 열을 하나만 넣어 주세요.')
        name_index = name_columns[0] if name_columns else None
        ips = []
        names = {}
        for row in reader:
            if not row or not any(cell.strip() for cell in row):
                continue
            if index >= len(row) or not row[index].strip():
                raise ValueError("CSV의 AP IP 열에 비어 있는 행이 있습니다.")
            ap_ip = row[index].strip()
            ips.append(ap_ip)
            if name_index is not None and name_index < len(row) and row[name_index].strip():
                from .core import safe_hostname
                name = safe_hostname(row[name_index])
                if not name:
                    raise ValueError('CSV 호스트명에 지원하지 않는 문자 또는 길이가 있습니다.')
                if ap_ip in names and names[ap_ip] != name:
                    raise ValueError('동일 AP IP에 서로 다른 호스트명이 지정되어 있습니다.')
                names[ap_ip] = name
            if len(ips) > 10000:
                raise ValueError("한 번에 최대 10,000개 AP까지 불러올 수 있습니다.")
        if not ips:
            raise ValueError("CSV에 AP IP가 없습니다.")
        return ips, names
    except (csv.Error, StopIteration) as exc:
        raise ValueError("CSV 형식을 읽을 수 없습니다. 첫 행의 IP 열 이름을 확인하세요.") from exc


def csv_ip_text(content: str) -> str:
    """Backward-compatible IP-only return value for existing callers."""
    return '\n'.join(csv_ap_entries(content)[0])


class WipsApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.events = queue.Queue()
        self.stop_event = threading.Event()
        self.worker = None
        self.results = []
        self.ap_hostnames = {}
        self.saved_config = None
        self.saved_mode = None
        self.journal_folder = None
        self.local_record_failed = False
        self.ui_failed = False
        self.phase = ''
        self.active_ap = ''
        self.active_attempt = 1
        self.phase_started = time.monotonic()
        self.last_activity = self.phase_started
        self.retry_until = None
        self.busy = False
        self.exporting = False
        self.report_file = None
        self.run_simulated = True
        self.closing = False
        self.form_widgets = []
        self.secret_entries = []
        self.controller_ip = tk.StringVar()
        self.controller_port = tk.StringVar(value="23")
        self.controller_user = tk.StringVar()
        self.controller_password = tk.StringVar()
        self.ap_port = tk.StringVar(value="50022")
        self.ap_user = tk.StringVar(value="root")
        self.ap_password = tk.StringVar()
        self.server_ip = tk.StringVar()
        self.shared_key = tk.StringVar()
        self.syntax = tk.StringVar(value=next(iter(SYNTAX)))
        self.nat_mode = tk.StringVar(value=next(iter(NAT)))
        self.timeout = tk.StringVar(value="20")
        self.demo = tk.BooleanVar(value=True)
        self.auto_recover = tk.BooleanVar(value=True)
        self.stop_on_error = tk.BooleanVar(value=True)
        self.auto_accept_ap_host_key = tk.BooleanVar(value=True)
        self.lookup_hostnames = tk.BooleanVar(value=True)
        self.status = tk.StringVar(value="먼저 모의 실행으로 작업 흐름을 확인하세요.")
        self.mode_label = tk.StringVar()
        self.root.title(f"WEC8500 WIPS Manager v{__version__} · AP 서버 설정")
        width = min(1220, max(960, self.root.winfo_screenwidth() - 60))
        height = min(920, max(640, self.root.winfo_screenheight() - 80))
        self.root.geometry(f"{width}x{height}")
        self.root.minsize(960, 640)
        self.root.configure(bg="#eef2f7")
        self.root.protocol("WM_DELETE_WINDOW", self._close)
        self.root.report_callback_exception = self._callback_error
        self._styles()
        self._build()
        self.demo.trace_add("write", self._mode_changed)
        self._mode_changed()
        self.root.after(100, self._pump)

    def _styles(self):
        style = ttk.Style(self.root)
        style.theme_use("clam")
        self.root.option_add("*Font", ("Malgun Gothic", 10))
        style.configure("TFrame", background="#eef2f7")
        style.configure("TLabel", background="#eef2f7", foreground="#192638")
        style.configure("TLabelframe", background="#eef2f7", bordercolor="#cbd5e1")
        style.configure("TLabelframe.Label", background="#eef2f7", foreground="#153e65", font=("Malgun Gothic", 10, "bold"))
        style.configure("TButton", padding=(12, 7))
        style.configure("Primary.TButton", background="#1769a8", foreground="white", font=("Malgun Gothic", 10, "bold"))
        style.map("Primary.TButton", background=[("disabled", "#aab7c4"), ("active", "#145987")])
        style.configure("TCheckbutton", background="#eef2f7")
        style.configure("Treeview", rowheight=29, background="white", fieldbackground="white", foreground="#192638")
        style.configure("Treeview.Heading", font=("Malgun Gothic", 9, "bold"), padding=5)
        style.configure("Hint.TLabel", foreground="#52667e", font=("Malgun Gothic", 9))

    def _entry(self, parent, label, var, row, column=0, secret=False, width=24):
        ttk.Label(parent, text=label).grid(row=row, column=column, sticky="w", padx=(0, 8), pady=4)
        entry = ttk.Entry(parent, textvariable=var, width=width, show="●" if secret else "")
        entry.grid(row=row, column=column + 1, sticky="ew", pady=4)
        self.form_widgets.append((entry, "normal"))
        if secret:
            self.secret_entries.append(entry)
        return entry

    def _build(self):
        header = tk.Frame(self.root, bg="#102c48", padx=22, pady=14)
        header.pack(fill="x")
        tk.Label(header, text=f"WEC8500  /  WIPS Manager  v{__version__}", bg="#102c48", fg="white", font=("Malgun Gothic", 20, "bold")).pack(anchor="w")
        tk.Label(header, text="WEC8500 Telnet 연결 유지  ·  AP SSH → 설정 → 확인 → exit 반복", bg="#102c48", fg="#c4d9ec", font=("Malgun Gothic", 10)).pack(anchor="w", pady=(4, 0))
        scroll_host = ttk.Frame(self.root)
        scroll_host.pack(fill="both", expand=True)
        self.page = tk.Canvas(scroll_host, bg="#eef2f7", highlightthickness=0)
        page_scroll = ttk.Scrollbar(scroll_host, orient="vertical", command=self.page.yview)
        page_scroll.pack(side="right", fill="y")
        self.page.pack(side="left", fill="both", expand=True)
        self.page.configure(yscrollcommand=page_scroll.set)
        body = ttk.Frame(self.page, padding=(18, 12))
        page_window = self.page.create_window((0, 0), window=body, anchor="nw")

        def resize_page(_event=None):
            self.page.itemconfigure(page_window, width=self.page.winfo_width(),
                                    height=max(self.page.winfo_height(), body.winfo_reqheight()))
            self.page.configure(scrollregion=self.page.bbox("all"))

        body.bind("<Configure>", resize_page)
        self.page.bind("<Configure>", resize_page)
        self.root.bind("<MouseWheel>", self._scroll_page)
        body.columnconfigure(0, weight=1)
        body.rowconfigure(4, weight=1)

        modebar = ttk.Frame(body)
        modebar.grid(row=0, column=0, sticky="ew", pady=(0, 8))
        demo_check = ttk.Checkbutton(modebar, text="모의 실행 (실제 장비 접속 안 함)", variable=self.demo)
        demo_check.pack(side="left")
        self.form_widgets.append((demo_check, "normal"))
        fill = ttk.Button(modebar, text="모의 데이터 채우기", command=self._fill_demo)
        fill.pack(side="left", padx=12)
        self.form_widgets.append((fill, "normal"))
        ttk.Label(modebar, textvariable=self.mode_label, style="Hint.TLabel").pack(side="right")

        conn = ttk.Frame(body)
        conn.grid(row=1, column=0, sticky="ew")
        conn.columnconfigure(0, weight=1)
        conn.columnconfigure(1, weight=1)
        ctl = ttk.LabelFrame(conn, text="1  WEC8500 Telnet 접속", padding=(12, 8))
        ctl.grid(row=0, column=0, sticky="nsew", padx=(0, 8))
        ctl.columnconfigure(1, weight=1)
        self.controller_entry = self._entry(ctl, "컨트롤러 IP", self.controller_ip, 0)
        self._entry(ctl, "Telnet 포트", self.controller_port, 1)
        self._entry(ctl, "ID", self.controller_user, 2)
        self._entry(ctl, "비밀번호", self.controller_password, 3, secret=True)
        ap = ttk.LabelFrame(conn, text="2  AP 접속 계정", padding=(12, 8))
        ap.grid(row=0, column=1, sticky="nsew", padx=(8, 0))
        ap.columnconfigure(1, weight=1)
        self._entry(ap, "AP SSH 포트", self.ap_port, 0)
        self._entry(ap, "AP ID", self.ap_user, 1)
        self._entry(ap, "AP 비밀번호", self.ap_password, 2, secret=True)
        self._entry(ap, "응답 제한 (초)", self.timeout, 3)
        auto_key = ttk.Checkbutton(ap, text="AP 최초 접속 확인에 yes 자동 응답", variable=self.auto_accept_ap_host_key)
        auto_key.grid(row=4, column=0, columnspan=2, sticky="w", pady=(5, 1))
        self.form_widgets.append((auto_key, "normal"))
        ttk.Label(ap, text="기존 호스트 키가 변경된 경우에는 접속을 중단합니다.", style="Hint.TLabel").grid(row=5, column=0, columnspan=2, sticky="w", pady=(0, 4))
        lookup = ttk.Checkbutton(ap, text='컨트롤러 AP 이름 조회', variable=self.lookup_hostnames)
        lookup.grid(row=6, column=0, columnspan=2, sticky='w', pady=(1, 3))
        self.form_widgets.append((lookup, 'normal'))

        targets = ttk.Frame(body)
        targets.grid(row=2, column=0, sticky="ew", pady=10)
        targets.columnconfigure(0, weight=1)
        targets.columnconfigure(1, weight=1)
        ips = ttk.LabelFrame(targets, text="3  대상 AP IP", padding=(12, 8))
        ips.grid(row=0, column=0, sticky="nsew", padx=(0, 8))
        ips.columnconfigure(0, weight=1)
        ips.rowconfigure(1, weight=1)
        ttk.Label(ips, text="IP를 한 줄씩 입력 · CSV 예: ap_ip,hostname (이름은 선택)", style="Hint.TLabel", wraplength=400).grid(row=0, column=0, columnspan=2, sticky="w", pady=(0, 5))
        self.ap_text = tk.Text(ips, height=5, width=38, wrap="none", relief="solid", borderwidth=1, font=("Consolas", 10), bg="white", fg="#192638", undo=True)
        self.ap_text.grid(row=1, column=0, sticky="nsew")
        ip_scroll = ttk.Scrollbar(ips, orient="vertical", command=self.ap_text.yview)
        ip_scroll.grid(row=1, column=1, sticky="ns")
        self.ap_text.configure(yscrollcommand=ip_scroll.set)
        self.form_widgets.append((self.ap_text, "normal"))
        import_button = ttk.Button(ips, text="CSV에서 AP IP 불러오기", command=self._load_csv)
        import_button.grid(row=2, column=0, sticky="w", pady=(6, 0))
        self.form_widgets.append((import_button, "normal"))

        change = ttk.LabelFrame(targets, text="4  WIPS 서버 설정·확인", padding=(12, 8))
        change.grid(row=0, column=1, sticky="nsew", padx=(8, 0))
        change.columnconfigure(1, weight=1)
        self._entry(change, "WIPS 서버 IP", self.server_ip, 0)
        self._entry(change, "특정키 / 공유키", self.shared_key, 1, secret=True)
        ttk.Label(change, text="명령 문법").grid(row=2, column=0, sticky="w", padx=(0, 8), pady=4)
        syntax = ttk.Combobox(change, textvariable=self.syntax, values=list(SYNTAX), state="readonly", width=35)
        syntax.grid(row=2, column=1, sticky="ew", pady=4)
        self.form_widgets.append((syntax, "readonly"))
        ttk.Label(change, text="NAT 모드").grid(row=3, column=0, sticky="w", padx=(0, 8), pady=4)
        nat = ttk.Combobox(change, textvariable=self.nat_mode, values=list(NAT), state="readonly")
        nat.grid(row=3, column=1, sticky="ew", pady=4)
        self.form_widgets.append((nat, "readonly"))
        ttk.Label(change, text="서버 IP 일치 확인은 공유키 없이 조회만 합니다.", style="Hint.TLabel").grid(row=4, column=0, columnspan=2, sticky="w", pady=(4, 1))

        actions = ttk.Frame(body)
        actions.grid(row=3, column=0, sticky="ew", pady=(0, 8))
        action_buttons = ttk.Frame(actions)
        action_buttons.pack(fill="x")
        self.inspect_button = ttk.Button(action_buttons, text="① 사전 조회", command=lambda: self._start("inspect"))
        self.inspect_button.pack(side="left")
        self.apply_button = ttk.Button(action_buttons, text="② 변경 및 검증", style="Primary.TButton", command=lambda: self._start("apply"))
        self.apply_button.pack(side="left", padx=8)
        self.verify_button = ttk.Button(action_buttons, text="③ 서버 IP 일치 확인", command=lambda: self._start("verify_ip"))
        self.verify_button.pack(side="left")
        self.stop_button = ttk.Button(action_buttons, text="중지", command=self._stop, state="disabled")
        self.stop_button.pack(side="left", padx=8)
        self.resume_button = ttk.Button(action_buttons, text="미완료 이어하기", command=self._resume, state="disabled")
        self.resume_button.pack(side="left")
        action_options = ttk.Frame(actions)
        action_options.pack(fill="x", pady=(6, 0))
        self.export_button = ttk.Button(action_options, text="결과 CSV 저장", command=self._export, state="disabled")
        self.export_button.pack(side="right")
        self.folder_button = ttk.Button(action_options, text="기록 폴더 열기", command=self._open_journal, state="disabled")
        self.folder_button.pack(side="right", padx=6)
        recovery = ttk.Checkbutton(action_options, text="자동 복구 (최대 2회)", variable=self.auto_recover)
        recovery.pack(side="left", padx=(0, 12))
        self.form_widgets.append((recovery, "normal"))
        stop_errors = ttk.Checkbutton(action_options, text="첫 오류 발생 시 중단", variable=self.stop_on_error)
        stop_errors.pack(side="left")
        ttk.Label(actions, text="③ IP 불일치는 계속 조회 · 이어하기는 이 창의 이전 목표로 실행 · 기록은 PC에만 저장 (암호·키 제외)", style="Hint.TLabel").pack(anchor="w", pady=(5, 0))
        self.form_widgets.append((stop_errors, "normal"))
        report_actions = ttk.Frame(actions)
        report_actions.pack(fill='x', pady=(7, 0))
        self.report_button = ttk.Button(report_actions, text='HTML·CSV 보고서 저장', command=self._save_report, state='disabled')
        self.report_button.pack(side='left')
        self.txt_button = ttk.Button(report_actions, text='선택 AP TXT 저장', command=self._save_selected_txt, state='disabled')
        self.txt_button.pack(side='left', padx=8)
        self.open_report_button = ttk.Button(report_actions, text='보고서 열기', command=self._open_report, state='disabled')
        self.open_report_button.pack(side='left')
        ttk.Label(report_actions, text='Ctrl / Shift로 AP 여러 개 선택', style='Hint.TLabel').pack(side='left', padx=12)

        results_frame = ttk.LabelFrame(body, text="작업 결과 · WIPS 서버 연결 상태가 아닌 설정값 확인 결과입니다", padding=8)
        results_frame.grid(row=4, column=0, sticky="nsew")
        results_frame.columnconfigure(0, weight=1)
        results_frame.rowconfigure(0, weight=1)
        columns = ("ap_ip", "hostname", "status", "target_ip", "after_ip", "before_ip", "before_nat", "after_nat", "key_check", "controller_return", "message")
        self.table = ttk.Treeview(results_frame, columns=columns, show="headings", height=5, selectmode="extended")
        headings = ("AP IP", "호스트명", "결과", "목표 서버", "조회된 서버", "변경 전 서버", "NAT 전", "NAT 후", "키 확인", "컨트롤러 복귀", "상세")
        widths = (125, 160, 145, 125, 125, 125, 60, 60, 90, 115, 280)
        for col, title, width in zip(columns, headings, widths):
            self.table.heading(col, text=title)
            self.table.column(col, width=width, minwidth=55, stretch=col == "message")
        self.table.grid(row=0, column=0, sticky="nsew")
        vertical = ttk.Scrollbar(results_frame, orient="vertical", command=self.table.yview)
        vertical.grid(row=0, column=1, sticky="ns")
        horizontal = ttk.Scrollbar(results_frame, orient="horizontal", command=self.table.xview)
        horizontal.grid(row=1, column=0, sticky="ew")
        self.table.configure(yscrollcommand=vertical.set, xscrollcommand=horizontal.set)
        self.table.tag_configure("demo", foreground="#235a87")
        self.table.bind("<Double-1>", self._result_details)

        footer = ttk.Frame(body)
        footer.grid(row=5, column=0, sticky="ew", pady=(8, 0))
        footer.columnconfigure(0, weight=1)
        ttk.Label(footer, textvariable=self.status, wraplength=880, justify='left').grid(row=0, column=0, sticky="w", pady=(0, 4))
        self.progress = ttk.Progressbar(footer, mode="determinate")
        self.progress.grid(row=1, column=0, sticky="ew")
        self.log = tk.Text(footer, height=3, wrap="word", state="disabled", relief="flat", bg="#e2e9f2", fg="#28445e", font=("Malgun Gothic", 9))
        self.log.grid(row=2, column=0, sticky="ew", pady=(5, 0))
        ttk.Label(footer, text="컨트롤러는 Telnet, AP는 SSH로 접속합니다. 조회된 WIPS 공유키는 AP 상세와 보고서에 원문으로 표시됩니다.", style="Hint.TLabel", wraplength=880, justify="left").grid(row=3, column=0, sticky="w", pady=(4, 0))

    def _mode_changed(self, *_):
        self.mode_label.set("DEMO · 네트워크 연결 없음" if self.demo.get() else "실제 장비 작업 · 입력한 대상에 접속")

    def _fill_demo(self):
        if self.busy:
            return
        self.demo.set(True)
        for var, value in ((self.controller_ip, "192.0.2.1"), (self.controller_port, "23"),
                           (self.controller_user, "demo"), (self.controller_password, "DemoPassword"),
                           (self.ap_port, "50022"), (self.ap_user, "root"), (self.ap_password, "DemoPassword"),
                           (self.server_ip, "198.51.100.20"), (self.shared_key, "DemoKey2026")):
            var.set(value)
        self.ap_text.delete("1.0", "end")
        self.ap_text.insert("1.0", "192.0.2.101\n192.0.2.102\n192.0.2.103")
        self.ap_hostnames = {f'192.0.2.{n}': f'DemoAP{n}' for n in (101, 102, 103)}
        self.status.set("모의 데이터입니다. 사전 조회 또는 변경 및 검증을 눌러 보세요.")

    def _load_csv(self):
        if self.busy:
            return
        filename = filedialog.askopenfilename(parent=self.root, title="AP IP CSV 선택", filetypes=[("CSV", "*.csv"), ("모든 파일", "*.*")])
        if not filename:
            return
        try:
            from .core import parse_ap_ips
            path = Path(filename)
            if path.stat().st_size > 2 * 1024 * 1024:
                raise ValueError("CSV 파일은 2 MB 이하로 선택해 주세요.")
            raw = path.read_bytes()
            try:
                text = raw.decode("utf-8-sig")
            except UnicodeDecodeError:
                text = raw.decode("cp949")
            raw_ips, names = csv_ap_entries(text)
            ips = parse_ap_ips('\n'.join(raw_ips))
            self.ap_hostnames = {ip: names[ip] for ip in ips if ip in names}
            self.ap_text.delete("1.0", "end")
            self.ap_text.insert("1.0", "\n".join(ips))
            self.status.set(f"AP {len(ips)}개를 불러왔습니다. CSV 호스트명 {len(self.ap_hostnames)}개 · 컨트롤러 조회 이름을 우선 사용합니다.")
        except (OSError, UnicodeError):
            messagebox.showerror("CSV 확인", "파일을 읽을 수 없습니다. UTF-8 또는 CP949 CSV인지 확인하세요.", parent=self.root)
        except ValueError as exc:
            messagebox.showerror("CSV 확인", str(exc), parent=self.root)

    def _snapshot(self, mode):
        from .core import RunConfig, parse_ap_ips
        try:
            controller_port = int(self.controller_port.get().strip())
            ap_port = int(self.ap_port.get().strip())
            timeout = float(self.timeout.get().strip())
        except ValueError as exc:
            raise ValueError("Telnet·SSH 포트와 응답 제한에는 숫자를 입력하세요.") from exc
        ap_ips = parse_ap_ips(self.ap_text.get('1.0', 'end'))
        cfg = RunConfig(
            controller_ip=self.controller_ip.get().strip(), controller_port=controller_port,
            controller_user=self.controller_user.get().strip(), controller_password=self.controller_password.get(),
            ap_ips=ap_ips, ap_port=ap_port,
            ap_user=self.ap_user.get().strip(), ap_password=self.ap_password.get(),
            server_ip=self.server_ip.get().strip(), shared_key=self.shared_key.get(),
            syntax=SYNTAX[self.syntax.get()], nat_mode=NAT[self.nat_mode.get()],
            timeout=timeout, demo=self.demo.get(), stop_on_error=self.stop_on_error.get(),
            auto_accept_ap_host_key=self.auto_accept_ap_host_key.get(),
            auto_recover=self.auto_recover.get(),
            lookup_hostnames=self.lookup_hostnames.get(),
            ap_hostnames={ip: self.ap_hostnames[ip] for ip in ap_ips if ip in self.ap_hostnames},
        )
        cfg.validate(mode)
        return cfg

    def _start(self, mode):
        if self.busy:
            return
        try:
            cfg = self._snapshot(mode)
        except ValueError as exc:
            messagebox.showerror("입력값 확인", str(exc), parent=self.root)
            return
        if mode == "apply" and not self._confirm_apply(cfg):
            return
        if self.results and not messagebox.askyesno("이전 결과 교체", "새 작업을 시작하면 화면의 이전 결과가 교체됩니다.\n필요한 결과는 먼저 CSV로 저장하세요.\n새 작업을 시작할까요?", parent=self.root, default="no"):
            return
        self._begin(cfg, mode)

    def _confirm_apply(self, cfg, resuming=False):
        context = "모의 실행 (실제 접속 없음)" if cfg.demo else "실제 장비 변경"
        ap_key_policy = "yes 자동 응답" if cfg.auto_accept_ap_host_key else "지문 확인 창"
        syntax = next((label for label, value in SYNTAX.items() if value == getattr(cfg, 'syntax', 'with_nat')), '확인 필요')
        nat = next((label for label, value in NAT.items() if value == getattr(cfg, 'nat_mode', 'keep')), '확인 필요')
        resume_text = "이전 작업과 같은 목표로 미완료 AP를 이어갑니다. 화면에서 수정한 입력값은 사용하지 않습니다.\n\n" if resuming else ''
        message = (f"{context}\n\n{resume_text}컨트롤러 Telnet: {cfg.controller_ip}:{cfg.controller_port}\n"
                   f"대상 AP: {len(cfg.ap_ips)}개\nAP SSH 포트: {cfg.ap_port}\nWIPS 서버: {cfg.server_ip}\n"
                   f"명령 문법: {syntax}\nNAT: {nat}\n공유키: ●●●●●●●●\n"
                   f"AP 최초 접속 확인: {ap_key_policy}\n\n"
                   "현재 설정을 먼저 조회하고 AP별 변경·검증 후 컨트롤러 복귀를 확인합니다.\n진행하시겠습니까?")
        return messagebox.askyesno("변경 대상 확인", message, parent=self.root, default="no")

    def _resume(self):
        from .core import GOOD_STATUSES
        if self.busy or self.saved_config is None:
            return
        completed = {result.ap_ip for result in self.results if result.status in GOOD_STATUSES}
        if all(ap in completed for ap in self.saved_config.ap_ips):
            messagebox.showinfo("이어하기", "미완료 AP가 없습니다.", parent=self.root)
            return
        cfg = copy.deepcopy(self.saved_config)
        mode = self.saved_mode
        if mode == 'apply' and not self._confirm_apply(cfg, resuming=True):
            return
        self._begin(cfg, mode, copy.deepcopy(self.results))

    def _begin(self, cfg, mode, resume_results=None):
        self.exporting = False
        self.report_file = None
        self.open_report_button.configure(state='disabled')
        self.saved_config = copy.deepcopy(cfg)
        self.saved_mode = mode
        self.results.clear()
        self.table.delete(*self.table.get_children())
        self.stop_event.clear()
        self.run_simulated = cfg.demo
        self.phase, self.active_ap = '접속 준비', ''
        self.active_attempt = 1
        self.phase_started = self.last_activity = time.monotonic()
        self.retry_until = None
        self.local_record_failed = False
        self.ui_failed = False
        self.journal_folder = None
        self.folder_button.configure(state='disabled')
        self.progress.configure(maximum=len(cfg.ap_ips), value=0)
        self._set_busy(True)
        self.status.set("모의 실행 중…" if cfg.demo else "장비 접속 준비 중…")
        self._log("이전 목표로 미완료 작업을 이어갑니다." if resume_results else ("모의 실행을 시작합니다." if cfg.demo else "실제 장비 작업을 시작합니다."))
        self.worker = threading.Thread(target=self._run, args=(cfg, mode, resume_results), name="wips-worker", daemon=False)
        try:
            self.worker.start()
        except RuntimeError:
            # No worker can publish its final events when OS thread creation fails.
            # Preserve prior possible-write evidence before enabling another resume.
            if resume_results:
                self.events.put(('worker_partial', {'results': resume_results}))
            self.events.put(("worker_error", {"message": "작업을 완료하지 못했습니다. 로컬 기록과 결과를 확인하세요. 미완료 이어하기로 다시 조회할 수 있습니다."}))
            self.events.put(("worker_end", {}))

    def _run(self, cfg, mode, resume_results=None):
        runner = None
        journal = None
        record_failed = False
        def recording_error():
            nonlocal record_failed
            if not record_failed:
                record_failed = True
                self.events.put(('local_record_error', {}))
        def emit(kind, data):
            if journal is not None and not record_failed:
                try:
                    journal.record(kind, data)
                except OSError:
                    recording_error()
            self.events.put((kind, data))
        try:
            from .core import Runner
            from .journal import LocalJournal
            try:
                journal = LocalJournal(cfg, mode)
                self.events.put(('journal', {'path': str(journal.directory)}))
            except OSError:
                recording_error()
            runner = Runner(cfg, emit, self._worker_confirm, self.stop_event, resume_results=resume_results)
            runner.run(mode)
        except Exception:
            if runner is not None:
                self.events.put(('worker_partial', {'results': runner.pending_results()}))
            self.events.put(("worker_error", {"message": "작업을 완료하지 못했습니다. 로컬 기록과 결과를 확인하세요. 미완료 이어하기로 다시 조회할 수 있습니다."}))
        finally:
            if journal is not None:
                try:
                    journal.close()
                except OSError:
                    recording_error()
            self.events.put(("worker_end", {}))

    def _open_journal(self):
        if self.journal_folder is None:
            return
        if os.name != 'nt':
            messagebox.showinfo('로컬 기록 폴더', str(self.journal_folder), parent=self.root)
            return
        try:
            os.startfile(str(self.journal_folder))
        except OSError:
            messagebox.showerror('폴더 열기 실패', '로컬 기록 폴더를 열지 못했습니다.', parent=self.root)

    def _worker_confirm(self, title, message):
        ready = threading.Event()
        answer = []
        self.events.put(("confirm", {"title": title, "message": message, "ready": ready, "answer": answer}))
        while not ready.wait(0.1):
            if self.stop_event.is_set():
                return False
        return bool(answer and answer[0] and not self.stop_event.is_set())

    def _pump(self):
        try:
            for _ in range(100):
                try:
                    kind, data = self.events.get_nowait()
                except queue.Empty:
                    break
                if kind == "log":
                    self._log(data["message"])
                elif kind == "progress":
                    self.active_ap = data['ap_ip']
                elif kind == 'stage':
                    self.phase = data['stage']
                    self.active_ap = data['ap_ip']
                    self.active_attempt = data.get('attempt', 1)
                    self.phase_started = time.monotonic()
                    self.retry_until = None
                elif kind == 'activity':
                    self.last_activity = time.monotonic()
                elif kind == 'retry':
                    self.active_ap = data['ap_ip']
                    self.active_attempt = data.get('attempt', 1)
                    self.phase = '재시도 대기'
                    self.phase_started = time.monotonic()
                    self.retry_until = self.phase_started + data['delay']
                    self._log(f"{self.active_ap} · 자동 복구 대기 · {data.get('error_code', '')}")
                elif kind == 'journal':
                    self.journal_folder = Path(data['path'])
                    self.folder_button.configure(state='normal')
                elif kind == 'local_record_error':
                    self.local_record_failed = True
                    self.status.set('로컬 기록 저장 실패 · 작업 결과는 메모리에 유지됩니다. 종료 후 CSV로 저장하세요.')
                    self._log('로컬 기록 저장에 실패했습니다. 작업은 메모리에서 계속되며 종료 후 결과 CSV를 직접 저장하세요.')
                elif kind == "result":
                    self._append_result(data['result'])
                elif kind == 'worker_partial':
                    merged = {result.ap_ip: result for result in self.results}
                    merged.update((result.ap_ip, result) for result in data['results'])
                    # Commit recovery evidence before rendering: a Tk error must never
                    # discard a later AP's possible-write / original-NAT state.
                    self.results = list(merged.values())
                    self.table.delete(*self.table.get_children())
                    for index, result in enumerate(self.results):
                        self._render_result(result, index)
                elif kind == "confirm":
                    approved = False
                    try:
                        if not self.closing and not self.stop_event.is_set():
                            approved = messagebox.askyesno(data["title"], data["message"], parent=self.root, default="no")
                    finally:
                        data["answer"].append(approved)
                        data["ready"].set()
                elif kind == "done":
                    self.phase, self.retry_until = '', None
                    self._show_completion(data.get('cancelled', False))
                elif kind == "worker_error":
                    self.phase, self.retry_until = '', None
                    self.status.set(data["message"])
                    self._log(data["message"])
                elif kind == "worker_end":
                    had_phase = bool(getattr(self, 'phase', ''))
                    self.phase, self.retry_until = '', None
                    self._set_busy(False)
                    if had_phase and not getattr(self, 'ui_failed', False):
                        self._show_completion(self.stop_event.is_set())
                elif kind == 'export_done':
                    if data.get('report_file'):
                        self.report_file = Path(data['report_file'])
                    self.status.set(f"{data['label']} · AP {data['count']}개 · {data['path']}")
                elif kind == 'export_error':
                    self.status.set('파일 저장에 실패했습니다. 저장 위치의 권한·남은 공간을 확인하세요. 결과는 화면에 유지됩니다.')
                elif kind == 'export_end':
                    self.exporting = False
                    self._set_busy(False)
            self._refresh_activity()
        except Exception:
            self.ui_failed = True
            self.stop_event.set()
            self.phase, self.retry_until = '', None
            self.status.set('화면 갱신 오류로 중지를 요청했습니다. 로컬 기록과 결과를 확인하세요.')
        finally:
            if self.closing and (self.worker is None or not self.worker.is_alive()):
                self.root.destroy()
            else:
                self.root.after(100, self._pump)

    def _append_result(self, result):
        self.results.append(result)
        self._render_result(result, len(self.results) - 1)

    def _render_result(self, result, index):
        values = [getattr(result, field, '') for field in ("ap_ip", "hostname", "status", "target_ip", "after_ip", "before_ip", "before_nat", "after_nat", "key_check", "controller_return", "message")]
        values[1] = values[1] or '미확인'
        if result.simulated:
            values[2] = f"[모의] {result.status}"
        self.table.insert("", "end", iid=str(index), values=values, tags=("demo",) if result.simulated else ())
        self.progress.configure(value=len(self.results))
        self.table.see(str(index))

    def _show_completion(self, cancelled):
        from .core import GOOD_STATUSES
        complete = sum(result.status in GOOD_STATUSES for result in self.results)
        pending = sum(result.status == '미실행' for result in self.results)
        saved_config = getattr(self, 'saved_config', None)
        missing = len(set(saved_config.ap_ips) - {result.ap_ip for result in self.results}) if saved_config is not None else 0
        attention = len(self.results) - complete - pending
        pending += missing
        suffix = '중지 요청으로 종료' if cancelled else '작업 종료'
        context = '모의 실행' if self.run_simulated else '실제 장비'
        warning = ' · 로컬 기록 실패: CSV 저장 필요' if getattr(self, 'local_record_failed', False) else ''
        if getattr(self, 'ui_failed', False):
            warning += ' · 화면 갱신 오류로 중지 요청됨'
        self.status.set(f'{context} · {suffix} · 완료 {complete} / 확인필요 {attention} / 미실행 {pending}{warning}')

    def _refresh_activity(self):
        if not getattr(self, 'busy', False) or not getattr(self, 'phase', '') or self.stop_event.is_set():
            return
        now = time.monotonic()
        elapsed = max(0, int(now - self.phase_started))
        idle = max(0, int(now - self.last_activity))
        if self.retry_until is not None:
            remaining = max(0, math.ceil(self.retry_until - now))
            text = f'{self.active_ap} · 재시도 대기 {remaining}초 · 시도 {self.active_attempt}'
        else:
            text = f'{self.active_ap} · {self.phase} · 시도 {self.active_attempt} · 단계 {elapsed}초 / 최근 응답 {idle}초 전'
        if self.local_record_failed:
            text += ' · 로컬 기록 실패'
        self.status.set(text)

    def _set_busy(self, busy):
        self.busy = busy
        for widget, idle_state in self.form_widgets:
            widget.configure(state="disabled" if busy else idle_state)
        self.inspect_button.configure(state="disabled" if busy else "normal")
        self.apply_button.configure(state="disabled" if busy else "normal")
        self.verify_button.configure(state="disabled" if busy else "normal")
        self.stop_button.configure(state="normal" if busy and not self.exporting else "disabled")
        self.export_button.configure(state="normal" if self.results and not busy else "disabled")
        self.report_button.configure(state='normal' if self.results and not busy else 'disabled')
        self.txt_button.configure(state='normal' if self.results and not busy else 'disabled')
        self.open_report_button.configure(state='normal' if self.report_file is not None and not busy else 'disabled')
        from .core import GOOD_STATUSES
        completed = {result.ap_ip for result in self.results if result.status in GOOD_STATUSES}
        can_resume = self.saved_config is not None and any(ap not in completed for ap in self.saved_config.ap_ips)
        self.resume_button.configure(state='normal' if can_resume and not busy else 'disabled')

    def _stop(self):
        self.stop_event.set()
        self.stop_button.configure(state="disabled")
        self.status.set("중지 요청 중… 이미 전송된 변경은 취소되지 않습니다. 결과 확인이 필요할 수 있습니다.")
        self._log("중지를 요청했습니다. 이후 AP 작업은 시작하지 않습니다.")

    def _export(self):
        if self.busy or not self.results:
            return
        filename = filedialog.asksaveasfilename(parent=self.root, title="작업 결과 저장", defaultextension=".csv", initialfile=f"wips_results_{datetime.now():%Y%m%d_%H%M%S}.csv", filetypes=[("CSV", "*.csv")])
        if filename:
            self._launch_export('csv', filename, self.results)

    def _save_report(self):
        if self.busy or not self.results:
            return
        folder = filedialog.askdirectory(parent=self.root, title='HTML·CSV 보고서 저장 위치 선택')
        if folder:
            self._launch_export('report', folder, self.results)

    def _save_selected_txt(self):
        if self.busy or not self.results:
            return
        selected = self.table.selection()
        if not selected:
            messagebox.showinfo('AP 선택', '결과 표에서 AP를 선택하세요. Ctrl 또는 Shift로 여러 개를 선택할 수 있습니다.', parent=self.root)
            return
        rows = [self.results[int(index)] for index in selected]
        folder = filedialog.askdirectory(parent=self.root, title='선택 AP TXT 저장 위치 선택')
        if folder:
            self._launch_export('txt', folder, rows)

    def _launch_export(self, kind, destination, results):
        if self.busy:
            return
        snapshot = copy.deepcopy(results)
        self.exporting = True
        self.phase, self.retry_until = '', None
        self._set_busy(True)
        self.status.set(f'AP {len(snapshot)}개 결과 파일 저장 중… 창을 닫으면 저장 완료 후 종료합니다.')
        self.worker = threading.Thread(target=self._run_export, args=(kind, destination, snapshot),
                                       name='wips-report-export', daemon=False)
        try:
            self.worker.start()
        except RuntimeError:
            # Reuse the existing failure path; results and destination are untouched.
            self.events.put(('export_error', {}))
            self.events.put(('export_end', {}))

    def _run_export(self, kind, destination, results):
        try:
            if kind == 'csv':
                from .core import export_results
                export_results(destination, results)
                path, label, report_file = Path(destination), 'CSV 저장 완료', ''
            elif kind == 'report':
                from .reports import write_report_bundle
                path = write_report_bundle(destination, results)
                label, report_file = 'HTML·CSV 보고서 저장 완료', str(path / 'report.html')
            elif kind == 'txt':
                from .reports import export_ap_txts
                path = export_ap_txts(destination, results)
                label, report_file = '선택 AP TXT 저장 완료', ''
            else:
                raise ValueError('unsupported export')
            self.events.put(('export_done', {'path': str(path), 'label': label,
                                            'report_file': report_file, 'count': len(results)}))
        except Exception:
            # Exceptions may include arbitrary paths or data; fixed UI text only.
            self.events.put(('export_error', {}))
        finally:
            self.events.put(('export_end', {}))

    def _open_report(self):
        if self.busy or self.report_file is None:
            return
        try:
            path = Path(self.report_file).resolve()
            if not path.is_file() or path.suffix.lower() != '.html':
                raise OSError('missing report')
            if os.name == 'nt':
                os.startfile(str(path))
            elif not webbrowser.open(path.as_uri()):
                raise OSError('browser unavailable')
        except Exception:
            messagebox.showerror('보고서 열기 실패', '저장된 HTML 보고서를 열지 못했습니다. 저장 폴더에서 report.html을 직접 열어 주세요.', parent=self.root)

    def _result_details(self, _event=None):
        selected = self.table.selection()
        if not selected:
            return
        item = self.results[int(selected[0])]
        details = (f"AP: {item.ap_ip}\n결과: {item.status}\n실행: {'모의' if item.simulated else '실제'}\n"
                   f"호스트명: {getattr(item, 'hostname', '') or '미확인'}\n이름 출처: {getattr(item, 'hostname_source', '') or '미확인'}\n"
                   f"조회 시각: {getattr(item, 'observed_at', '') or '미확인'}\n"
                   f"목표 서버 IP: {getattr(item, 'target_ip', '') or '-'}\nIP 확인: {getattr(item, 'ip_check', '') or '-'}\n"
                   f"서버 IP: {item.before_ip or '-'} → {item.after_ip or '-'}\n"
                   f"NAT: {item.before_nat or '-'} → {item.after_nat or '-'}\n키 확인: {item.key_check}\n"
                   f"컨트롤러 복귀: {item.controller_return or '-'}\n"
                   f"시도: {getattr(item, 'attempts', 1)} / 단계: {getattr(item, 'stage', '') or '-'}\n"
                   f"오류 코드: {getattr(item, 'error_code', '') or '-'}\n\n{item.message}")
        before = getattr(item, 'summary_before', '')
        after = getattr(item, 'summary_after', '')
        if before:
            details += f'\n\n[최초/조회 설정]\n{before}'
        if after:
            details += f'\n\n[변경 후/복구 조회 설정]\n{after}'
        messagebox.showinfo("AP 작업 결과", details, parent=self.root)

    def _log(self, message):
        self.log.configure(state="normal")
        self.log.insert("end", f"{datetime.now():%H:%M:%S}  {message}\n")
        # Keep the UI responsive for long batches; exports carry all AP results.
        lines = int(self.log.index("end-1c").split(".")[0])
        if lines > 300:
            self.log.delete("1.0", f"{lines - 300}.0")
        self.log.see("end")
        self.log.configure(state="disabled")

    def _scroll_page(self, event):
        if isinstance(event.widget, (tk.Text, ttk.Treeview, ttk.Combobox)):
            return
        if event.delta:
            self.page.yview_scroll(-1 if event.delta > 0 else 1, "units")
            return "break"

    def _close(self):
        if getattr(self, 'exporting', False):
            if messagebox.askyesno('파일 저장 중 종료', '파일 저장이 끝난 뒤 프로그램을 닫을까요?', parent=self.root, default='no'):
                self.closing = True
                self.status.set('파일 저장 완료 후 종료합니다…')
            return
        if self.busy:
            if not messagebox.askyesno("작업 중 종료", "작업을 중지하고 종료할까요?\n이미 전송된 변경은 취소되지 않습니다.\n세션이 종료될 때까지 잠시 기다립니다.", parent=self.root, default="no"):
                return
            self.closing = True
            self._stop()
        else:
            self.root.destroy()

    def _callback_error(self, _error_type, _error, _traceback):
        messagebox.showerror("화면 처리 오류", "화면 작업을 처리하지 못했습니다. 진행 중인 작업은 중지하고 결과를 확인하세요.", parent=self.root)


def main(demo_fill=False):
    root = tk.Tk()
    app = WipsApp(root)
    if demo_fill:
        app._fill_demo()
    root.mainloop()

