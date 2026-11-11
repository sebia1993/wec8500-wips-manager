"""Optional Windows profile layer around the unchanged, stabilized WipsApp."""
from __future__ import annotations

import tkinter as tk
from tkinter import messagebox, ttk

from .core import RunConfig, _ipv4, parse_ap_ips
from .gui import WipsApp, NAT, SYNTAX
from .profile_store import ProfileError, ProfileStore, binding, normalize_settings

_AUTO = object()


class ProfileApp(WipsApp):
    def __init__(self, root, *, store=_AUTO, load_profile=True):
        self._profile = None
        self._loading_profile = False
        self._profile_notice = ''
        if store is _AUTO:
            try:
                store = ProfileStore()
            except ProfileError as exc:
                store = None
                self._profile_notice = str(exc)
        self.profile_store = store
        super().__init__(root)
        self.root.title("WEC8500 WIPS Manager v1.5.1 · profile.1 · Windows 보호 프로필")
        for variable in (self.controller_ip, self.controller_port, self.ap_user,
                         self.ap_port, self.server_ip):
            variable.trace_add('write', self._profile_context_changed)
        if load_profile and self.profile_store is not None:
            self._load_profile(silent=True)
        else:
            self.profile_status.set(self._profile_notice or '저장된 정보 없이 수동 입력합니다.')
        self._sync_profile_controls()

    def _build(self):
        super()._build()
        self.use_saved_ap = tk.BooleanVar(self.root, value=False)
        self.use_saved_key = tk.BooleanVar(self.root, value=False)
        self.profile_status = tk.StringVar(self.root, value='저장된 기본 프로필 없음')
        bar = ttk.Frame(self.root, padding=(18, 7))
        bar.pack(fill='x', before=self.page.master)
        top = ttk.Frame(bar)
        top.pack(fill='x')
        ttk.Label(top, text='기본 프로필', font=('Malgun Gothic', 10, 'bold')).pack(side='left', padx=(0, 10))
        self.profile_save_button = ttk.Button(top, text='설정 저장', command=self._save_profile_dialog)
        self.profile_save_button.pack(side='left')
        self.profile_load_button = ttk.Button(top, text='저장 설정 불러오기', command=self._load_profile)
        self.profile_load_button.pack(side='left', padx=6)
        self.profile_delete_button = ttk.Button(top, text='저장 설정 삭제', command=self._delete_profile)
        self.profile_delete_button.pack(side='left')
        ttk.Label(top, text='WEC8500 ID·비밀번호는 저장하지 않습니다.', style='Hint.TLabel').pack(side='left', padx=12)
        options = ttk.Frame(bar)
        options.pack(fill='x', pady=(4, 0))
        self.saved_ap_check = ttk.Checkbutton(options, text='빈 입력 시 저장된 AP 비밀번호 사용', variable=self.use_saved_ap)
        self.saved_ap_check.pack(side='left')
        self.saved_key_check = ttk.Checkbutton(options, text='변경 작업에 저장된 공유키 사용 (빈 입력 시)', variable=self.use_saved_key)
        self.saved_key_check.pack(side='left', padx=12)
        ttk.Label(bar, textvariable=self.profile_status, style='Hint.TLabel', wraplength=1120).pack(anchor='w')

    def _mode_changed(self, *_):
        super()._mode_changed()
        if hasattr(self, 'use_saved_ap'):
            self._sync_profile_controls()

    def _profile_context_changed(self, *_):
        if not self._loading_profile:
            self._sync_profile_controls()

    def _matches(self, kind):
        if self._profile is None or kind not in self._profile.secrets or self.demo.get():
            return False
        try:
            current = dict(controller_ip=_ipv4(self.controller_ip.get(), '컨트롤러 IP'),
                           controller_port=int(self.controller_port.get().strip()),
                           ap_user=self.ap_user.get().strip(), ap_port=int(self.ap_port.get().strip()),
                           server_ip=self.server_ip.get().strip())
            return binding(current, kind) == binding(self._profile.settings, kind)
        except (ValueError, TypeError, KeyError):
            return False

    def _sync_profile_controls(self):
        if self._loading_profile or not hasattr(self, 'profile_save_button'):
            return
        available = self.profile_store is not None and not self.busy
        for button in (self.profile_save_button, self.profile_load_button, self.profile_delete_button):
            button.configure(state='normal' if available else 'disabled')
        for kind, variable, widget in (('ap_password', self.use_saved_ap, self.saved_ap_check),
                                       ('shared_key', self.use_saved_key, self.saved_key_check)):
            matched = self._matches(kind)
            if not matched:
                variable.set(False)
            widget.configure(state='normal' if available and matched else 'disabled')

    def _set_busy(self, busy):
        super()._set_busy(busy)
        self._sync_profile_controls()

    def _fill_demo(self):
        if self.busy:
            return
        self.use_saved_ap.set(False)
        self.use_saved_key.set(False)
        super()._fill_demo()
        self.profile_status.set('모의 실행: 저장된 비밀정보를 사용하거나 저장 프로필을 덮어쓰지 않습니다.')
        self._sync_profile_controls()

    def _collect_settings(self, include_targets=True):
        try:
            ips = parse_ap_ips(self.ap_text.get('1.0', 'end')) if include_targets else []
            data = dict(controller_ip=self.controller_ip.get().strip(),
                        controller_port=int(self.controller_port.get().strip()),
                        ap_user=self.ap_user.get().strip(), ap_port=int(self.ap_port.get().strip()),
                        server_ip=self.server_ip.get().strip(), syntax=SYNTAX[self.syntax.get()],
                        nat_mode=NAT[self.nat_mode.get()], timeout=float(self.timeout.get().strip()),
                        auto_recover=self.auto_recover.get(), stop_on_error=self.stop_on_error.get(),
                        auto_accept_ap_host_key=self.auto_accept_ap_host_key.get(),
                        lookup_hostnames=self.lookup_hostnames.get(), ap_ips=ips,
                        ap_hostnames={ip:self.ap_hostnames[ip] for ip in ips if ip in self.ap_hostnames})
            return normalize_settings(data)
        except (ValueError, KeyError):
            raise ProfileError('프로필의 IP·포트·AP 계정·옵션·대상 목록을 확인하세요.') from None

    def _snapshot(self, mode):
        password = self.ap_password.get()
        key = self.shared_key.get()
        use_ap = not password and self.use_saved_ap.get()
        use_key = mode == 'apply' and not key and self.use_saved_key.get()
        if self.demo.get() or not (use_ap or use_key):
            return super()._snapshot(mode)
        # Mirror the existing form snapshot; persistence validation must not make
        # unused NAT/target fields mandatory for a query-only operation.
        try:
            controller_port = int(self.controller_port.get().strip())
            ap_port = int(self.ap_port.get().strip())
            timeout = float(self.timeout.get().strip())
        except ValueError:
            raise ValueError('Telnet·SSH 포트와 응답 제한에는 숫자를 입력하세요.') from None
        ips = parse_ap_ips(self.ap_text.get('1.0', 'end'))
        cfg = RunConfig(
            controller_ip=self.controller_ip.get().strip(), controller_port=controller_port,
            controller_user=self.controller_user.get().strip(), controller_password=self.controller_password.get(),
            ap_ips=ips, ap_port=ap_port, ap_user=self.ap_user.get().strip(),
            ap_password='SavedValueValidationOnly' if use_ap else password,
            server_ip=self.server_ip.get().strip(), shared_key='SavedValueValidationOnly' if use_key else key,
            syntax=SYNTAX[self.syntax.get()], nat_mode=NAT[self.nat_mode.get()], timeout=timeout,
            demo=False, stop_on_error=self.stop_on_error.get(), auto_recover=self.auto_recover.get(),
            auto_accept_ap_host_key=self.auto_accept_ap_host_key.get(),
            lookup_hostnames=self.lookup_hostnames.get(),
            ap_hostnames={ip:self.ap_hostnames[ip] for ip in ips if ip in self.ap_hostnames})
        cfg.validate(mode)
        if self.profile_store is None or self._profile is None:
            raise ProfileError('저장된 정보가 없습니다. 직접 입력하세요.')
        # Bind secrets only to endpoints/identity, not unrelated operation options.
        context = dict(controller_ip=cfg.controller_ip, controller_port=cfg.controller_port,
                       ap_user=cfg.ap_user, ap_port=cfg.ap_port,
                       server_ip=cfg.server_ip if use_key else '')
        if use_ap:
            cfg.ap_password = self.profile_store.secret(self._profile, 'ap_password', context)
        if use_key:
            cfg.shared_key = self.profile_store.secret(self._profile, 'shared_key', context)
        cfg.validate(mode)
        return cfg

    def _load_profile(self, silent=False):
        if self.busy or self.profile_store is None:
            return
        try:
            profile = self.profile_store.load()
        except ProfileError as exc:
            self._profile = None
            self.use_saved_ap.set(False); self.use_saved_key.set(False)
            self.profile_status.set(str(exc))
            self._sync_profile_controls()
            if not silent:
                messagebox.showerror('저장 설정 확인', str(exc), parent=self.root)
            return
        if profile is None:
            self._profile = None
            self.profile_status.set('저장된 기본 프로필이 없습니다. 처음 한 번 입력하고 설정 저장을 누르세요.')
            self._sync_profile_controls()
            return
        self._loading_profile = True
        try:
            self._profile = profile
            for name in ('controller_ip','controller_port','ap_user','ap_port','server_ip','timeout',
                         'auto_recover','stop_on_error','auto_accept_ap_host_key','lookup_hostnames'):
                getattr(self, name).set(profile.settings[name])
            self.syntax.set(next(label for label,value in SYNTAX.items() if value == profile.settings['syntax']))
            self.nat_mode.set(next(label for label,value in NAT.items() if value == profile.settings['nat_mode']))
            self.ap_text.delete('1.0', 'end')
            self.ap_text.insert('1.0', '\n'.join(profile.settings['ap_ips']))
            self.ap_hostnames = dict(profile.settings['ap_hostnames'])
            for variable in (self.controller_user,self.controller_password,self.ap_password,self.shared_key):
                variable.set('')
            self.demo.set(False)
            self.use_saved_ap.set('ap_password' in profile.secrets)
            self.use_saved_key.set('shared_key' in profile.secrets)
        finally:
            self._loading_profile = False
        self.profile_status.set('실장비 기본 프로필을 불러왔습니다. WEC8500 ID·비밀번호와 AP 대상을 확인한 뒤 실행하세요. 자동 접속하지 않습니다.')
        self._sync_profile_controls()

    def _save_profile_values(self, save_ap, save_key, save_targets):
        if self.busy or self.profile_store is None:
            raise ProfileError('작업 중이거나 저장을 지원하지 않는 환경입니다.')
        if self.demo.get():
            raise ProfileError('모의 데이터는 실장비 프로필에 저장하지 않습니다. 실장비 설정을 입력하세요.')
        if any(type(value) is not bool for value in (save_ap,save_key,save_targets)):
            raise ProfileError('저장 항목을 확인하세요.')
        data = self._collect_settings(include_targets=save_targets)
        selected = {}
        for kind, wanted, variable, use in (('ap_password',save_ap,self.ap_password,self.use_saved_ap),
                                           ('shared_key',save_key,self.shared_key,self.use_saved_key)):
            if not wanted:
                continue
            value = variable.get()
            if not value:
                if self._profile is None or not use.get():
                    raise ProfileError('저장할 AP 비밀번호 또는 공유키를 직접 입력하세요.')
                value = self.profile_store.secret(self._profile,kind,data)
            selected[kind] = value
        # Do not replace in-memory profile until the complete encrypted file is committed.
        profile = self.profile_store.save(data, **selected)
        self._profile = profile
        self.use_saved_ap.set(save_ap); self.use_saved_key.set(save_key)
        if save_ap: self.ap_password.set('')
        if save_key: self.shared_key.set('')
        self.profile_status.set('기본 프로필 저장 완료. WEC8500 ID·비밀번호는 저장하지 않았습니다. 선택하지 않은 비밀정보는 저장소에서 제외했습니다.')
        self._sync_profile_controls()

    def _save_profile_dialog(self):
        if self.busy or self.profile_store is None:
            return
        if self.demo.get():
            messagebox.showinfo('설정 저장', '모의 실행 상태에서는 실장비 프로필을 저장하지 않습니다.', parent=self.root)
            return
        dialog = tk.Toplevel(self.root)
        dialog.title('기본 프로필 저장')
        dialog.transient(self.root)
        dialog.resizable(False, False)
        body = ttk.Frame(dialog,padding=18);body.pack(fill='both',expand=True)
        ttk.Label(body, text='일반 설정은 저장합니다. 비밀정보와 AP 목록은 아래에서 선택하세요.\nWEC8500 ID·비밀번호는 선택할 수 없으며 저장하지 않습니다.', wraplength=560).pack(anchor='w',pady=(0,12))
        save_ap=tk.BooleanVar(dialog,value=bool(self._profile and 'ap_password' in self._profile.secrets))
        save_key=tk.BooleanVar(dialog,value=bool(self._profile and 'shared_key' in self._profile.secrets))
        save_targets=tk.BooleanVar(dialog,value=bool(self._profile and self._profile.settings['ap_ips']))
        for label,var in [('AP 비밀번호를 Windows 사용자 범위로 암호화 저장',save_ap),
                          ('변경 목표 WIPS 공유키를 Windows 사용자 범위로 암호화 저장',save_key),
                          ('AP IP 목록·hostname 저장 (다음 작업 전 대상 확인 필요)',save_targets)]:
            ttk.Checkbutton(body,text=label,variable=var).pack(anchor='w',pady=4)
        ttk.Label(body,text='기존 기본 프로필을 교체합니다. 체크 해제한 비밀정보는 새 저장소에서 제외됩니다.\n동일 Windows 사용자로 실행되는 다른 프로그램까지 차단하는 앱 전용 금고는 아닙니다.\n사내 저장 정책이 허용하는 경우에만 저장하세요.',wraplength=560,style='Hint.TLabel').pack(anchor='w',pady=12)
        buttons=ttk.Frame(body);buttons.pack(fill='x')
        def save():
            try:
                self._save_profile_values(save_ap.get(),save_key.get(),save_targets.get())
            except ProfileError as exc:
                messagebox.showerror('설정 저장 실패',str(exc),parent=dialog)
                return
            dialog.destroy()
        ttk.Button(buttons,text='취소',command=dialog.destroy).pack(side='right')
        ttk.Button(buttons,text='선택한 항목 저장',command=save).pack(side='right',padx=8)
        dialog.grab_set()
        dialog.protocol('WM_DELETE_WINDOW',dialog.destroy)
        dialog.bind('<Escape>',lambda _:dialog.destroy())

    def _delete_profile(self):
        if self.busy or self.profile_store is None:
            return
        if not messagebox.askyesno('저장 설정 삭제', '일반 설정과 암호화된 AP 비밀번호·공유키를 삭제할까요?\n보고서와 이 창의 이전 작업 이어하기 정보는 삭제하지 않습니다.', parent=self.root,default='no'):
            return
        try:
            self.profile_store.delete()
        except ProfileError as exc:
            messagebox.showerror('삭제 실패',str(exc),parent=self.root)
            return
        self._profile=None
        self.use_saved_ap.set(False);self.use_saved_key.set(False)
        self.ap_password.set('');self.shared_key.set('')
        self.profile_status.set('저장된 프로필을 삭제했습니다. 현재 일반 입력값·이전 결과는 유지되며 비밀정보는 다시 입력해야 합니다.')
        self._sync_profile_controls()


def main(demo_fill=False):
    root=tk.Tk()
    app=ProfileApp(root,load_profile=not demo_fill)
    if demo_fill:
        app._fill_demo()
    root.mainloop()
