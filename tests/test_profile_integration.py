"""Saved-profile GUI -> real Runner -> loopback Telnet, not Windows cryptography."""
import gc
from pathlib import Path
import tempfile
import time
import tkinter as tk
import unittest
from unittest.mock import patch

from test_gui import destroy_test_root
from test_integration import _TelnetController
from test_profile_store import TokenProtector, settings
from wec_wips.profile_store import ProfileStore
from wec_wips.profile_ui import ProfileApp


class ProfileIntegrationTests(unittest.TestCase):
    def run_profile(self, mode, expected_status):
        with tempfile.TemporaryDirectory() as folder, _TelnetController() as server:
            data=settings()
            data.update(controller_ip='127.0.0.1',controller_port=server.port,
                        ap_ips=['192.0.2.10'],ap_hostnames={'192.0.2.10':'CSV-LAB'},
                        auto_recover=False,timeout=2)
            crypto=TokenProtector();store=ProfileStore(Path(folder)/'profile',crypto)
            store.save(data,ap_password='APIntegrationSecret',shared_key='NewIntegrationKey')
            crypto.calls.clear()
            try:root=tk.Tk()
            except tk.TclError as exc:self.skipTest(f'No display: {exc}')
            app=None
            try:
                app=ProfileApp(root,store=store)
                self.assertEqual(crypto.calls,[])
                self.assertEqual(server.tcp_connections,0)
                app.controller_user.set('controlleradmin')
                app.controller_password.set('ControllerIntegrationSecret')
                with patch.dict('os.environ',{'XDG_STATE_HOME':folder,'LOCALAPPDATA':folder}),patch('wec_wips.gui.messagebox.askyesno',return_value=True):
                    app._start(mode)
                    deadline=time.monotonic()+10
                    while app.busy and time.monotonic()<deadline:
                        root.update();time.sleep(.005)
                self.assertFalse(app.busy)
                app.worker.join(1);self.assertFalse(app.worker.is_alive())
                self.assertEqual([r.status for r in app.results],[expected_status])
                self.assertEqual(app.results[0].controller_return,'복귀확인')
                self.assertEqual(app.results[0].hostname,'LAB-AP10')
                self.assertEqual(app.controller_password.get(),'ControllerIntegrationSecret')
                self.assertEqual(app.ap_password.get(),'')
                writes=[line for phase,line in server.commands if line.startswith('config ')]
                self.assertEqual(len(writes),1 if mode=='apply' else 0)
                self.assertEqual(sum(kind=='unprotect' for kind,_ in crypto.calls),2 if mode=='apply' else 1)
                self.assertEqual(server.tcp_connections,1)
                for path in Path(folder).rglob('*'):
                    if path.is_file():
                        raw=path.read_bytes()
                        for secret in (b'ControllerIntegrationSecret',b'APIntegrationSecret',b'NewIntegrationKey'):
                            self.assertNotIn(secret,raw,f'Unexpected secret in {path.name}')
            finally:
                if app and app.worker and app.worker.is_alive():
                    app.stop_event.set();app.worker.join(5)
                destroy_test_root(root);app=root=None;gc.collect()
            self.assertEqual(server.errors,[])

    def test_inspect_restored_profile(self):self.run_profile('inspect','조회완료')
    def test_verify_ip_restored_profile(self):self.run_profile('verify_ip','IP불일치')
    def test_apply_restored_profile(self):self.run_profile('apply','변경확인')

if __name__=='__main__':unittest.main()
