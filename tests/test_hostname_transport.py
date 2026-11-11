"""Synthetic hostname inventory and prompt parsing; no production equipment."""
from collections import deque
from types import SimpleNamespace
from unittest.mock import patch
import threading
import unittest

from test_transport import Peer
from wec_wips.transport import Session, TransportError

HEADER = 'AP_ID Profile AP_NAME MAC_Address IPv4Addr State Location\r\n'
TABLE = HEADER + '1 ap_1 RND-F09-AP01 aa:bb:cc:dd:ee:01 192.0.2.11 1/1/5 room\r\n'

class HostnameTransportTests(unittest.TestCase):
    def setUp(self):
        self.cfg = SimpleNamespace(controller_ip='192.0.2.1',controller_port=23,
            controller_user='admin',controller_password='CtlSecret',ap_port=50022,
            ap_user='root',ap_password='APSecret',shared_key='WipsSecret',timeout=.18,
            auto_accept_ap_host_key=True,lookup_hostnames=True)
        self.stop=threading.Event()

    def peer(self, table=TABLE, prompt='AP#'):
        return Peer({'admin\n':[b'Password:'], 'CtlSecret\n':[b'WEC8500#'],
                     'show ap summary\n':[(table+'WEC8500#').encode()] if table is not None else [],
                     'ssh 192.0.2.11 root 50022\n':[b'Password:'],
                     'ssh 192.0.2.12 root 50022\n':[b'Password:'],
                     'APSecret\n':[prompt.encode()],
                     'exit\n':[b'WEC8500#']})

    def connect(self, peers):
        connector=patch('wec_wips.transport.TelnetChannel.connect', side_effect=peers)
        mocked=connector.start();self.addCleanup(connector.stop)
        session=Session(self.cfg,self.stop,lambda *_:False)
        session.connect('192.0.2.11')
        return session,mocked

    def test_controller_name_preferred_and_query_once_for_multiple_aps(self):
        p=self.peer(TABLE+'2 ap_2 RND-F09-AP02 aa:bb:cc:dd:ee:02 192.0.2.12 1/1/5\r\n')
        s,m=self.connect([p])
        self.assertEqual(getattr(s,'ap_hostname',None),'RND-F09-AP01')
        self.assertEqual(s.hostname_source,'컨트롤러 AP_NAME')
        s.leave_ap();s.connect('192.0.2.12')
        self.assertEqual(s.ap_hostname,'RND-F09-AP02')
        self.assertEqual(p.sent.count('show ap summary\n'),1)
        self.assertEqual(m.call_count,1)

    def test_supported_table_header_variants(self):
        from wec_wips.transport import parse_ap_names
        for header in (HEADER,'AP_ID CFG_NAME AP_Name Mac_Address IPv4Addr\r\n'):
            value=header+'1 ap_1 AP_f4d9fb23d049 f4:d9:fb:23:d0:49 192.0.2.11\r\n1/1/5\r\n'
            self.assertEqual(parse_ap_names(value),{'192.0.2.11':'AP_f4d9fb23d049'})

    def test_parser_ignores_banner_and_conflicting_duplicates(self):
        from wec_wips.transport import parse_ap_names
        text='AP Mgnt interface IP: 192.0.2.1\r\n'+TABLE
        text+='2 ap_2 OTHER aa:bb:cc:dd:ee:02 192.0.2.11 1/1/5\r\n'
        text+='3 ap_3 GOOD aa:bb:cc:dd:ee:03 192.0.2.12 1/1/5\r\n'
        text+='4 ap_4 INVALIDMAC xx:bb:cc:dd:ee:03 192.0.2.13 1/1/5\r\n'
        self.assertEqual(parse_ap_names(text),{'192.0.2.12':'GOOD'})
        self.assertEqual(parse_ap_names('1 ap_1 SECRET aa:bb:cc:dd:ee:01 192.0.2.11\n'),{})

    def test_secret_name_rejected_but_safe_prompt_used(self):
        p=self.peer(TABLE.replace('RND-F09-AP01','WipsSecret'),prompt='AP-11#')
        s,_=self.connect([p]);self.assertEqual(s.ap_hostname,'AP-11')
        self.assertEqual(s.hostname_source,'AP 프롬프트')

    def test_generic_prompt_has_no_hostname(self):
        p=self.peer('% Invalid command\r\n',prompt='AP#')
        s,_=self.connect([p]);self.assertEqual(s.ap_hostname,'')
        self.assertEqual(s.hostname_source,'')
        self.assertTrue(s._ready)

    def test_prompt_host_part_only_and_disabled_query(self):
        self.cfg.lookup_hostnames=False
        p=self.peer(prompt='root@RND-AP11:~#')
        s,_=self.connect([p]);self.assertEqual(s.ap_hostname,'RND-AP11')
        self.assertNotIn('show ap summary\n',p.sent)

    def test_query_timeout_reauthenticates_once_without_repeating_query(self):
        p=self.peer(None);fresh=self.peer(prompt='AP-11#')
        s,m=self.connect([p,fresh]);self.assertEqual(s.ap_hostname,'AP-11')
        self.assertTrue(p.closed);self.assertEqual(m.call_count,2)
        self.assertEqual(p.sent.count('show ap summary\n'),1)
        self.assertNotIn('show ap summary\n',fresh.sent)
        self.assertNotIn('ssh 192.0.2.11 root 50022\n',p.sent)

    def test_query_connection_drop_falls_back_to_fresh_login(self):
        p=self.peer();p.replies['show ap summary\n']=[b'']
        fresh=self.peer(prompt='AP-11#')
        s,m=self.connect([p,fresh]);self.assertEqual(s.ap_hostname,'AP-11')
        self.assertEqual(m.call_count,2)

    def test_controller_auth_failure_is_not_retried(self):
        p=self.peer();p.replies['CtlSecret\n']=[b'Login incorrect\r\nUsername:']
        with patch('wec_wips.transport.TelnetChannel.connect',return_value=p) as connect:
            s=Session(self.cfg,self.stop,lambda *_:False)
            with self.assertRaises(TransportError) as cm:s.connect('192.0.2.11')
            self.assertEqual(cm.exception.code,'CONTROLLER_AUTH_FAILED')
            self.assertEqual(connect.call_count,1)
            self.assertNotIn('show ap summary\n',p.sent)

    def test_ap_auth_failure_retains_only_current_controller_name(self):
        p=self.peer();p.replies['APSecret\n']=[b'Permission denied\r\nWEC8500#']
        with patch('wec_wips.transport.TelnetChannel.connect',return_value=p):
            s=Session(self.cfg,self.stop,lambda *_:False)
            with self.assertRaises(TransportError) as cm:s.connect('192.0.2.11')
            self.assertEqual(cm.exception.code,'AP_AUTH_FAILED')
            self.assertEqual(s.ap_hostname,'RND-F09-AP01')
            self.assertEqual(s.hostname_source,'컨트롤러 AP_NAME')

    def test_changed_host_key_unchanged_and_no_yes_or_ap_password(self):
        p=self.peer();p.replies['ssh 192.0.2.11 root 50022\n']=[b'WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!']
        with patch('wec_wips.transport.TelnetChannel.connect',return_value=p):
            s=Session(self.cfg,self.stop,lambda *_:False)
            with self.assertRaises(TransportError) as cm:s.connect('192.0.2.11')
            self.assertEqual(cm.exception.code,'HOST_KEY_CHANGED')
            self.assertNotIn('yes\n',p.sent);self.assertNotIn('APSecret\n',p.sent)

    def test_observer_has_inventory_stage_without_names_or_raw_text(self):
        p=self.peer();events=[]
        with patch('wec_wips.transport.TelnetChannel.connect',return_value=p):
            s=Session(self.cfg,self.stop,lambda *_:False);s.set_observer(lambda k,d:events.append((k,d)))
            s.connect('192.0.2.11')
        self.assertIn(('stage',{'stage':'AP 이름 조회'}),events)
        for secret in ('CtlSecret','APSecret','WipsSecret','RND-F09-AP01','aa:bb'):
            self.assertNotIn(secret,repr(events))

    def test_cancel_during_optional_lookup_does_not_reauthenticate(self):
        parent=self
        class StopPeer(Peer):
            def sendall(self,data):
                super().sendall(data)
                if data=='show ap summary\n':parent.stop.set()
        original=self.peer()
        peer=StopPeer(original.replies)
        with patch('wec_wips.transport.TelnetChannel.connect',return_value=peer) as connect:
            session=Session(self.cfg,self.stop,lambda *_:False)
            with self.assertRaises(TransportError) as cm:session.connect('192.0.2.11')
            self.assertEqual(cm.exception.code,'CANCELLED')
            self.assertEqual(connect.call_count,1)
            self.assertFalse(any(command.startswith('ssh ') for command in peer.sent))

    def test_conflicting_invalid_name_does_not_leave_first_mapping(self):
        from wec_wips.transport import parse_ap_names
        text=TABLE+'2 ap_2 AP aa:bb:cc:dd:ee:02 192.0.2.11 1/1/5\r\n'
        self.assertEqual(parse_ap_names(text),{})
