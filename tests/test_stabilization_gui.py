"""Large result queue regression; GUI behavior and processing policy stay unchanged."""
import gc
import ipaddress
import threading
import time
import unittest

from test_gui import destroy_test_root
from wec_wips.core import Result, RunConfig
from wec_wips.gui import WipsApp


class LargeQueueTests(unittest.TestCase):
    def test_ten_thousand_results_and_activity_events_are_not_lost(self):
        import tkinter as tk
        try:
            root = tk.Tk()
        except tk.TclError as exc:
            self.skipTest(f'No display: {exc}')
        app = None
        try:
            app = WipsApp(root)
            addresses = [str(ipaddress.IPv4Address('198.18.0.1') + i) for i in range(10000)]
            app.saved_config = RunConfig('192.0.2.1', 23, '', '', addresses, 50022, '', '', demo=True)
            app.saved_mode = 'inspect'
            app.progress.configure(maximum=len(addresses))
            app._set_busy(True)
            started = time.monotonic()
            for address in addresses:
                app.events.put(('activity', {'ap_ip': address}))
                app.events.put(('activity', {'ap_ip': address}))
                app.events.put(('result', {'result': Result('2026-11-11T00:00:00+09:00', address, '조회완료', mode='inspect', simulated=True)}))
            app.events.put(('worker_end', {}))
            # Exercise the production bounded consumer, not an alternate bulk renderer.
            pumps = 0
            while not app.events.empty():
                app._pump()
                root.update_idletasks()
                pumps += 1
                self.assertLess(pumps, 400)
            self.assertEqual([result.ap_ip for result in app.results], addresses)
            self.assertEqual(len(app.table.get_children()), 10000)
            self.assertEqual(int(float(app.progress['value'])), 10000)
            self.assertFalse(app.busy)
            self.assertFalse(app.ui_failed)
            self.assertEqual(str(app.inspect_button['state']), 'normal')
            self.assertEqual(str(app.stop_button['state']), 'disabled')
            self.assertEqual(pumps, 301)
            print(f'QUEUE_METRIC rows=10000 events=30001 pumps={pumps} seconds={time.monotonic()-started:.3f}', flush=True)
        finally:
            destroy_test_root(root)
            del app
            gc.collect()


if __name__ == '__main__':
    unittest.main()
