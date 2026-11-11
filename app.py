"""Windows 11 entry point: python app.py [--demo]."""
import argparse
import sys


def main():
    parser = argparse.ArgumentParser(description="WEC8500 AP WIPS Manager")
    parser.add_argument("--demo", action="store_true", help="Fill the GUI with fictional demo data; no network access")
    args = parser.parse_args()
    if sys.platform == "win32":
        try:
            import ctypes
            ctypes.windll.shcore.SetProcessDpiAwareness(1)
        except (AttributeError, OSError):
            pass
    from wec_wips.gui import main as gui_main
    gui_main(demo_fill=args.demo)


if __name__ == "__main__":
    main()
