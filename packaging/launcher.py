"""Launch the bundled GUI with user-owned file-dialog defaults."""
from pathlib import Path
import os


def main():
    # The single-file launcher extracts the runtime to a temporary directory.
    # Keep open/save dialogs outside that directory so CSV exports survive exit.
    home = Path.home()
    documents = home / "Documents"
    os.chdir(documents if documents.is_dir() else home)
    from app import main as application_main
    application_main()


if __name__ == "__main__":
    main()
