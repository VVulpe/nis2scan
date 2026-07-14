"""Allow running nis2scan as a module: python -m nis2scan"""

from nis2scan.cli.cli import app

if __name__ == "__main__":
    app()
