"""WSGI entry point: gunicorn -w 2 --threads 4 -b 127.0.0.1:8080 wsgi:app"""

import logging

from nehemiah_dns.config import load_env_file
from nehemiah_dns.web import create_app

load_env_file(".env")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
app = create_app()
