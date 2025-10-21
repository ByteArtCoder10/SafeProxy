import logging

logging.basicConfig(
    level=logging.INFO,
    filename="D:/SafeProxy/src/logs/safe_proxy.log",
    filemode="w",
    format="%(asctime)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s"
)