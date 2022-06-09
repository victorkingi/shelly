import logging

FMT = "[{levelname:^9}] {asctime} {name}: {message}"
FORMATS = {
    logging.DEBUG: FMT,
    logging.INFO: f"\33[36m{FMT}\33[0m",
    logging.WARNING: f"\33[33m{FMT}\33[0m",
    logging.ERROR: f"\33[31m{FMT}\33[0m",
    logging.CRITICAL: f"\33[31m\33[1m{FMT}\33[0m"
}

class CustomFormatter(logging.Formatter):
    def format(self, record):
        log_fmt = FORMATS[record.levelno]
        formatter = logging.Formatter(log_fmt, style="{")
        return formatter.format(record)


std_out = logging.StreamHandler()
std_out.setFormatter(CustomFormatter())

fh = logging.FileHandler('vm.log')
fh_formatter = logging.Formatter('[%(levelname)s] %(asctime)s %(name)s: %(message)s')
fh.setFormatter(fh_formatter)

logging.basicConfig(level=logging.DEBUG, handlers=[fh])

log = logging.getLogger("VM-execution")

