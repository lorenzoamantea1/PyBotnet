import logging, re, sys

class LoggerFormatter(logging.Formatter):
    GREY = "\x1b[38;20m"
    CYAN = "\x1b[38;5;51;48;5;21m"
    YELLOW = "\x1b[38;5;220m"
    YELLOW_2 = "\x1b[38;5;220;48;5;94m"
    RED = "\x1b[38;5;203;48;5;52m"
    BOLD_RED = "\x1b[1;38;5;196m"
    RESET = "\x1b[0m"

    BASE_FORMAT = (
        "[%(asctime)s] "
        "%(levelname)-8s "
        "| %(name)s - "
        "%(message)s "
        "(%(filename)s:%(lineno)d)"
    )
    DATE_FORMAT = "%H:%M:%S"

    FORMATS = {
        logging.DEBUG: YELLOW + BASE_FORMAT + RESET,
        logging.INFO: GREY + BASE_FORMAT + RESET,
        logging.WARNING: YELLOW_2 + BASE_FORMAT + RESET,
        logging.ERROR: RED + BASE_FORMAT + RESET,
        logging.CRITICAL: BOLD_RED + BASE_FORMAT + RESET
    }

    def __init__(self, use_color: bool = True):
        super().__init__()
        self.use_color = use_color and sys.stdout.isatty()

    def format(self, record):
        if self.use_color:
            log_fmt = self.FORMATS.get(record.levelno, self.GREY + self.BASE_FORMAT + self.RESET)
        else:
            log_fmt = self.BASE_FORMAT

        formatter = logging.Formatter(log_fmt, datefmt=self.DATE_FORMAT)
        output = formatter.format(record)

        if self.use_color and record.levelno == logging.INFO:
            output = re.sub(r"\bINFO\b", f"{self.CYAN}INFO{self.RESET}{self.GREY}", output)

        return output