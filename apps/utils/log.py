import logging


class LogFile:
    def __init__(self):
        self.logger = logging.getLogger(__name__)

        # Check if a FileHandler is already present
        file_handler_present = any(isinstance(handler, logging.FileHandler) for handler in self.logger.handlers)

        # Only add the FileHandler if it's not already present
        if not file_handler_present:
            f_handler = logging.FileHandler("messages.log", encoding='utf-8')
            f_handler.setLevel(logging.ERROR)
            f_format = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            f_handler.setFormatter(f_format)
            self.logger.addHandler(f_handler)

    def error(self, trace, e):
        print(e)
        self.logger.error(trace + str(e))

    def warning(self, w):
        self.logger.warning(w)

    def info(self, w):
        self.logger.info(w)
