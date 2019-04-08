class MissingParameters(Exception):
    def __init__(self, message):
        self.message = message

    def __str__(self):
        return "Missing required parameter: {}".format(self.message)
