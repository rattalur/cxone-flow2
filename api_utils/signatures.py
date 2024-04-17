import hashlib, hmac

class signature:

    @staticmethod
    def get(algorithm_name, secret, payload):
        h = hmac.new(bytes(secret, 'UTF-8'), payload, algorithm_name)
        return str(h.hexdigest())

    