import hashlib
import base64
import hmac

from constants import PWD_HASH_SALT, PWD_HASH_ITERATIONS

from dao.user import UserDAO


class UserService:

    def __init__(self, dao: UserDAO):
        self.dao = dao

    def get_one(self, uid):

        return self.dao.get_one(uid)

    def get_all(self):

        return self.dao.get_all()

    def get_by_name(self, name):

        return self.dao.get_by_name(name)

    def create(self, user_d):

        user_d['password'] = self.get_hash(user_d.get('password'))
        return self.dao.create(user_d)

    def update(self, user_d):

        user_d['password'] = self.get_hash(user_d.get('password'))
        self.dao.update(user_d)
        return self.dao

    def delete(self, uid):

        self.dao.delete(uid)

    def get_hash(self, password):

        return base64.b64encode(hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            PWD_HASH_SALT,
            PWD_HASH_ITERATIONS,
        ))

    def compare_passwords(self, pas_hash, other_pas) -> bool:

        decode_digest = base64.b64decode(pas_hash)

        hash_digest = hashlib.pbkdf2_hmac(
            'sha256',
            other_pas.encode('utf-8'),
            PWD_HASH_SALT,
            PWD_HASH_ITERATIONS,
        )

        return hmac.compare_digest(decode_digest, hash_digest)