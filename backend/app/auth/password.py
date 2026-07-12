import bcrypt

class PasswordHasher:
    """
    Password hashing and verification utility.
    """
    
    @staticmethod
    def hash_password(password: str) -> str:
        """
        Hash a plain password using bcrypt.
        """
        pw_bytes = password.encode('utf-8')
        salt = bcrypt.gensalt()
        hashed_bytes = bcrypt.hashpw(pw_bytes, salt)
        return hashed_bytes.decode('utf-8')

    @staticmethod
    def verify_password(plain_password: str, hashed_password: str) -> bool:
        """
        Verify a plain password against its hashed value.
        """
        try:
            pw_bytes = plain_password.encode('utf-8')
            hashed_bytes = hashed_password.encode('utf-8')
            return bcrypt.checkpw(pw_bytes, hashed_bytes)
        except Exception:
            return False
