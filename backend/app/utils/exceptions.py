from fastapi import HTTPException, status

class AISecurityException(HTTPException):
    """
    Base exception for AI Security Auditor custom errors.
    """
    def __init__(self, detail: str, status_code: int = status.HTTP_400_BAD_REQUEST):
        super().__init__(status_code=status_code, detail=detail)
