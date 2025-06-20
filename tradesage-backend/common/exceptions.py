from fastapi import HTTPException, status  # Corrected from HTTTPException to HTTPException

class TradesageException(HTTPException):  # Fixed from HTTTPException to HTTPException
    def __init__(self, status_code: int = 500, message: str = "Internal Server Error"):
        self.message = message
        self.status_code = status_code
        super().__init__(status_code=status_code, detail=self.message)

class AuthenticationError(TradesageException):
    def __init__(self, message: str = "Authentication Failed"):
        super().__init__(message, status.HTTP_401_UNAUTHORIZED)

class AuthorizationError(TradesageException):
    def __init__(self, message: str = "Authorization Failed"):
        super().__init__(message, status.HTTP_403_FORBIDDEN)

class TenantNotFoundError(TradesageException):
    def __init__(self, tenant_id:str):
        super().__init__(f"Tenant {tenant_id} not found ", status.HTTP_404_NOT_FOUND)

class UserNotFoundError(TradesageException):
    def __init__(self, user_id: str):
        super().__init__(f"User {user_id} not found", status.HTTP_404_NOT_FOUND)
class ValidationError(TradesageException):
    def __init__(self, message: str = "Validation Error"):
        super().__init__(message, status.HTTP_422_UNPROCESSABLE_ENTITY)
class DatabaseError(TradesageException):
    def __init__(self, message: str = "Database Error"):
        super().__init__(f"Database error: {message}", status.HTTP_500_INTERNAL_SERVER_ERROR)