from pydantic import BaseModel, EmailStr


class RegisterRequest(BaseModel):
    email: EmailStr
    password: str
    first_name: str
    last_name: str


class UserDevicesQuery(BaseModel):
    page: int = 1
    page_size: int = 25


class DeviceCreateRequest(BaseModel):
    name: str


class AuthHeaders(BaseModel):
    token: str


class DeviceEditRequest(BaseModel):
    name: str | None = None


class DeviceConfigEditRequest(BaseModel):
    enabled_manually: bool | None = None
    enabled_auto: bool | None = None


class DevicePath(BaseModel):
    device_id: int
