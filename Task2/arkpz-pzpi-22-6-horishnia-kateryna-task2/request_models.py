from pydantic import BaseModel, EmailStr, Field


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
    electricity_price: float


class AuthHeaders(BaseModel):
    token: str


class DeviceEditRequest(BaseModel):
    name: str | None = None


class DeviceConfigEditRequest(BaseModel):
    enabled_manually: bool | None = None
    enabled_auto: bool | None = None
    electricity_price: float | None = None


class DevicePath(BaseModel):
    device_id: int


class DeviceScheduleAddRequest(BaseModel):
    start_hour: int = Field(ge=0, le=23)
    end_hour: int = Field(ge=0, le=23)


class SchedulePath(DevicePath):
    schedule_id: int


class DeviceReportsQuery(BaseModel):
    page: int = 1
    page_size: int = 25
