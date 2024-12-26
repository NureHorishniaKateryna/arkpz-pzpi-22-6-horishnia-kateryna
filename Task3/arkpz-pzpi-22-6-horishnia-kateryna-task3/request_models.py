from pydantic import BaseModel, EmailStr, Field


class RegisterRequest(BaseModel):
    email: EmailStr
    password: str
    first_name: str
    last_name: str

    is_admin: bool = False


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


class DeviceReportRequest(BaseModel):
    enabled: bool
    was_enabled_for: int | None = None


class PaginationQuery(BaseModel):
    page: int = 1
    page_size: int = 25


class UserPath(BaseModel):
    user_id: int


class EditUserRequest(BaseModel):
    email: EmailStr | None = None
    password: str | None = None
    first_name: str | None = None
    last_name: str | None = None
