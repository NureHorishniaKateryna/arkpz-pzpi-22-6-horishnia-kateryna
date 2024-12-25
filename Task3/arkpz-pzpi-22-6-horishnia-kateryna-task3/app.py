from datetime import datetime, UTC
from time import time

import bcrypt
import jwt
from flask_openapi3 import OpenAPI
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from errors import NotAuthorizedError
from models import ModelsBase, User, UserSession, IotDevice, DeviceConfiguration, DeviceSchedule, DeviceReport
from request_models import RegisterRequest, UserDevicesQuery, DeviceCreateRequest, AuthHeaders, DeviceEditRequest, \
    DeviceConfigEditRequest, DevicePath, DeviceScheduleAddRequest, SchedulePath, DeviceReportsQuery, \
    DeviceReportRequest, PaginationQuery, UserPath, EditUserRequest

app = OpenAPI(__name__, doc_prefix="/docs")
JWT_EXPIRE_TIME = 60 * 60 * 24
JWT_KEY = b"0123456789abcdef"  # urandom(16)
# app.config["SQLALCHEMY_DATABASE_URL"] = "sqlite://test.db"

engine = create_engine("sqlite:///test.db")
ModelsBase.metadata.create_all(engine)
DBSession = sessionmaker(engine)
session = DBSession()


@app.errorhandler(NotAuthorizedError)
def handle_not_authorized(_):
    return {"error": "Not authorized!"}, 401


def auth_user(token: str) -> User:
    token = jwt.decode(token, JWT_KEY, algorithms=["HS256"])
    user = session.query(User).filter_by(id=token["user"]).join(UserSession) \
        .filter(UserSession.id == token["session"]).scalar()
    if user is None:
        raise NotAuthorizedError

    return user


def auth_admin(token: str) -> User:
    user = auth_user(token)
    if not user.is_admin:
        raise NotAuthorizedError

    return user


def auth_device(token: str) -> IotDevice:
    try:
        device_id, key = token.split(".")
        device_id = int(device_id)
    except ValueError:
        raise NotAuthorizedError

    device = session.query(IotDevice).filter_by(id=device_id, api_key=key).join(DeviceConfiguration).scalar()
    if device is None:
        raise NotAuthorizedError

    return device


@app.post("/api/auth/register")
def register(body: RegisterRequest):
    if session.query(User).filter_by(email=body.email).scalar() is not None:
        return {"error": "User with this email already exists!"}, 400

    password_hash = bcrypt.hashpw(body.password.encode("utf8"), bcrypt.gensalt()).decode("utf8")
    user = User(email=body.email, password=password_hash, first_name=body.first_name, last_name=body.last_name)
    user_session = UserSession(user=user)
    session.add(user)
    session.add(user_session)
    session.commit()

    return {
        "token": jwt.encode({
            "user": user.id,
            "session": user_session.id,
            "exp": int(time() + JWT_EXPIRE_TIME)
        }, JWT_KEY)
    }


@app.post("/api/auth/login")
def login(body: RegisterRequest):
    user = session.query(User).filter_by(email=body.email).scalar()
    if user is None:
        return {"error": "User with this credentials does not exist!"}, 400

    if not bcrypt.checkpw(body.password.encode("utf8"), user.password.encode("utf8")):
        return {"error": "User with this credentials does not exist!"}, 400

    user_session = UserSession(user=user)
    session.add(user_session)
    session.commit()

    return {
        "token": jwt.encode({
            "user": user.id,
            "session": user_session.id,
            "exp": int(time() + JWT_EXPIRE_TIME)
        }, JWT_KEY, algorithm="HS256")
    }


@app.get("/api/devices")
def get_user_devices(query: UserDevicesQuery, header: AuthHeaders):
    user = auth_user(header.token)

    query_ = session.query(IotDevice).filter_by(user=user).join(DeviceConfiguration)

    count = query_.count()
    query_ = query_.limit(query.page_size).offset((query.page - 1) * query.page_size)

    return {
        "count": count,
        "result": [device.to_json() for device in query_.all()],
    }


@app.post("/api/devices")
def create_device(body: DeviceCreateRequest, header: AuthHeaders):
    user = auth_user(header.token)

    device = IotDevice(user=user, name=body.name)
    config = DeviceConfiguration(device=device, electricity_price=body.electricity_price)
    session.add(device)
    session.add(config)
    session.commit()

    return device.to_json()


@app.get("/api/devices/<int:device_id>")
def get_device(path: DevicePath, header: AuthHeaders):
    user = auth_user(header.token)

    device = session.query(IotDevice).filter_by(id=path.device_id, user=user).join(DeviceConfiguration).scalar()
    if device is None:
        return {"error": "Unknown device!"}, 404

    return device.to_json()


@app.patch("/api/devices/<int:device_id>")
def edit_device(path: DevicePath, body: DeviceEditRequest, header: AuthHeaders):
    user = auth_user(header.token)

    device = session.query(IotDevice).filter_by(id=path.device_id, user=user).join(DeviceConfiguration).scalar()
    if device is None:
        return {"error": "Unknown device!"}, 404

    if body.name:
        device.name = body.name
        session.commit()

    return device.to_json()


@app.patch("/api/devices/<int:device_id>/config")
def edit_device_config(path: DevicePath, body: DeviceConfigEditRequest, header: AuthHeaders):
    user = auth_user(header.token)

    device = session.query(IotDevice).filter_by(id=path.device_id, user=user).join(DeviceConfiguration).scalar()
    if device is None:
        return {"error": "Unknown device!"}, 404

    if body.enabled_manually is not None:
        device.configuration.enabled = body.enabled_manually
    if body.enabled_auto is not None:
        device.configuration.enabled_auto = body.enabled_auto
    if body.electricity_price is not None:
        device.configuration.electricity_price = body.electricity_price

    if body.enabled_manually is not None or body.enabled_auto is not None or body.electricity_price is not None:
        session.commit()

    return device.to_json()


@app.delete("/api/devices/<int:device_id>")
def delete_device(path: DevicePath, header: AuthHeaders):
    user = auth_user(header.token)

    session.query(IotDevice).filter_by(id=path.device_id, user=user).delete()

    return "", 204


@app.get("/api/devices/<int:device_id>/schedule")
def get_device_schedule(path: DevicePath, header: AuthHeaders):
    user = auth_user(header.token)

    device = session.query(IotDevice).filter_by(id=path.device_id, user=user).join(DeviceConfiguration).scalar()
    if device is None:
        return {"error": "Unknown device!"}, 404

    schedule_items = session.query(DeviceSchedule).filter_by(device=device).order_by("start_hour").all()

    return [schedule.to_json() for schedule in schedule_items]


@app.post("/api/devices/<int:device_id>/schedule")
def add_device_schedule_item(path: DevicePath, body: DeviceScheduleAddRequest, header: AuthHeaders):
    if body.start_hour >= body.end_hour:
        return {"error": "End hour cannot be less than start hour!"}, 400

    user = auth_user(header.token)

    device = session.query(IotDevice).filter_by(id=path.device_id, user=user).join(DeviceConfiguration).scalar()
    if device is None:
        return {"error": "Unknown device!"}, 404

    schedule = DeviceSchedule(device=device, start_hour=body.start_hour, end_hour=body.end_hour)
    session.add(schedule)
    session.commit()

    return schedule.to_json()


@app.post("/api/devices/<int:device_id>/schedule/<int:schedule_id>")
def delete_device_schedule_item(path: SchedulePath, body: DeviceScheduleAddRequest, header: AuthHeaders):
    if body.start_hour >= body.end_hour:
        return {"error": "End hour cannot be less than start hour!"}, 400

    user = auth_user(header.token)

    device = session.query(IotDevice).filter_by(id=path.device_id, user=user).join(DeviceConfiguration).scalar()
    if device is None:
        return {"error": "Unknown device!"}, 404

    session.query(DeviceSchedule).filter_by(device=device, id=path.schedule_id).delete()

    return "", 204


@app.get("/api/devices/<int:device_id>/reports")
def get_device_reports(path: DevicePath, query: DeviceReportsQuery, header: AuthHeaders):
    user = auth_user(header.token)

    device = session.query(IotDevice).filter_by(id=path.device_id, user=user).join(DeviceConfiguration).scalar()
    query_ = session.query(DeviceReport).filter_by(device=device).order_by("time")

    count = query_.count()
    query_ = query_.limit(query.page_size).offset((query.page - 1) * query.page_size)

    return {
        "count": count,
        "result": [report.to_json() for report in query_.all()],
    }


@app.get("/api/device/config")
def get_device_config(header: AuthHeaders):
    device = auth_device(header.token)
    return device.configuration.to_json()


@app.post("/api/device/report")
def report_device_state(body: DeviceReportRequest, header: AuthHeaders):
    device = auth_device(header.token)

    report = DeviceReport(
        device=device, time=datetime.now(UTC), enabled=body.enabled,
        enabled_for=body.enabled_for if body.enabled else None
    )
    session.add(report)
    session.commit()

    return "", 204


@app.get("/api/admin/users")
def admin_get_users(query: PaginationQuery, header: AuthHeaders):
    auth_admin(header.token)

    query_ = session.query(User).order_by("id")

    count = query_.count()
    query_ = query_.limit(query.page_size).offset((query.page - 1) * query.page_size)

    return {
        "count": count,
        "result": [user.to_json() for user in query_.all()],
    }


@app.get("/api/admin/users/<int:user_id>")
def admin_get_user(path: UserPath, header: AuthHeaders):
    auth_admin(header.token)

    user = session.query(User).filter_by(id=path.user_id).scalar()
    if user is None:
        return {"error": "Unknown user!"}, 404

    return user.to_json()


@app.patch("/api/admin/users/<int:user_id>")
def admin_edit_user(path: UserPath, body: EditUserRequest, header: AuthHeaders):
    auth_admin(header.token)

    user = session.query(User).filter_by(id=path.user_id).scalar()
    if user is None:
        return {"error": "Unknown user!"}, 404

    if body.email is not None:
        user.email = body.email
    if body.password is not None:
        user.password = bcrypt.hashpw(body.password.encode("utf8"), bcrypt.gensalt())
    if body.first_name is not None:
        user.first_name = body.first_name
    if body.last_name is not None:
        user.last_name = body.last_name

    if body.email is not None or body.password is not None or body.first_name is not None or body.last_name is not None:
        session.commit()

    return user.to_json()


@app.delete("/api/admin/users/<int:user_id>")
def admin_delete_user(path: UserPath, header: AuthHeaders):
    auth_admin(header.token)

    session.query(User).filter_by(id=path.user_id).delete()
    return "", 204


@app.get("/api/admin/devices")
def admin_get_devices(query: PaginationQuery, header: AuthHeaders):
    auth_admin(header.token)

    query_ = session.query(IotDevice).order_by("id")

    count = query_.count()
    query_ = query_.limit(query.page_size).offset((query.page - 1) * query.page_size)

    return {
        "count": count,
        "result": [device.to_json() for device in query_.all()],
    }


@app.get("/api/admin/devices/<int:device_id>")
def admin_get_device(path: DevicePath, header: AuthHeaders):
    auth_admin(header.token)

    device = session.query(IotDevice).filter_by(id=path.device_id).scalar()
    return device.to_json()


@app.patch("/api/admin/users/<int:device_id>")
def admin_edit_device(path: DevicePath, body: DeviceEditRequest, header: AuthHeaders):
    auth_admin(header.token)

    device = session.query(IotDevice).filter_by(id=path.device_id).scalar()
    if device is None:
        return {"error": "Unknown device!"}, 404

    if body.name is not None:
        device.name = body.name

    if body.name is not None:
        session.commit()

    return device.to_json()


@app.delete("/api/admin/users/<int:device_id>")
def admin_delete_device(path: DevicePath, header: AuthHeaders):
    auth_admin(header.token)

    session.query(IotDevice).filter_by(id=path.device_id).delete()
    return "", 204


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=9090, debug=True, reload=True)
