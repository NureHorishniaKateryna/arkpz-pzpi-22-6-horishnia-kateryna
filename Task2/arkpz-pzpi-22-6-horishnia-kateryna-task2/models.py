from __future__ import annotations

from sqlalchemy import Column, Integer, Boolean, String, create_engine, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship

ModelsBase = declarative_base()

class User(ModelsBase):
    __tablename__ = "users"

    id: int = Column(Integer, primary_key=True)
    email: str = Column(String(255), nullable=False, unique=True)
    password: str = Column(String(64), nullable=False)
    first_name: str = Column(String(64), nullable=False)
    last_name: str = Column(String(64), nullable=False)
    is_admin: bool = Column(Boolean, default=False)


class UserSession(ModelsBase):
    __tablename__ = "sessions"

    id: int = Column(Integer, primary_key=True)
    user_id: int = Column(Integer, ForeignKey("users.id"))
    user = relationship("User")


class IotDevice(ModelsBase):
    __tablename__ = "iot_devices"

    id: int = Column(Integer, primary_key=True)
    user_id: int = Column(Integer, ForeignKey("users.id"))
    user = relationship("User")
    name: str = Column(String(64), nullable=False)
    configuration = relationship("DeviceConfiguration", uselist=False, back_populates="device")

    def to_json(self) -> dict:
        return {
            "id": self.id,
            "user_id": self.user_id,
            "name": self.name,
            "configuration": self.configuration.to_json(),
        }


class DeviceConfiguration(ModelsBase):
    __tablename__ = "device_configurations"

    id: int = Column(Integer, primary_key=True)
    device_id: int = Column(Integer, ForeignKey("iot_devices.id"))
    device = relationship("IotDevice", back_populates="configuration")
    enabled: bool = Column(Boolean, nullable=False, default=True)
    enabled_auto: bool = Column(Boolean, nullable=False, default=True)

    def to_json(self) -> dict:
        return {
            "enabled_manually": self.enabled,
            "enabled_auto": self.enabled_auto,
        }


class DeviceSchedule(ModelsBase):
    __tablename__ = "device_schedule"

    id: int = Column(Integer, primary_key=True)
    device_id: int = Column(Integer, ForeignKey("iot_devices.id"))
    device = relationship("IotDevice")
    start_hour: int = Column(Integer, nullable=False)
    end_hour: int = Column(Integer, nullable=False)


