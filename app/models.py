from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Boolean, LargeBinary, Text
from sqlalchemy.orm import relationship
from datetime import datetime
from . import Base


class User(Base):
    __tablename__ = 'users'

    id = Column(Integer, primary_key=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    files = relationship('File', back_populates='owner')

    def __repr__(self):
        return f"<User {self.email}>"


class File(Base):
    __tablename__ = 'files'

    id = Column(Integer, primary_key=True)
    owner_id = Column(Integer, ForeignKey('users.id'), nullable=False, index=True)
    filename = Column(String(1024), nullable=False)
    content_type = Column(String(255))
    size = Column(Integer)
    storage_key = Column(String(1024), unique=True, nullable=False)
    sha256 = Column(String(128), index=True)
    scan_status = Column(String(50), default='pending')
    created_at = Column(DateTime, default=datetime.utcnow)

    owner = relationship('User', back_populates='files')

    def __repr__(self):
        return f"<File {self.filename} owner={self.owner_id}>"


class AuditLog(Base):
    __tablename__ = 'audit_logs'

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=True)
    action = Column(String(255), nullable=False)
    object_type = Column(String(50))
    object_id = Column(String(255))
    ip_address = Column(String(50))
    details = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)

    user = relationship('User')

    def __repr__(self):
        return f"<Audit {self.action} user={self.user_id} obj={self.object_type}:{self.object_id}>"
