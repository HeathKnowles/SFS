from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Boolean, Text
from sqlalchemy.orm import relationship
from datetime import datetime
from ..extensions import Base


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


class FileShare(Base):
    __tablename__ = 'file_shares'

    id = Column(Integer, primary_key=True)
    file_id = Column(Integer, ForeignKey('files.id'), nullable=False, index=True)
    token = Column(String(128), unique=True, nullable=False, index=True)
    created_by = Column(Integer, ForeignKey('users.id'), nullable=False)
    expires_at = Column(DateTime, nullable=True)
    max_uses = Column(Integer, nullable=True)
    uses = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.utcnow)

    file = relationship('File')
    creator = relationship('User')

    def is_active(self):
        from datetime import datetime
        if self.expires_at and datetime.utcnow() > self.expires_at:
            return False
        if self.max_uses is not None and self.uses >= self.max_uses:
            return False
        return True

    def __repr__(self):
        return f"<FileShare token={self.token} file={self.file_id} active={self.is_active()}>"
