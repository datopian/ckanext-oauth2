import logging

log = logging.getLogger(__name__)

from typing import Optional
from typing_extensions import Self
from sqlalchemy import Column, Text
from sqlalchemy.ext.declarative import declarative_base
from ckan.model import meta
import logging

log = logging.getLogger(__name__)

Base = declarative_base()


class UserToken(Base):
    __tablename__ = "user_token"

    user_name = Column(Text, primary_key=True)
    access_token = Column(Text, nullable=True)
    token_type = Column(Text, nullable=True)
    refresh_token = Column(Text, nullable=True)
    expires_in = Column(Text, nullable=True)
    provider = Column(Text, nullable=True)

    def __init__(
        self,
        user_name: str = "",
        access_token: Optional[str] = None,
        token_type: Optional[str] = None,
        refresh_token: Optional[str] = None,
        expires_in: Optional[str] = None,
        provider: Optional[str] = None,
    ) -> None:
        self.user_name = user_name
        self.access_token = access_token
        self.token_type = token_type
        self.refresh_token = refresh_token
        self.expires_in = expires_in
        self.provider = provider

    @classmethod
    def by_user_name(cls, user_name: str) -> Optional[Self]:
        if not user_name:
            return None

        log.info(f"User name that we are querying is {user_name}")
        return meta.Session.query(cls).filter(cls.user_name == user_name).first()
