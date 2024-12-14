"""This module contains the SQLAlchemy base class."""
from sqlalchemy.ext.asyncio import AsyncAttrs
from sqlalchemy.orm import DeclarativeBase

# pylint: disable=R0903


class Base(AsyncAttrs, DeclarativeBase):
    """
    The base class for all SQLAlchemy models.
    """
