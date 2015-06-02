import datetime

from sqlalchemy import Column, ForeignKey, Integer, String, Text, create_engine, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship

Base = declarative_base()


class User(Base):
    """
    User class. Keep user info.
    """
    __tablename__ = 'user'
    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False)
    email = Column(String(250), nullable=False)

    @property
    def serialize(self):
        """
        Return object data in easily serializeable format
        """
        return {
            'id': self.id,
            'name': self.name,
            'email': self.email
        }


class Category(Base):
    """
    Category class. Keep categories names
    """
    __tablename__ = 'category'
    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False)
    # user_id = Column(Integer, ForeignKey('user.id'))
    # user = relationship(User)

    @property
    def serialize(self):
        """
        Return object data in easily serializeable format
        """
        return {
            'id': self.id,
            'name': self.name
        }


class Item(Base):
    """
    Item class. Keep items information
    """
    __tablename__ = 'item'
    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False)
    description = Column(Text, nullable=True)
    category_id = Column(Integer, ForeignKey('category.id'))
    category = relationship(Category)
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship(User)
    created_date = Column(DateTime, default=datetime.datetime.now)

    @property
    def serialize(self):
        """
        Return object data in easily serializeable format
        """
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description
        }


engine = create_engine('sqlite:///itemcatalog.db')
Base.metadata.create_all(engine)