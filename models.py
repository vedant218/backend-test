from sqlalchemy import Column, Integer, String, Boolean, ForeignKey, DateTime
from database import Base
from database import engine
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func



class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    role = Column(String)
    is_deleted = Column(Boolean, default=False)
    
    borrow_history = relationship("BorrowHistory", back_populates="user")


class Book(Base):
    __tablename__ = "books"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String(100), index=True, nullable=False)
    author = Column(String(100), nullable=False)
    status = Column(String(20), default='available', nullable=False)
    
    borrow_history = relationship("BorrowHistory", back_populates="book")


class BorrowHistory(Base):
    __tablename__ = "borrow_history"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    book_id = Column(Integer, ForeignKey("books.id"), nullable=False)
    action = Column(String(20), nullable=False)
    timestamp = Column(DateTime, server_default=func.now(), nullable=False)
    user = relationship("User", back_populates="borrow_history")
    book = relationship("Book", back_populates="borrow_history")


# Create the database tables if they don't exist

User.metadata.create_all(bind=engine)
