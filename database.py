from sqlalchemy import create_engine, Column, Integer, String, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import datetime

DATABASE_URL = "sqlite:///./scams.db"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class FlaggedDomain(BaseModel if False else Base):
    __tablename__ = "flagged_domains"

    id = Column(Integer, primary_key=True, index=True)
    domain = Column(String, unique=True, index=True)
    report_count = Column(Integer, default=1)
    last_reported = Column(DateTime, default=datetime.datetime.utcnow)

Base.metadata.create_all(bind=engine)