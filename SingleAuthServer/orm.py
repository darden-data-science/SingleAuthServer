from sqlalchemy import BigInteger, Column, Integer, JSON, Unicode, create_engine
from sqlalchemy.orm import declarative_base, sessionmaker
from sqlalchemy.pool import StaticPool


Base = declarative_base()


class User(Base):
    __tablename__ = "users"

    id = Column(
        BigInteger().with_variant(Integer, "sqlite"),
        primary_key=True,
        autoincrement=True,
    )
    username = Column(Unicode(255), unique=True, nullable=False)
    auth_state = Column(JSON)


def create_session_factory(db_url):
    engine_options = {"future": True}
    if db_url in {"sqlite://", "sqlite:///:memory:"}:
        engine_options["connect_args"] = {"check_same_thread": False}
        engine_options["poolclass"] = StaticPool

    engine = create_engine(db_url, **engine_options)
    Base.metadata.create_all(engine)
    return engine, sessionmaker(bind=engine, expire_on_commit=False, future=True)
