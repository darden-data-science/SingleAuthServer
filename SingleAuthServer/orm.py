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


class LoginStateNonce(Base):
    """A login-state nonce that has already been redeemed.

    Deliberately keyed on the nonce alone and NOT on the username: providers
    where the caller supplies the username (rather than deriving it from a
    signed assertion) would otherwise let an attacker replay one login state
    under a different name and dodge a per-user check.

    Rows are pruned once past expires_at, so this table stays bounded by
    login_state_ttl rather than growing with login volume.
    """

    __tablename__ = "login_state_nonces"

    nonce = Column(Unicode(64), primary_key=True)
    expires_at = Column(
        BigInteger().with_variant(Integer, "sqlite"),
        nullable=False,
        index=True,
    )


def create_session_factory(db_url):
    engine_options = {"future": True}
    if db_url in {"sqlite://", "sqlite:///:memory:"}:
        engine_options["connect_args"] = {"check_same_thread": False}
        engine_options["poolclass"] = StaticPool

    engine = create_engine(db_url, **engine_options)
    Base.metadata.create_all(engine)
    return engine, sessionmaker(bind=engine, expire_on_commit=False, future=True)
