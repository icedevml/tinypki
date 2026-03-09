from typing import Annotated

from fastapi import Depends
from sqlalchemy import URL, create_engine
from sqlmodel import Session
from starlette.templating import Jinja2Templates

from .config import POSTGRES_USER, POSTGRES_PASSWORD, PG_HOST, PG_PORT


def get_session():
    with Session(engine) as session:
        yield session


templates = Jinja2Templates(directory="templates")

SessionDep = Annotated[Session, Depends(get_session)]

url_object = URL.create(
    "postgresql",
    username=POSTGRES_USER,
    password=POSTGRES_PASSWORD,
    host=PG_HOST,
    port=PG_PORT,
    database="tinypki")

engine = create_engine(url_object)
