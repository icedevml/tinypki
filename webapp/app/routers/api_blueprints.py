from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlmodel import Session, select

from ..dbmodels.tinypki import TinyBlueprint, SubjectMode, KeygenFlow
from ..dependencies import get_session

router = APIRouter()


class BlueprintOut(BaseModel):
    name: str = Field(...)
    provisioner_name: str
    not_before: str
    not_after_days: int
    invitation_validity_days: int
    key_algorithm: str
    keygen_flow: KeygenFlow
    subject_mode: SubjectMode

    model_config = {"from_attributes": True}


class ListBlueprintsResponse(BaseModel):
    blueprints: list[BlueprintOut]


@router.get("/api/blueprints")
def route_api_list_blueprints(
        session: Session = Depends(get_session)
) -> ListBlueprintsResponse:
    blueprints = list(session.exec(
        select(TinyBlueprint)
    ).all())

    return ListBlueprintsResponse(
        blueprints=blueprints
    )
