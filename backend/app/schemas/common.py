from datetime import datetime
from typing import Annotated

from pydantic import PlainSerializer

from app.core.time import utc_iso


UTCDateTime = Annotated[
    datetime,
    PlainSerializer(utc_iso, return_type=str, when_used="json"),
]
