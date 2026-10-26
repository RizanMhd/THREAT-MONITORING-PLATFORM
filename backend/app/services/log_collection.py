import json
import time
from typing import List, Dict, Any, Optional
from datetime import datetime
from sqlalchemy.orm import Session
from app.models import Event, LogSource
from app.schemas.event import EventCreate


class LogCollectionService:
    def __init__(self, db: Session):
        self.db = db

    def ingest_events(self, events: List[EventCreate], source_id: str) -> int:
        accepted = 0
        for ev in events:
            event_data = ev.model_dump()
            event_data["ts"] = event_data.get("ts") or time.time()
            event_data["source_id"] = source_id
            db_event = Event(**event_data)
            self.db.add(db_event)
            accepted += 1
        self.db.commit()
        return accepted

    def get_log_sources(self) -> List[LogSource]:
        return self.db.query(LogSource).filter(LogSource.is_active == 1).all()

    def create_log_source(self, source_data: dict) -> LogSource:
        source = LogSource(**source_data)
        self.db.add(source)
        self.db.commit()
        self.db.refresh(source)
        return source

    def update_log_source(self, source_id: str, updates: dict) -> Optional[LogSource]:
        source = self.db.query(LogSource).filter(LogSource.id == source_id).first()
        if not source:
            return None
        for key, value in updates.items():
            if hasattr(source, key):
                setattr(source, key, value)
        self.db.commit()
        self.db.refresh(source)
        return source

    def delete_log_source(self, source_id: str) -> bool:
        source = self.db.query(LogSource).filter(LogSource.id == source_id).first()
        if not source:
            return False
        self.db.delete(source)
        self.db.commit()
        return True