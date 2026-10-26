import json
from typing import Dict, Any, Optional
from datetime import datetime
from app.schemas.event import EventCreate


class NormalizationService:
    NORMALIZED_FIELDS = [
        "ip", "user", "event_type", "country", "detail", "role", "source_id", "raw_data", "ts"
    ]

    @staticmethod
    def normalize_cloudtrail(raw_event: Dict[str, Any]) -> EventCreate:
        detail = raw_event.get("detail", {})
        request_params = detail.get("requestParameters", {})
        response_elements = detail.get("responseElements", {})
        
        return EventCreate(
            ip=detail.get("sourceIPAddress", "0.0.0.0"),
            user=detail.get("userIdentity", {}).get("userName", detail.get("userIdentity", {}).get("arn", "unknown")),
            event_type=NormalizationService._map_cloudtrail_event(detail.get("eventName", "")),
            country=raw_event.get("country", "-"),
            detail=json.dumps({
                "eventName": detail.get("eventName"),
                "eventSource": detail.get("eventSource"),
                "requestParameters": request_params,
                "responseElements": response_elements,
            }),
            role=detail.get("userIdentity", {}).get("type", "unknown"),
            source_id="cloudtrail",
            raw_data=raw_event,
            ts=NormalizationService._parse_timestamp(detail.get("eventTime")),
        )

    @staticmethod
    def normalize_cloudwatch(raw_event: Dict[str, Any]) -> EventCreate:
        message = raw_event.get("message", "")
        try:
            log_data = json.loads(message) if isinstance(message, str) else message
        except json.JSONDecodeError:
            log_data = {"message": message}

        return EventCreate(
            ip=log_data.get("sourceIP", log_data.get("clientip", "0.0.0.0")),
            user=log_data.get("user", log_data.get("username", "-")),
            event_type=log_data.get("eventType", log_data.get("action", "unknown")),
            country=log_data.get("country", "-"),
            detail=json.dumps(log_data),
            role=log_data.get("role"),
            source_id="cloudwatch",
            raw_data=raw_event,
            ts=NormalizationService._parse_timestamp(raw_event.get("timestamp")),
        )

    @staticmethod
    def normalize_ids_alert(raw_event: Dict[str, Any]) -> EventCreate:
        return EventCreate(
            ip=raw_event.get("src_ip", raw_event.get("source_ip", "0.0.0.0")),
            user=raw_event.get("user", "-"),
            event_type=raw_event.get("alert_type", raw_event.get("signature", "ids_alert")),
            country=raw_event.get("geoip", {}).get("country_code", "-") if raw_event.get("geoip") else "-",
            detail=json.dumps(raw_event),
            role=raw_event.get("priority"),
            source_id="ids",
            raw_data=raw_event,
            ts=NormalizationService._parse_timestamp(raw_event.get("timestamp")),
        )

    @staticmethod
    def normalize_generic(raw_event: Dict[str, Any], source_id: str) -> EventCreate:
        return EventCreate(
            ip=raw_event.get("ip", raw_event.get("source_ip", "0.0.0.0")),
            user=raw_event.get("user", raw_event.get("username", "-")),
            event_type=raw_event.get("type", raw_event.get("event_type", "unknown")),
            country=raw_event.get("country", "-"),
            detail=raw_event.get("detail", json.dumps(raw_event)),
            role=raw_event.get("role"),
            source_id=source_id,
            raw_data=raw_event,
            ts=NormalizationService._parse_timestamp(raw_event.get("ts", raw_event.get("timestamp"))),
        )

    @staticmethod
    def _map_cloudtrail_event(event_name: str) -> str:
        mapping = {
            "ConsoleLogin": "login_success",
            "FailedLogin": "login_failed",
            "CreateUser": "user_created",
            "DeleteUser": "user_deleted",
            "AttachUserPolicy": "policy_attached",
            "DetachUserPolicy": "policy_detached",
            "CreateAccessKey": "access_key_created",
            "DeleteAccessKey": "access_key_deleted",
            "AuthorizeSecurityGroupIngress": "security_group_modified",
            "RevokeSecurityGroupIngress": "security_group_modified",
            "CreateSecurityGroup": "security_group_created",
            "DeleteSecurityGroup": "security_group_deleted",
            "RunInstances": "instance_launched",
            "TerminateInstances": "instance_terminated",
        }
        return mapping.get(event_name, f"aws_{event_name.lower()}")

    @staticmethod
    def _parse_timestamp(ts: Any) -> Optional[float]:
        if ts is None:
            return None
        if isinstance(ts, (int, float)):
            return float(ts)
        if isinstance(ts, str):
            for fmt in ["%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S.%f"]:
                try:
                    return datetime.strptime(ts, fmt).timestamp()
                except ValueError:
                    continue
        return None

    @classmethod
    def normalize(
        cls,
        raw_event: Dict[str, Any],
        source_type: str,
        source_id: Optional[str] = None,
    ) -> EventCreate:
        normalizers = {
            "cloudtrail": cls.normalize_cloudtrail,
            "cloudwatch": cls.normalize_cloudwatch,
            "ids": cls.normalize_ids_alert,
        }
        normalizer = normalizers.get(source_type)
        if normalizer:
            return normalizer(raw_event)
        return cls.normalize_generic(raw_event, source_id or f"{source_type}-raw")