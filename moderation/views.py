from __future__ import annotations

import base64
import json
import re
import uuid

import requests
from django.conf import settings
from django.http import HttpRequest, HttpResponse, JsonResponse
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods

from .models import BlockingReason, IncomingProductEvent, ModerationCard, OutgoingModerationEvent


CODE_RE = re.compile(r"^[A-Z_]+$")


def parse_bool(value: str | None) -> bool | None:
    if value is None:
        return None
    if value.lower() in {"true", "1", "yes"}:
        return True
    if value.lower() in {"false", "0", "no"}:
        return False
    return None


def error(status: int, code: str, message: str) -> JsonResponse:
    return JsonResponse({"code": code, "message": message}, status=status)


def reason_payload(reason: BlockingReason) -> dict:
    return {
        "id": str(reason.id),
        "code": reason.code,
        "title": reason.title,
        "description": reason.description or None,
        "hard_block": reason.hard_block,
        "is_active": reason.is_active,
    }


def request_json(request: HttpRequest) -> dict:
    """Parse JSON body. Raises json.JSONDecodeError or TypeError if not an object."""
    if not request.body:
        return {}
    data = json.loads(request.body.decode("utf-8"))
    if not isinstance(data, dict):
        raise TypeError("JSON body must be an object")
    return data


def parse_uuid(value: str | None) -> uuid.UUID | None:
    if not value:
        return None
    try:
        return uuid.UUID(value)
    except ValueError:
        return None


def decode_jwt_sub(token: str) -> uuid.UUID | None:
    parts = token.split(".")
    if len(parts) < 2:
        return None
    padded = parts[1] + "=" * (-len(parts[1]) % 4)
    try:
        claims = json.loads(base64.urlsafe_b64decode(padded.encode("ascii")))
    except (ValueError, json.JSONDecodeError):
        return None
    return parse_uuid(str(claims.get("sub", "")))


def current_moderator_id(request: HttpRequest) -> uuid.UUID | None:
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        moderator_id = decode_jwt_sub(auth.removeprefix("Bearer ").strip())
        if moderator_id:
            return moderator_id
    return parse_uuid(request.headers.get("X-Moderator-Id"))


def has_skus(snapshot: dict) -> bool:
    skus = snapshot.get("skus")
    if isinstance(skus, list):
        return len(skus) > 0
    product = snapshot.get("product")
    if isinstance(product, dict) and isinstance(product.get("skus"), list):
        return len(product["skus"]) > 0
    return False


def status_for_protocol(card: ModerationCard) -> str:
    if card.status == ModerationCard.Status.MODERATED:
        return "APPROVED"
    return card.status


def ticket_payload(card: ModerationCard) -> dict:
    zero_uuid = "00000000-0000-0000-0000-000000000000"
    return {
        "id": str(card.id),
        "product_id": str(card.product_id),
        "seller_id": str(card.seller_id) if card.seller_id else zero_uuid,
        "category_id": str(card.category_id) if card.category_id else None,
        "kind": card.kind,
        "status": status_for_protocol(card),
        "queue_priority": card.queue_priority,
        "assigned_moderator_id": str(card.assigned_moderator_id) if card.assigned_moderator_id else None,
        "claimed_at": card.claimed_at.isoformat() if card.claimed_at else None,
        "claim_expires_at": card.claim_expires_at.isoformat() if card.claim_expires_at else None,
        "decision_at": card.decision_at.isoformat() if card.decision_at else None,
        "created_at": card.created_at.isoformat(),
        "updated_at": card.updated_at.isoformat() if card.updated_at else None,
    }


def product_decision_payload(card: ModerationCard) -> dict:
    return {"product_id": str(card.product_id), "status": card.status}


def find_card(*, ticket_id=None, product_id=None) -> ModerationCard | None:
    queryset = ModerationCard.objects.all()
    try:
        if ticket_id is not None:
            return queryset.get(id=ticket_id)
        return queryset.get(product_id=product_id)
    except ModerationCard.DoesNotExist:
        return None


CLAIM_TTL_MINUTES = 30


def stable_event_idempotency_key(
    card: ModerationCard,
    event_type: str,
    *,
    hard_block: bool | None = None,
) -> uuid.UUID:
    """
    Ключ на одно решение (цикл модерации).

    - Повтор доставки того же решения (тот же decision_at + характер решения) → тот же ключ.
    - Новое решение после EDITED (новый decision_at) → новый ключ → новое событие в B2B.
    - Soft vs hard BLOCKED различаются (hard_block в ключе), чтобы soft-undelivered
      не подменял последующий hard-block.
    """
    cycle = card.decision_at.isoformat() if card.decision_at else "none"
    hb = ""
    if event_type == "BLOCKED" and hard_block is not None:
        hb = f":hb={bool(hard_block)}"
    return uuid.uuid5(uuid.NAMESPACE_URL, f"neomarket:moderation:{card.id}:{event_type}:{cycle}{hb}")


def ensure_outgoing_event(card: ModerationCard, payload: dict, event_type: str) -> OutgoingModerationEvent:
    """
    Сохраняет outbox-запись с стабильным ключом ДО HTTP в B2B.

    Порядок канона доставки: сначала decision+outbox, потом send.
    Повтор того же цикла (тот же decision_at / hard_block) → тот же idempotency_key.
    """
    hard_block = payload.get("hard_block") if event_type == "BLOCKED" else None
    if hard_block is not None:
        hard_block = bool(hard_block)
    idem_key = stable_event_idempotency_key(card, event_type, hard_block=hard_block)

    existing = OutgoingModerationEvent.objects.filter(idempotency_key=idem_key).first()
    if existing is not None:
        if not existing.payload:
            existing.payload = {
                **payload,
                "idempotency_key": str(idem_key),
                "occurred_at": timezone.now().isoformat(),
            }
            existing.save(update_fields=["payload"])
        return existing

    request_payload = {
        **payload,
        "idempotency_key": str(idem_key),
        "occurred_at": timezone.now().isoformat(),
    }
    return OutgoingModerationEvent.objects.create(
        card=card,
        event_type=event_type,
        payload=request_payload,
        idempotency_key=idem_key,
        delivered=False,
    )


def deliver_outgoing_event(event: OutgoingModerationEvent) -> OutgoingModerationEvent:
    """HTTP-доставка сохранённого outbox-события. Не меняет ключ и payload решения."""
    if event.delivered:
        return event
    if not settings.B2B_BASE_URL:
        event.delivered = True
        event.delivered_at = timezone.now()
        event.save(update_fields=["delivered", "delivered_at"])
        return event

    request_payload = event.payload or {}
    if "idempotency_key" not in request_payload:
        request_payload = {
            **request_payload,
            "idempotency_key": str(event.idempotency_key),
            "occurred_at": timezone.now().isoformat(),
        }
        event.payload = request_payload
        event.save(update_fields=["payload"])

    url = f"{settings.B2B_BASE_URL.rstrip('/')}/api/v1/moderation/events"
    response = requests.post(
        url,
        json=request_payload,
        headers={"X-Service-Key": settings.B2B_SERVICE_KEY},
        timeout=settings.B2B_TIMEOUT_SECONDS,
    )
    if response.status_code >= 400:
        raise requests.HTTPError(f"B2B moderation event failed: {response.status_code}", response=response)
    event.delivered = True
    event.delivered_at = timezone.now()
    event.payload = request_payload
    event.save(update_fields=["delivered", "delivered_at", "payload"])
    return event


def send_moderation_event(card: ModerationCard, payload: dict, event_type: str) -> OutgoingModerationEvent:
    """Сохранить outbox (стабильный ключ) и попытаться доставить."""
    event = ensure_outgoing_event(card, payload, event_type)
    return deliver_outgoing_event(event)


def deliver_pending_outgoing_events(*, limit: int = 100) -> dict:
    """
    Фоновая доотправка сохранённых решений без нового действия модератора.
    Не зависит от is_active причины блокировки — шлёт payload as-is.
    """
    delivered = failed = skipped = 0
    qs = (
        OutgoingModerationEvent.objects.filter(delivered=False)
        .select_related("card")
        .order_by("created_at")[:limit]
    )
    for event in qs:
        if event.card_id is None:
            skipped += 1
            continue
        try:
            deliver_outgoing_event(event)
            delivered += 1
        except requests.RequestException:
            failed += 1
    return {"delivered": delivered, "failed": failed, "skipped": skipped}


def approve_card(request: HttpRequest, *, ticket_id=None, product_id=None, protocol_response: bool) -> JsonResponse:
    """
    MOD-3 approve.

    Канон: при ошибке B2B статус остаётся IN_REVIEW; outbox + decision_at сохраняют
    idempotency_key для повторной доставки того же решения.
    Удалённый товар (до или во время обработки) → всегда 404.
    """
    from django.db import transaction

    moderator_id = current_moderator_id(request)
    if moderator_id is None:
        return error(401, "UNAUTHORIZED", "Moderator identity is required")

    card = find_card(ticket_id=ticket_id, product_id=product_id)
    if card is None:
        return error(404, "NOT_FOUND", "Product not found in moderation queue")

    try:
        payload = request_json(request)
    except json.JSONDecodeError:
        return error(400, "INVALID_JSON", "Request body must be valid JSON")
    except TypeError:
        return error(400, "INVALID_REQUEST", "Request body must be a JSON object")

    try:
        with transaction.atomic():
            try:
                card = ModerationCard.objects.select_for_update().get(pk=card.pk)
            except ModerationCard.DoesNotExist:
                return error(404, "NOT_FOUND", "Product not found in moderation queue")

            # OpenAPI / канон: неподходящий статус (включая HARD_BLOCKED) → 409
            if card.status == ModerationCard.Status.HARD_BLOCKED:
                return error(409, "HARD_BLOCKED", "Product is permanently blocked")

            # Уже MODERATED: lost success response — redelivery с тем же ключом
            if card.status == ModerationCard.Status.MODERATED:
                if card.assigned_moderator_id != moderator_id:
                    return error(409, "INVALID_STATUS", "Product is not in review status")
                event_payload = {
                    "product_id": str(card.product_id),
                    "event_type": "MODERATED",
                    "moderator_id": str(card.assigned_moderator_id) if card.assigned_moderator_id else None,
                    "moderator_comment": card.decision_comment or None,
                }
                try:
                    send_moderation_event(card, event_payload, "MODERATED")
                except requests.RequestException:
                    return error(500, "B2B_EVENT_FAILED", "Could not deliver moderation decision to B2B")
                if not ModerationCard.objects.filter(pk=card.pk).exists():
                    return error(404, "NOT_FOUND", "Product not found in moderation queue")
                return JsonResponse(ticket_payload(card) if protocol_response else product_decision_payload(card))

            if card.status != ModerationCard.Status.IN_REVIEW:
                return error(409, "INVALID_STATUS", "Product is not in review status")
            if card.assigned_moderator_id != moderator_id:
                return error(409, "NOT_ASSIGNED", "This moderation card is not assigned to you")
            if not has_skus(card.json_after or {}):
                return error(409, "NO_SKUS", "Product has no SKUs, cannot approve")

            # Повтор после отказа B2B: undelivered + decision_at уже есть → тот же ключ
            undelivered = (
                OutgoingModerationEvent.objects.filter(
                    card=card, event_type="MODERATED", delivered=False
                )
                .order_by("-created_at")
                .first()
            )
            if undelivered is None or card.decision_at is None:
                card.decision_at = timezone.now()
            card.decision_comment = str(
                payload.get("moderator_comment") or payload.get("comment") or card.decision_comment or ""
            ).strip()
            card.blocking_reason = None
            card.field_reports = []
            # Канон: до успешной доставки в B2B тикет остаётся на рассмотрении
            card.status = ModerationCard.Status.IN_REVIEW
            card.save(
                update_fields=[
                    "status",
                    "decision_at",
                    "decision_comment",
                    "blocking_reason",
                    "field_reports",
                    "updated_at",
                ]
            )

            event_payload = {
                "product_id": str(card.product_id),
                "event_type": "MODERATED",
                "moderator_id": str(card.assigned_moderator_id) if card.assigned_moderator_id else None,
                "moderator_comment": card.decision_comment or None,
            }
            try:
                send_moderation_event(card, event_payload, "MODERATED")
            except requests.RequestException:
                # status остаётся IN_REVIEW; outbox + decision_at сохранены для retry с тем же ключом
                return error(500, "B2B_EVENT_FAILED", "Could not deliver moderation decision to B2B")

            # Товар могли удалить во время/сразу после доставки — единый 404
            try:
                card = ModerationCard.objects.select_for_update().get(pk=card.pk)
            except ModerationCard.DoesNotExist:
                return error(404, "NOT_FOUND", "Product not found in moderation queue")

            card.status = ModerationCard.Status.MODERATED
            card.save(update_fields=["status", "updated_at"])

    except ModerationCard.DoesNotExist:
        return error(404, "NOT_FOUND", "Product not found in moderation queue")

    return JsonResponse(ticket_payload(card) if protocol_response else product_decision_payload(card))


def blocking_reason_from_payload(payload: dict) -> BlockingReason | None:
    """Legacy helper: первая валидная причина (для совместимости)."""
    reasons, err = resolve_all_blocking_reasons(payload)
    if err or not reasons:
        return None
    return reasons[0]


def resolve_all_blocking_reasons(payload: dict) -> tuple[list[BlockingReason] | None, str | None]:
    """
    Валидирует ВЕСЬ список blocking_reason_ids (или legacy blocking_reason_id).
    Возвращает (reasons, error_message).
    """
    reason_ids = payload.get("blocking_reason_ids")
    if reason_ids is not None:
        if not isinstance(reason_ids, list):
            return None, "blocking_reason_ids must be an array"
        if len(reason_ids) < 1:
            return None, "blocking_reason_ids must be a non-empty array"
        resolved: list[BlockingReason] = []
        seen: set[uuid.UUID] = set()
        for raw in reason_ids:
            parsed = parse_uuid(str(raw)) if raw is not None else None
            if parsed is None:
                return None, f"invalid blocking_reason_id: {raw}"
            if parsed in seen:
                continue
            seen.add(parsed)
            reason = BlockingReason.objects.filter(id=parsed, is_active=True).first()
            if reason is None:
                return None, f"blocking reason not found or inactive: {parsed}"
            resolved.append(reason)
        if not resolved:
            return None, "blocking_reason_ids must contain at least one valid reason"
        return resolved, None

    reason_id = payload.get("blocking_reason_id")
    if reason_id is None:
        return None, "blocking_reason_ids or blocking_reason_id is required"
    parsed = parse_uuid(str(reason_id))
    if parsed is None:
        return None, "invalid blocking_reason_id"
    reason = BlockingReason.objects.filter(id=parsed, is_active=True).first()
    if reason is None:
        return None, "blocking reason not found or inactive"
    return [reason], None


def validate_block_comment(payload: dict) -> tuple[str | None, str | None]:
    """Комментарий модератора: опционален, maxLength 2000 (OpenAPI)."""
    raw = payload.get("moderator_comment")
    if raw is None:
        raw = payload.get("comment")
    if raw is None:
        return "", None
    if not isinstance(raw, (str, int, float)):
        return None, "comment must be a string"
    text = str(raw).strip()
    if len(text) > 2000:
        return None, "comment must be at most 2000 characters"
    return text, None


def normalize_field_reports(value) -> list[dict] | None:
    if value is None:
        return []
    if not isinstance(value, list):
        return None
    normalized = []
    for item in value:
        if not isinstance(item, dict):
            return None
        field_path = item.get("field_path") or item.get("field_name")
        message = item.get("message") or item.get("comment")
        if not field_path or not message:
            return None
        field_path_s = str(field_path).strip()
        message_s = str(message).strip()
        if not field_path_s or not message_s:
            return None
        if len(message_s) > 1000:
            return None
        severity = item.get("severity", "ERROR")
        if severity not in {"INFO", "WARNING", "ERROR"}:
            return None
        entry: dict = {"field_path": field_path_s, "message": message_s, "severity": severity}
        sku_raw = item.get("sku_id")
        if sku_raw is not None:
            sku_id = parse_uuid(str(sku_raw))
            if sku_id is None:
                return None
            entry["sku_id"] = str(sku_id)
        normalized.append(entry)
    return normalized


def b2b_field_reports(field_reports: list[dict]) -> list[dict]:
    return [
        {
            "field_name": report["field_path"],
            "comment": report["message"],
            **({"sku_id": report["sku_id"]} if report.get("sku_id") else {}),
        }
        for report in field_reports
    ]


def decline_card(request: HttpRequest, *, ticket_id=None, product_id=None, protocol_response: bool) -> JsonResponse:
    from django.db import transaction

    moderator_id = current_moderator_id(request)
    if moderator_id is None:
        return error(401, "UNAUTHORIZED", "Moderator identity is required")

    card = find_card(ticket_id=ticket_id, product_id=product_id)
    if card is None:
        return error(404, "NOT_FOUND", "Product not found in moderation queue")

    try:
        payload = request_json(request)
    except json.JSONDecodeError:
        return error(400, "INVALID_JSON", "Request body must be valid JSON")
    except TypeError:
        return error(400, "INVALID_REQUEST", "Request body must be a JSON object")
    if not isinstance(payload, dict):
        return error(400, "INVALID_REQUEST", "Request body must be a JSON object")

    # --- Redelivery сохранённого HARD_BLOCKED без зависимости от is_active причины ---
    if card.status == ModerationCard.Status.HARD_BLOCKED:
        undelivered = (
            OutgoingModerationEvent.objects.filter(card=card, event_type="BLOCKED", delivered=False)
            .order_by("-created_at")
            .first()
        )
        if undelivered is not None and (undelivered.payload or {}).get("hard_block") is True:
            try:
                deliver_outgoing_event(undelivered)
            except requests.RequestException:
                return error(500, "B2B_EVENT_FAILED", "Could not deliver moderation decision to B2B")
            card.refresh_from_db()
            return JsonResponse(ticket_payload(card) if protocol_response else product_decision_payload(card))
        return error(409, "HARD_BLOCKED", "Product is permanently blocked")

    # Полная валидация тела для *нового* решения
    reasons, reason_err = resolve_all_blocking_reasons(payload)
    if reason_err:
        code = "UNKNOWN_REASON" if "not found" in reason_err else "INVALID_REQUEST"
        return error(400, code, reason_err)
    assert reasons is not None
    primary_reason = next((r for r in reasons if r.hard_block), reasons[0])
    is_hard = any(r.hard_block for r in reasons)

    comment, comment_err = validate_block_comment(payload)
    if comment_err:
        return error(400, "INVALID_REQUEST", comment_err)

    if "field_reports" in payload and not isinstance(payload.get("field_reports"), (list, type(None))):
        return error(400, "INVALID_FIELD_REPORTS", "field_reports must be an array")
    try:
        field_reports = normalize_field_reports(payload.get("field_reports"))
    except Exception:
        return error(400, "INVALID_FIELD_REPORTS", "field_reports are invalid")
    if field_reports is None:
        return error(
            400,
            "INVALID_FIELD_REPORTS",
            "field_reports items must include field_path/message; severity in INFO|WARNING|ERROR; message ≤1000",
        )

    target_status = ModerationCard.Status.HARD_BLOCKED if is_hard else ModerationCard.Status.BLOCKED
    outgoing: OutgoingModerationEvent | None = None

    try:
        with transaction.atomic():
            try:
                card = ModerationCard.objects.select_for_update().get(pk=card.pk)
            except ModerationCard.DoesNotExist:
                return error(404, "NOT_FOUND", "Product not found in moderation queue")

            # Гонка: параллельный hard-block успел завершиться
            if card.status == ModerationCard.Status.HARD_BLOCKED:
                return error(409, "HARD_BLOCKED", "Product is permanently blocked")

            # Повтор soft BLOCKED (lost response) — redelivery с тем же ключом
            if card.status == ModerationCard.Status.BLOCKED and card.assigned_moderator_id == moderator_id and not is_hard:
                undelivered = (
                    OutgoingModerationEvent.objects.filter(card=card, event_type="BLOCKED", delivered=False)
                    .order_by("-created_at")
                    .first()
                )
                if undelivered is not None:
                    outgoing = undelivered
                else:
                    event_payload = {
                        "product_id": str(card.product_id),
                        "event_type": "BLOCKED",
                        "moderator_id": str(card.assigned_moderator_id) if card.assigned_moderator_id else None,
                        "moderator_comment": card.decision_comment or None,
                        "blocking_reason_id": str(card.blocking_reason_id) if card.blocking_reason_id else str(primary_reason.id),
                        "hard_block": False,
                        "field_reports": b2b_field_reports(card.field_reports or []),
                    }
                    outgoing = ensure_outgoing_event(card, event_payload, "BLOCKED")
            elif card.status != ModerationCard.Status.IN_REVIEW:
                return error(409, "INVALID_STATUS", "Product is not in review status")
            elif card.assigned_moderator_id != moderator_id:
                return error(409, "NOT_ASSIGNED", "This moderation card is not assigned to you")
            else:
                # 1) Сначала save решения + outbox (ключ фиксируется до HTTP)
                card.status = target_status
                card.decision_at = timezone.now()
                card.decision_comment = comment or ""
                card.blocking_reason = primary_reason
                card.field_reports = field_reports
                card.save(
                    update_fields=[
                        "status",
                        "decision_at",
                        "decision_comment",
                        "blocking_reason",
                        "field_reports",
                        "updated_at",
                    ]
                )
                event_payload = {
                    "product_id": str(card.product_id),
                    "event_type": "BLOCKED",
                    "moderator_id": str(card.assigned_moderator_id) if card.assigned_moderator_id else None,
                    "moderator_comment": card.decision_comment or None,
                    "blocking_reason_id": str(primary_reason.id),
                    "hard_block": is_hard,
                    "field_reports": b2b_field_reports(field_reports),
                }
                outgoing = ensure_outgoing_event(card, event_payload, "BLOCKED")
    except ModerationCard.DoesNotExist:
        return error(404, "NOT_FOUND", "Product not found in moderation queue")

    # 2) HTTP вне транзакции: при сбое решение и ключ уже сохранены → фоновая доотправка
    if outgoing is not None:
        try:
            deliver_outgoing_event(outgoing)
        except requests.RequestException:
            return error(500, "B2B_EVENT_FAILED", "Could not deliver moderation decision to B2B")

    card.refresh_from_db()
    return JsonResponse(ticket_payload(card) if protocol_response else product_decision_payload(card))


def require_service_key(request: HttpRequest) -> bool:
    return request.headers.get("X-Service-Key") == settings.SERVICE_KEY


ALLOWED_INCOMING_EVENT_TYPES = {
    "PRODUCT_CREATED",
    "PRODUCT_EDITED",
    "PRODUCT_DELETED",
    "CREATED",
    "EDITED",
    "DELETED",
}

ALIASES_INCOMING = {
    "PRODUCT_CREATED": "CREATED",
    "PRODUCT_EDITED": "EDITED",
    "PRODUCT_DELETED": "DELETED",
}


def normalize_incoming_event(payload: dict) -> tuple[str, str, uuid.UUID | None, dict, str | None]:
    """
    Приводит тело к канону IncomingB2BEvent.
    Возвращает (event_type_normalized, idempotency_key, product_id, event_payload, error_message).
    error_message is set when schema is violated.
    """
    raw_type = payload.get("event_type") or payload.get("event") or payload.get("type") or ""
    event_type = str(raw_type).upper().strip()
    if not event_type:
        return "", "", None, {}, "event_type is required"
    if event_type not in ALLOWED_INCOMING_EVENT_TYPES:
        return "", "", None, {}, f"event_type must be one of PRODUCT_CREATED, PRODUCT_EDITED, PRODUCT_DELETED"

    idempotency_key = str(payload.get("idempotency_key") or payload.get("event_id") or "").strip()
    if not idempotency_key:
        return "", "", None, {}, "idempotency_key is required"

    # Канон IncomingB2BEvent: payload — вложенный объект; legacy — плоские поля
    if isinstance(payload.get("payload"), dict):
        event_payload = payload["payload"]
        # Каноническая форма требует occurred_at
        if not payload.get("occurred_at") and payload.get("event_type"):
            return "", "", None, {}, "occurred_at is required"
    else:
        event_payload = payload

    product_id = parse_uuid(str(event_payload.get("product_id", "")))
    if product_id is None:
        return "", "", None, {}, "payload.product_id is required and must be uuid"

    normalized = ALIASES_INCOMING.get(event_type, event_type)

    if normalized == "CREATED":
        if not event_payload.get("seller_id"):
            # legacy flat CREATED may omit seller — допустим null seller only for legacy "event"
            if payload.get("event_type") in {"PRODUCT_CREATED"} or isinstance(payload.get("payload"), dict):
                return "", "", None, {}, "payload.seller_id is required for PRODUCT_CREATED"
        if "json_after" not in event_payload and "product" not in event_payload and isinstance(payload.get("payload"), dict):
            return "", "", None, {}, "payload.json_after is required for PRODUCT_CREATED"
    elif normalized == "EDITED":
        if isinstance(payload.get("payload"), dict):
            if not event_payload.get("seller_id"):
                return "", "", None, {}, "payload.seller_id is required for PRODUCT_EDITED"
            if "json_after" not in event_payload:
                return "", "", None, {}, "payload.json_after is required for PRODUCT_EDITED"

    return normalized, idempotency_key, product_id, event_payload, None


@csrf_exempt
@require_http_methods(["POST"])
def product_event(request: HttpRequest) -> JsonResponse:
    if not require_service_key(request):
        return error(401, "UNAUTHORIZED", "X-Service-Key is required")
    try:
        payload = request_json(request)
    except json.JSONDecodeError:
        return error(400, "INVALID_JSON", "Request body must be valid JSON")
    except TypeError:
        return error(400, "INVALID_REQUEST", "Request body must be a JSON object")

    event_type, idempotency_key, product_id, event_payload, schema_error = normalize_incoming_event(payload)
    if schema_error:
        return error(400, "INVALID_REQUEST", schema_error)
    if product_id is None or not event_type or not idempotency_key:
        return error(400, "INVALID_REQUEST", "product_id, event_type and idempotency_key are required")
    if IncomingProductEvent.objects.filter(idempotency_key=idempotency_key).exists():
        return JsonResponse({"status": "duplicate_ignored"}, status=202)

    IncomingProductEvent.objects.create(
        idempotency_key=idempotency_key,
        event_type=event_type,
        product_id=product_id,
        payload=payload,
    )
    card = ModerationCard.objects.filter(product_id=product_id).first()

    if event_type == "DELETED":
        if card is not None:
            card.delete()
        return JsonResponse({"status": "archived"}, status=202)

    if card is not None and card.status == ModerationCard.Status.HARD_BLOCKED:
        return JsonResponse({"status": "ignored_hard_blocked"}, status=202)

    if event_type == "CREATED":
        if card is not None:
            return JsonResponse({"status": "duplicate_created"}, status=202)
        seller_id = parse_uuid(str(event_payload.get("seller_id", ""))) if event_payload.get("seller_id") else None
        category_raw = event_payload.get("category_id")
        category_id = parse_uuid(str(category_raw)) if category_raw else None
        json_after = event_payload.get("json_after") or event_payload.get("product") or {}
        if not isinstance(json_after, dict):
            return error(400, "INVALID_REQUEST", "payload.json_after must be an object")
        # Удаляем приватные поля продавца (канон)
        json_after = {**json_after}
        skus = json_after.get("skus")
        if isinstance(skus, list):
            cleaned_skus = []
            for sku in skus:
                if isinstance(sku, dict):
                    sku = {**sku}
                    sku.pop("cost_price", None)
                    sku.pop("reserved_quantity", None)
                    cleaned_skus.append(sku)
                else:
                    cleaned_skus.append(sku)
            json_after["skus"] = cleaned_skus
        priority = event_payload.get("queue_priority")
        try:
            queue_priority = int(priority) if priority is not None else 1
        except (TypeError, ValueError):
            queue_priority = 1
        if queue_priority < 1 or queue_priority > 4:
            queue_priority = 1
        ModerationCard.objects.create(
            product_id=product_id,
            seller_id=seller_id,
            category_id=category_id,
            kind=ModerationCard.Kind.CREATE,
            status=ModerationCard.Status.PENDING,
            queue_priority=queue_priority,
            json_before=None,
            json_after=json_after,
        )
        return JsonResponse({"status": "accepted"}, status=202)

    if event_type == "EDITED" and card is not None:
        from django.db import transaction

        with transaction.atomic():
            try:
                card = ModerationCard.objects.select_for_update().get(pk=card.pk)
            except ModerationCard.DoesNotExist:
                return error(400, "INVALID_REQUEST", "Product not found in moderation")
            # Канон: EDITED на HARD_BLOCKED игнорируется (в т.ч. гонка с hard-block)
            if card.status == ModerationCard.Status.HARD_BLOCKED:
                return JsonResponse({"status": "ignored_hard_blocked"}, status=202)
            card.status = ModerationCard.Status.PENDING
            card.assigned_moderator_id = None
            card.claimed_at = None
            card.claim_expires_at = None
            card.decision_at = None
            OutgoingModerationEvent.objects.filter(card=card, delivered=False).delete()
            card.json_before = card.json_after
            next_after = event_payload.get("json_after") or event_payload.get("product") or card.json_after
            if isinstance(next_after, dict):
                next_after = {**next_after}
                skus = next_after.get("skus")
                if isinstance(skus, list):
                    cleaned = []
                    for sku in skus:
                        if isinstance(sku, dict):
                            sku = {**sku}
                            sku.pop("cost_price", None)
                            sku.pop("reserved_quantity", None)
                            cleaned.append(sku)
                        else:
                            cleaned.append(sku)
                    next_after["skus"] = cleaned
            card.json_after = next_after
            card.kind = ModerationCard.Kind.EDIT
            card.save(
                update_fields=[
                    "decision_at",
                    "status",
                    "assigned_moderator_id",
                    "claimed_at",
                    "claim_expires_at",
                    "json_before",
                    "json_after",
                    "kind",
                    "updated_at",
                ]
            )
    return JsonResponse({"status": "accepted"}, status=202)


def flush_outbox(request: HttpRequest) -> JsonResponse:
    """Внутренняя доотправка undelivered без действия модератора (X-Service-Key)."""
    if not require_service_key(request):
        return error(401, "UNAUTHORIZED", "Valid X-Service-Key is required")
    limit = 100
    try:
        body = request_json(request) if request.body else {}
        if isinstance(body, dict) and body.get("limit") is not None:
            limit = max(1, min(500, int(body["limit"])))
    except Exception:
        limit = 100
    result = deliver_pending_outgoing_events(limit=limit)
    return JsonResponse(result)


def claim_next_card(request: HttpRequest) -> JsonResponse | HttpResponse:
    """
    MOD-2 / OpenAPI: взять следующий PENDING-тикет в работу.
    POST /api/v1/queue/claim  и  POST /api/v1/product-moderation/get-next
    """
    from datetime import timedelta

    from django.db import transaction

    moderator_id = current_moderator_id(request)
    if moderator_id is None:
        return error(401, "UNAUTHORIZED", "Moderator identity is required")

    try:
        body = request_json(request)
    except json.JSONDecodeError:
        return error(400, "INVALID_JSON", "Request body must be valid JSON")
    except TypeError:
        return error(400, "INVALID_REQUEST", "Request body must be a JSON object")

    priority_filter = body.get("queue_priority") or body.get("queueId") or body.get("queue_id")
    try:
        priority_filter = int(priority_filter) if priority_filter is not None else None
    except (TypeError, ValueError):
        priority_filter = None
    if priority_filter is not None and (priority_filter < 1 or priority_filter > 4):
        return error(400, "INVALID_REQUEST", "queue_priority must be 1..4")

    category_ids = body.get("category_ids") or []
    parsed_categories: list[uuid.UUID] = []
    if isinstance(category_ids, list):
        for raw in category_ids:
            cid = parse_uuid(str(raw))
            if cid:
                parsed_categories.append(cid)

    with transaction.atomic():
        queryset = (
            ModerationCard.objects.select_for_update(skip_locked=True)
            .filter(status=ModerationCard.Status.PENDING)
            .order_by("queue_priority", "created_at")
        )
        if priority_filter is not None:
            queryset = queryset.filter(queue_priority=priority_filter)
        if parsed_categories:
            queryset = queryset.filter(category_id__in=parsed_categories)

        card = queryset.first()
        if card is None:
            return HttpResponse(status=204)

        now = timezone.now()
        card.status = ModerationCard.Status.IN_REVIEW
        card.assigned_moderator_id = moderator_id
        card.claimed_at = now
        card.claim_expires_at = now + timedelta(minutes=CLAIM_TTL_MINUTES)
        card.save(
            update_fields=[
                "status",
                "assigned_moderator_id",
                "claimed_at",
                "claim_expires_at",
                "updated_at",
            ]
        )

    return JsonResponse(ticket_payload(card))


@csrf_exempt
@require_http_methods(["POST"])
def queue_claim(request: HttpRequest) -> JsonResponse | HttpResponse:
    return claim_next_card(request)


@csrf_exempt
@require_http_methods(["POST"])
def get_next_card(request: HttpRequest) -> JsonResponse | HttpResponse:
    """Канон MOD-2: POST /api/v1/product-moderation/get-next"""
    return claim_next_card(request)


@csrf_exempt
@require_http_methods(["GET", "POST"])
def blocking_reasons(request: HttpRequest) -> JsonResponse:
    if request.method == "GET":
        hard_block = parse_bool(request.GET.get("hard_block"))
        is_active = parse_bool(request.GET.get("is_active"))
        if is_active is None:
            is_active = True

        queryset = BlockingReason.objects.all()
        if hard_block is not None:
            queryset = queryset.filter(hard_block=hard_block)
        queryset = queryset.filter(is_active=is_active)
        return JsonResponse([reason_payload(reason) for reason in queryset], safe=False)

    try:
        payload = request_json(request)
    except json.JSONDecodeError:
        return error(400, "INVALID_JSON", "Request body must be valid JSON")

    code = str(payload.get("code", "")).strip().upper()
    title = str(payload.get("title", "")).strip()
    hard_block = payload.get("hard_block")
    if not CODE_RE.fullmatch(code) or not title or not isinstance(hard_block, bool):
        return error(400, "INVALID_REQUEST", "code, title and hard_block are required")
    if BlockingReason.objects.filter(code=code).exists():
        return error(409, "DUPLICATE_REASON", "Blocking reason code already exists")

    reason = BlockingReason.objects.create(
        code=code,
        title=title,
        description=str(payload.get("description", "")).strip(),
        hard_block=hard_block,
    )
    return JsonResponse(reason_payload(reason), status=201)


@csrf_exempt
@require_http_methods(["PATCH", "DELETE"])
def blocking_reason_detail(request: HttpRequest, reason_id) -> JsonResponse | HttpResponse:
    try:
        reason = BlockingReason.objects.get(id=reason_id)
    except BlockingReason.DoesNotExist:
        return error(404, "NOT_FOUND", "Blocking reason not found")

    if request.method == "DELETE":
        reason.delete()
        return HttpResponse(status=204)

    try:
        payload = request_json(request)
    except json.JSONDecodeError:
        return error(400, "INVALID_JSON", "Request body must be valid JSON")

    if "title" in payload:
        title = str(payload["title"]).strip()
        if not title:
            return error(400, "INVALID_REQUEST", "title must not be empty")
        reason.title = title
    if "description" in payload:
        reason.description = str(payload["description"]).strip()
    if "is_active" in payload:
        if not isinstance(payload["is_active"], bool):
            return error(400, "INVALID_REQUEST", "is_active must be boolean")
        reason.is_active = payload["is_active"]
    reason.save()
    return JsonResponse(reason_payload(reason))


@csrf_exempt
@require_http_methods(["POST"])
def approve_ticket(request: HttpRequest, ticket_id) -> JsonResponse:
    return approve_card(request, ticket_id=ticket_id, protocol_response=True)


@csrf_exempt
@require_http_methods(["POST"])
def approve_product(request: HttpRequest, product_id) -> JsonResponse:
    return approve_card(request, product_id=product_id, protocol_response=False)


@csrf_exempt
@require_http_methods(["POST"])
def block_ticket(request: HttpRequest, ticket_id) -> JsonResponse:
    return decline_card(request, ticket_id=ticket_id, protocol_response=True)


@csrf_exempt
@require_http_methods(["POST"])
def decline_ticket(request: HttpRequest, ticket_id) -> JsonResponse:
    return decline_card(request, ticket_id=ticket_id, protocol_response=True)


@csrf_exempt
@require_http_methods(["POST"])
def decline_product(request: HttpRequest, product_id) -> JsonResponse:
    return decline_card(request, product_id=product_id, protocol_response=False)
