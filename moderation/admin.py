from __future__ import annotations

from django import forms
from django.contrib import admin, messages
from django.core.exceptions import PermissionDenied, ValidationError

from .models import (
    AdminActionLog,
    BlockingReason,
    IncomingProductEvent,
    ModerationCard,
    OutgoingModerationEvent,
)


@admin.register(BlockingReason)
class BlockingReasonAdmin(admin.ModelAdmin):
    list_display = ("code", "title", "hard_block", "is_active")
    list_filter = ("hard_block", "is_active")
    search_fields = ("code", "title")
    readonly_fields = ("created_at", "updated_at")
    actions = ("deactivate",)

    @admin.action(description="Deactivate selected reasons")
    def deactivate(self, request, queryset):
        queryset.update(is_active=False)

    def delete_model(self, request, obj):
        obj.delete()

    def delete_queryset(self, request, queryset):
        queryset.update(is_active=False)


class ModerationCardAdminForm(forms.ModelForm):
    unlock_reason = forms.CharField(
        required=False,
        widget=forms.Textarea(attrs={"rows": 3}),
        help_text="Обязательно при аварийном снятии HARD_BLOCKED. Не путать с комментарием блокировки.",
        label="Причина аварийного снятия",
    )

    class Meta:
        model = ModerationCard
        fields = "__all__"


@admin.register(ModerationCard)
class ModerationCardAdmin(admin.ModelAdmin):
    form = ModerationCardAdminForm
    list_display = ("product_id", "status", "assigned_moderator_id", "blocking_reason", "decision_at")
    list_filter = ("status", "blocking_reason", "kind")
    search_fields = ("product_id", "seller_id", "assigned_moderator_id")
    readonly_fields = ("created_at", "updated_at", "claimed_at", "claim_expires_at", "decision_comment")

    def get_readonly_fields(self, request, obj=None):
        readonly = list(super().get_readonly_fields(request, obj))
        if obj is not None and obj.status == ModerationCard.Status.HARD_BLOCKED and not request.user.is_superuser:
            readonly = list(
                set(readonly)
                | {"status", "blocking_reason", "decision_at", "product_id", "decision_comment", "field_reports"}
            )
        return readonly

    def save_model(self, request, obj, form, change):
        if not change:
            super().save_model(request, obj, form, change)
            return

        try:
            original = ModerationCard.objects.get(pk=obj.pk)
        except ModerationCard.DoesNotExist:
            original = None

        if original is not None and original.status == ModerationCard.Status.HARD_BLOCKED:
            if obj.status != original.status:
                if not request.user.is_superuser:
                    raise PermissionDenied(
                        "Only a superuser may lift HARD_BLOCKED status outside the normal flow."
                    )
                # Канон: аварийное снятие только в очередь (PENDING)
                if obj.status != ModerationCard.Status.PENDING:
                    raise ValidationError(
                        {
                            "status": (
                                "Emergency unlock of HARD_BLOCKED is allowed only to PENDING (queue)."
                            )
                        }
                    )
                unlock_reason = (form.cleaned_data.get("unlock_reason") or "").strip()
                if not unlock_reason:
                    raise ValidationError(
                        {
                            "unlock_reason": (
                                "Separate unlock_reason is required for emergency HARD_BLOCKED unlock "
                                "(do not reuse the original blocking comment)."
                            )
                        }
                    )
                # Не затираем исходный decision_comment блокировки причиной снятия
                obj.decision_comment = original.decision_comment
                obj.assigned_moderator_id = None
                obj.claimed_at = None
                obj.claim_expires_at = None
                super().save_model(request, obj, form, change)
                AdminActionLog.objects.create(
                    card=obj,
                    product_id=obj.product_id,
                    actor=getattr(request.user, "username", None) or str(request.user.pk),
                    action="EMERGENCY_UNLOCK",
                    from_status=original.status,
                    to_status=obj.status,
                    unlock_reason=unlock_reason,
                )
                try:
                    messages.warning(
                        request,
                        f"HARD_BLOCKED → PENDING by {request.user}; reason logged in AdminActionLog.",
                        fail_silently=True,
                    )
                except Exception:
                    pass
                return

        super().save_model(request, obj, form, change)


@admin.register(AdminActionLog)
class AdminActionLogAdmin(admin.ModelAdmin):
    list_display = ("created_at", "action", "product_id", "from_status", "to_status", "actor")
    list_filter = ("action", "from_status", "to_status")
    search_fields = ("product_id", "actor", "unlock_reason")
    readonly_fields = (
        "id",
        "card",
        "product_id",
        "actor",
        "action",
        "from_status",
        "to_status",
        "unlock_reason",
        "created_at",
    )

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False


@admin.register(OutgoingModerationEvent)
class OutgoingModerationEventAdmin(admin.ModelAdmin):
    list_display = ("event_type", "card", "delivered", "created_at", "delivered_at")
    list_filter = ("event_type", "delivered")
    search_fields = ("idempotency_key", "card__product_id")
    actions = ("redeliver_selected",)

    @admin.action(description="Redeliver selected undelivered events to B2B")
    def redeliver_selected(self, request, queryset):
        from .views import deliver_outgoing_event
        import requests

        ok = fail = 0
        for event in queryset.filter(delivered=False):
            try:
                deliver_outgoing_event(event)
                ok += 1
            except requests.RequestException:
                fail += 1
        self.message_user(request, f"Redelivered={ok}, failed={fail}")


@admin.register(IncomingProductEvent)
class IncomingProductEventAdmin(admin.ModelAdmin):
    list_display = ("event_type", "product_id", "idempotency_key", "created_at")
    list_filter = ("event_type",)
    search_fields = ("idempotency_key", "product_id")
