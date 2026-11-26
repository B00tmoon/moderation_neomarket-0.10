from __future__ import annotations

import uuid

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    dependencies = [
        ("moderation", "0003_incoming_product_events"),
    ]

    operations = [
        migrations.CreateModel(
            name="AdminActionLog",
            fields=[
                ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("product_id", models.UUIDField(blank=True, null=True)),
                ("actor", models.CharField(max_length=150)),
                ("action", models.CharField(default="EMERGENCY_UNLOCK", max_length=64)),
                ("from_status", models.CharField(max_length=32)),
                ("to_status", models.CharField(max_length=32)),
                ("unlock_reason", models.TextField()),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                (
                    "card",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="admin_actions",
                        to="moderation.moderationcard",
                    ),
                ),
            ],
            options={"ordering": ["-created_at"]},
        ),
    ]
