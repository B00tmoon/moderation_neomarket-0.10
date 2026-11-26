from __future__ import annotations

from django.core.management.base import BaseCommand

from moderation.views import deliver_pending_outgoing_events


class Command(BaseCommand):
    help = "Доотправка сохранённых исходящих событий в B2B без действия модератора."

    def add_arguments(self, parser):
        parser.add_argument("--limit", type=int, default=100)

    def handle(self, *args, **options):
        result = deliver_pending_outgoing_events(limit=options["limit"])
        self.stdout.write(
            self.style.SUCCESS(
                f"delivered={result['delivered']} failed={result['failed']} skipped={result['skipped']}"
            )
        )
