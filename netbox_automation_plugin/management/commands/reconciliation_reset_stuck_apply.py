"""Reset a reconciliation run stuck in apply_in_progress without recorded apply summary."""

from django.core.management.base import BaseCommand, CommandError

from netbox_automation_plugin.sync.reconciliation.service import try_reset_stuck_reconciliation_apply_run


class Command(BaseCommand):
    help = (
        "Reset a reconciliation run stuck in apply_in_progress when apply_results has no "
        "summary (e.g. worker killed mid-apply). Uses a non-blocking row lock; skips if "
        "another process holds the run."
    )

    def add_arguments(self, parser):
        parser.add_argument("run_id", type=int, help="MAASOpenStackReconciliationRun primary key")

    def handle(self, *args, **options):
        ok, msg = try_reset_stuck_reconciliation_apply_run(run_id=int(options["run_id"]))
        if not ok:
            raise CommandError(msg)
        self.stdout.write(self.style.SUCCESS(msg))
