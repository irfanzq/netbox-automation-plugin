from django import forms
from django.utils.translation import gettext_lazy as _


class MAASOpenStackSyncForm(forms.Form):
    """
    Form for MAAS / OpenStack Sync workflow.

    Phase 1: Drift Audit only (read-only). Full Sync and scope toggles come later.
    """

    mode = forms.ChoiceField(
        choices=[
            ("audit", _("Drift Audit (read-only)")),
            # ("apply", _("Full Sync (apply to branch)")),  # Phase 2
        ],
        initial="audit",
        label=_("Mode"),
        help_text=_("Drift Audit: compare MAAS, OpenStack, and NetBox; produce report. No changes."),
        widget=forms.RadioSelect(attrs={"class": "form-check-input"}),
    )
