from django import forms
from django.utils.translation import gettext_lazy as _


class MAASOpenStackSyncForm(forms.Form):
    """
    Form for MAAS / OpenStack Sync workflow.

    Phase 1: Drift Audit only. Mode is fixed to audit (hidden) so the UI stays a single clear action.
    """

    mode = forms.CharField(
        widget=forms.HiddenInput(),
        initial="audit",
        required=False,
    )
