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

    sites = forms.MultipleChoiceField(
        label=_("Sites"),
        required=False,
        choices=(),
        widget=forms.SelectMultiple(
            attrs={
                "class": "form-select maas-sync-ms-native d-none",
                "aria-hidden": "true",
                "tabindex": "-1",
            }
        ),
        help_text=_("Optional. Limit report to selected NetBox sites."),
    )

    locations = forms.MultipleChoiceField(
        label=_("Locations"),
        required=False,
        choices=(),
        widget=forms.SelectMultiple(
            attrs={
                "class": "form-select maas-sync-ms-native d-none",
                "aria-hidden": "true",
                "tabindex": "-1",
            }
        ),
        help_text=_("Optional. Select one or more NetBox locations."),
    )

    def __init__(self, *args, site_choices=None, location_choices=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["sites"].choices = [("__all__", _("Select all sites"))] + (site_choices or [])
        self.fields["locations"].choices = [("__all__", _("Select all locations"))] + (location_choices or [])
