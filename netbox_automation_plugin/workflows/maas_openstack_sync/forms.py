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
        help_text=_(
            "Optional. Choose “All sites (no filter)” for a full audit, or pick specific sites. "
            "Leaving the field empty also runs a full audit."
        ),
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
        help_text=_(
            "Optional. Choose “All locations (no filter)” for a full audit, or pick specific locations; "
            "OpenStack sections use the same location-based scope. Empty means no location filter."
        ),
    )

    def __init__(self, *args, site_choices=None, location_choices=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["sites"].choices = [("__all__", _("All sites (no filter)"))] + (site_choices or [])
        self.fields["locations"].choices = [
            ("__all__", _("All locations (no filter)"))
        ] + (location_choices or [])
