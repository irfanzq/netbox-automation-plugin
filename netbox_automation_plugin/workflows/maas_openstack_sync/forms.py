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

    sites = forms.ChoiceField(
        label=_("Site"),
        required=True,
        choices=(),
        error_messages={
            "required": _("Select a site."),
            "invalid_choice": _("Select a valid site."),
        },
        widget=forms.Select(
            attrs={
                "class": "form-select",
                "id": "id_sites",
                "aria-required": "true",
            },
        ),
        help_text=_("Required. Choose one NetBox site to scope the drift audit."),
    )

    locations = forms.ChoiceField(
        label=_("Location"),
        required=True,
        choices=(),
        error_messages={
            "required": _("Select a location."),
            "invalid_choice": _("Select a valid location."),
        },
        widget=forms.Select(
            attrs={
                "class": "form-select",
                "id": "id_locations",
                "aria-required": "true",
            },
        ),
        help_text=_(
            "Required. Choose one location under that site; OpenStack sections use the same scope."
        ),
    )

    def __init__(
        self,
        *args,
        site_choices=None,
        location_choices=None,
        location_meta=None,
        **kwargs,
    ):
        super().__init__(*args, **kwargs)
        self._location_meta = dict(location_meta or {})
        self.fields["sites"].choices = site_choices or []
        self.fields["locations"].choices = location_choices or []

    def clean(self):
        cleaned = super().clean()
        site = (cleaned.get("sites") or "").strip()
        loc_key = (cleaned.get("locations") or "").strip()
        if site and loc_key:
            meta = self._location_meta.get(loc_key) or {}
            loc_site = (meta.get("site_slug") or "").strip()
            if loc_site and loc_site != site:
                raise forms.ValidationError(
                    _("The selected location does not belong to the selected site.")
                )
        return cleaned
