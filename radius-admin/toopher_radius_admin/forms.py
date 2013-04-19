from django import forms
from django.utils.translation import ugettext_lazy as _

class RadiusAdminToopherSetupForm(forms.Form):
    legend = 'Toopher API Setup'
    url_name = 'radius-admin-toopher-setup'
    def __init__(self, *args, **kwargs):
        super(RadiusAdminToopherSetupForm, self).__init__(*args, **kwargs)
        self.fields.keyOrder = ['toopher_consumer_key', 'toopher_consumer_secret', 'toopher_api_address']
    
    toopher_consumer_key = forms.CharField(
        label=_('Toopher Consumer Key'),
        required=False,
    )
    
    toopher_consumer_secret = forms.CharField(
        label=_('Toopher Consumer Secret'),
        required=False,
    )
    
    toopher_api_address = forms.CharField(
        label=_('Toopher API Endpoint'),
        required=False,
    )