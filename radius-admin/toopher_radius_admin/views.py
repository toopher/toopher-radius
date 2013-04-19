from django.views.generic import View, TemplateView
from django.views.generic.edit import FormView
from account.mixins import LoginRequiredMixin
from toopher_radius_admin.forms import *
from django.core.urlresolvers import reverse_lazy as reverse

import logging
logger = logging.getLogger(__name__)

class DashboardView(LoginRequiredMixin, TemplateView):
    template_name = "toopher_radius_admin/dashboard.html"
    
class BackendConfigView(LoginRequiredMixin, TemplateView):
    template_name = "toopher_radius_admin/backend_config.html"
    
class VpnSettingsView(LoginRequiredMixin, TemplateView):
    template_name = "toopher_radius_admin/vpn_settings.html" 
    
class UserManagementView(LoginRequiredMixin, TemplateView):
    template_name = "toopher_radius_admin/user_management.html"

    
class AdministrationView(LoginRequiredMixin, TemplateView):
    template_name = "toopher_radius_admin/radius_admin/base.html"
    
class AdministrationToopherSetupView(LoginRequiredMixin, FormView):
    template_name = "toopher_radius_admin/radius_admin/toopher_setup.html"
    form_class = RadiusAdminToopherSetupForm
    success_url = reverse('radius-admin-toopher-setup')

class AdministrationServerControlView(LoginRequiredMixin, TemplateView):
    template_name = "toopher_radius_admin/radius_admin/server_control.html"

class AdministrationRemoteAccessView(LoginRequiredMixin, TemplateView):
    template_name = "toopher_radius_admin/radius_admin/remote_access.html"

class AdministrationAdvancedView(LoginRequiredMixin, TemplateView):
    template_name = "toopher_radius_admin/radius_admin/advanced.html"