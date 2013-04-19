from django.views.generic import View, TemplateView
from account.mixins import LoginRequiredMixin

import logging
logger = logging.getLogger(__name__)

class HomeView(LoginRequiredMixin, TemplateView):
    template_name = "toopher_radius_admin/home.html"
 

