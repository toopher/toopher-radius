from django.conf import settings
from django.conf.urls import patterns, include, url
from django.conf.urls.static import static

from django.contrib import admin
from toopher_radius_admin.views import *

admin.autodiscover()


urlpatterns = patterns("",
    url(r'^$', DashboardView.as_view(), name='home'),
    url(r'^dashboard$', DashboardView.as_view(), name='dashboard'),
    url(r'^backend_config$', BackendConfigView.as_view(), name='backend-config'),
    url(r'^vpn_settings$', VpnSettingsView.as_view(), name='vpn-settings'),
    url(r'^user_management$', UserManagementView.as_view(), name='user-management'),
    
    url(r'^radius_admin/$', AdministrationView.as_view(), name='radius-admin'),
    url(r'^radius_admin/toopher_setup$', AdministrationToopherSetupView.as_view(), name='radius-admin-toopher-setup'),
    url(r'^radius_admin/server_control$', AdministrationServerControlView.as_view(), name='radius-admin-server-control'),
    url(r'^radius_admin/remote_access$', AdministrationRemoteAccessView.as_view(), name='radius-admin-remote-access'),
    url(r'^radius_admin/advanced$', AdministrationAdvancedView.as_view(), name='radius-admin-advanced'),
    
    
    url(r"^admin/", include(admin.site.urls)),
    
        
    url(r"^account/", include("account.urls")),
    
    
    
)

urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)