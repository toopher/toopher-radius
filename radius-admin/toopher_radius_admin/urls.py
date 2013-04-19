from django.conf import settings
from django.conf.urls import patterns, include, url
from django.conf.urls.static import static

from django.contrib import admin
from toopher_radius_admin.views import *

admin.autodiscover()


urlpatterns = patterns("",
    url(r'^$', HomeView.as_view(), name='home'),
    url(r"^admin/", include(admin.site.urls)),
    
        
    url(r"^account/", include("account.urls")),
    
    
    
)

urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)