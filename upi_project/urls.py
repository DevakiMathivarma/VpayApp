from django.contrib import admin
from django.urls import path, include
from django.contrib import admin
from core import views as core_views
from django.views.generic import RedirectView
from django.conf import settings
from django.conf.urls.static import static


urlpatterns = [
   

    path('admin/', admin.site.urls),
      path('admin/analytics/', admin.site.admin_view(core_views.admin_analytics_view), name='admin-analytics'),
    path('googlelogin/', RedirectView.as_view(
        url='/accounts/google/login/?process=login&next=/',
        permanent=False),
        name='google_login_redirect'
    ),
    path('', include('core.urls')),  # include app routes (core app)
    path("accounts/", include("allauth.urls")),   # <- required

]
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
