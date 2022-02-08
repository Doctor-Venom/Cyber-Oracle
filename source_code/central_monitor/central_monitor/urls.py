"""central_monitor URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/3.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path
from django.urls import include
from rest_framework.authtoken.views import obtain_auth_token
from home import views as home_views
from downloads import views as downloads_views
from settings import views as settings_views
from alerts import views as alerts_views

urlpatterns = [
    path('', include('home.urls')),
    path('downloads/', downloads_views.main_view, name='downloads'),
    path('alerts/', alerts_views.alerts_view, name='alerts'),
    path('settings/', include('settings.urls')),
    path('admin/', admin.site.urls),
    path('api/', include('api.urls')),
    path('api-auth/', include('rest_framework.urls', namespace='api-auth'), name='api-auth'),
    path('api-token-auth/', obtain_auth_token, name='api-token-auth'),
]


admin.site.site_header = "Cyberoracle - Database Administration"
admin.site.index_title = "Database Administration"
admin.site.site_title = "Cyberoracle"