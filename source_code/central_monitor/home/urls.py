"""central_monitor home app URL Configuration

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

from django.urls import path
from . import views

urlpatterns = [
    path('', views.home_view, name='home'),
    path('dashboard/', views.dashboard_view, name='dashboard_app_view'),
    path('host_monitor/', views.host_monitor_view, name='host_monitor_app_view'),
    path('network_monitor/', views.network_monitor_view, name='network_monitor_app_view'),
    path('password_cracker/', views.password_cracker_view, name='password_cracker_app_view'),
    path('log_analyzer/', views.log_analyzer_view, name='log_analyzer_app_view'),
    path('active_directory/', views.active_directory_view, name='active_directory_app_view'),
    path('host_detail/', views.host_detail_view, name='host_detail_view'),
]