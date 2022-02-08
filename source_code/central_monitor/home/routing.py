#THIS IS FOR DJANGO CHANNELS
from django.urls import re_path
from . import consumers

websocket_urlpatterns = [
    re_path('ws/xterm_terminal/', consumers.xterm_terminal_consumer.as_asgi()),
    re_path('ws/host_control/', consumers.host_control_consumer.as_asgi()),
]