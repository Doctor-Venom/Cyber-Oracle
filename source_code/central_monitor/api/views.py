from django.shortcuts import render

from rest_framework import viewsets

from .serializers import HostSerializer
from .models import Host

from django.core.exceptions import PermissionDenied
import json
from pathlib import Path
from django.conf import settings

# Create your views here.


class HostViewSet(viewsets.ModelViewSet):
    queryset = Host.objects.all()
    serializer_class = HostSerializer

    # https://www.django-rest-framework.org/community/3.0-announcement/
    # https://stackoverflow.com/questions/55081085/validate-user-on-update-request-in-django-rest-framework
    def perform_create(self, serializer):
        with open(f'{settings.BASE_DIR}/config_files/CMConfig.json' , 'r') as f:
            conf = json.loads(f.read())
            if self.request.user.username != conf['AGENT_AUTH_USERNAME']: raise PermissionDenied('[0] Permission Denied!')
            serializer.save()
    def perform_update(self, serializer):
        obj = self.get_object()
        if self.request.user != obj.owner_user: raise PermissionDenied('[1] Permission Denied!')
        serializer.save()


'''
logic flow:
    -when agent starts for the first time, it will need to register..
    -for registration it will send a post request to the API to create a host object
    -to send this request the agent will authenticate as default conf['AGENT_AUTH_USERNAME']
    -the host object will be created with a new user account (randomly generated creds by agent and send in registration POST request in settigns['AGENT_AUTH_USERNAME'] and settings['AGENT_AUTH_PASSWORD'])
    -the created user will be the owner of the host object, and only him is allowed to send PATCH requests for it
    -the agent saves the newly generated creds in the new_settings file, after registration complete this file will become  the SETTINGS and will be available on both the host and central monitor
'''