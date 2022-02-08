from rest_framework import permissions
import json
from pathlib import Path
from django.conf import settings

#https://stackoverflow.com/questions/55081085/validate-user-on-update-request-in-django-rest-framework
class RequestTypesWhitelist(permissions.BasePermission):
    """
    Global permission to allow only POST and PATCH requests to the API
    """

    def has_permission(self, request, view):
        if request.method not in ['POST', 'PATCH']: return False
        with open(f'{settings.BASE_DIR}/config_files/CMConfig.json' , 'r') as f:
            conf = json.loads(f.read())
            if request.method == 'POST' and request.user.username != conf['AGENT_AUTH_USERNAME']: return False # NOTE: if anything fuks up in the API, then this is the reason
        return True
