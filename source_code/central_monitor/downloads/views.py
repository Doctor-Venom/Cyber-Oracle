from django.http.response import HttpResponseNotAllowed
from django.shortcuts import render
import os
from django.conf import settings
from django.http import HttpResponse, Http404
import zipfile
import json
from api.models import get_initial_host_settings
from django.contrib.admin.views.decorators import staff_member_required
import uuid
# Create your views here.

@staff_member_required
def main_view(request, *args, **kwargs):
    if request.method == 'GET' and request.GET.get('platform', None) and request.GET.get('type', None):
        return download(request, request.GET['platform'], request.GET['type'])
    else:
        ctx={
            'windows_agent_download_link' : '/downloads?platform=windows&type=host',
            'linux_agent_download_link' : '/downloads?platform=linux&type=host',
        }
        return render(request=request, template_name='downloads_template.html', context=ctx)

@staff_member_required
def download(request, platform, type):
    if type == 'host':
        installer_filename={'windows':'windows_host_agent_installer.exe', 'linux_host_agent_installer.elf':''}[platform]
        uninstaller_filename={'windows':'windows_host_agent_uninstaller.exe', 'linux_host_agent_uninstaller.elf':''}[platform]
        def is_safe_path(basedir, path, follow_symlinks=True): # filtering input to defend against path traversal (not needed anymore)
            # resolves symbolic links
            if follow_symlinks: matchpath = os.path.realpath(path)
            else: matchpath = os.path.abspath(path)
            return str(basedir) == str(os.path.commonpath((basedir, matchpath)))

        installer_file_path = os.path.join(settings.MEDIA_ROOT, installer_filename)
        uninstaller_file_path = os.path.join(settings.MEDIA_ROOT, uninstaller_filename)
        settings_file_path = os.path.join(settings.MEDIA_ROOT, f'initial_host_settings.json') # WTF: filename was f'{uuid.uuid4()}initial_host_settings.json' but i removed the uuid.. why did i include a uuid here?????
        if is_safe_path(settings.MEDIA_ROOT, installer_file_path) and is_safe_path(settings.MEDIA_ROOT, uninstaller_file_path) and is_safe_path(settings.MEDIA_ROOT, settings_file_path):
            initial_host_settings = get_initial_host_settings()
            if '[[[ MANDATORY OPTION NOT SET!!! ]]]' in initial_host_settings.values(): # if mandatory options not configured then agent wont work, hence dont allow a donwload
                return HttpResponse('Central Monitor Setup Is Incomplete!<br>Mandatory options are not set in the default agent settings, agents will fail to run.<hr>(Click <a href="/settings/">here</a> to Finish Setup.)')
            with open(settings_file_path, 'w') as f: f.write(json.dumps(initial_host_settings))
            response = HttpResponse(content_type='application/zip')
            zip_file = zipfile.ZipFile(response, 'w')
            zip_file.write(installer_file_path, installer_filename)
            zip_file.write(uninstaller_file_path, uninstaller_filename)
            zip_file.write(settings_file_path, 'initial_host_settings.json')
            response['Content-Disposition'] = f'attachment; filename=Cyber_Oracle_Host_Agent_{platform}.zip'
            return response
        raise Http404
    else:
        raise Http404


