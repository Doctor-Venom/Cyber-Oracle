from django.shortcuts import render
from alerts.models import Alert
from central_monitor.my_decorators import superuser_required
from django.http import Http404, HttpResponseBadRequest, JsonResponse
import json

# Create your views here.
@superuser_required
def alerts_view(request, *args, **kwargs):
    is_ajax = request.headers.get('X-Requested-With') == 'XMLHttpRequest' # https://testdriven.io/blog/django-ajax-xhr/
    if is_ajax:
        if request.method == 'GET':
            alert_id = request.GET.get('alert_id')
            alert = Alert.objects.get(id=alert_id)
            alert.is_viewed = True
            alert.save(update_fields=['is_viewed'])
            ctx={
                'source_type' : alert.source_type,
                'source_id' : alert.source_id,
                'severity_score' : alert.severity_score,
                'date_time' : alert.date_time,
                'data' : json.dumps(alert.data, indent=2, separators=(',', ': ')).replace('\\n', '\n') # FIXME: the conversion here to json string is temporary, must send it as dict and make better visualization in alert_details_modal_template.html
            }
            return render(request=request, template_name='alert_details_modal_template.html', context=ctx)
        if request.method == 'POST':
            POST = json.load(request)
            if POST.get('action') == 'delete':
                try:
                    alert_id = POST.get('alert_id')
                    if alert_id == 'all':
                        Alert.objects.all().delete()
                        return JsonResponse({'success': True, 'status_code': 200, 'msg': f'all alerts have been deleted'}, status=200)
                    elif alert_id == 'seen':
                        Alert.objects.filter(is_viewed=True).delete()
                        return JsonResponse({'success': True, 'status_code': 200, 'msg': f'seen alerts have been deleted'}, status=200)
                    else:
                        Alert.objects.get(id=alert_id).delete()
                        return JsonResponse({'success': True, 'status_code': 200, 'msg': f'alert with id {alert_id} has been deleted'}, status=200)
                except:
                    return JsonResponse({'success': False, 'status_code': 404, 'msg': f'error occured when deleting alert(s)'}, status=404)
    else:
        if request.method == 'GET':
            alerts_list=[]
            for alert in Alert.objects.all().iterator():
                alert_id = alert.id
                date_time = alert.date_time
                source_type = alert.source_type 
                source_id = alert.source_id.host_id if source_type != 'Local' else 'N/A'
                source_name = '/'.join(source_id.split('$')[1:3]) if source_id != 'N/A' else 'N/A'
                severity_score = alert.severity_score
                severety_level = alert.severety_level
                is_viewed = alert.is_viewed
                general_info = alert.data['data']['general_info']
                alerts_list.append([alert_id, date_time, source_type, source_id, source_name, severity_score, severety_level, is_viewed, general_info])
            ctx={'alerts_list': alerts_list}
            return render(request=request, template_name='alerts_template.html', context=ctx)
