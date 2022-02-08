from rest_framework import serializers

from .models import Host


class HostSerializer(serializers.HyperlinkedModelSerializer):
    class Meta:
        model = Host
        fields = (
            'host_os_type',
            'host_id',
            'agent_id',
            'settings',
            'program_info',
            'process_info',
            'password_info',
            'privesc_info',
            'exploit_info',
            'system_info',
            'network_info',
            'nmap_info',
            'eventlog_info',
            'schedtask_info',
            )
