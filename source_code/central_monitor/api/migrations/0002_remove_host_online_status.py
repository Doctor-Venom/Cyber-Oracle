# Generated by Django 3.1.5 on 2021-09-12 13:00

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0001_initial'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='host',
            name='online_status',
        ),
    ]
