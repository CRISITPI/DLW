# Generated by Django 2.0.7 on 2019-07-31 12:13

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('dlw', '0009_user_master_created'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='user_master',
            name='created',
        ),
    ]
