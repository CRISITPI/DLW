# Generated by Django 2.0.7 on 2019-07-31 15:06

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('dlw', '0011_user_master_created'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='user_master',
            name='created',
        ),
    ]
