# Generated by Django 2.0.7 on 2019-08-01 14:12

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('dlw', '0018_template_permission'),
    ]

    operations = [
        migrations.AddField(
            model_name='navbar',
            name='permission_id',
            field=models.IntegerField(null=True),
        ),
    ]
