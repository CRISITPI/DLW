# Generated by Django 2.0.7 on 2019-08-08 20:27

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('dlw', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='roles',
            name='parent',
            field=models.CharField(max_length=50, null=True),
        ),
    ]