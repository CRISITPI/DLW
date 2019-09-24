# Generated by Django 2.0.7 on 2019-09-24 07:51

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('dlw', '0002_auto_20190924_1320'),
    ]

    operations = [
        migrations.CreateModel(
            name='MachiningAirBox',
            fields=[
                ('sno', models.AutoField(primary_key=True, serialize=False)),
                ('bo_no', models.CharField(max_length=20, null=True)),
                ('bo_date', models.DateField(null=True)),
                ('airbox_sno', models.CharField(max_length=20, null=True)),
                ('airbox_make', models.CharField(max_length=20, null=True)),
                ('in_qty', models.IntegerField(null=True)),
                ('out_qty', models.IntegerField(null=True)),
                ('date', models.DateField(null=True)),
                ('loco_type', models.CharField(max_length=20, null=True)),
                ('dispatch_to', models.CharField(max_length=20, null=True)),
            ],
        ),
    ]
