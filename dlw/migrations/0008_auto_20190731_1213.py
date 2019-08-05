# Generated by Django 2.0.7 on 2019-07-31 06:43

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('dlw', '0007_auto_20190729_1733'),
    ]

    operations = [
        migrations.CreateModel(
            name='user_master',
            fields=[
                ('emp_id', models.CharField(max_length=15, primary_key=True, serialize=False)),
                ('role', models.CharField(max_length=25, null=True)),
                ('name', models.CharField(max_length=50, null=True)),
                ('designation', models.CharField(max_length=50, null=True)),
                ('department', models.CharField(max_length=50, null=True)),
                ('email', models.CharField(max_length=50, null=True)),
                ('contactno', models.CharField(max_length=10, null=True)),
            ],
        ),
        migrations.RenameField(
            model_name='navbar',
            old_name='usertype',
            new_name='role',
        ),
    ]
