# Generated by Django 2.0.7 on 2019-09-21 12:59

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('dlw', '0022_annual_production_jpo_loconame_materialname_namedgn'),
    ]

    operations = [
        migrations.CreateModel(
            name='testing_purpose',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('first', models.CharField(max_length=50, null=True)),
                ('second', models.CharField(max_length=50, null=True)),
            ],
        ),
    ]
