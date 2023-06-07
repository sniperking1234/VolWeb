# Generated by Django 3.2.18 on 2023-04-23 11:15

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('windows_engine', '0023_drivermodule_tag'),
    ]

    operations = [
        migrations.AlterField(
            model_name='drivermodule',
            name='ServiceKey',
            field=models.TextField(null=True),
        ),
        migrations.AlterField(
            model_name='handles',
            name='GrantedAccess',
            field=models.TextField(null=True),
        ),
        migrations.AlterField(
            model_name='handles',
            name='HandleValue',
            field=models.IntegerField(null=True),
        ),
        migrations.AlterField(
            model_name='handles',
            name='Offset',
            field=models.TextField(null=True),
        ),
    ]