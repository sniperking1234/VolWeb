# Generated by Django 3.2.12 on 2022-03-07 16:30

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('iocs', '0002_auto_20220307_1630'),
    ]

    operations = [
        migrations.AlterField(
            model_name='newioc',
            name='context',
            field=models.CharField(max_length=255),
        ),
    ]
