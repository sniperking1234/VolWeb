# Generated by Django 5.1.1 on 2024-10-11 14:38

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("evidences", "0001_initial"),
    ]

    operations = [
        migrations.AlterField(
            model_name="evidence",
            name="os",
            field=models.CharField(
                choices=[("Windows", "windows"), ("Linux", "linux")], max_length=10
            ),
        ),
    ]