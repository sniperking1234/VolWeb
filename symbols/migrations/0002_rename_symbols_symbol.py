# Generated by Django 4.2.4 on 2024-02-27 17:15

from django.db import migrations


class Migration(migrations.Migration):
    dependencies = [
        ("symbols", "0001_initial"),
    ]

    operations = [
        migrations.RenameModel(
            old_name="Symbols",
            new_name="Symbol",
        ),
    ]
