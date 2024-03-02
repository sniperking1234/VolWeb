# Generated by Django 4.2.4 on 2024-02-27 16:42

from django.db import migrations, models


class Migration(migrations.Migration):
    initial = True

    dependencies = []

    operations = [
        migrations.CreateModel(
            name="Symbols",
            fields=[
                ("id", models.AutoField(primary_key=True, serialize=False)),
                ("name", models.CharField(max_length=100)),
                (
                    "os",
                    models.CharField(
                        choices=[("Windows", "Windows"), ("Linux", "Linux")],
                        max_length=50,
                    ),
                ),
                ("description", models.TextField(max_length=500)),
                ("symbols_file", models.FileField(upload_to="symbols/uploads")),
            ],
        ),
    ]
