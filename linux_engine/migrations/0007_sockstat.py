# Generated by Django 4.2.4 on 2024-03-03 17:27

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    dependencies = [
        ("evidences", "0005_delete_imagesignature"),
        ("linux_engine", "0006_elfs"),
    ]

    operations = [
        migrations.CreateModel(
            name="Sockstat",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("artefacts", models.JSONField(null=True)),
                (
                    "evidence",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="linux_sockstat_evidence",
                        to="evidences.evidence",
                    ),
                ),
            ],
        ),
    ]
