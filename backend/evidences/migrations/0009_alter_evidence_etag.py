# Generated by Django 5.1.1 on 2024-11-26 10:56

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("evidences", "0008_alter_evidence_etag"),
    ]

    operations = [
        migrations.AlterField(
            model_name="evidence",
            name="etag",
            field=models.CharField(max_length=256, unique=True),
        ),
    ]
