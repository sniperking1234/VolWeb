# Generated by Django 4.2.11 on 2024-06-05 17:03

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('evidences', '0004_evidence_dump_endpoint_evidence_dump_region'),
        ('windows_engine', '0005_thrdscan'),
    ]

    operations = [
        migrations.CreateModel(
            name='DriverIrp',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('artefacts', models.JSONField(null=True)),
                ('evidence', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='windows_driverirp_evidence', to='evidences.evidence')),
            ],
        ),
    ]
