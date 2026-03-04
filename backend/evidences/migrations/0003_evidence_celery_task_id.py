from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("evidences", "0002_evidence_extraction_control"),
    ]

    operations = [
        migrations.AddField(
            model_name="evidence",
            name="celery_task_id",
            field=models.CharField(blank=True, default="", max_length=255),
        ),
    ]
