from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("evidences", "0001_initial"),
    ]

    operations = [
        migrations.AddField(
            model_name="evidence",
            name="extraction_control",
            field=models.CharField(default="idle", max_length=20),
        ),
    ]
