# Generated by Django 4.2.4 on 2023-08-14 23:31

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='Case',
            fields=[
                ('case_id', models.AutoField(primary_key=True, serialize=False)),
                ('case_name', models.CharField(max_length=500)),
                ('case_description', models.TextField()),
                ('linked_users', models.ManyToManyField(to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.CreateModel(
            name='MemoryDump',
            fields=[
                ('dump_id', models.AutoField(primary_key=True, serialize=False)),
                ('dump_name', models.CharField(max_length=250)),
                ('dump_os', models.CharField(choices=[('Windows', 'Windows'), ('Linux', 'Linux')], max_length=10)),
                ('dump_linked_case', models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, to='main.case')),
            ],
        ),
        migrations.CreateModel(
            name='ImageSignature',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('md5', models.CharField(max_length=32, null=True)),
                ('sha1', models.CharField(max_length=40, null=True)),
                ('sha256', models.CharField(max_length=64, null=True)),
                ('investigation', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='main.case')),
            ],
        ),
    ]
