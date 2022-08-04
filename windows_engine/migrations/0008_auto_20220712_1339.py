# Generated by Django 3.2.13 on 2022-07-12 13:39

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('investigations', '0001_initial'),
        ('windows_engine', '0007_auto_20220707_2021'),
    ]

    operations = [
        migrations.AlterField(
            model_name='cmdline',
            name='PID',
            field=models.IntegerField(null=True),
        ),
        migrations.AlterField(
            model_name='envars',
            name='PID',
            field=models.IntegerField(null=True),
        ),
        migrations.AlterField(
            model_name='malfind',
            name='PID',
            field=models.IntegerField(null=True),
        ),
        migrations.AlterField(
            model_name='netscan',
            name='PID',
            field=models.IntegerField(null=True),
        ),
        migrations.AlterField(
            model_name='netstat',
            name='PID',
            field=models.IntegerField(null=True),
        ),
        migrations.AlterField(
            model_name='privs',
            name='PID',
            field=models.IntegerField(null=True),
        ),
        migrations.AlterField(
            model_name='psscan',
            name='Handles',
            field=models.IntegerField(null=True),
        ),
        migrations.AlterField(
            model_name='psscan',
            name='PID',
            field=models.IntegerField(null=True),
        ),
        migrations.AlterField(
            model_name='psscan',
            name='PPID',
            field=models.IntegerField(null=True),
        ),
        migrations.AlterField(
            model_name='psscan',
            name='Threads',
            field=models.IntegerField(null=True),
        ),
        migrations.AlterField(
            model_name='skeletonkeycheck',
            name='PID',
            field=models.IntegerField(null=True),
        ),
        migrations.CreateModel(
            name='Handles',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('PID', models.IntegerField()),
                ('Offset', models.BigIntegerField()),
                ('Name', models.TextField(null=True)),
                ('HandleValue', models.IntegerField()),
                ('GrantedAccess', models.BigIntegerField()),
                ('Type', models.CharField(max_length=255)),
                ('investigation', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='windows_handles_investigation', to='investigations.uploadinvestigation')),
            ],
        ),
        migrations.CreateModel(
            name='DllList',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('PID', models.IntegerField()),
                ('Base', models.BigIntegerField()),
                ('Name', models.TextField()),
                ('Path', models.TextField()),
                ('Size', models.BigIntegerField()),
                ('LoadTime', models.CharField(max_length=255, null=True)),
                ('File_output', models.CharField(max_length=500)),
                ('investigation', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='windows_dllist_investigation', to='investigations.uploadinvestigation')),
            ],
        ),
    ]