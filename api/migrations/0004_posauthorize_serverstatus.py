# Generated by Django 4.0.7 on 2022-09-25 15:22

from django.db import migrations, models
import django.utils.timezone


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0003_rename_password_otppassword_verification_code'),
    ]

    operations = [
        migrations.CreateModel(
            name='PosAuthorize',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('Token', models.CharField(blank=True, default='', max_length=1006)),
                ('created', models.DateTimeField(default=django.utils.timezone.now)),
            ],
        ),
        migrations.CreateModel(
            name='ServerStatus',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('version', models.CharField(blank=True, default='', max_length=50)),
                ('status', models.CharField(blank=True, default='', max_length=50)),
                ('created_at', models.DateTimeField(default=django.utils.timezone.now)),
            ],
        ),
    ]
