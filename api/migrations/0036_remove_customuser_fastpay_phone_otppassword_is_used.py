# Generated by Django 4.0.7 on 2022-11-24 20:29

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0035_portalauthorize_remove_posauthorize_access_token'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='customuser',
            name='fastpay_phone',
        ),
        migrations.AddField(
            model_name='otppassword',
            name='is_used',
            field=models.BooleanField(blank=True, default=False, verbose_name='is_used'),
        ),
    ]
