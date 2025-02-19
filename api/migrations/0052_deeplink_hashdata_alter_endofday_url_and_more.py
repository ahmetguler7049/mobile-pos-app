# Generated by Django 4.0.7 on 2022-12-17 21:47

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0051_alter_mobiletransactionhistory_qrlink'),
    ]

    operations = [
        migrations.AddField(
            model_name='deeplink',
            name='hashData',
            field=models.TextField(blank=True, default='', verbose_name='hashData'),
        ),
        migrations.AlterField(
            model_name='endofday',
            name='url',
            field=models.TextField(blank=True, default='', verbose_name='URL'),
        ),
        migrations.AlterField(
            model_name='portalauthorize',
            name='access_token',
            field=models.TextField(blank=True, default='', verbose_name='access_token'),
        ),
        migrations.AlterField(
            model_name='posauthorize',
            name='Token',
            field=models.TextField(blank=True, default='', verbose_name='Token'),
        ),
    ]
