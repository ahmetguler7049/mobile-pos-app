# Generated by Django 4.0.7 on 2022-12-17 18:50

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0050_alter_customuser_vehicles_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='mobiletransactionhistory',
            name='QRLink',
            field=models.URLField(blank=True, default='https://banapos.com/qr/?', verbose_name='QRLink'),
        ),
    ]
