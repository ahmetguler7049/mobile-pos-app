# Generated by Django 4.0.7 on 2022-12-12 21:07

from django.db import migrations, models
import django.utils.timezone


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0046_endofday'),
    ]

    operations = [
        migrations.AddField(
            model_name='endofday',
            name='expires_at',
            field=models.DateTimeField(default=django.utils.timezone.now),
        ),
    ]
