# Generated by Django 4.0.7 on 2022-09-25 15:32

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0005_alter_serverstatus_status'),
    ]

    operations = [
        migrations.AddField(
            model_name='serverstatus',
            name='message',
            field=models.CharField(blank=True, default='', max_length=150),
        ),
    ]
