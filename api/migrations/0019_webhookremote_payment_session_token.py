# Generated by Django 4.0.7 on 2022-10-22 21:26

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0018_webhookremote'),
    ]

    operations = [
        migrations.AddField(
            model_name='webhookremote',
            name='payment_session_token',
            field=models.CharField(default='', max_length=16, verbose_name='Payment Session Token'),
        ),
    ]
