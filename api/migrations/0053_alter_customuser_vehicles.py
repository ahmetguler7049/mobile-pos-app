# Generated by Django 4.0.7 on 2022-12-20 21:07

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0052_deeplink_hashdata_alter_endofday_url_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='customuser',
            name='vehicles',
            field=models.ManyToManyField(blank=True, to='api.vehicles'),
        ),
    ]
