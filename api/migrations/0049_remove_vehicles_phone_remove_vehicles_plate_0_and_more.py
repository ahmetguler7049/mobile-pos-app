# Generated by Django 4.0.7 on 2022-12-15 19:18

from django.db import migrations, models
import django.utils.timezone


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0048_remove_customuser_plate_numbers'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='vehicles',
            name='phone',
        ),
        migrations.RemoveField(
            model_name='vehicles',
            name='plate_0',
        ),
        migrations.RemoveField(
            model_name='vehicles',
            name='plate_1',
        ),
        migrations.RemoveField(
            model_name='vehicles',
            name='plate_2',
        ),
        migrations.RemoveField(
            model_name='vehicles',
            name='plate_3',
        ),
        migrations.RemoveField(
            model_name='vehicles',
            name='plate_4',
        ),
        migrations.RemoveField(
            model_name='vehicles',
            name='plate_5',
        ),
        migrations.RemoveField(
            model_name='vehicles',
            name='plate_6',
        ),
        migrations.RemoveField(
            model_name='vehicles',
            name='plate_7',
        ),
        migrations.RemoveField(
            model_name='vehicles',
            name='plate_8',
        ),
        migrations.RemoveField(
            model_name='vehicles',
            name='plate_9',
        ),
        migrations.AddField(
            model_name='customuser',
            name='vehicles',
            field=models.ManyToManyField(null=True, to='api.vehicles'),
        ),
        migrations.AddField(
            model_name='vehicles',
            name='plate',
            field=models.CharField(blank=True, default='', max_length=8),
        ),
        migrations.AddField(
            model_name='vehicles',
            name='timestamp',
            field=models.DateTimeField(default=django.utils.timezone.now, verbose_name='Timestamp'),
        ),
    ]
