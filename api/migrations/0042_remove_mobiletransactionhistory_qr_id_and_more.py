# Generated by Django 4.0.7 on 2022-12-05 18:14

from django.db import migrations, models
import django.utils.timezone


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0041_mobiletransactionhistory_qr_id_and_more'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='mobiletransactionhistory',
            name='qr_id',
        ),
        migrations.AddField(
            model_name='deeplink',
            name='TransactionType',
            field=models.CharField(blank=True, choices=[('Sale', 'Sale'), ('Void', 'Void'), ('Refund', 'Refund')], default='Sale', max_length=10),
        ),
        migrations.AddField(
            model_name='mobiletransactionhistory',
            name='end_time',
            field=models.DateTimeField(blank=True, null=True, verbose_name='Bitiş'),
        ),
        migrations.AddField(
            model_name='mobiletransactionhistory',
            name='start_time',
            field=models.DateTimeField(blank=True, null=True, verbose_name='Başlangıç'),
        ),
        migrations.AddField(
            model_name='paymentsession',
            name='timestamp',
            field=models.DateTimeField(default=django.utils.timezone.now, verbose_name='Timestamp'),
        ),
        migrations.AddField(
            model_name='voidrefundsession',
            name='timestamp',
            field=models.DateTimeField(default=django.utils.timezone.now, verbose_name='Timestamp'),
        ),
        migrations.AlterField(
            model_name='paymentsession',
            name='TransactionType',
            field=models.CharField(blank=True, choices=[('Sale', 'Sale')], default='Sale', max_length=10),
        ),
        migrations.AlterField(
            model_name='voidrefundsession',
            name='TransactionType',
            field=models.CharField(blank=True, choices=[('Void', 'Void'), ('Refund', 'Refund')], default='Void', max_length=10),
        ),
    ]
