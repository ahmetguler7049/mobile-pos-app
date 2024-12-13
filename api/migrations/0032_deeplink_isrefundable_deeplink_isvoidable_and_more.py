# Generated by Django 4.0.7 on 2022-11-14 22:16

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0031_remove_mobiletransactionhistory_orderid_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='deeplink',
            name='IsRefundable',
            field=models.BooleanField(blank=True, null=True, verbose_name='IsRefundable'),
        ),
        migrations.AddField(
            model_name='deeplink',
            name='IsVoidable',
            field=models.BooleanField(blank=True, null=True, verbose_name='IsVoidable'),
        ),
        migrations.CreateModel(
            name='VoidRefundSession',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('OrderID', models.CharField(blank=True, default='', editable=False, max_length=40)),
                ('TransactionType', models.CharField(blank=True, default='', max_length=10)),
                ('payment_session', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, to='api.paymentsession', verbose_name='Payment Session')),
            ],
        ),
    ]
