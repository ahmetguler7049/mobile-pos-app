# Generated by Django 4.0.7 on 2022-12-05 23:27

import django.core.validators
from django.db import migrations, models
import django.utils.timezone


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0043_mobiletransactionhistory_transactiontype'),
    ]

    operations = [
        migrations.CreateModel(
            name='DailyBalanceInfo',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('phone', models.CharField(blank=True, default='99999999999', max_length=11, validators=[django.core.validators.MinLengthValidator(11)], verbose_name='Telefon')),
                ('tckn', models.CharField(default='11111111111', max_length=11, validators=[django.core.validators.MinLengthValidator(11)], verbose_name='TC No')),
                ('balance', models.DecimalField(blank=True, decimal_places=2, default=0.0, max_digits=5, max_length=50, verbose_name='Bakiye')),
                ('timestamp', models.DateTimeField(default=django.utils.timezone.now, verbose_name='Timestamp')),
            ],
        ),
        migrations.AlterField(
            model_name='customuser',
            name='phone',
            field=models.CharField(max_length=11, unique=True, validators=[django.core.validators.MinLengthValidator(11)], verbose_name='Telefon'),
        ),
        migrations.AlterField(
            model_name='customuser',
            name='tckn',
            field=models.CharField(default='11111111111', max_length=11, validators=[django.core.validators.MinLengthValidator(11)], verbose_name='TC No'),
        ),
        migrations.AlterField(
            model_name='mobiletransactionhistory',
            name='phone',
            field=models.CharField(blank=True, default='99999999999', max_length=11, validators=[django.core.validators.MinLengthValidator(11)], verbose_name='Telefon'),
        ),
        migrations.AlterField(
            model_name='vehicles',
            name='phone',
            field=models.CharField(blank=True, default='99999999999', max_length=11, validators=[django.core.validators.MinLengthValidator(11)], verbose_name='Telefon'),
        ),
    ]
