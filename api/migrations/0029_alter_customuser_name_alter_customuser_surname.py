# Generated by Django 4.0.7 on 2022-11-12 22:35

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0028_alter_paymentsession_amount'),
    ]

    operations = [
        migrations.AlterField(
            model_name='customuser',
            name='name',
            field=models.CharField(blank=True, default='', max_length=50),
        ),
        migrations.AlterField(
            model_name='customuser',
            name='surname',
            field=models.CharField(blank=True, default='', max_length=50),
        ),
    ]
