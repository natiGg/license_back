# Generated by Django 4.0.4 on 2022-09-21 16:50

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='school',
            name='profile_pic',
            field=models.ImageField(blank=True, null=True, upload_to='profiles/'),
        ),
        migrations.AddField(
            model_name='student',
            name='profile_pic',
            field=models.ImageField(blank=True, null=True, upload_to='profiles/'),
        ),
    ]