# Generated by Django 4.0.4 on 2022-09-21 16:54

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0002_school_profile_pic_student_profile_pic'),
    ]

    operations = [
        migrations.AlterField(
            model_name='school',
            name='profile_pic',
            field=models.ImageField(blank=True, null=True, upload_to='student_profiles/'),
        ),
        migrations.AlterField(
            model_name='student',
            name='profile_pic',
            field=models.ImageField(blank=True, null=True, upload_to='school_profiles/'),
        ),
        migrations.AlterModelTable(
            name='school',
            table='School',
        ),
        migrations.AlterModelTable(
            name='student',
            table='Student',
        ),
    ]