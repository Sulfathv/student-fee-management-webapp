from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("student_fee_app", "0023_alter_enrollment_enrollment_date"),
    ]

    operations = [
        migrations.AddField(
            model_name="courseoffer",
            name="start_date",
            field=models.DateField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name="courseoffer",
            name="end_date",
            field=models.DateField(blank=True, null=True),
        ),
    ]
