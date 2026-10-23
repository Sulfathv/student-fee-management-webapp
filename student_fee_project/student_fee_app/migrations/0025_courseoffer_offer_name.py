from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("student_fee_app", "0024_courseoffer_date_period"),
    ]

    operations = [
        migrations.AddField(
            model_name="courseoffer",
            name="offer_name",
            field=models.CharField(default="Global offer", max_length=100),
        ),
    ]
