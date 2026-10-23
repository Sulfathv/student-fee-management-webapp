from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    dependencies = [
        ("student_fee_app", "0025_usertotp"),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name="DeletionAudit",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("actor_username", models.CharField(max_length=150)),
                ("object_type", models.CharField(max_length=80)),
                ("object_id", models.CharField(max_length=80)),
                ("object_label", models.CharField(max_length=255)),
                ("reason", models.TextField()),
                ("deleted_at", models.DateTimeField(auto_now_add=True)),
                ("actor", models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name="deletion_audits", to=settings.AUTH_USER_MODEL)),
            ],
            options={
                "ordering": ["-deleted_at", "-id"],
            },
        ),
    ]
