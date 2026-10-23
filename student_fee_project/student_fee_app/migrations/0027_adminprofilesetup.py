from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


def create_setup_states_for_existing_admins(apps, schema_editor):
    app_label, model_name = settings.AUTH_USER_MODEL.split(".")
    User = apps.get_model(app_label, model_name)
    AdminProfileSetup = apps.get_model("student_fee_app", "AdminProfileSetup")
    for user in User.objects.filter(is_superuser=True).iterator():
        AdminProfileSetup.objects.get_or_create(user_id=user.pk, defaults={"completed": False})


class Migration(migrations.Migration):
    dependencies = [
        ("student_fee_app", "0026_deletionaudit"),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name="AdminProfileSetup",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("completed", models.BooleanField(default=False)),
                ("user", models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, related_name="admin_profile_setup", to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.RunPython(create_setup_states_for_existing_admins, migrations.RunPython.noop),
    ]
