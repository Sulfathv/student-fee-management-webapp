from django.conf import settings
from django.db import models

# Create your models here.

class Course(models.Model):
    c_reg = models.CharField(max_length=20,unique=True,null=True, blank=True)
    course_id = models.AutoField(primary_key=True)
    course_name = models.CharField(max_length=100)
    duration = models.IntegerField()
    course_fee = models.DecimalField(max_digits=10, decimal_places=2)
    division = models.CharField(max_length=20, null=True, blank=True)

    def __str__(self):
        return self.c_reg
class Student_details(models.Model):
    student_reg = models.CharField(max_length=20, unique=True,null=True, blank=True)
    student_id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=100)
    phone = models.CharField(max_length=15)
    course_id = models.ForeignKey(Course, on_delete=models.CASCADE, null=True, blank=True)
    course_fee = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        default=0
    )
    down_payment = models.DecimalField(
            max_digits=10,
            decimal_places=2,
            default=0
        )
    remaining_amount = models.DecimalField(
    max_digits=10,
    decimal_places=2,
    default=0
)
    
    installment= models.IntegerField(default=0)
    division = models.CharField(max_length=10, null=True, blank=True)
    status = models.CharField(max_length=20,default="pending")

    def __str__(self):
        return self.name
class Enrollment(models.Model):
    student = models.ForeignKey(Student_details, on_delete=models.CASCADE)
    course = models.ForeignKey(Course, on_delete=models.CASCADE)
    enrollment_date = models.DateField( null=True, blank=True, default=None)
    down_payment = models.DecimalField(max_digits=10, decimal_places=2, default=0)
    installment = models.IntegerField()
    division = models.CharField(max_length=20, blank=True)
    status = models.CharField(max_length=20, default="pending")
    def __str__(self):
        return f"{self.student.name} - {self.course.course_name}"

class Fee(models.Model):
    fee_id = models.AutoField(primary_key=True)

    enrollment = models.ForeignKey(
    Enrollment,
    on_delete=models.CASCADE,
    related_name="fees",
    null=True,
    blank=True
     )

    total_fee = models.DecimalField(
        max_digits=10,
        decimal_places=2
    )

    due_date = models.DateField(
        null=True,
        blank=True
    )

    payment_date = models.DateField(
        null=True,
        blank=True
    )

    amount = models.DecimalField(
        max_digits=10,
        decimal_places=2
    )

    balance = models.DecimalField(
        max_digits=10,
        decimal_places=2
    )
    installment_number = models.IntegerField(
        null=True,
        blank=True
    )

    def __str__(self):
        return str(self.fee_id)


    
class Payment(models.Model):

    enrollment = models.ForeignKey(
    Enrollment,
    on_delete=models.CASCADE,
    related_name="payments",
    null=True,
    blank=True
)
    payment_date = models.DateField()

    payment_amount = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        default=0
    )

    payment_type = models.CharField(
        max_length=20,
        default="Installment"
    )

    installment_number = models.IntegerField(
        null=True,
        blank=True
    )
    def __str__(self):
      if self.enrollment:
        return f"Payment for {self.enrollment.student.name} on {self.payment_date}"
      return f"Payment on {self.payment_date}"


class CourseOffer(models.Model):
    offer_name = models.CharField(max_length=100, default="Global offer")
    offer_value = models.DecimalField(
        max_digits=5,
        decimal_places=2,
        default=0
    )

    is_active = models.BooleanField(
        default=True
    )

    start_date = models.DateField(null=True, blank=True)
    end_date = models.DateField(null=True, blank=True)

    @property
    def is_currently_active(self):
        from django.utils import timezone

        today = timezone.localdate()
        return (
            self.is_active
            and (self.start_date is None or self.start_date <= today)
            and (self.end_date is None or self.end_date >= today)
        )

    def __str__(self):
        return f"{self.offer_name}: {self.offer_value}%"

    

class UserTOTP(models.Model):
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="totp_settings")
    secret = models.CharField(max_length=64)
    enabled = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"TOTP settings for {self.user.username}"


class DeletionAudit(models.Model):
    actor = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="deletion_audits",
    )
    actor_username = models.CharField(max_length=150)
    object_type = models.CharField(max_length=80)
    object_id = models.CharField(max_length=80)
    object_label = models.CharField(max_length=255)
    reason = models.TextField()
    deleted_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-deleted_at", "-id"]

    def __str__(self):
        return f"{self.object_type} {self.object_label} deleted by {self.actor_username}"


class AdminProfileSetup(models.Model):
    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="admin_profile_setup",
    )
    completed = models.BooleanField(default=False)

    def __str__(self):
        return f"Administrator setup for {self.user.get_username()}"

