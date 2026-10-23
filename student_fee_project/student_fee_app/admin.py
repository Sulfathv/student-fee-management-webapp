from django.contrib import admin
from .models import Student_details, Course, Fee, Payment

# Register your models here.
admin.site.register(Student_details)
admin.site.register(Course)
admin.site.register(Fee)
admin.site.register(Payment)
