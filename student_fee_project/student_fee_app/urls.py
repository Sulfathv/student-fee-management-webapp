from django.contrib.auth.decorators import login_required
from django.urls import path
from . import views

fresh = views.fresh_page
protected = lambda view: fresh(login_required(view))
write_protected = lambda view: fresh(views.write_access_required(view))

urlpatterns = [
    path('', fresh(views.entry_view), name='entry'),
    path('signup/', fresh(views.signup_view), name='signup'),
    path('add-user/', protected(views.signup_view), name='add_user'),
    path('login/', fresh(views.login_view), name='login'),
    path('welcome-admin/', protected(views.admin_first_login_setup_view), name='admin_first_login_setup'),
    path('reset-password/', fresh(views.password_reset_view), name='password_reset'),
    path('security/totp/', protected(views.totp_setup_view), name='totp_setup'),
    path('home/', protected(views.home), name='home'),
    path('logout/', protected(views.logout_view), name='logout'),
    path('delete-account/', protected(views.delete_account_view), name='delete_account'),
    path('add/', write_protected(views.add), name='add'),
    path('addstudent/', write_protected(views.addstudent), name='addstudent'),
    path('students/', protected(views.StudentListView.as_view()), name='student_details'),
    path('courses/', protected(views.CourseListView.as_view()), name='course_details'),
    path('payment_form/', write_protected(views.payment), name='payment_form'),
    path('fees/', protected(views.FeeListView.as_view()), name='fee_details'),
    path('payment_details/<int:student_id>/', protected(views.PaymentDetailView.as_view()), name='payment_details'),
    path('addfee/', write_protected(views.addfee), name='addfee'),
    path('add_course/', write_protected(views.add_course), name='add_course'),
    path('get-student-courses/', protected(views.get_student_courses), name='get_student_courses'),
    path('editstudent/<int:student_id>/', write_protected(views.editstudent), name='editstudent'),
    path('editcourse/<int:course_id>/', write_protected(views.editcourse), name='editcourse'),
    path('students/<int:student_id>/delete/', write_protected(views.delete_student), name='delete_student'),
    path('courses/<int:course_id>/delete/', write_protected(views.delete_course), name='delete_course'),
    path('payments/<int:payment_id>/delete/', write_protected(views.delete_payment), name='delete_payment'),
    path('audit-log/', write_protected(views.DeletionAuditListView.as_view()), name='audit_log'),
    path('users/', write_protected(views.UserListView.as_view()), name='user_list'),
    path('users/<int:user_id>/delete/', write_protected(views.delete_user_account), name='delete_user_account'),
    path('search-students/', protected(views.search_students), name='search_students'),
    path('update-offer/', write_protected(views.update_offer), name='update_offer'),
]


