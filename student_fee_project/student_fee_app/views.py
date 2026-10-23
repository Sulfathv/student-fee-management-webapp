from django.contrib.auth import authenticate, login, logout, get_user_model, update_session_auth_hash
from django.contrib.auth.decorators import login_required
from django.views.decorators.csrf import ensure_csrf_cookie
from django.views.decorators.cache import never_cache
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.db import IntegrityError

from decimal import Decimal, InvalidOperation
import base64
import hashlib
import hmac
import secrets
import struct
import time
from urllib.parse import quote
from django.core.paginator import Paginator
from django.db import transaction
from django.db.models.aggregates import Max, Sum
from django.db.models.expressions import OuterRef, Subquery
from django.forms import models
from django.shortcuts import redirect, render,get_object_or_404
from django.http import HttpResponse, HttpResponseForbidden, JsonResponse
from django.template import context
from .models import Course, Payment, Student_details, Fee, Enrollment, CourseOffer, UserTOTP, DeletionAudit, AdminProfileSetup
from django .views import View
from django. views.generic import ListView, DetailView
from django.db.models import Count,Q
from datetime import date, timedelta
from django.http import JsonResponse
from dateutil.relativedelta import relativedelta
from django.contrib import messages
from calendar import monthrange
from functools import wraps

def generate_totp_secret():
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")

def totp_code(secret, timestamp=None):
    timestamp = time.time() if timestamp is None else timestamp
    key = base64.b32decode(secret + "=" * ((8 - len(secret) % 8) % 8), casefold=True)
    counter = int(timestamp // 30)
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return f"{value % 1_000_000:06d}"

def verify_totp(secret, code, timestamp=None):
    timestamp = time.time() if timestamp is None else timestamp
    if not code or len(code) != 6 or not code.isdigit():
        return False
    return any(hmac.compare_digest(totp_code(secret, timestamp + offset * 30), code) for offset in (-1, 0, 1))

def admin_profile_setup_required(user):
    if not user.is_superuser:
        return False
    setup, _ = AdminProfileSetup.objects.get_or_create(user=user)
    return not setup.completed
def fresh_page(view_func):
    return never_cache(ensure_csrf_cookie(view_func))

def entry_view(request):
    if request.user.is_authenticated:
        return redirect('home')
    if not get_user_model().objects.exists():
        return redirect('signup')
    return redirect('login')

@ensure_csrf_cookie
@never_cache
def signup_view(request):
    if request.user.is_authenticated:
        return redirect('home')
    User = get_user_model()
    if User.objects.exists():
        return redirect('login')
    if request.method == 'POST':
        username = request.POST.get('username', '').strip()
        password = request.POST.get('password', '')
        confirmation = request.POST.get('confirm_password', '')
        errors = []
        if not all((username, password, confirmation)):
            errors.append('Enter a username, password, and password confirmation.')
        if password != confirmation:
            errors.append('The passwords do not match.')
        if User.objects.filter(username__iexact=username).exists():
            errors.append('That username is already in use.')
        candidate = User(username=username, is_staff=True, is_superuser=True)
        try:
            validate_password(password, candidate)
        except ValidationError as exc:
            errors.extend(exc.messages)
        if not errors:
            try:
                with transaction.atomic():
                    if User.objects.exists():
                        errors.append('An administrator account has already been created. Please log in.')
                    else:
                        candidate.set_password(password)
                        candidate.save()
            except IntegrityError:
                errors.append('That username is already in use.')
            if not errors:
                messages.success(request, 'The first account was created as Administrator.')
                return redirect('home' if request.user.is_authenticated else 'login')
        return render(request, 'signup.html', {
            'errors': errors, 'username': username,
        })
    return render(request, 'signup.html')
def write_access_required(view_func):
    @wraps(view_func)
    def _wrapped(request, *args, **kwargs):
        if not request.user.is_authenticated:
            return redirect('login')
        if not request.user.is_superuser:
            return HttpResponseForbidden('This account has read-only access.')
        return view_func(request, *args, **kwargs)
    return _wrapped
@ensure_csrf_cookie
@never_cache
def password_reset_view(request):
    is_authenticated = request.user.is_authenticated
    if request.method == 'POST':
        username = request.user.username if is_authenticated else request.POST.get('username', '').strip()
        password = request.POST.get('new_password', '')
        confirmation = request.POST.get('confirm_new_password', '')
        totp_code_value = request.POST.get('totp_code', '').strip()
        user = request.user if is_authenticated else get_user_model().objects.filter(username__iexact=username).first()
        errors = []
        if user and not user.is_superuser:
            errors.append('Invalid username or password.')
        if not all((username, password, confirmation)):
            errors.append('Complete all fields to reset your password.')
        if user is None:
            errors.append('No account was found for that username.')
        if password != confirmation:
            errors.append('The passwords do not match.')
        totp = UserTOTP.objects.filter(user=user, enabled=True).first() if user else None
        if user and not is_authenticated and not totp:
            errors.append('Password recovery is unavailable until an administrator authenticator is configured.')
        elif totp and not verify_totp(totp.secret, totp_code_value):
            errors.append('Enter a valid current authenticator code to reset this password.')
        if user and password:
            try:
                validate_password(password, user)
            except ValidationError as exc:
                errors.extend(exc.messages)
        if not errors:
            user.set_password(password)
            user.save(update_fields=['password'])
            if is_authenticated:
                logout(request)
            messages.success(request, 'Your password was updated. Please log in.')
            return redirect('login')
        return render(request, 'password_reset.html', {
            'errors': errors, 'username': username, 'totp_required': bool(totp),
        })
    return render(request, 'password_reset.html', {
        'username': request.user.username if is_authenticated else '',
    })
@ensure_csrf_cookie
@never_cache
def login_view(request):
    pending_user_id = request.session.get('pending_totp_user_id')
    if request.method == 'GET' and request.GET.get('cancel_totp') == '1':
        request.session.pop('pending_totp_user_id', None)
        pending_user_id = None
    if request.user.is_authenticated:
        if request.session.get('needs_admin_first_login_setup'):
            return redirect('admin_first_login_setup')
        return redirect('home')
    if request.method == 'POST' and pending_user_id:
        user = get_user_model().objects.filter(pk=pending_user_id, is_active=True).first()
        if not user or not user.is_superuser:
            request.session.pop('pending_totp_user_id', None)
            return render(request, 'login.html', {'error_message': 'Invalid username or password.'})
        totp = UserTOTP.objects.filter(user=user, enabled=True).first() if user else None
        code = request.POST.get('totp_code', '').strip()
        if user and totp and verify_totp(totp.secret, code):
            request.session.pop('pending_totp_user_id', None)
            needs_setup = admin_profile_setup_required(user)
            login(request, user)
            if needs_setup:
                request.session['needs_admin_first_login_setup'] = True
                return redirect('admin_first_login_setup')
            return redirect('home')
        return render(request, 'login.html', {
            'requires_totp': True,
            'username': user.username if user else '',
            'error_message': 'The authenticator code is invalid. Try the current code from your app.',
        })
    if request.method == 'POST':
        username = request.POST.get('username', '').strip()
        password = request.POST.get('password', '')
        user = authenticate(request, username=username, password=password)
        if user is not None and not user.is_superuser:
            user = None
        if user is not None:
            totp = UserTOTP.objects.filter(user=user, enabled=True).first()
            if totp:
                request.session['pending_totp_user_id'] = user.pk
                return render(request, 'login.html', {'requires_totp': True, 'username': user.username})
            needs_setup = admin_profile_setup_required(user)
            login(request, user)
            if needs_setup:
                request.session['needs_admin_first_login_setup'] = True
                return redirect('admin_first_login_setup')
            return redirect('home')
        return render(request, 'login.html', {'error_message': 'Invalid username or password.'})
    if pending_user_id:
        user = get_user_model().objects.filter(pk=pending_user_id).first()
        if user and user.is_superuser:
            return render(request, 'login.html', {'requires_totp': True, 'username': user.username})
        request.session.pop('pending_totp_user_id', None)
    return render(request, 'login.html')


@ensure_csrf_cookie
@never_cache
@login_required
def admin_first_login_setup_view(request):
    if not request.user.is_superuser or not request.session.get('needs_admin_first_login_setup'):
        return redirect('home')

    user = request.user
    setup, _ = AdminProfileSetup.objects.get_or_create(user=user)
    if setup.completed:
        request.session.pop('needs_admin_first_login_setup', None)
        return redirect('home')
    username = user.username
    errors = []

    if request.method == 'POST':
        username = request.POST.get('username', '').strip()
        password = request.POST.get('password', '')
        confirmation = request.POST.get('confirm_password', '')
        User = get_user_model()
        candidate = User(username=username)

        if not all((username, password, confirmation)):
            errors.append('Enter a username, password, and password confirmation to finish administrator setup.')
        if password != confirmation:
            errors.append('The passwords do not match.')
        if username and username.casefold() == user.username.casefold():
            errors.append('Choose a new username to replace your initial sign-in username.')
        if User.objects.filter(username__iexact=username).exclude(pk=user.pk).exists():
            errors.append('That username is already in use.')
        try:
            User._meta.get_field('username').clean(username, candidate)
        except ValidationError as exc:
            errors.extend(exc.messages)
        if password:
            if user.check_password(password):
                errors.append('Choose a new password to replace your initial sign-in password.')
            try:
                validate_password(password, candidate)
            except ValidationError as exc:
                errors.extend(exc.messages)

        if not errors:
            user.username = username
            user.set_password(password)
            user.save(update_fields=['username', 'password'])
            setup.completed = True
            setup.save(update_fields=['completed'])
            update_session_auth_hash(request, user)
            request.session.pop('needs_admin_first_login_setup', None)
            messages.success(request, 'Administrator account details were updated.')
            return redirect('home')

    return render(request, 'admin_first_login_setup.html', {
        'username': username,
        'errors': errors,
    })
@login_required
def totp_setup_view(request):
    totp, _ = UserTOTP.objects.get_or_create(
        user=request.user,
        defaults={"secret": generate_totp_secret()},
    )
    errors = []
    if request.method == 'POST':
        code = request.POST.get('totp_code', '').strip()
        if totp.enabled:
            return redirect('home')
        if verify_totp(totp.secret, code):
            totp.enabled = True
            totp.save(update_fields=['enabled'])
            messages.success(request, 'TOTP two-factor sign-in is enabled.')
            return redirect('home')
        else:
            errors.append('The code did not match. Check that your phone date and time are set automatically, wait for a fresh six-digit code, and use the QR code or secret key currently shown here.')
    provisioning_uri = ''
    if not totp.enabled:
        issuer = "Fee Management"
        label = quote(issuer + ": " + request.user.username, safe="")
        provisioning_uri = f"otpauth://totp/{label}?secret={totp.secret}&issuer={quote(issuer, safe='')}&algorithm=SHA1&digits=6&period=30"
    return render(request, 'totp_setup.html', {
        'totp_enabled': totp.enabled,
        'totp_secret': totp.secret if not totp.enabled else '',
        'provisioning_uri': provisioning_uri,
        'errors': errors,
    })
@login_required
def delete_account_view(request):
    if request.method == 'POST':
        user = request.user
        if user.is_superuser:
            messages.error(request, 'Administrator accounts cannot be deleted here.')
            return redirect('home')
        reason, valid = get_deletion_credentials(request)
        if not valid:
            return redirect('home')
        with transaction.atomic():
            audit_entries = [DeletionAudit(
                actor=user,
                actor_username=user.get_username(),
                object_type="User account",
                object_id=str(user.pk),
                object_label=user.get_username(),
                reason=reason,
            )]
            if UserTOTP.objects.filter(user=user).exists():
                audit_entries.append(DeletionAudit(
                    actor=user,
                    actor_username=user.get_username(),
                    object_type="Authenticator settings",
                    object_id=str(user.pk),
                    object_label=f"TOTP settings for {user.get_username()}",
                    reason=reason,
                ))
            if AdminProfileSetup.objects.filter(user=user).exists():
                audit_entries.append(DeletionAudit(
                    actor=user,
                    actor_username=user.get_username(),
                    object_type="Administrator setup record",
                    object_id=str(user.pk),
                    object_label=f"Administrator setup for {user.get_username()}",
                    reason=reason,
                ))
            DeletionAudit.objects.bulk_create(audit_entries)
            user.delete()
        logout(request)
        messages.success(request, 'Your account has been deleted.')
        return redirect('login')
    return redirect('home')


@login_required
def delete_user_account(request, user_id):
    if request.method != 'POST':
        return redirect('user_list')
    target = get_object_or_404(get_user_model(), pk=user_id)
    if target.pk == request.user.pk or target.is_superuser or target.is_staff:
        messages.error(request, 'This account cannot be deleted from the user list.')
        return redirect('user_list')
    password = request.POST.get('deletion_password', '')
    if not password or not request.user.check_password(password):
        messages.error(request, 'The password is incorrect. The user account was not deleted.')
        return redirect('user_list')
    with transaction.atomic():
        audit_entries = [DeletionAudit(
            actor=request.user,
            actor_username=request.user.get_username(),
            object_type='User account',
            object_id=str(target.pk),
            object_label=target.get_username(),
            reason='',
        )]
        if UserTOTP.objects.filter(user=target).exists():
            audit_entries.append(DeletionAudit(
                actor=request.user,
                actor_username=request.user.get_username(),
                object_type='Authenticator settings',
                object_id=str(target.pk),
                object_label=f'TOTP settings for {target.get_username()}',
                reason='',
            ))
        DeletionAudit.objects.bulk_create(audit_entries)
        target.delete()
    messages.success(request, f'User account “{target.get_username()}” was deleted.')
    return redirect('user_list')

@login_required
def logout_view(request):
    if request.method != 'POST':
        return redirect('home')
    logout(request)
    return redirect('login')  # Redirect to the login page after logout


def get_deletion_credentials(request):
    reason = request.POST.get('deletion_reason', '').strip()
    password = request.POST.get('deletion_password', '')
    if not reason:
        messages.error(request, 'Enter a reason before deleting this record.')
        return '', False
    if not password or not request.user.check_password(password):
        messages.error(request, 'The password is incorrect. Nothing was deleted.')
        return '', False
    return reason, True

@login_required
def home(request):

    total_students = Student_details.objects.count()
    students = Student_details.objects.all()

    # ---------------------------------------------
    # SELECTED MONTH
    # ---------------------------------------------

    selected_month = request.GET.get("month", "").strip()
    current_year = date.today().year
    valid_month_values = {f"{current_year}-{month:02d}" for month in range(1, 13)}
    if selected_month not in valid_month_values:
        selected_month = ""

    payment_queryset = Payment.objects.all()

    pending_fee_queryset = Fee.objects.filter(
        installment_number__isnull=False,
        balance__gt=0
    )

    # ---------------------------------------------
    # MONTH FILTER
    # ---------------------------------------------

    if selected_month:

        try:
            year, month = map(
                int,
                selected_month.split("-")
            )

            payment_queryset = Payment.objects.filter(
                payment_date__year=year,
                payment_date__month=month
            )

            pending_fee_queryset = Fee.objects.filter(
                installment_number__isnull=False,
                due_date__year=year,
                due_date__month=month,
                balance__gt=0
            )

        except (ValueError, TypeError):

            selected_month = ""
            payment_queryset = Payment.objects.all()
            pending_fee_queryset = Fee.objects.filter(
                installment_number__isnull=False,
                balance__gt=0
            )
    #students who have spenging in the selected month
    # 
    pending_fee_rows = pending_fee_queryset.values(
        "enrollment__student__name",
        "enrollment__student__student_reg",
        "enrollment__course__course_name",
        "installment_number",
        "due_date",
        "balance"
    ).order_by("due_date", "enrollment_id", "installment_number")
    page_obj = Paginator(pending_fee_rows, 25).get_page(request.GET.get("page"))
    today = date.today()
    for row in page_obj.object_list:
        due_date = row["due_date"]
        if due_date is None:
            row["due_status"] = "Date not set"
            row["due_status_class"] = "unknown"
        elif due_date < today:
            row["due_status"] = "Overdue"
            row["due_status_class"] = "overdue"
        elif due_date <= today + timedelta(days=30):
            row["due_status"] = "Due soon"
            row["due_status_class"] = "soon"
        else:
            row["due_status"] = "Upcoming"
            row["due_status_class"] = "upcoming"
    # ---------------------------------------------
    # TOTAL FEES
    # ---------------------------------------------

    course_fee_rows = Fee.objects.values(
        "enrollment_id"
    ).annotate(
        course_total=Max("total_fee")
    )

    total_fees = sum(
        row["course_total"] or Decimal("0")
        for row in course_fee_rows
    )

    # ---------------------------------------------
    # COLLECTED FEES
    # ---------------------------------------------

    collected_fees = payment_queryset.aggregate(
        total=Sum("payment_amount")
    )["total"] or Decimal("0")
    all_collected_fees = Payment.objects.aggregate(
        total=Sum("payment_amount")
    )["total"] or Decimal("0")
    collection_rate = (
        (all_collected_fees / total_fees * Decimal("100")).quantize(Decimal("0.1"))
        if total_fees else Decimal("0.0")
    )
    collection_rate = min(max(collection_rate, Decimal("0.0")), Decimal("100.0"))

    # ---------------------------------------------
    # PENDING FEES
    # ---------------------------------------------
    if not selected_month:
        pending_fees = total_fees - all_collected_fees
    else:
        pending_fees = pending_fee_queryset.aggregate(
            total=Sum("balance")
        )["total"] or Decimal("0")
    pending_fees = max(pending_fees, Decimal("0"))
    overdue_fees = pending_fee_queryset.filter(
        due_date__lt=date.today()
    ).aggregate(total=Sum("balance"))["total"] or Decimal("0")
    overdue_installments = pending_fee_queryset.filter(
        due_date__lt=date.today()
    ).count()
    # ---------------------------------------------
    # HOME PAGE TRANSACTIONS
    #
    # ONE ROW PER ENROLLMENT
    # ONLY LATEST PAYMENT
    # ---------------------------------------------

    latest_payment_id = Payment.objects.filter(
        enrollment_id=OuterRef("enrollment_id")
    ).order_by(
        "-payment_date",
        "-id"
    ).values("id")[:1]

    latest_payments = list(
    Payment.objects.filter(
        id=Subquery(latest_payment_id)
    ).select_related(
        "enrollment__student",
        "enrollment__course"
    ).order_by(
        "-payment_date",
        "-id"
    )
)

    for payment in latest_payments:

     enrollment = payment.enrollment

    # Course total fee
     total_fee = Fee.objects.filter(
        enrollment=enrollment
     ).values_list(
        "total_fee",
        flat=True
     ).first() or Decimal("0")

    # Total amount paid for this enrollment
     total_paid = Payment.objects.filter(
        enrollment=enrollment
     ).aggregate(
        total=Sum("payment_amount")
     )["total"] or Decimal("0")

    # Balance after latest payment
     payment.home_balance = total_fee - total_paid

     if payment.home_balance < Decimal("0"):
        payment.home_balance = Decimal("0")
     payment.home_due_date = Fee.objects.filter(
        enrollment=enrollment,
        installment_number=payment.installment_number
     ).values_list(
        "due_date",
        flat=True
     ).first()
    # ---------------------------------------------
    # MONTH DROPDOWN
    # ---------------------------------------------
    months = []
    for month in range(1, 13):
        month_value = f"{current_year}-{month:02d}"
        month_name = date(current_year, month, 1).strftime("%B %Y")
        months.append((month_value, month_name))
    selected_month_label = dict(months).get(selected_month, "")
    # ---------------------------------------------
    # RETURN
    # ---------------------------------------------

    return render(
        request,
        "home.html",
        {
            "total_students": total_students,
            "total_fees": total_fees,
            "pending_fees": pending_fees,
            "overdue_fees": overdue_fees,
            "overdue_installments": overdue_installments,
            "collected_fees": collected_fees,
            "all_collected_fees": all_collected_fees,
            "collection_rate": collection_rate,

            # IMPORTANT
            "latest_payments": latest_payments,

            "students": students,
            "months": months,
            "selected_month": selected_month,
            "selected_month_label": selected_month_label,
            "pending_fee_rows": page_obj.object_list,
            "page_obj": page_obj,
        }
    )
def add(request):
    return render(request, "add_student.html")


def addstudent(request):

    courses = Course.objects.all()

    # Active common offer
    offer = CourseOffer.objects.first()
    if offer and not offer.is_currently_active:
        offer = None

    # Show discounted fee in Add Student form
    for c in courses:

        if offer:
            discount = (
                c.course_fee * offer.offer_value
            ) / Decimal("100")

            c.final_fee = c.course_fee - discount

        else:
            c.final_fee = c.course_fee

    if request.method == "POST":

        student_reg = request.POST.get("student_reg")
        
        name = request.POST.get("name")
        phone = request.POST.get("phone")
        course_id = request.POST.get("course_id")
        division = request.POST.get("division")

        down_payment = Decimal(
            request.POST.get("down_payment") or "0"
        )

        payment_date = request.POST.get("payment_date")

        # ---------------------------------
        # SELECT COURSE
        # ---------------------------------

        course = Course.objects.get(
            course_id=course_id
        )

        # ---------------------------------
        # COURSE FEE + OFFER
        # ---------------------------------

        original_course_fee = course.course_fee

        if offer:
            discount = (
                original_course_fee * offer.offer_value
            ) / Decimal("100")

            course_fee = original_course_fee - discount

        else:
            course_fee = original_course_fee

        # ---------------------------------
        # INSTALLMENT COUNT
        # ---------------------------------

        installment = course.duration

        # ---------------------------------
        # BALANCE AFTER DOWN PAYMENT
        # ---------------------------------

        balance = course_fee - down_payment

        if balance <= 0:
            balance = Decimal("0")
            status = "Paid"
        else:
            status = "Pending"

        # ---------------------------------
        # CREATE STUDENT
        # ---------------------------------

        student = Student_details.objects.create(
            student_reg=student_reg,
            
            name=name,
            phone=phone,
            course_id=course,
            course_fee=course_fee,
            down_payment=down_payment,
            remaining_amount=balance,
            installment=installment,
            division=division,
            status=status
        )

        # ---------------------------------
        # CREATE ENROLLMENT
        # ---------------------------------

        if payment_date:
            joining_date = date.fromisoformat(payment_date)
        else:
            joining_date = date.today()
        

        enrollment = Enrollment.objects.create(
            student=student,
            course=course,
            enrollment_date=joining_date,
            down_payment=down_payment,
            installment=installment,
            division=division,
            status=status
        )

        # ---------------------------------
        # INSTALLMENT AMOUNT
        # ---------------------------------

        if installment > 0:
            installment_amount = (
                balance / Decimal(installment)
            ).quantize(Decimal("0.01"))
        else:
            installment_amount = Decimal("0.00")

        
       
        # ---------------------------------
        # CREATE INSTALLMENT FEE ROWS
        # ---------------------------------

        for i in range(1, installment + 1):

            # Calculate month
            total_months = (
                joining_date.year * 12
                + joining_date.month
                - 1
                + i
            )

            due_year = total_months // 12
            due_month = total_months % 12 + 1

            # Always due on 10th
            due_date = date(
                due_year,
                due_month,
                10
            )

            # Last installment gets rounding balance
            if i == installment:

                previous_amount = (
                    installment_amount
                    * (installment - 1)
                )

                amount = balance - previous_amount

            else:
                amount = installment_amount

            Fee.objects.create(
                enrollment=enrollment,
                total_fee=course_fee,
                due_date=due_date,
                payment_date=None,
                amount=amount,
                balance=amount,
                installment_number=i
            )

        # ---------------------------------
        # SAVE DOWN PAYMENT
        # ---------------------------------

        if down_payment > 0:

            Payment.objects.create(
                enrollment=enrollment,
                payment_date=payment_date,
                payment_amount=down_payment,
                payment_type="Down Payment",
                installment_number=None
            )

        return redirect("home")

    return render(
        request,
        "add_student.html",
        {
            "courses": courses
        }
    )
def payment(request):
    return render(request, "payment_form.html")

def addfee(request):

    students = Student_details.objects.all()
    courses = Course.objects.all()

    if request.method == "POST":
        def reject_payment(message):
            messages.error(request, message)
            return redirect("home")

        enrollment_id = request.POST.get("enrollment_id", "").strip()
        raw_amount = request.POST.get("amount", "").strip()
        raw_payment_date = request.POST.get("payment_date", "").strip()

        try:
            amount = Decimal(raw_amount)
        except (InvalidOperation, TypeError):
            return reject_payment("Enter a valid payment amount.")

        if not amount.is_finite() or amount <= 0:
            return reject_payment("Payment amount must be greater than ₹0.00.")
        try:
            normalized_amount = amount.quantize(Decimal("0.01"))
        except InvalidOperation:
            return reject_payment("Enter a payment amount with at most 2 decimal places.")
        if amount != normalized_amount:
            return reject_payment("Payment amount can have at most 2 decimal places.")

        try:
            payment_date = date.fromisoformat(raw_payment_date)
        except (TypeError, ValueError):
            return reject_payment("Choose a valid payment date.")

        try:
            enrollment_pk = int(enrollment_id)
        except (TypeError, ValueError):
            return reject_payment("Select a student and course before saving the payment.")

        with transaction.atomic():
            enrollment = Enrollment.objects.select_related("student", "course").filter(
                pk=enrollment_pk
            ).first()
            if enrollment is None:
                return reject_payment("That student enrollment could not be found. Select it again.")

            fees = list(
                Fee.objects.select_for_update().filter(
                    enrollment=enrollment,
                    installment_number__isnull=False,
                    balance__gt=0
                ).order_by("installment_number")
            )
            outstanding_balance = sum((fee.balance for fee in fees), Decimal("0.00"))
            if outstanding_balance <= 0:
                return reject_payment("This enrollment has no outstanding balance.")
            if amount > outstanding_balance:
                return reject_payment(
                    f"Payment exceeds the outstanding balance of ₹{outstanding_balance:.2f}. "
                    "Enter that amount or less."
                )

            Payment.objects.create(
                enrollment=enrollment,
                payment_date=payment_date,
                payment_amount=amount,
                payment_type="Installment",
                installment_number=fees[0].installment_number
            )

            remaining_payment = amount
            for fee in fees:
                if remaining_payment <= 0:
                    break
                if remaining_payment >= fee.balance:
                    remaining_payment -= fee.balance
                    fee.balance = Decimal("0.00")
                else:
                    fee.balance -= remaining_payment
                    remaining_payment = Decimal("0.00")
                fee.payment_date = payment_date
                fee.save(update_fields=["balance", "payment_date"])

            remaining_balance = outstanding_balance - amount
            enrollment.status = "Closed" if remaining_balance <= 0 else "Paid"
            enrollment.save(update_fields=["status"])

            student = enrollment.student
            student.remaining_amount = remaining_balance
            student.status = "Closed" if remaining_balance <= 0 else "Paid"
            student.save(update_fields=["remaining_amount", "status"])

        messages.success(request, f"Payment of ₹{amount:.2f} was recorded.")
        return redirect("fee_details")

    return render(
        request,
        "payment_form.html",
        {
            "students": students,
            "courses": courses
        }
    )
def add_course(request):
    if request.method == "POST":
        c_reg = request.POST.get("c_reg")
        course_name = request.POST.get("course_name")
        duration = request.POST.get("duration")
        course_fee = request.POST.get("course_fee")
        division = request.POST.get("division")

        

        Course.objects.create(
            c_reg=c_reg,
            course_name=course_name,
            duration=duration,
            course_fee=course_fee,
            division=division
        )

        return redirect("course_details")

    return render(request, "add_course.html")



def editstudent(request, student_id):
    student = get_object_or_404(
        Student_details,
        student_id=student_id
    )

    if request.method == "POST":
        student.student_reg=request.POST.get("student_reg")
        student.name = request.POST.get("name")
        student.phone = request.POST.get("phone")
        student.division = request.POST.get("division")

        course_id = request.POST.get("course_id")

        if course_id:
            student.course_id = Course.objects.get(
                course_id=course_id
            )

        student.save()

        print("UPDATED PHONE:", student.phone)

        return redirect("student_details")

    return redirect("student_details")
    

def editcourse(request, course_id):
    course = get_object_or_404(Course, course_id=course_id)

    if request.method == "POST":
        course.c_reg=request.POST.get("c_reg")
        course.course_name = request.POST.get("course_name")
        course.course_fee = request.POST.get("course_fee")
        course.duration = request.POST.get("duration")
        course.division = request.POST.get("division")

        course.save()

        return redirect("course_details")

    return redirect("course_details")


def delete_student(request, student_id):
    if request.method != "POST":
        return redirect("student_details")
    student = get_object_or_404(Student_details, student_id=student_id)
    reason, valid = get_deletion_credentials(request)
    if not valid:
        return redirect("student_details")
    with transaction.atomic():
        actor = request.user
        actor_username = actor.get_username()
        enrollments = list(Enrollment.objects.filter(student=student).select_related("course"))
        fees = list(Fee.objects.filter(enrollment__student=student).select_related("enrollment", "enrollment__course"))
        payments = list(Payment.objects.filter(enrollment__student=student).select_related("enrollment", "enrollment__course"))
        audit_entries = [DeletionAudit(
            actor=actor,
            actor_username=actor_username,
            object_type="Student",
            object_id=str(student.student_id),
            object_label=f"{student.name} ({student.student_reg or 'no registration'})",
            reason=reason,
        )]
        audit_entries.extend(DeletionAudit(
            actor=actor,
            actor_username=actor_username,
            object_type="Enrollment",
            object_id=str(enrollment.pk),
            object_label=f"{student.name} · {enrollment.course.course_name}",
            reason=reason,
        ) for enrollment in enrollments)
        audit_entries.extend(DeletionAudit(
            actor=actor,
            actor_username=actor_username,
            object_type="Fee schedule row",
            object_id=str(fee.fee_id),
            object_label=f"{student.name} · installment {fee.installment_number or 'n/a'} · ₹{fee.amount}",
            reason=reason,
        ) for fee in fees)
        audit_entries.extend(DeletionAudit(
            actor=actor,
            actor_username=actor_username,
            object_type="Payment transaction",
            object_id=str(payment.pk),
            object_label=f"{student.name} · ₹{payment.payment_amount} · {payment.payment_date}",
            reason=reason,
        ) for payment in payments)
        DeletionAudit.objects.bulk_create(audit_entries)
        student.delete()
    messages.success(request, "Student and associated enrollment records were deleted.")
    return redirect("student_details")


def delete_course(request, course_id):
    if request.method != "POST":
        return redirect("course_details")
    course = get_object_or_404(Course, course_id=course_id)
    reason, valid = get_deletion_credentials(request)
    if not valid:
        return redirect("course_details")
    if Student_details.objects.filter(course_id=course).exists() or Enrollment.objects.filter(course=course).exists():
        messages.error(request, "This course has student or enrollment records. Move those records before deleting the course.")
    else:
        with transaction.atomic():
            DeletionAudit.objects.create(
                actor=request.user,
                actor_username=request.user.get_username(),
                object_type="Course",
                object_id=str(course.course_id),
                object_label=f"{course.c_reg or 'no code'} · {course.course_name}",
                reason=reason,
            )
            course.delete()
        messages.success(request, "Course deleted.")
    return redirect("course_details")


def delete_payment(request, payment_id):
    if request.method != "POST":
        return redirect("fee_details")
    payment = get_object_or_404(Payment, pk=payment_id)
    reason, valid = get_deletion_credentials(request)
    if not valid:
        return redirect("fee_details")
    student_name = payment.enrollment.student.name if payment.enrollment else "Unlinked payment"
    with transaction.atomic():
        DeletionAudit.objects.create(
            actor=request.user,
            actor_username=request.user.get_username(),
            object_type="Payment transaction",
            object_id=str(payment.pk),
            object_label=f"{student_name} · ₹{payment.payment_amount} · {payment.payment_date}",
            reason=reason,
        )
        payment.delete()
    messages.success(request, "Payment transaction deleted.")
    return redirect("fee_details")


class DeletionAuditListView(ListView):
    model = DeletionAudit
    template_name = "audit_log.html"
    context_object_name = "audit_entries"
    paginate_by = 25

    def get_queryset(self):
        return DeletionAudit.objects.select_related("actor").all()


class UserListView(ListView):
    template_name = 'user_list.html'
    context_object_name = 'users'
    paginate_by = 25

    def get_queryset(self):
        return get_user_model().objects.order_by('-is_superuser', '-is_staff', 'username')


class StudentListView(ListView):
    model = Student_details
    template_name = "student_details.html"
    context_object_name = "students"
    paginate_by = 25

    def get_paginate_by(self, queryset):
        requested_rows = self.request.GET.get("rows", str(self.paginate_by))
        if requested_rows == "all":
            return max(queryset.count(), 1)
        try:
            requested = int(requested_rows)
        except (TypeError, ValueError):
            requested = self.paginate_by
        return requested if requested in {10, 25, 50, 100, 250} else self.paginate_by

    def get_queryset(self):
        query = self.request.GET.get("q", "").strip()
        division = self.request.GET.get("division", "").strip()
        students = Student_details.objects.select_related("course_id")
        if query:
            students = students.filter(
                Q(name__icontains=query) |
                Q(student_reg__icontains=query) |
                Q(phone__icontains=query) |
                Q(course_id__course_name__icontains=query) |
                Q(division__icontains=query)
            )
        if division:
            students = students.filter(division=division)
        return students.order_by("student_id")

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        page_students = list(context["students"])
        today = date.today()
        student_ids = [student.student_id for student in page_students]
        enrollments = Enrollment.objects.filter(
            student_id__in=student_ids
        ).select_related("course").order_by("student_id", "-enrollment_date", "-id")
        enrollment_by_student = {}
        for enrollment in enrollments:
            enrollment_by_student.setdefault(enrollment.student_id, enrollment)

        enrollment_ids = [enrollment.id for enrollment in enrollment_by_student.values()]
        fees_by_enrollment = {}
        fees = Fee.objects.filter(
            enrollment_id__in=enrollment_ids,
            installment_number__isnull=False
        ).order_by("enrollment_id", "installment_number")
        for fee in fees:
            fees_by_enrollment.setdefault(fee.enrollment_id, []).append(fee)

        payments_by_enrollment = {}
        payments = Payment.objects.filter(
            enrollment_id__in=enrollment_ids
        ).order_by("payment_date", "id")
        for payment in payments:
            payments_by_enrollment.setdefault(payment.enrollment_id, []).append(payment)

        detail_by_student = {}
        for student in page_students:
            enrollment = enrollment_by_student.get(student.student_id)
            fee_rows = fees_by_enrollment.get(enrollment.id, []) if enrollment else []
            student_payments = payments_by_enrollment.get(enrollment.id, []) if enrollment else []
            total_fee = (fee_rows[0].total_fee if fee_rows else student.course_fee) or Decimal("0")
            down_payment = (enrollment.down_payment if enrollment else student.down_payment) or Decimal("0")
            installment_paid = sum(
                (payment.payment_amount for payment in student_payments if payment.payment_type.lower() == "installment"),
                Decimal("0")
            )
            total_paid = min(total_fee, down_payment + installment_paid)
            balance = (
                sum((fee.balance for fee in fee_rows), Decimal("0"))
                if fee_rows else max(total_fee - total_paid, Decimal("0"))
            )
            overdue_rows = [fee for fee in fee_rows if fee.balance > 0 and fee.due_date and fee.due_date < today]
            upcoming_rows = [fee for fee in fee_rows if fee.balance > 0 and fee.due_date and fee.due_date >= today]
            overdue_balance = sum((fee.balance for fee in overdue_rows), Decimal("0"))
            upcoming_balance = max(balance - overdue_balance, Decimal("0"))
            installment_count = enrollment.installment if enrollment else student.installment or 0
            paid_installment_count = sum(1 for fee in fee_rows if fee.balance <= 0)

            student.display_total_fee = total_fee
            student.display_balance = balance
            student.display_paid = total_paid
            student.display_overdue = overdue_balance
            student.display_upcoming = upcoming_balance
            student.display_installment = f"{paid_installment_count}/{installment_count}"
            student.joining_date = enrollment.enrollment_date if enrollment else None
            student.display_course = enrollment.course if enrollment else student.course_id
            student.display_division = (enrollment.division if enrollment else student.division) or ""
            nearest_upcoming = min((fee.due_date for fee in upcoming_rows), default=None)
            days_to_next_due = (nearest_upcoming - today).days if nearest_upcoming else None
            if balance <= 0:
                student.display_status = "Fully paid"
            elif overdue_rows:
                student.display_status = "Overdue"
            elif days_to_next_due is not None and days_to_next_due <= 7:
                student.display_status = "Due soon"
            elif total_paid > 0:
                student.display_status = "On track"
            else:
                student.display_status = "Upcoming"
            student.display_status_detail = (
                f"{(today - min(fee.due_date for fee in overdue_rows)).days} days overdue"
                if overdue_rows else
                f"Due in {days_to_next_due} days" if days_to_next_due is not None else "No installment dates"
            )
            student.display_paid_rate = min(total_paid / total_fee * 100, Decimal("100")) if total_fee else Decimal("0")
            student.display_overdue_rate = min(overdue_balance / total_fee * 100, Decimal("100")) if total_fee else Decimal("0")
            student.display_upcoming_rate = min(upcoming_balance / total_fee * 100, Decimal("100")) if total_fee else Decimal("0")
            name_parts = (student.name or "").split()
            student.initials = "".join(part[0] for part in name_parts[:2]).upper() or "?"

            for fee in fee_rows:
                fee.is_overdue = bool(fee.balance > 0 and fee.due_date and fee.due_date < today)
                fee.is_paid = fee.balance <= 0
                fee.days_until_due = (fee.due_date - today).days if fee.due_date else None
                fee.days_overdue = (today - fee.due_date).days if fee.due_date and fee.due_date < today else 0
                fee.latest_payment = next(
                    (payment for payment in reversed(student_payments) if payment.installment_number == fee.installment_number),
                    None
                )

            detail_by_student[student.student_id] = {
                "student": student,
                "enrollment": enrollment,
                "fees": fee_rows,
                "payments": student_payments,
                "total_fee": total_fee,
                "down_payment": down_payment,
                "total_paid": total_paid,
                "balance": balance,
                "overdue_balance": overdue_balance,
                "upcoming_balance": upcoming_balance,
                "overdue_rows": overdue_rows,
                "upcoming_rows": upcoming_rows,
                "installment_count": installment_count,
                "paid_installment_count": paid_installment_count,
            }

        selected_id = self.request.GET.get("selected", "")
        selected_detail = detail_by_student.get(int(selected_id)) if selected_id.isdigit() else None
        if selected_detail is None and page_students:
            selected_detail = detail_by_student[page_students[0].student_id]

        total_students = Student_details.objects.count()
        enrolled_students = Enrollment.objects.values("student_id").distinct().count()
        fee_pool = Student_details.objects.aggregate(total=Sum("course_fee"))["total"] or Decimal("0")
        collected = Payment.objects.aggregate(total=Sum("payment_amount"))["total"] or Decimal("0")
        overdue_fees = Fee.objects.filter(
            installment_number__isnull=False, balance__gt=0, due_date__lt=today
        )
        overdue_total = overdue_fees.aggregate(total=Sum("balance"))["total"] or Decimal("0")
        overdue_students = overdue_fees.values("enrollment__student_id").distinct().count()
        collection_rate = min(
            (collected / fee_pool * Decimal("100")) if fee_pool else Decimal("0"),
            Decimal("100")
        ).quantize(Decimal("0.1"))

        page_obj = context.get("page_obj")
        context.update({
            "students": page_students,
            "selected_detail": selected_detail,
            "total_students_count": total_students,
            "enrolled_students_count": enrolled_students,
            "fee_pool": fee_pool,
            "fees_settled": collected,
            "overdue_total": overdue_total,
            "overdue_students": overdue_students,
            "collection_rate": collection_rate,
            "displayed_start": page_obj.start_index() if page_obj and page_obj.object_list else 0,
            "displayed_end": page_obj.end_index() if page_obj and page_obj.object_list else 0,
            "rows_per_page": self.request.GET.get("rows") if self.request.GET.get("rows") == "all" or self.request.GET.get("rows") in {"10", "25", "50", "100", "250"} else str(self.paginate_by),
        })
        if page_obj:
            query = self.request.GET.copy()
            if page_obj.has_previous():
                query["page"] = page_obj.previous_page_number()
                context["previous_page_url"] = "?" + query.urlencode()
            if page_obj.has_next():
                query["page"] = page_obj.next_page_number()
                context["next_page_url"] = "?" + query.urlencode()
        return context
class CourseListView(ListView):
    model = Course
    template_name = "course_details.html"
    context_object_name = "courses"
    paginate_by = 25

    def get_paginate_by(self, queryset):
        requested_rows = self.request.GET.get("rows", str(self.paginate_by))
        if requested_rows == "all":
            return max(queryset.count(), 1)
        try:
            rows = int(requested_rows)
        except (TypeError, ValueError):
            rows = self.paginate_by
        return rows if rows in {10, 25, 50, 100, 250} else self.paginate_by

    def get_queryset(self):
        query = self.request.GET.get("q", "").strip()
        division = self.request.GET.get("division", "").strip()
        courses = Course.objects.annotate(
            student_count=Count("student_details", distinct=True)
        )
        if query:
            search_filter = (
                Q(course_name__icontains=query)
                | Q(c_reg__icontains=query)
                | Q(division__icontains=query)
            )
            try:
                search_filter |= Q(duration=int(query))
            except ValueError:
                pass
            courses = courses.filter(search_filter)
        if division:
            courses = courses.filter(division=division)
        return courses.order_by("course_id")

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        current_offer = CourseOffer.objects.first()
        offer_value = current_offer.offer_value if current_offer else Decimal("0")
        offer_active = bool(current_offer and current_offer.is_currently_active)
        page_courses = list(context["courses"])
        for course in page_courses:
            course.discount_amount = (
                course.course_fee * offer_value / Decimal("100")
                if offer_active else Decimal("0")
            )
            course.final_fee = course.course_fee - course.discount_amount
            course.offer_percent = offer_value if offer_active else Decimal("0")
        page_obj = context.get("page_obj")
        total_enrollments = Enrollment.objects.count()
        context.update({
            "courses": page_courses,
            "offer": offer_value if offer_value else "",
            "offer_active": offer_active,
            "offer_enabled": bool(current_offer and current_offer.is_active),
            "offer_start_date": current_offer.start_date if current_offer else None,
            "offer_end_date": current_offer.end_date if current_offer else None,
            "offer_name": current_offer.offer_name if current_offer else "",
            "divisions": Course.objects.exclude(division__isnull=True).exclude(division="").values_list("division", flat=True).distinct().order_by("division"),
            "course_count": Course.objects.count(),
            "total_enrollments": total_enrollments,
            "preview_course": page_courses[0] if page_courses else None,
            "displayed_start": page_obj.start_index() if page_obj and page_obj.object_list else 0,
            "displayed_end": page_obj.end_index() if page_obj and page_obj.object_list else 0,
            "rows_per_page": self.request.GET.get("rows") if self.request.GET.get("rows") == "all" or self.request.GET.get("rows") in {"10", "25", "50", "100", "250"} else str(self.paginate_by),
            "selected_division": self.request.GET.get("division", ""),
        })
        if page_obj:
            query = self.request.GET.copy()
            if page_obj.has_previous():
                query["page"] = page_obj.previous_page_number()
                context["previous_page_url"] = "?" + query.urlencode()
            if page_obj.has_next():
                query["page"] = page_obj.next_page_number()
                context["next_page_url"] = "?" + query.urlencode()
        return context
class FeeListView(ListView):
    model = Payment
    template_name = "fee_details.html"
    context_object_name = "payments"
    paginate_by = 25

    def get_paginate_by(self, queryset):
        requested_rows = self.request.GET.get("rows", str(self.paginate_by))
        if requested_rows == "all":
            return max(queryset.count(), 1)
        try:
            rows = int(requested_rows)
        except (TypeError, ValueError):
            rows = self.paginate_by
        return rows if rows in {10, 25, 50, 100, 250} else self.paginate_by

    def get_queryset(self):
        query = self.request.GET.get("q", "").strip()
        payment_type = self.request.GET.get("type", "all").strip()
        period = self.request.GET.get("period", "all").strip()
        today = date.today()
        payments = Payment.objects.select_related(
            "enrollment", "enrollment__student", "enrollment__course"
        )
        if query:
            payments = payments.filter(
                Q(enrollment__student__name__icontains=query)
                | Q(enrollment__student__student_reg__icontains=query)
                | Q(enrollment__course__course_name__icontains=query)
            )
        start_date = self.request.GET.get("start_date", "").strip()
        end_date = self.request.GET.get("end_date", "").strip()
        if period == "custom_date_range" and start_date and end_date:
            payments = payments.filter(payment_date__range=[start_date, end_date])
        elif period == "this_month":
            payments = payments.filter(payment_date__year=today.year, payment_date__month=today.month)
        if payment_type == "down_payment":
            payments = payments.filter(payment_type__iexact="Down Payment")
        elif payment_type == "installment":
            payments = payments.filter(payment_type__iexact="Installment")
        return payments.order_by("-payment_date", "-id")

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        today = date.today()
        all_payments = Payment.objects.all()
        month_payments = all_payments.filter(payment_date__year=today.year, payment_date__month=today.month)
        page_obj = context.get("page_obj")
        context.update({
            "total_collected": all_payments.aggregate(total=Sum("payment_amount"))["total"] or Decimal("0"),
            "transaction_count": all_payments.count(),
            "collected_month": month_payments.aggregate(total=Sum("payment_amount"))["total"] or Decimal("0"),
            "filter_counts": {
                "all": all_payments.count(),
                "down_payment": all_payments.filter(payment_type__iexact="Down Payment").count(),
                "installment": all_payments.filter(payment_type__iexact="Installment").count(),
            },
            "displayed_start": page_obj.start_index() if page_obj and page_obj.object_list else 0,
            "displayed_end": page_obj.end_index() if page_obj and page_obj.object_list else 0,
            "rows_per_page": self.request.GET.get("rows") if self.request.GET.get("rows") == "all" or self.request.GET.get("rows") in {"10", "25", "50", "100", "250"} else str(self.paginate_by),
            "selected_period": self.request.GET.get("period", "all"),
            "selected_type": self.request.GET.get("type", "all"),
            "today": today,
        })
        if page_obj:
            query = self.request.GET.copy()
            if page_obj.has_previous():
                query["page"] = page_obj.previous_page_number()
                context["previous_page_url"] = "?" + query.urlencode()
            if page_obj.has_next():
                query["page"] = page_obj.next_page_number()
                context["next_page_url"] = "?" + query.urlencode()
        return context
class PaymentDetailView(ListView):
    model = Payment
    template_name = "payment_date.html"
    context_object_name = "payments"

    def get_queryset(self):
        student_id = self.kwargs["student_id"]

        enrollment = Enrollment.objects.filter(
            student_id=student_id
        ).first()

        if not enrollment:
            return Payment.objects.none()

        payments = Payment.objects.filter(
            enrollment=enrollment
        ).order_by("payment_date", "id")

        installment_number = 0

        for payment in payments:
            if payment.payment_type.lower() == "installment":
                installment_number += 1
                payment.display_installment = installment_number
            else:
                payment.display_installment = None

        return payments

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)

        student_id = self.kwargs["student_id"]

        student = Student_details.objects.get(
            student_id=student_id
        )

        enrollment = Enrollment.objects.filter(
            student=student
        ).first()

        if not enrollment:
            context["student"] = student
            context["enrollment"] = None
            context["fee"] = None
            context["paid"] = Decimal("0")
            context["down_payment"] = Decimal("0")
            context["installment_paid"] = Decimal("0")
            context["balance"] = Decimal("0")
            context["monthly_installment"] = Decimal("0")
            context["installment_rows"] = []
            return context

        fee = Fee.objects.filter(
            enrollment=enrollment
        ).first()

        # Installment payments മാത്രം
        installment_paid = Payment.objects.filter(
            enrollment=enrollment,
            payment_type__iexact="Installment"
        ).aggregate(
            total=Sum("payment_amount")
        )["total"] or Decimal("0")

        # Down payment Enrollment-ൽ നിന്ന്
        down_payment = enrollment.down_payment or Decimal("0")

        total_paid = down_payment + installment_paid

        # Total fee
        if fee:
            total_fee = fee.total_fee
        else:
            total_fee = enrollment.course.course_fee

        # Balance
        balance = total_fee - total_paid

        if balance < 0:
            balance = Decimal("0")
        is_closed=balance <=Decimal("0")
        # Installment count
        installment_count = enrollment.installment or 0

        # Down payment minus ചെയ്ത ശേഷമുള്ള amount
        remaining_fee = total_fee - down_payment

        # Monthly installment
        if installment_count > 0:
            monthly_installment = (
                remaining_fee / installment_count
            ).quantize(Decimal("0.01"))
        else:
            monthly_installment = Decimal("0")

        # ==========================================
        # DOWN PAYMENT + ALL INSTALLMENTS
        # ==========================================

        installment_rows = []

    

        down_payment_payment = Payment.objects.filter(
            enrollment=enrollment,
            payment_type__iexact="Down Payment"
        ).order_by("payment_date").first()
        installment_rows.append({
            "number": "Down Payment",
            "payment": down_payment_payment,
            "amount": down_payment,
            "due_date": None,
            "payment_date": (down_payment_payment.payment_date if down_payment_payment else None),
            "is_down_payment": True
        })
        installment_payments = list(Payment.objects.filter(
            enrollment=enrollment,
            payment_type__iexact="Installment"
        ).order_by("payment_date", "id"))

        # Installments
        for number in range(1, installment_count + 1):

            if number <= len(installment_payments):
                payment = installment_payments[number - 1]
            else:
                payment = None
            if fee and fee.due_date:
        # Fee-ൽ due date ഉണ്ടെങ്കിൽ അത് ഉപയോഗിക്കുക
             first_due_date = fee.due_date
            else:
        # Fee-ൽ due date ഇല്ലെങ്കിൽ
        # current month-ന്റെ 10th date ഉപയോഗിക്കുക
             today = date.today()
             first_due_date = today.replace(day=10)

        # ഓരോ installment-നും next month
            installment_due_date = (
            first_due_date + relativedelta(months=number - 1)
    )


        #     if fee and fee.due_date:
        #      installment_due_date = (
        #     fee.due_date + relativedelta(months=number - 1)
        #    )
        #     else:
        #      installment_due_date = None


            installment_rows.append({
                "number": number,
                "payment": payment,
                "amount": (
                    payment.payment_amount
                    if payment
                    else Decimal("0")
                ),
                "due_date": installment_due_date,
                "payment_date":( 
                            payment.payment_date  
                            if payment else None),
                "is_down_payment": False,
                "is_closed": is_closed and payment is None,
            })

        # Context
        context["student"] = student
        context["enrollment"] = enrollment
        context["fee"] = fee
        context["paid"] = total_paid
        context["down_payment"] = down_payment
        context["installment_paid"] = installment_paid
        context["balance"] = balance
        context["monthly_installment"] = monthly_installment
        context["installment_rows"] = installment_rows

        return context
    
def student_details(request):
    query = request.GET.get('q', '').strip()

    if query:
        students = Student_details.objects.filter(
            name__icontains=query
        ) | Student_details.objects.filter(
            phone__icontains=query
        )
    else:
        students = Student_details.objects.all()

    return render(request, 'student_details.html', {
        'students': students,
        'query': query
    })


def get_student_courses(request):

    name = request.GET.get("name", "").strip()

    enrollments = Enrollment.objects.filter(
        student__name__iexact=name
    ).select_related("student", "course")

    data = []

    for enrollment in enrollments:
        balance = Fee.objects.filter(
            enrollment=enrollment,
            installment_number__isnull=False,
            balance__gt=0
        ).aggregate(total=Sum("balance"))["total"] or Decimal("0.00")
        data.append({
            "enrollment_id": enrollment.id,
            "course_name": enrollment.course.course_name,
            "balance": str(balance),
        })

    return JsonResponse(data, safe=False)
def search_students(request):
    query = request.GET.get("q", "").strip()

    students = Student_details.objects.filter(
        name__istartswith=query
    ).values("name").distinct()

    return JsonResponse(list(students), safe=False)

def update_offer(request):

    if request.method == "POST":

        if request.POST.get("action") == "cancel":
            offer = CourseOffer.objects.first()
            if offer:
                offer.is_active = False
                offer.offer_name = ""
                offer.offer_value = Decimal("0")
                offer.start_date = None
                offer.end_date = None
                offer.save(update_fields=["is_active", "offer_name", "offer_value", "start_date", "end_date"])
                messages.success(request, "Global offer cancelled and its settings cleared.")
            else:
                messages.info(request, "There is no global offer to cancel.")
            return redirect("course_details")

        offer_value = request.POST.get("offer_value", 0)
        offer_name = request.POST.get("offer_name", "").strip()

        # Saving settings enables the offer; use Cancel offer to disable it.
        is_active = True
        start_date_raw = request.POST.get("start_date", "").strip()
        end_date_raw = request.POST.get("end_date", "").strip()

        try:
            offer_value = float(offer_value)
            start_date = date.fromisoformat(start_date_raw) if start_date_raw else None
            end_date = date.fromisoformat(end_date_raw) if end_date_raw else None

            if start_date and end_date and end_date < start_date:
                messages.error(request, "Offer end date must be on or after its start date.")
                return redirect("course_details")

            if not offer_name:
                messages.error(request, "Please enter an offer name.")
                return redirect("course_details")

            if offer_value < 0 or offer_value > 100:
                messages.error(
                    request,
                    "Offer must be between 0% and 100%."
                )
                return redirect("course_details")

            offer = CourseOffer.objects.first()

            if offer:
                offer.offer_name = offer_name
                offer.offer_value = offer_value
                offer.is_active = is_active
                offer.start_date = start_date
                offer.end_date = end_date
                offer.save()

            else:
                CourseOffer.objects.create(
                    offer_name=offer_name,
                    offer_value=offer_value,
                    is_active=is_active,
                    start_date=start_date,
                    end_date=end_date
                )

            messages.success(
                request,
                "Global offer settings saved successfully."
            )

        except ValueError:
            messages.error(
                request,
                "Please enter a valid offer."
            )

    return redirect("course_details")
    



























