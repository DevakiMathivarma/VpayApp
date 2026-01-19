# core/views.py
from django.shortcuts import render, redirect
from django.urls import reverse
from django.contrib import messages
from django.contrib.auth import login as auth_login, logout as auth_logout, get_user_model
from django.contrib.auth.decorators import login_required
from django.db import transaction
from django.utils import timezone
from django.http import JsonResponse, HttpResponseBadRequest
import secrets
import datetime
import json
from django.utils import timezone
from django.db.models import Count, Sum
from django.db.models.functions import TruncDate
from datetime import timedelta
from django.contrib.admin.views.decorators import staff_member_required
from .models import MobileOTP
from .forms import RegistrationForm, LoginOTPForm, ResendOTPForm

from django.core.mail import send_mail
import random
import datetime
import logging
logger = logging.getLogger(__name__)
User = get_user_model()

# email otp view
# ================= EMAIL OTP HELPERS =====================

OTP_LENGTH = 6
OTP_EXPIRY_MINUTES = 5
MAX_VERIFY_ATTEMPTS = 5

def generate_email_otp(length=OTP_LENGTH):
    """Generate a random numeric OTP."""
    return str(random.randint(100000, 999999))

def send_email_otp(user, purpose):
    """Create OTP, store it in DB, and send it via email."""
    # Mark any previous unused OTPs as used
    MobileOTP.objects.filter(user=user, used=False, purpose=purpose).update(used=True)

    otp_code = generate_email_otp()
    expiry = timezone.now() + datetime.timedelta(minutes=OTP_EXPIRY_MINUTES)

    MobileOTP.objects.create(
        user=user,
        otp=otp_code,
        expires_at=expiry,
        purpose=purpose,
        used=False
    )

    subject = "Your GapyPay OTP Verification Code"
    message = f"Hello {user.username},\n\nYour one-time password (OTP) is: {otp_code}\nThis OTP is valid for {OTP_EXPIRY_MINUTES} minutes.\n\nThanks,\nGapyPay Team"
    from_email = "noreply@gapypay.com"
    send_mail(subject, message, from_email, [user.email], fail_silently=False)

    logger.info(f"[EMAIL OTP] Sent to {user.email} | OTP: {otp_code}")
    return otp_code


def register_view(request):
    """Handle user registration with email OTP verification."""
    if request.method == 'GET':
        return render(request, 'core/register.html')

    username = request.POST.get('username')
    email = request.POST.get('email')
    phone = request.POST.get('phone')
    password = request.POST.get('password')
    confirm_password = request.POST.get('confirm_password')

    # Validation checks
    if not all([username, email, phone, password, confirm_password]):
        messages.error(request, "All fields are required.")
        return render(request, 'core/register.html')

    if password != confirm_password:
        messages.error(request, "Passwords do not match.")
        return render(request, 'core/register.html')

    if User.objects.filter(username=username).exists():
        messages.error(request, "Username already exists.")
        return render(request, 'core/register.html')

    if User.objects.filter(email=email).exists():
        messages.error(request, "Email already registered.")
        return render(request, 'core/register.html')

    # Create user and send OTP
    with transaction.atomic():
        user = User.objects.create_user(
            username=username,
            email=email,
            phone_number=phone,
            is_phone_verified=False
        )
        user.set_password(password)
        user.save()

       # send_email_otp(user, purpose='REGISTER')

    messages.success(request, f"Account created! Please Login")
    return redirect(f"{reverse('core:login')}?username={username}")

def get_post_login_redirect_name(user):
    """
    Returns the URL name to redirect to after login
    based on whether the user has a PAN number in TestKYC.
    """
    try:
        kyc = TestKYC.objects.get(user=user)
    except TestKYC.DoesNotExist:
        # No KYC row → treat as no PAN
        return 'core:test_view'  # or the URL name for /test

    if kyc.pan_number:
        return 'core:vpay_dashboard'  # URL name for /vpay_dashboard
    else:
        return 'core:test_view'            # URL name for /test


# email otp loginview
from django.contrib.auth import authenticate

def login_view(request):
    if request.method == 'GET':
        return render(request, 'core/login.html')
    logger.info('coming here ')
    # Which button was clicked?
    if 'password' in request.POST:
        # Normal username + password login
        username = request.POST.get('username')
        password = request.POST.get('password')
        logger.info(username)
        logger.info(password)
        user = authenticate(request, username=username, password=password)
        if user:
            auth_login(request, user)
            messages.success(request, "Logged in successfully.")
            return redirect(get_post_login_redirect_name(user))  # 👈 changed
        else:
            messages.error(request, "Invalid username or password.")
            return render(request, 'core/login.html')

    elif 'send_otp' in request.POST:
        # Send OTP to user email
        username = request.POST.get('username')
        user = User.objects.filter(username=username).first()
        if not user:
            messages.error(request, "User not found.")
            return render(request, 'core/login.html')

        send_email_otp(user, 'LOGIN')
        messages.success(request, f"OTP sent to {user.email}. Check your inbox.")
        return render(request, 'core/login.html', {'otp_sent': True, 'username': username})

    elif 'verify_otp' in request.POST:
        username = request.POST.get('username')
        otp_input = request.POST.get('otp')

        user = User.objects.filter(username=username).first()
        if not user:
            messages.error(request, "User not found.")
            return render(request, 'core/login.html')

        otp_obj = MobileOTP.objects.filter(user=user, used=False, purpose='LOGIN').order_by('-created_at').first()
        if not otp_obj:
            messages.error(request, "No active OTP found. Please request a new OTP.")
            return render(request, 'core/login.html', {'otp_sent': True, 'username': username})

        # Check expiry
        if otp_obj.is_expired():
            otp_obj.mark_used()
            messages.error(request, "OTP expired. Please request a new one.")
            return render(request, 'core/login.html', {'username': username})

        # Check attempts
        if otp_obj.attempts >= MAX_VERIFY_ATTEMPTS:
            otp_obj.mark_used()
            messages.error(request, "Too many attempts. Please request a new OTP.")
            return render(request, 'core/login.html', {'username': username})

        # Verify OTP
        if otp_input != otp_obj.otp:
            otp_obj.attempts += 1
            otp_obj.save()
            remaining = MAX_VERIFY_ATTEMPTS - otp_obj.attempts
            messages.error(request, f"Invalid OTP. {remaining} attempts remaining.")
            return render(request, 'core/login.html', {'otp_sent': True, 'username': username})

        # OTP correct → mark used, log in
        otp_obj.mark_used()
        auth_login(request, user)
        messages.success(request, "Logged in successfully.")
        return redirect(get_post_login_redirect_name(user))  # 👈 changed

    return render(request, 'core/login.html')
# core/views.py
from django.shortcuts import redirect
from django.urls import reverse
from urllib.parse import urlencode

def google_login_redirect(request):
    # Force dashboard always (ignore incoming next)
    next_url = '/dashboard/'
    base = reverse('socialaccount_login', args=['google'])  # -> /accounts/google/login/
    qs = urlencode({'next': next_url})
    return redirect(f"{base}?{qs}")



def logout_view(request):
    """Logout and redirect to login."""
    auth_logout(request)
    messages.info(request, "You have been logged out.")
    return redirect('core:login')

def is_ajax(request):
    return request.headers.get('x-requested-with') == 'XMLHttpRequest'

from django.views.decorators.http import require_POST
from django.http import JsonResponse
from django.utils import timezone
import datetime
from django.core.mail import send_mail
import random
import socket

@require_POST
def resend_otp_view(request):
    """
    Resend OTP to user's registered email address.
    Works for AJAX and normal POST requests.
    """
    username = request.POST.get('username')
    try:
        print
        logger.info("host ",settings.EMAIL_HOST)
        logger.info("port", settings.EMAIL_PORT)
        socket.create_connection((settings.EMAIL_HOST, settings.EMAIL_PORT), timeout=5)
    except Exception as e:
        logger.info(e)
        messages.error(request, "Email server not reachable right now.")
        return redirect("login")
    if not username:
        if request.headers.get('x-requested-with') == 'XMLHttpRequest':
            return JsonResponse({'ok': False, 'message': 'Username is required.'}, status=400)
        messages.error(request, "Username is required.")
        return redirect('core:login')

    # Find user
    user = User.objects.filter(username__iexact=username).first()
    if not user:
        if request.headers.get('x-requested-with') == 'XMLHttpRequest':
            return JsonResponse({'ok': False, 'message': 'User not found.'}, status=404)
        messages.error(request, "User not found.")
        return redirect('core:login')

    # Throttle: prevent spamming OTP
    last_otp = MobileOTP.objects.filter(user=user).order_by('-created_at').first()
    if last_otp and (timezone.now() - last_otp.created_at).total_seconds() < 60:
        wait = 60 - int((timezone.now() - last_otp.created_at).total_seconds())
        if request.headers.get('x-requested-with') == 'XMLHttpRequest':
            return JsonResponse({'ok': False, 'message': f'Please wait {wait}s before resending OTP.'}, status=429)
        messages.error(request, f"Please wait {wait}s before resending OTP.")
        return redirect('core:login')

    # Invalidate previous unused OTPs
    MobileOTP.objects.filter(user=user, used=False, purpose='LOGIN').update(used=True)

    # Generate new OTP
    otp_code = str(random.randint(100000, 999999))
    expiry = timezone.now() + datetime.timedelta(minutes=5)
    MobileOTP.objects.create(
        user=user,
        otp=otp_code,
        expires_at=expiry,
        used=False,
        purpose='LOGIN'
    )

    # Send OTP via email
    subject = "Your Vetritech Pay Login OTP"
    message = f"Dear {user.username},\n\nYour new OTP is: {otp_code}\nIt will expire in 5 minutes.\n\nThanks,\nGapyPay Team"
    try:
        send_mail(subject, message, settings.EMAIL_HOST, [user.email], fail_silently=False)
    except Exception as e:
        logger.info(e)

    logger.info(f"[EMAIL RESEND OTP] Sent to {user.email} | OTP: {otp_code}")

    # For AJAX requests (JS fetch in your login.html)
    if request.headers.get('x-requested-with') == 'XMLHttpRequest':
        return JsonResponse({'ok': True, 'message': f'OTP resent successfully to {user.email}.'})

    # For normal form submit
    messages.success(request, f"OTP resent successfully to {user.email}.")
    return redirect('core:login')



from django.views.decorators.http import require_POST
from django.http import JsonResponse
from django.contrib.auth import login as auth_login, authenticate
from django.utils import timezone
import datetime

@require_POST
def ajax_verify_otp(request):
    """
    AJAX endpoint: verify OTP and login user.
    Expects POST: username, otp
    Returns JSON: { ok: bool, message: str, redirect: url }
    """
    username = request.POST.get('username', '').strip()
    otp_input = request.POST.get('otp', '').strip()

    if not username or not otp_input:
        return JsonResponse({'ok': False, 'message': 'Username and OTP are required.'}, status=400)

    user = User.objects.filter(username__iexact=username).first()
    if not user:
        return JsonResponse({'ok': False, 'message': 'User not found.'}, status=404)

    # Find the latest unused OTP for LOGIN purpose
    otp_obj = MobileOTP.objects.filter(user=user, used=False, purpose='LOGIN').order_by('-created_at').first()
    if not otp_obj:
        return JsonResponse({'ok': False, 'message': 'No active OTP found. Please request again.'}, status=400)

    # Expiry
    if otp_obj.expires_at < timezone.now():
        otp_obj.used = True
        otp_obj.save()
        return JsonResponse({'ok': False, 'message': 'OTP expired. Request a new one.'}, status=400)

    # Attempts limit
    MAX_VERIFY = getattr(settings, 'MAX_VERIFY_ATTEMPTS', 5)
    if getattr(otp_obj, 'attempts', 0) >= MAX_VERIFY:
        otp_obj.used = True
        otp_obj.save()
        return JsonResponse({'ok': False, 'message': 'Too many attempts. OTP invalidated.'}, status=400)

    # Check OTP
    if otp_obj.otp != otp_input:
        otp_obj.attempts = (otp_obj.attempts or 0) + 1
        otp_obj.save()
        remaining = MAX_VERIFY - otp_obj.attempts
        return JsonResponse({'ok': False, 'message': f'Invalid OTP. {remaining} attempts left.'}, status=400)

    # OTP correct: mark used and login
    otp_obj.used = True
    otp_obj.save()

    # Mark user as verified if desired
    user.is_phone_verified = True
    user.save()

    # Login user
    auth_login(request, user)

    return JsonResponse({'ok': True, 'message': 'OTP verified. Logging in...', 'redirect': reverse('core:dashboard')})




# ----------------- Views -----------------
def home_view(request):
    # Simple landing: redirect to login
    return redirect('core:login')




# dashboard page
# core/views.py
import json
import hmac
import hashlib
from decimal import Decimal

from django.shortcuts import render, redirect, get_object_or_404
from django.conf import settings
from django.http import JsonResponse, HttpResponseBadRequest, HttpResponse
from django.contrib.auth.decorators import login_required
from django.views.decorators.csrf import csrf_exempt
from django.urls import reverse
from django.utils import timezone
import django.db.models as models

import razorpay

from .models import Transaction, Notification
from .forms import RegistrationForm  # you already have forms; used only if needed

# Razorpay client (test)
razorpay_client = razorpay.Client(auth=(settings.RAZORPAY_KEY_ID, settings.RAZORPAY_KEY_SECRET))


@login_required
def dashboard_view(request):
    user = request.user
    # basic aggregates
    recent_txns = user.transactions.order_by('-created_at')[:10]
    total_sent = user.transactions.filter(status=Transaction.STATUS_SUCCESS).aggregate(
        total=models.Sum('amount'))['total'] or Decimal('0.00')
    logger.info("asd")
    logger.info(settings.RAZORPAY_KEY_ID)
    context = {
        'user': user,
        'recent_txns': recent_txns,
        'total_sent': total_sent,
        'razorpay_key_id': settings.RAZORPAY_KEY_ID,
    }
    return render(request, 'core/dashboard.html', context)



# views.py (top)
from django.contrib.auth.decorators import login_required
from django.http import HttpResponseBadRequest, JsonResponse
from decimal import Decimal
import razorpay
# ... other imports ...


def create_order_razor_view(request):
    if request.method != 'POST':
        return HttpResponseBadRequest("POST required")

    try:
        data = request.POST
        amount = Decimal(data.get('amount'))
        to_upi = data.get('to_upi', '').strip() or None
        provider_pref = data.get('provider', '').strip() or None
    except Exception:
        return JsonResponse({'ok': False, 'message': 'Invalid data'}, status=400)

    if amount <= 0:
        return JsonResponse({'ok': False, 'message': 'Amount must be positive'}, status=400)

    # safe: request.user is guaranteed to be a real User here
    txn = Transaction.objects.create(
        user=request.user,
        amount=amount,
        to_upi=to_upi,
        provider=provider_pref,
        status=Transaction.STATUS_PENDING,
        created_at=timezone.now()
    )

    amount_paise = int(amount * Decimal('100'))
    try:
        razor_order = razorpay_client.order.create({
            'amount': amount_paise,
            'currency': 'INR',
            'receipt': f"txn_{txn.id}",
            'payment_capture': 1,
        })
    except Exception as e:
        txn.mark_failed(reason=str(e))
        return JsonResponse({'ok': False, 'message': 'Razorpay order creation failed', 'detail': str(e)}, status=500)

    txn.razorpay_order_id = razor_order.get('id')
    txn.save(update_fields=['razorpay_order_id'])

    return JsonResponse({
        'ok': True,
        'order_id': razor_order.get('id'),
        'txn_id': txn.id,
        'amount_paise': amount_paise
    })



@login_required
def verify_payment_view(request):
    """
    Called by frontend after Razorpay checkout success.
    Expects POST JSON: {razorpay_payment_id, razorpay_order_id, razorpay_signature, txn_id}
    Verifies signature and updates Transaction.
    """
    if request.method != 'POST':
        return HttpResponseBadRequest("POST required")

    razorpay_payment_id = request.POST.get('razorpay_payment_id')
    razorpay_order_id = request.POST.get('razorpay_order_id')
    razorpay_signature = request.POST.get('razorpay_signature')
    txn_id = request.POST.get('txn_id')

    if not (razorpay_payment_id and razorpay_order_id and razorpay_signature and txn_id):
        return JsonResponse({'ok': False, 'message': 'Missing parameters'}, status=400)

    txn = get_object_or_404(Transaction, pk=txn_id, user=request.user)

    # verify signature: hmac_sha256(order_id + "|" + payment_id, secret) == signature
    msg = f"{razorpay_order_id}|{razorpay_payment_id}".encode('utf-8')
    expected = hmac.new(settings.RAZORPAY_KEY_SECRET.encode('utf-8'), msg, hashlib.sha256).hexdigest()
    if expected != razorpay_signature:
        txn.mark_failed(reason='Signature mismatch')
        return JsonResponse({'ok': False, 'message': 'Signature verification failed'}, status=400)

    # optionally call Razorpay API to fetch payment details and confirm status
    try:
        payment = razorpay_client.payment.fetch(razorpay_payment_id)
    except Exception as e:
        txn.mark_failed(reason=str(e))
        return JsonResponse({'ok': False, 'message': 'Failed to fetch payment from Razorpay'}, status=500)

    # check captured status
    if payment.get('status') == 'captured':
        txn.mark_success(payment_id=razorpay_payment_id, signature=razorpay_signature)
        # add notification
        Notification.objects.create(user=request.user, message=f"Payment of ₹{txn.amount} successful (Payment ID {razorpay_payment_id}).")
        # optionally send SMS/email here using Twilio/email functions you already have
        return JsonResponse({'ok': True, 'message': 'Payment verified', 'txn_id': txn.id})
    else:
        txn.mark_failed(reason=f"Razorpay payment status: {payment.get('status')}")
        return JsonResponse({'ok': False, 'message': 'Payment not captured'}, status=400)


@csrf_exempt
def razorpay_webhook(request):
    """
    Webhook endpoint for Razorpay. Configure this URL in Razorpay dashboard webhook settings.
    Verify signature header 'X-Razorpay-Signature'.
    This updates transactions to success/failed as events arrive.
    """
    payload = request.body
    sig = request.META.get('HTTP_X_RAZORPAY_SIGNATURE', '')

    # Verify using HMAC SHA256 of payload with secret
    expected_sig = hmac.new(settings.RAZORPAY_KEY_SECRET.encode('utf-8'), payload, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected_sig, sig):
        return HttpResponse(status=400)

    event = json.loads(payload.decode('utf-8'))
    # Example event handling
    event_type = event.get('event')
    data = event.get('payload', {})

    # handle payment captured
    if event_type == 'payment.captured':
        payment_entity = data.get('payment', {}).get('entity', {})
        razorpay_payment_id = payment_entity.get('id')
        razorpay_order_id = payment_entity.get('order_id')
        amount = payment_entity.get('amount')  # paise

        # find transaction by order id
        txn = Transaction.objects.filter(razorpay_order_id=razorpay_order_id).first()
        if txn:
            txn.mark_success(payment_id=razorpay_payment_id)
            Notification.objects.create(user=txn.user, message=f"Payment of ₹{txn.amount} succeeded via webhook.")
    elif event_type == 'payment.failed':
        payment_entity = data.get('payment', {}).get('entity', {})
        razorpay_order_id = payment_entity.get('order_id')
        reason = payment_entity.get('error_description') or 'payment failed'
        txn = Transaction.objects.filter(razorpay_order_id=razorpay_order_id).first()
        if txn:
            txn.mark_failed(reason=reason)
            Notification.objects.create(user=txn.user, message=f"Payment failed: {reason}")

    return HttpResponse(status=200)


import json
import hmac
import hashlib
from decimal import Decimal, InvalidOperation

from django.http import JsonResponse, HttpResponseBadRequest
from django.contrib.auth.decorators import login_required

# --- helper to safely mark a transaction failed without raising ---
def _safe_mark_failed(txn, reason):
    """
    Try to call txn.mark_failed(reason=...), otherwise set a status field
    and save gracefully. Prevents error-paths from raising secondary exceptions.
    """
    try:
        if hasattr(txn, 'mark_failed'):
            txn.mark_failed(reason=str(reason))
            return
    except Exception:
        # swallow and try fallback below
        pass

    try:
        # best-effort fallback updates
        if hasattr(txn, 'status'):
            failed_val = getattr(txn.__class__, 'STATUS_FAILED', None)
            txn.status = failed_val if failed_val is not None else 'failed'
        if hasattr(txn, 'failure_reason'):
            txn.failure_reason = str(reason)
        elif hasattr(txn, 'failure_note'):
            txn.failure_note = str(reason)
        try:
            txn.save()
        except Exception:
            pass
    except Exception:
        pass



def create_order_view(request):
    logger.info(request.user)
    """
    AJAX endpoint to create a Transaction (PENDING) and (optionally) a Razorpay Order.
    Expects POST: { amount: '500.00', to_upi: 'name@upi', provider: 'gpay'|'razorpay' }
    Returns JSON: { ok: True, order_id: 'order_xxx' or null, txn_id: <id>, amount_paise: 50000 }
    """

    if request.method != 'POST':
        return HttpResponseBadRequest("POST required")

    # Parse + validate inputs
    try:
        data = request.POST
        raw_amount = data.get('amount')
        if raw_amount is None:
            return JsonResponse({'ok': False, 'message': 'Missing amount'}, status=400)
        try:
            amount = Decimal(raw_amount)
        except (InvalidOperation, TypeError, ValueError):
            return JsonResponse({'ok': False, 'message': 'Invalid amount'}, status=400)

        to_upi = data.get('to_upi', '').strip() or None
        provider_pref = (data.get('provider', '') or '').strip().lower() or None
        txn_num = request.POST.get('txn_num')
    except Exception:
        return JsonResponse({'ok': False, 'message': 'Invalid data'}, status=400)

    if amount <= 0:
        return JsonResponse({'ok': False, 'message': 'Amount must be positive'}, status=400)

    # create local Transaction (PENDING)
    txn = Transaction.objects.create(
        user=request.user,
        amount=amount,
        to_upi=to_upi,
        provider=provider_pref,
        status=Transaction.STATUS_PENDING,
        created_at=timezone.now(),
        txn_num=txn_num or None
    )

    # amount in paise
    amount_paise = int(amount * 100)


    # For UPI-app providers (gpay, phonepe, bhim, or unspecified), do NOT call Razorpay.
    # Return txn info so frontend can open intent or show QR (upi:// or intent://)
    return JsonResponse({
        'ok': True,
        'order_id': None,
        'txn_id': txn.txn_num or txn.id,
        'amount_paise': amount_paise
    })

from django.core.mail import send_mail
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail

@require_POST
def i_paid(request):
    """
    Confirm payment by txn_num sent from browser localStorage.
    Expects JSON body: {"txn_num": "TXN..."}
    """
    message = Mail(
    from_email='mathivarmaganesan@gmail.com',
    to_emails='devakimathivarma@gmail.com',
    subject='Sending with Twilio SendGrid is Fun',
    html_content='<strong>and easy to do anywhere, even with Python</strong>')
    try:
        import os
        sg = SendGridAPIClient(os.environ.get('SENDGRID_API_KEY'))
        # sg.set_sendgrid_data_residency("eu")
        # uncomment the above line if you are sending mail using a regional EU subuser
        response = sg.send(message)
        # print(response.status_code)
        # # print(response.body)
        # print(response.headers)
    except Exception as e:
        print(e)
    try:
        payload = json.loads(request.body.decode('utf-8'))
        txn_num = payload.get('txn_numb')
        
    except Exception:
        return JsonResponse({'ok': False, 'message': 'Invalid request'}, status=400)

    if not txn_num:
        return JsonResponse({'ok': False, 'message': 'Missing txn_num'}, status=400)

    try:
        txn = Transaction.objects.get(user=request.user, txn_num=txn_num, status='PENDING')
    except Transaction.DoesNotExist:
        return JsonResponse({'ok': False, 'message': 'Transaction not found or already processed'}, status=404)

    # mark paid
    txn.status = Transaction.STATUS_SUCCESS if hasattr(Transaction, 'STATUS_SUCCESS') else 'PAID'
    txn.save(update_fields=['status', 'updated_at'])

    # send email (customize recipients)
    try:
        subject = f'Payment received: {txn.txn_num} — ₹{txn.amount}'
        message_text = f'User {request.user} confirmed payment for {txn.to_upi}. Txn: {txn.txn_num}'

        mail = Mail(
            from_email=settings.DEFAULT_FROM_EMAIL,
            to_emails=settings.DEFAULT_NOTIFICATION_EMAIL,  # send to yourself/dev email
            subject=subject,
            html_content=f"<pre>{message_text}</pre>"
            )

        sg = SendGridAPIClient(os.environ.get('SENDGRID_API_KEY'))
        print('about tosend')
        sg.send(mail)   # ← no storing, no printing, no response needed
        print('about sent')

        messages.success(request, "Marked paid and email notification sent.")
    except Exception as e:
        # email failure does not prevent success; report it optionally
        return JsonResponse({'ok': False, 'message': 'Marked paid but failed to send email', 'error': str(e)}, status=500)

    return JsonResponse({'ok': True, 'message': 'Marked paid'})



@login_required
def verify_payment_view(request):
    """
    Called by frontend after Razorpay checkout success.
    Expects POST JSON: {razorpay_payment_id, razorpay_order_id, razorpay_signature, txn_id}
    Verifies signature and updates Transaction.
    """
    if request.method != 'POST':
        return HttpResponseBadRequest("POST required")

    razorpay_payment_id = request.POST.get('razorpay_payment_id')
    razorpay_order_id = request.POST.get('razorpay_order_id')
    razorpay_signature = request.POST.get('razorpay_signature')
    txn_id = request.POST.get('txn_id')

    if not (razorpay_payment_id and razorpay_order_id and razorpay_signature and txn_id):
        return JsonResponse({'ok': False, 'message': 'Missing parameters'}, status=400)

    txn = get_object_or_404(Transaction, pk=txn_id, user=request.user)

    # verify signature: hmac_sha256(order_id + "|" + payment_id, secret) == signature
    try:
        msg = f"{razorpay_order_id}|{razorpay_payment_id}".encode('utf-8')
        expected = hmac.new(settings.RAZORPAY_KEY_SECRET.encode('utf-8'), msg, hashlib.sha256).hexdigest()
    except Exception:
        _safe_mark_failed(txn, 'Signature verification setup error')
        return JsonResponse({'ok': False, 'message': 'Signature verification failed'}, status=400)

    if expected != razorpay_signature:
        _safe_mark_failed(txn, 'Signature mismatch')
        return JsonResponse({'ok': False, 'message': 'Signature verification failed'}, status=400)

    # optionally call Razorpay API to fetch payment details and confirm status
    try:
        payment = razorpay_client.payment.fetch(razorpay_payment_id)
    except Exception as e:
        _safe_mark_failed(txn, str(e))
        return JsonResponse({'ok': False, 'message': 'Failed to fetch payment from Razorpay'}, status=500)

    # check captured status
    if payment.get('status') == 'captured':
        try:
            txn.mark_success(payment_id=razorpay_payment_id, signature=razorpay_signature)
        except Exception:
            # fallback if mark_success doesn't exist
            try:
                txn.status = getattr(Transaction, 'STATUS_SUCCESS', 'success')
                txn.save()
            except Exception:
                pass

        # add notification
        try:
            Notification.objects.create(user=request.user, message=f"Payment of ₹{txn.amount} successful (Payment ID {razorpay_payment_id}).")
        except Exception:
            pass

        return JsonResponse({'ok': True, 'message': 'Payment verified', 'txn_id': txn.id})
    else:
        _safe_mark_failed(txn, f"Razorpay payment status: {payment.get('status')}")
        return JsonResponse({'ok': False, 'message': 'Payment not captured'}, status=400)


@csrf_exempt
def razorpay_webhook(request):
    """
    Webhook endpoint for Razorpay. Configure this URL in Razorpay dashboard webhook settings.
    Verify signature header 'X-Razorpay-Signature'.
    This updates transactions to success/failed as events arrive.
    """
    payload = request.body
    sig = request.META.get('HTTP_X_RAZORPAY_SIGNATURE', '')

    # Verify using HMAC SHA256 of payload with secret
    try:
        expected_sig = hmac.new(settings.RAZORPAY_KEY_SECRET.encode('utf-8'), payload, hashlib.sha256).hexdigest()
    except Exception:
        return HttpResponse(status=400)

    if not hmac.compare_digest(expected_sig, sig):
        return HttpResponse(status=400)

    try:
        event = json.loads(payload.decode('utf-8'))
    except Exception:
        return HttpResponse(status=400)

    event_type = event.get('event')
    data = event.get('payload', {})

    # handle payment captured
    if event_type == 'payment.captured':
        payment_entity = data.get('payment', {}).get('entity', {})
        razorpay_payment_id = payment_entity.get('id')
        razorpay_order_id = payment_entity.get('order_id')
        amount = payment_entity.get('amount')  # paise

        # find transaction by order id
        txn = Transaction.objects.filter(razorpay_order_id=razorpay_order_id).first()
        if txn:
            try:
                txn.mark_success(payment_id=razorpay_payment_id)
            except Exception:
                try:
                    txn.status = getattr(Transaction, 'STATUS_SUCCESS', 'success')
                    txn.save()
                except Exception:
                    pass
            try:
                Notification.objects.create(user=txn.user, message=f"Payment of ₹{txn.amount} succeeded via webhook.")
            except Exception:
                pass

    elif event_type == 'payment.failed':
        payment_entity = data.get('payment', {}).get('entity', {})
        razorpay_order_id = payment_entity.get('order_id')
        reason = payment_entity.get('error_description') or 'payment failed'
        txn = Transaction.objects.filter(razorpay_order_id=razorpay_order_id).first()
        if txn:
            _safe_mark_failed(txn, reason)
            try:
                Notification.objects.create(user=txn.user, message=f"Payment failed: {reason}")
            except Exception:
                pass

    return HttpResponse(status=200)


# recharge
import json
from decimal import Decimal
from django.shortcuts import render, redirect, get_object_or_404
from django.urls import reverse
from django.conf import settings
from django.http import JsonResponse, HttpResponseBadRequest
from django.views.decorators.http import require_POST
from django.views.decorators.csrf import ensure_csrf_cookie
from .models import Operator, RechargePlan, RechargeOrder

# ---------------- Dashboard ----------------
def dashboard_view(request):
    user = request.user
    recent_txns = user.transactions.order_by('-created_at')[:20]
    operators = Operator.objects.all()[:6]
    recent = RechargeOrder.objects.order_by('-created_at')[:6]
    return render(request, "core/dashboard.html", {"operators": operators, "recent": recent,'razorpay_key_id': settings.RAZORPAY_KEY_ID,'recent_txns':recent_txns})


# ---------------- Recharge page ----------------
def recharge_view(request):
    operators = Operator.objects.all().order_by("name")
    return render(request, "core/recharge.html", {"operators": operators})

# ---------------- Plans API (AJAX) ----------------
def api_get_plans(request, operator_code):
    try:
        op = Operator.objects.get(code=operator_code)
    except Operator.DoesNotExist:
        return JsonResponse({"ok": False, "error": "Operator not found"}, status=404)

    plans_qs = op.plans.all()
    if plans_qs.exists():
        plans = [{"id": p.id, "title": p.title, "amount": float(p.amount), "validity": p.validity, "desc": p.description} for p in plans_qs]
        return JsonResponse({"ok": True, "plans": plans})
    else:
        # Fallback mock plans (replace with provider call if you prefer)
        mock = [
            {"id": "P100", "title": "Talktime - ₹49", "amount": 49.00, "validity": "NA", "desc": "Instant talktime"},
            {"id": "P200", "title": "Data - ₹99", "amount": 99.00, "validity": "28 days", "desc": "1GB/day pack"},
            {"id": "P300", "title": "Full plan - ₹199", "amount": 199.00, "validity": "56 days", "desc": "Data + calls"},
        ]
        return JsonResponse({"ok": True, "plans": mock})

# ---------------- Create order and redirect to UPI page ----------------
@require_POST
def create_recharge(request):
    mobile = request.POST.get("mobile", "").strip()
    operator_code = request.POST.get("operator")
    plan_id = request.POST.get("plan_id")
    amount = request.POST.get("amount")

    if not mobile or not amount:
        return HttpResponseBadRequest("mobile and amount are required")

    try:
        amount_val = Decimal(amount)
        if amount_val <= 0:
            return HttpResponseBadRequest("invalid amount")
    except:
        return HttpResponseBadRequest("invalid amount format")

    operator = Operator.objects.filter(code=operator_code).first() if operator_code else None
    plan = RechargePlan.objects.filter(pk=plan_id).first() if plan_id else None

    order = RechargeOrder.objects.create(
        user=request.user if request.user.is_authenticated else None,
        mobile=mobile,
        operator=operator,
        plan=plan,
        amount=amount_val,
        status="INITIATED"
    )

    return redirect(reverse("core:recharge_upi_page", kwargs={"order_id": order.id}))

# ---------------- UPI page (GET shows page; POST used by AJAX to submit TXN id) ----------------
@ensure_csrf_cookie
def recharge_upi_page(request, order_id):
    order = get_object_or_404(RechargeOrder, pk=order_id)

    if request.method == "POST":
        # Accept JSON { upi_tid: "..." } from frontend
        try:
            data = json.loads(request.body.decode())
            tid = data.get("upi_tid")
            if not tid:
                return JsonResponse({"ok": False, "error": "No tid provided"}, status=400)
            # Save tid and mark as PAID
            order.upi_tid = tid
            order.status = "PAID"
            order.save()
            # Immediately call provider to perform recharge (mocked)
            provider_resp = call_recharge_provider(order)
            # Update based on provider response
            if provider_resp.get("status") == "SUCCESS":
                order.status = "SUCCESS"
                order.provider_txn = provider_resp.get("provider_txn", "")
            elif provider_resp.get("status") == "FAILED":
                order.status = "FAILED"
                order.notes = provider_resp.get("message", "")
            else:
                order.status = "PROCESSING"
                order.provider_txn = provider_resp.get("provider_txn", "")
                order.notes = provider_resp.get("message", "")
            order.save()
            return JsonResponse({"ok": True, "provider": provider_resp})
        except Exception as e:
            return JsonResponse({"ok": False, "error": str(e)}, status=400)

    # GET: build upi params for front-end to open
    upi_vpa = getattr(settings, "MERCHANT_UPI", "yourmerchant@bank")
    upi_name = getattr(settings, "MERCHANT_NAME", "GapyPay")
    note = f"Recharge {order.mobile} order:{order.id}"
    upi_params = {
        "pa": upi_vpa,
        "pn": upi_name,
        "am": str(order.amount),
        "tn": note,
        "tid": str(order.id),
        "cu": "INR",
    }
    return render(request, "core/recharge_upi_page.html", {"order": order, "upi_params": upi_params})

# ---------------- Submit TXN via regular POST fallback (form submit) ----------------
@require_POST
def submit_upi_tid(request, order_id):
    order = get_object_or_404(RechargeOrder, pk=order_id)
    tid = request.POST.get("upi_tid", "").strip()
    if not tid:
        return redirect(reverse("core:recharge_upi_page", kwargs={"order_id": order.id}))
    order.upi_tid = tid
    order.status = "PAID"
    order.save()
    provider_resp = call_recharge_provider(order)
    if provider_resp.get("status") == "SUCCESS":
        order.status = "SUCCESS"
        order.provider_txn = provider_resp.get("provider_txn", "")
    elif provider_resp.get("status") == "FAILED":
        order.status = "FAILED"
        order.notes = provider_resp.get("message", "")
    else:
        order.status = "PROCESSING"
        order.provider_txn = provider_resp.get("provider_txn", "")
    order.save()
    return redirect(reverse("core:recharge_upi_page", kwargs={"order_id": order.id}))

# ---------------- Mock provider call ----------------
def call_recharge_provider(order: RechargeOrder):
    """
    Replace this with real provider integration. For Option 1 you still need
    a recharge provider (Roundpay/Scriza/A1Topup) to actually perform the recharge.
    This mock simulates success/failure.
    """
    try:
        import random, time
        time.sleep(0.4)
        outcome = random.choices(["SUCCESS", "PROCESSING", "FAILED"], weights=[0.75, 0.18, 0.07], k=1)[0]
        provider_txn = f"MOCK{random.randint(111111,999999)}"
        return {"status": outcome, "provider_txn": provider_txn, "message": "Mock response"}
    except Exception as e:
        return {"status": "PROCESSING", "provider_txn": "", "message": str(e)}


from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from .models import Transaction


from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.shortcuts import render
from .models import Transaction
from django.urls import reverse

@login_required
def transactions_view(request):
    """
    Render dashboard with recent transactions for the logged-in user.
    Shows the latest 20 by default. If the request is AJAX, return JSON.
    """
    recent_txns = (
        Transaction.objects
        .filter(user=request.user)
        .order_by('-created_at')[:20]   # latest first, limit 20
    )

    # Robust AJAX detection
    if request.headers.get('x-requested-with', '').lower() == 'xmlhttprequest':
        data = []
        for t in recent_txns:
            # Build a minimal retry_url if you want to surface an action for pending txns.
            # Example: if provider is 'razorpay' you might link back to a retry/pay page.
            retry_url = ''
            # if t.status.lower() == 'pending' and t.provider == 'razorpay':
            #     retry_url = reverse('core:retry_payment', args=[t.id])

            data.append({
                'id': t.id,                              # stable numeric id (used to fetch detail)
                'txn_num': getattr(t, 'txn_num', '') or '',  # optional fallback token
                'date': t.created_at.strftime("%b %d, %H:%M"),
                'to': t.to_upi or getattr(t, 'to', '-') or '-',
                'amount': float(t.amount or 0),
                'provider': t.provider or '-',
                'status': t.status or '-',
                'retry_url': retry_url,
                
            })
        return JsonResponse({"ok": True, "transactions": data})

    # Non-AJAX (normal page render)
    return render(request, "core/dashboard.html", {
        'recent_txns': recent_txns
    })


# transdetails
from django.http import JsonResponse, Http404
from django.contrib.auth.decorators import login_required
from .models import Transaction

@login_required
def transaction_detail(request, txn_id):
    # Accept AJAX only ideally
    print('comin')
    try:
        txn = Transaction.objects.get(id=txn_id)
    except Transaction.DoesNotExist:
        raise Http404("Transaction not found")

    # Build timeline list (example; adapt to your model fields)
    timeline = []
    timeline.append({'event': 'Created', 'at': txn.created_at.isoformat()})
    if txn.qr_generated_at: timeline.append({'event':'QR Generated','at': txn.qr_generated_at.isoformat()})
    if txn.i_paid_at: timeline.append({'event':'I-Paid Submitted','at': txn.i_paid_at.isoformat()})
    if txn.razorpay_paid_at: timeline.append({'event':'Razorpay Paid','at': txn.razorpay_paid_at.isoformat()})
    # More events...

    data = {
        'id': txn.id,
        'txn_num': txn.txn_num,
        'to': txn.to_upi,
        'amount': float(txn.amount),
        'status': txn.status,
        'provider': txn.provider,
        'created_at': txn.created_at.strftime('%Y-%m-%d %H:%M:%S %Z'),
        'razorpay_order_id': txn.razorpay_order_id,
        'razorpay_payment_id': txn.razorpay_payment_id,
        'upi_reference': txn.upi_reference,
        'timeline': timeline,
        # raw payloads if you store them
        'raw_payload': txn.raw_payload or {},
        # optional action link for pending payments (retry) or recharge page
        'retry_url': txn.get_retry_url() if hasattr(txn,'get_retry_url') else '',
        'qr_generated_at': txn.qr_generated_at and txn.qr_generated_at.strftime('%Y-%m-%d %H:%M:%S') or '',
'i_paid_at': txn.i_paid_at and txn.i_paid_at.strftime('%Y-%m-%d %H:%M:%S') or '',
'razorpay_paid_at': txn.razorpay_paid_at and txn.razorpay_paid_at.strftime('%Y-%m-%d %H:%M:%S') or '',
'verified_at': txn.verified_at and txn.verified_at.strftime('%Y-%m-%d %H:%M:%S') or '',
'upi_reference': txn.upi_reference or '',
'raw_payload': txn.raw_payload or {},
'retry_url': txn.get_retry_url(),
    }
    return JsonResponse({'ok': True, 'transaction': data})


# core/views.py (example)
import json
from django.http import JsonResponse, HttpResponseBadRequest
from django.views.decorators.http import require_POST
from django.views.decorators.csrf import csrf_exempt  # not needed if using CSRF token properly
from django.utils.dateparse import parse_date
from django.db.models import Q
from .models import Transaction  # your model

@require_POST
def filter_transactions_api(request):
    try:
        payload = json.loads(request.body.decode('utf-8') or '{}')
    except json.JSONDecodeError:
        return HttpResponseBadRequest('Invalid JSON')

    q = (payload.get('q') or '').strip()
    date_from = parse_date(payload.get('date_from'))  # returns None if invalid
    date_to = parse_date(payload.get('date_to'))
    status = (payload.get('status') or '').strip().lower()

    qs = Transaction.objects.all()

    if q:
        # search in UPI id, txn id, receiver name, provider — adjust fields
        qs = qs.filter(
            Q(to_upi__icontains=q) |
            Q(txn_num__icontains=q) |
            Q(provider__icontains=q) |
            Q(amount__icontains=q)
        )

    if date_from:
        qs = qs.filter(created_at__date__gte=date_from)  # if date is DateTimeField
    if date_to:
        qs = qs.filter(created_at__date__lte=date_to)

    if status:
        qs = qs.filter(status__iexact=status)

    # order and limit results (optional)
    qs = qs.order_by('-created_at')[:200]

    # build JSON response
    transactions = []
    for t in qs:
        transactions.append({
            'id': t.id,
            'date': t.created_at.strftime('%Y-%m-%d %H:%M') if t.created_at else '',
            'to': t.to_upi,
            'txn_id': t.txn_num,
            'amount': float(t.amount),
            'provider': t.provider,
            'status': t.status.lower()
        })

    return JsonResponse({'transactions': transactions})


# core/views.py
import json
from datetime import timedelta

from django.conf import settings
from django.contrib.admin.views.decorators import staff_member_required
from django.contrib.auth import get_user_model
from django.db.models import Count, Sum
from django.db.models.functions import TruncDate
from django.shortcuts import render
from django.utils import timezone

from .models import (
    Transaction,
    TestKYC,
    LiveKYC,
    TestKeys,
    SandboxKey,
)
from .models import PaymentSession   # <- from payments/models.py


@staff_member_required
def admin_analytics_view(request):
    """
    Admin-only analytics dashboard with:
    - Merchant / KYC stats
    - Payment / Transaction stats
    - Sandbox (PaymentSession) usage
    """
    User = get_user_model()

    # ----- Dates / ranges -----
    now = timezone.now()
    if timezone.is_naive(now):
        now = timezone.make_aware(now, timezone.get_default_timezone())
    today = now.date()
    days = 14
    start_date = today - timedelta(days=days - 1)

    # ==========================
    # 1) MERCHANT / KYC METRICS
    # ==========================
    total_merchants = User.objects.count()

    test_kyc_total = TestKYC.objects.count()
    test_kyc_approved = TestKYC.objects.filter(is_verified=True).count()

    live_kyc_total = LiveKYC.objects.count()
    live_kyc_approved = LiveKYC.objects.filter(is_verified=True).count()

    test_keys_total = TestKeys.objects.count()
    sandbox_keys_total = SandboxKey.objects.count()

    # KYC funnel (for chart)
    kyc_funnel_labels = [
        "Registered",
        "Test KYC Submitted",
        "Test KYC Approved",
        "Live KYC Submitted",
        "Live KYC Approved",
    ]
    kyc_funnel_counts = [
        total_merchants,
        test_kyc_total,
        test_kyc_approved,
        live_kyc_total,
        live_kyc_approved,
    ]

    # ==========================
    # 2) PAYMENT / TRANSACTIONS
    # ==========================
    tx_qs = Transaction.objects.all()

    success_val = getattr(Transaction, "STATUS_SUCCESS", "SUCCESS")
    pending_val = getattr(Transaction, "STATUS_PENDING", "PENDING")
    failed_val = getattr(Transaction, "STATUS_FAILED", "FAILED")

    total_txns = tx_qs.count()
    success_count = tx_qs.filter(status__iexact=success_val).count()
    pending_count = tx_qs.filter(status__iexact=pending_val).count()
    failed_count = tx_qs.filter(status__iexact=failed_val).count()

    total_amount = tx_qs.aggregate(total=Sum("amount"))["total"] or 0
    total_amount = float(total_amount)

    avg_ticket_size = float(total_amount / total_txns) if total_txns else 0.0
    success_rate = float(success_count * 100.0 / total_txns) if total_txns else 0.0

    # Active users in period (any txn in last N days)
    active_users = (
        tx_qs.filter(created_at__date__gte=start_date)
        .values("user_id")
        .distinct()
        .count()
    )

    # Transactions per day (bar chart)
    daily_tx_qs = (
        tx_qs.filter(created_at__date__gte=start_date)
        .annotate(day=TruncDate("created_at"))
        .values("day")
        .annotate(count=Count("id"))
        .order_by("day")
    )
    day_map = {row["day"]: row["count"] for row in daily_tx_qs}

    tx_labels = []
    tx_series = []
    for i in range(days):
        d = start_date + timedelta(days=i)
        tx_labels.append(d.strftime("%Y-%m-%d"))
        tx_series.append(day_map.get(d, 0))

    # Status distribution (donut)
    status_dist_qs = tx_qs.values("status").annotate(count=Count("id"))
    status_labels = []
    status_counts = []
    for row in status_dist_qs:
        status_labels.append((row["status"] or "Unknown").title())
        status_counts.append(row["count"])

    # Provider distribution (top 10)
    provider_qs = (
        tx_qs.values("provider")
        .annotate(count=Count("id"))
        .order_by("-count")[:10]
    )
    provider_labels = [row["provider"] or "Unknown" for row in provider_qs]
    provider_counts = [row["count"] for row in provider_qs]

    # Top merchants by volume (small table)
    top_merchants_qs = (
        tx_qs.values("user_id", "user__username")
        .annotate(tx_count=Count("id"), tx_amount=Sum("amount"))
        .order_by("-tx_amount")[:5]
    )
    top_merchants = [
        {
            "username": row["user__username"] or f"User {row['user_id']}",
            "tx_count": row["tx_count"],
            "tx_amount": float(row["tx_amount"] or 0),
        }
        for row in top_merchants_qs
    ]

    # ==========================
    # 3) SANDBOX / PAYMENTSESSION
    # ==========================
    ps_qs = PaymentSession.objects.all()
    sandbox_total_sessions = ps_qs.count()
    sandbox_success = ps_qs.filter(status="success").count()
    sandbox_pending = ps_qs.filter(status="pending").count()
    sandbox_failed = ps_qs.filter(status="failed").count()

    # daily sandbox sessions (line chart)
    sandbox_daily_qs = (
        ps_qs.filter(created_at__date__gte=start_date)
        .annotate(day=TruncDate("created_at"))
        .values("day")
        .annotate(count=Count("id"))
        .order_by("day")
    )
    sandbox_day_map = {row["day"]: row["count"] for row in sandbox_daily_qs}

    sandbox_labels = []
    sandbox_series = []
    for i in range(days):
        d = start_date + timedelta(days=i)
        sandbox_labels.append(d.strftime("%Y-%m-%d"))
        sandbox_series.append(sandbox_day_map.get(d, 0))

    # sandbox status distribution
    sandbox_status_qs = ps_qs.values("status").annotate(count=Count("id"))
    sandbox_status_labels = []
    sandbox_status_counts = []
    for row in sandbox_status_qs:
        sandbox_status_labels.append((row["status"] or "unknown").title())
        sandbox_status_counts.append(row["count"])

    context = {
        # ---- Merchant / KYC cards ----
        "total_merchants": total_merchants,
        "test_kyc_total": test_kyc_total,
        "test_kyc_approved": test_kyc_approved,
        "live_kyc_total": live_kyc_total,
        "live_kyc_approved": live_kyc_approved,
        "test_keys_total": test_keys_total,
        "sandbox_keys_total": sandbox_keys_total,
        "kyc_funnel_labels_json": json.dumps(kyc_funnel_labels),
        "kyc_funnel_counts_json": json.dumps(kyc_funnel_counts),

        # ---- Transactions / payments cards ----
        "total_txns": total_txns,
        "success_count": success_count,
        "pending_count": pending_count,
        "failed_count": failed_count,
        "total_amount": total_amount,
        "avg_ticket_size": avg_ticket_size,
        "success_rate": success_rate,
        "active_users": active_users,

        # charts
        "labels_json": json.dumps(tx_labels),
        "series_json": json.dumps(tx_series),
        "status_labels_json": json.dumps(status_labels),
        "status_counts_json": json.dumps(status_counts),
        "provider_labels_json": json.dumps(provider_labels),
        "provider_counts_json": json.dumps(provider_counts),

        # top merchants table
        "top_merchants": top_merchants,

        # ---- Sandbox / PaymentSession ----
        "sandbox_total_sessions": sandbox_total_sessions,
        "sandbox_success": sandbox_success,
        "sandbox_pending": sandbox_pending,
        "sandbox_failed": sandbox_failed,
        "sandbox_labels_json": json.dumps(sandbox_labels),
        "sandbox_series_json": json.dumps(sandbox_series),
        "sandbox_status_labels_json": json.dumps(sandbox_status_labels),
        "sandbox_status_counts_json": json.dumps(sandbox_status_counts),
    }

    return render(request, "admin/analytics.html", context)

from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from .models import TestKYC, LiveKYC

# ---------- TEST MODE (single page) ----------

@login_required
def test_kyc_view(request):
    """
    Render the single-page Test Mode KYC form.
    The form posts to test_kyc_submit.
    """
    return render(request, "kyc/test_kyc.html")


@login_required
def test_kyc_submit(request):
    """
    Handle final POST from the single-page Test Mode form.
    Save fields and files to TestKYC model (no verification logic here).
    """
    print('coming kyc')
    if request.method != "POST":
        return redirect("kyc:test_view")  # adjust name in urls if needed

    # Get or create the user's TestKYC record
    kyc, _ = TestKYC.objects.get_or_create(user=request.user)

    # Text fields
    kyc.full_name = request.POST.get("full_name", "").strip()
    kyc.email = request.POST.get("email", "").strip()
    kyc.mobile_number = request.POST.get("mobile_number", "").strip()
    kyc.business_name = request.POST.get("business_name", "").strip()
    kyc.business_type = request.POST.get("business_type", "").strip()
    kyc.address = request.POST.get("address", "").strip()

    kyc.pan_number = request.POST.get("pan_number", "").strip()
    kyc.bank_account_number = request.POST.get("bank_account_number", "").strip()
    kyc.ifsc_code = request.POST.get("ifsc_code", "").strip()

    # Files (only set if provided)
    pan_doc = request.FILES.get("pan_document")
    id_proof = request.FILES.get("id_proof")
    bank_proof = request.FILES.get("bank_proof")
    extra_doc = request.FILES.get("extra_doc")

    if pan_doc:
        kyc.pan_document = pan_doc
    if id_proof:
        kyc.id_proof = id_proof
    if bank_proof:
        kyc.bank_proof = bank_proof
    # you can store extra_doc in a separate model or ignore; here we save to verification_notes for reference
    if extra_doc:
        # if you want to keep a reference, you can append its name to notes (or create model for extras)
        notes = kyc.verification_notes or ""
        notes += f"\nExtra uploaded: {extra_doc.name}"
        kyc.verification_notes = notes

    # Keep default verification flags (no verification performed)
    kyc.save()

    return render(request, "vpay/vpay_dashboard.html")


# ---------- LIVE MODE (single page) ----------

@login_required
def live_kyc_view(request):
    """
    Render the single-page Live Mode KYC form.
    The form posts to live_kyc_submit.
    """
    return render(request, "kyc/live_kyc.html")


@login_required
def live_kyc_submit(request):
    """
    Handle final POST from the single-page Live Mode form.
    Save fields and files to LiveKYC model (no verification logic).
    """
    if request.method != "POST":
        return redirect("kyc:live_view")  # adjust name in urls if needed

    kyc, _ = LiveKYC.objects.get_or_create(user=request.user)

    # Step 1: Aadhaar & Address
    aadhaar_front = request.FILES.get("aadhaar_front")
    aadhaar_back = request.FILES.get("aadhaar_back")
    address_proof = request.FILES.get("address_proof")
    registered_address = request.POST.get("registered_address", "").strip()
    if aadhaar_front:
        kyc.aadhaar_front = aadhaar_front
    if aadhaar_back:
        kyc.aadhaar_back = aadhaar_back
    if address_proof:
        kyc.address_proof = address_proof

    # Step 2: Business proofs
    gst_certificate = request.FILES.get("gst_certificate")
    business_registration_proof = request.FILES.get("business_registration_proof")
    shop_establishment = request.FILES.get("shop_establishment")
    msme_certificate = request.FILES.get("msme_certificate")
    incorporation_or_partnership = request.FILES.get("incorporation_or_partnership")
    if gst_certificate:
        kyc.gst_certificate = gst_certificate
    if business_registration_proof:
        kyc.business_registration_proof = business_registration_proof
    if msme_certificate:
        kyc.msme_certificate = msme_certificate
    # Reuse partnership_deed / incorporation field if provided
    if incorporation_or_partnership:
        kyc.partnership_deed = incorporation_or_partnership

    # Step 3: Director / UBO details (text fields + optional file)
    kyc.director_name = request.POST.get("director_name", "").strip()
    kyc.director_pan = request.POST.get("director_pan", "").strip()
    kyc.director_aadhaar = request.POST.get("director_aadhaar", "").strip()
    kyc.ubo_name = request.POST.get("ubo_name", "").strip()
    kyc.ubo_percentage = request.POST.get("ubo_percentage", "").strip()
    ubo_document = request.FILES.get("ubo_document")
    if ubo_document:
        kyc.ubo_document = ubo_document

    # Step 4: Selfie, signature & bank
    selfie = request.FILES.get("selfie")
    signature = request.FILES.get("signature")
    cancelled_cheque = request.FILES.get("cancelled_cheque")
    board_resolution = request.FILES.get("board_resolution")
    if selfie:
        kyc.selfie = selfie
    if signature:
        kyc.signature = signature
    if cancelled_cheque:
        kyc.cancelled_cheque = cancelled_cheque
    if board_resolution:
        kyc.board_resolution = board_resolution

    # Leave bank_name_match / is_verified as defaults for later verification
    kyc.save()

    return redirect("kyc:status")


# ---------- STATUS PAGE ----------

@login_required
def kyc_status(request):
    test_kyc = TestKYC.objects.filter(user=request.user).first()
    live_kyc = LiveKYC.objects.filter(user=request.user).first()

    return render(request, "kyc/status.html", {
        "test_kyc": test_kyc,
        "live_kyc": live_kyc
    })


# core/views.py
import hashlib
from django.shortcuts import redirect, render
from django.http import JsonResponse, HttpResponseBadRequest, HttpResponseForbidden
from django.utils import timezone
from django.conf import settings
from django.views.decorators.http import require_POST, require_GET
from django.contrib.auth.decorators import login_required
from .models import EmailVerificationToken
from .utils import send_verification_email

# POST: create token and send mail
from django.contrib.auth.decorators import login_required
from django.views.decorators.http import require_POST
from django.utils import timezone
from django.http import JsonResponse

from .models import EmailVerificationToken
from .utils import send_verification_email   # <--- IMPORTANT

import logging
from django.utils import timezone
from django.http import JsonResponse
from django.contrib.auth.decorators import login_required
from django.views.decorators.http import require_POST

from .models import EmailVerificationToken
from .utils import send_verification_email

logger = logging.getLogger(__name__)

@login_required
@require_POST
def send_email_verification(request):
    user = request.user

    # === DEBUG LOG: which user hit this endpoint ===
    logger.info(
        "send_email_verification: user=%s | id=%s | email=%s | ip=%s | ua=%s",
        getattr(user, "username", None),
        getattr(user, "pk", None),
        getattr(user, "email", None),
        request.META.get("REMOTE_ADDR"),
        request.META.get("HTTP_USER_AGENT")
    )

    # === Validate email BEFORE creating token ===
    if not user.email or "@" not in user.email:
        return JsonResponse({
            "ok": False,
            "error": "No valid email found for this account.",
            "debug": {
                "username": getattr(user, "username", None),
                "user_id": getattr(user, "pk", None),
                "email": getattr(user, "email", None),
            }
        }, status=400)

    # === Rate limit ===
    last = EmailVerificationToken.objects.filter(user=user).order_by("-created_at").first()
    if last and (timezone.now() - last.created_at).total_seconds() < 60:
        return JsonResponse({"ok": False, "error": "Please wait before requesting again."}, status=429)

    # === Create token AFTER validation ===
    raw_token, tok_obj = EmailVerificationToken.create_token_for_user(
        user, ttl_hours=24, request=request
    )

    # === Build verify URL ===
    verify_url = request.build_absolute_uri(
        f"/kyc/verify-email/?uid={user.pk}&token={raw_token}"
    )

    # === Send email ===
    try:
        ok = send_verification_email(
            user.email,
            verify_url,
            recipient_name=user.get_full_name()
            
        )
        print(verify_url)
    except Exception as exc:
        logger.exception("Unexpected error during send_verification_email")
        ok = False

    if not ok:
        logger.error("Email send failed for user=%s email=%s", user.username, user.email)

        # DEV ONLY → avoid 429 while testing
        try:
            tok_obj.delete()
        except Exception:
            logger.exception("Failed to delete token after send failure")

        return JsonResponse({
            "ok": False,
            "error": "Failed to send verification email. Check logs for details."
        }, status=500)

    return JsonResponse({"ok": True, "message": "Verification email sent."})




# GET: verify link clicked from email
@require_GET
def verify_email_link(request):
    uid = request.GET.get("uid")
    token = request.GET.get("token")
    if not uid or not token:
        return HttpResponseBadRequest("Invalid verification link.")

    token_hash = hashlib.sha256(token.encode()).hexdigest()
    try:
        tok = EmailVerificationToken.objects.get(user_id=uid, token_hash=token_hash, used_at__isnull=True)
    except EmailVerificationToken.DoesNotExist:
        # show friendly page explaining failure / expiry
        return render(request, "kyc/verify_failed.html", {"reason": "invalid_or_used"})

    if tok.expires_at < timezone.now():
        return render(request, "kyc/verify_failed.html", {"reason": "expired"})

    # mark token used and mark user's email verified
    tok.mark_used()
    u = tok.user
    u.email_verified = True
    u.email_verified_at = timezone.now()
    u.save(update_fields=["email_verified", "email_verified_at"])

    # Redirect to your app page (SPA route) telling frontend to show "verified"
    # e.g. /kyc?email_verified=1&uid=...
    redirect_url = f"/kyc?email_verified=1&uid={u.pk}"
    return redirect(redirect_url)


# GET: API for polling email status (login required)
@login_required
@require_GET
def email_status(request):
    return JsonResponse({"email_verified": bool(request.user.email_verified)})


# core/views.py (add at top)
from django.shortcuts import get_object_or_404, redirect
from django.http import JsonResponse, HttpResponseBadRequest, HttpResponse
from django.views.decorators.http import require_POST, require_GET
from django.contrib.auth.decorators import login_required
from django.utils import timezone
from django.core.validators import validate_email
from django.core.exceptions import ValidationError
from django.urls import reverse

from .models import TestKYC, EmailVerificationToken
from .utils import send_verification_email  # your utility
import hashlib

# ---------- Helper validation ----------
import re
NAME_RE = re.compile(r"^[A-Za-zÀ-ÖØ-öø-ÿ'-. ]{2,120}$")
MOBILE_RE = re.compile(r"^\+?\d{7,15}$")
BUSINESS_RE = re.compile(r"^[A-Za-z0-9&\.\-,/ ]{2,150}$")

def validate_personal_payload(data):
    errors = {}
    name = data.get("full_name", "").strip()
    email = data.get("email", "").strip()
    mobile = data.get("mobile_number", "").strip()
    business_name = data.get("business_name", "").strip()
    address = data.get("address", "").strip()

    if not name or not NAME_RE.match(name):
        errors["full_name"] = "Enter a valid name (letters, spaces, - .' only, min 2 chars)."
    try:
        if email:
            validate_email(email)
        else:
            errors["email"] = "Email is required."
    except ValidationError:
        errors["email"] = "Enter a valid email address."

    if not mobile or not MOBILE_RE.match(mobile):
        errors["mobile_number"] = "Enter a valid mobile (7-15 digits, optional leading +)."

    if not business_name or not BUSINESS_RE.match(business_name):
        errors["business_name"] = "Enter a valid business name."

    if not address or len(address.strip()) < 8 or len(address.split()) < 2:
        errors["address"] = "Enter a valid address (min length, at least two words)."

    return errors

# ---------- API: GET / POST personal ----------
@login_required
@require_GET
def api_get_kyc_personal(request):
    # returns JSON with TestKYC data (or null)
    try:
        tk = TestKYC.objects.get(user=request.user)
    except TestKYC.DoesNotExist:
        return JsonResponse({"exists": False, "data": None})
    data = {
        "exists": True,
        "data": {
            "full_name": tk.full_name,
            "email": tk.email,
            "mobile_number": tk.mobile_number,
            "business_name": tk.business_name,
            "business_type": tk.business_type,
            "address": tk.address,
            "email_verified": tk.email_verified,
            "email_verification_method": tk.email_verification_method,
            "email_verified_at": tk.email_verified_at.isoformat() if tk.email_verified_at else None,
        }
    }
    return JsonResponse(data)

@login_required
@require_POST
def api_save_kyc_personal(request):
    # Accept JSON body or form-encoded
    payload = request.POST or {}
    # If client sent JSON
    if request.content_type == "application/json":
        import json
        try:
            payload = json.loads(request.body.decode())
        except Exception:
            return JsonResponse({"ok": False, "error": "Invalid JSON"}, status=400)

    # validate
    errors = validate_personal_payload(payload)
    if errors:
        return JsonResponse({"ok": False, "errors": errors}, status=400)

    # create or update TestKYC
    tk, created = TestKYC.objects.get_or_create(user=request.user)
    # If email changed and previously verified, clear verification
    new_email = payload.get("email", "").strip()
    if tk.email and new_email and tk.email.lower() != tk.email.lower():
        tk.email_verified = False
        tk.email_verified_at = None
        tk.email_verification_method = None

    tk.full_name = payload.get("full_name").strip()
    tk.email = new_email
    tk.mobile_number = payload.get("mobile_number").strip()
    tk.business_name = payload.get("business_name").strip()
    tk.business_type = payload.get("business_type", "").strip()
    tk.address = payload.get("address").strip()
    tk.save()

    return JsonResponse({"ok": True, "data": {
        "full_name": tk.full_name,
        "email": tk.email,
        "mobile_number": tk.mobile_number,
        "business_name": tk.business_name,
        "business_type": tk.business_type,
        "address": tk.address,
        "email_verified": tk.email_verified,
    }})

# ---------- send verification (improved) ----------
@login_required
@require_POST
def send_email_verification_view(request):
    """
    Triggers sending a verification email. This view prefers the email stored
    on TestKYC (if present) and falls back to User.email. Returns JSON.
    """
    user = request.user
    # rate-limit: don't allow creating a new token if last one created < 60s ago
    last = EmailVerificationToken.objects.filter(user=user).order_by("-created_at").first()
    if last and (timezone.now() - last.created_at).total_seconds() < 60:
        return JsonResponse({"ok": False, "error": "Please wait before requesting again."}, status=429)

    # pick email: TestKYC.email preferred
    try:
        tk = TestKYC.objects.get(user=user)
        target_email = tk.email or user.email
    except TestKYC.DoesNotExist:
        target_email = user.email

    if not target_email or "@" not in target_email:
        return JsonResponse({"ok": False, "error": "No valid email found for this account.", "debug": {"username": user.username, "user_id": user.pk, "email": target_email}}, status=400)

    # create token
    raw_token, tok_obj = EmailVerificationToken.create_token_for_user(
        user, ttl_hours=24, request=request
    )

    verify_url = request.build_absolute_uri(
        reverse("core:verify_email_link") + f"?uid={user.pk}&token={raw_token}"
    )

    ok = send_verification_email(
        to_email=target_email,
        verify_url=verify_url,
        recipient_name=user.get_full_name() or user.username
    )

    if not ok:
        return JsonResponse({"ok": False, "error": "Failed to send verification email."}, status=500)

    # success
    return JsonResponse({"ok": True, "message": "Verification email sent."})

# ---------- verify link ----------
def verify_email_link(request):
    """
    Called when user clicks the link in email:
      /verify-email/?uid=123&token=xyz
    Will verify token, mark token used, and set TestKYC.email_verified=True.
    Redirects to /test/?email_verified=1 on success.
    """
    uid = request.GET.get("uid")
    token = request.GET.get("token")
    if not uid or not token:
        return HttpResponseBadRequest("Missing parameters.")

    # find user tokens; tokens are hashed in DB
    import hashlib
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    try:
        tok = EmailVerificationToken.objects.get(user_id=uid, token_hash=token_hash, used_at__isnull=True)
    except EmailVerificationToken.DoesNotExist:
        return HttpResponse("Invalid or expired token.", status=400)

    # ensure not expired
    if tok.expires_at < timezone.now():
        return HttpResponse("Token expired.", status=400)

    # mark used
    tok.mark_used()

    # mark TestKYC email verified if exists
    try:
        tk = TestKYC.objects.get(user_id=uid)
        tk.mark_email_verified(method="email_link")
    except TestKYC.DoesNotExist:
        # if no TestKYC, we could optionally create one; skip for now
        pass

    # Optionally also mark User.email_verified if you want (commented):
    user = tok.user
    user.email_verified = True
    user.email_verified_at = timezone.now()
    user.save(update_fields=['email_verified','email_verified_at'])

    # redirect to test page and let frontend detect param
    redirect_url = reverse("core:test_view") + "?email_verified=1"
    return redirect(redirect_url)

# ---------- email status API ----------
@login_required
@require_GET
def email_status(request):
    try:
        tk = TestKYC.objects.get(user=request.user)
        return JsonResponse({"email_verified": bool(tk.email_verified)})
    except TestKYC.DoesNotExist:
        # fallback: check User.email_verified if you want
        return JsonResponse({"email_verified": False})


# Add imports near top of core/views.py if not already present
from django.views.decorators.http import require_POST
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse, HttpResponseBadRequest
from django.core.mail import send_mail
from django.conf import settings
import re
from django.utils import timezone

# Regex constants (same as JS)
PAN_RE = re.compile(r'^[A-Z]{5}\d{4}[A-Z]$', re.IGNORECASE)
ACC_RE = re.compile(r'^\d{6,20}$')
IFSC_RE = re.compile(r'^[A-Za-z]{4}0[A-Za-z0-9]{6}$')

# Helper: check and set attribute only if model has it
def _set_if_has(obj, field, value):
    if hasattr(obj, field):
        setattr(obj, field, value)
        return True
    return False


@login_required
@require_POST
def api_save_kyc_pan(request):
    """
    POST expects: pan_number (text), pan_document (file)
    Returns JSON: { ok: True } or { ok: False, errors: {...} }
    Saves to TestKYC fields: pan_number, pan_document (if model has them).
    """
    user = request.user
    errors = {}

    pan_number = (request.POST.get('pan_number') or '').strip()
    pan_file = request.FILES.get('pan_document')

    # Validate
    if not pan_number or not PAN_RE.match(pan_number):
        errors['pan_number'] = "Enter a valid PAN (format: 5 letters, 4 digits, 1 letter)."
    if not pan_file:
        errors['pan_document'] = "Upload PAN document (image/pdf)."

    if errors:
        return JsonResponse({'ok': False, 'errors': errors}, status=400)

    # Save into TestKYC
    try:
        from .models import TestKYC
        kyc, _ = TestKYC.objects.get_or_create(user=user)
        # store normalized pan (uppercase)
        _set_if_has(kyc, 'pan_number', pan_number.upper())
        # set file only if field exists (use the field name your model has)
        if hasattr(kyc, 'pan_document'):
            kyc.pan_document = pan_file
        # optional: clear any previous pan verification flags if present
        if hasattr(kyc, 'pan_verified'):
            setattr(kyc, 'pan_verified', False)
        # save
        kyc.save()
    except Exception as e:
        # don't leak internals; log server side if you want
        return JsonResponse({'ok': False, 'error': 'Failed to save PAN. Try again.'}, status=500)

    return JsonResponse({'ok': True, 'message': 'PAN saved.'})


@login_required
@require_POST
def api_save_kyc_bank(request):
    """
    POST expects: bank_account_number (text), ifsc_code (text), bank_proof (file)
    Returns JSON similar to api_save_kyc_pan.
    Saves to TestKYC fields: bank_account_number, ifsc_code, bank_proof (if exist).
    """
    user = request.user
    errors = {}

    acc = (request.POST.get('bank_account_number') or '').strip()
    ifsc = (request.POST.get('ifsc_code') or '').strip()
    bank_proof = request.FILES.get('bank_proof')

    # Validate
    if not acc or not ACC_RE.match(acc):
        errors['bank_account_number'] = "Enter valid account number (6–20 digits)."
    if not ifsc or not IFSC_RE.match(ifsc):
        errors['ifsc_code'] = "Enter valid IFSC (e.g. SBIN0001234)."
    if not bank_proof:
        errors['bank_proof'] = "Upload cancelled cheque or bank statement."

    if errors:
        return JsonResponse({'ok': False, 'errors': errors}, status=400)

    try:
        from .models import TestKYC
        kyc, _ = TestKYC.objects.get_or_create(user=user)
        _set_if_has(kyc, 'bank_account_number', acc)
        _set_if_has(kyc, 'ifsc_code', ifsc.upper())
        if hasattr(kyc, 'bank_proof'):
            kyc.bank_proof = bank_proof
        # clear any previous bank verification flag if present
        if hasattr(kyc, 'bank_verified'):
            setattr(kyc, 'bank_verified', False)
        kyc.save()
    except Exception as e:
        return JsonResponse({'ok': False, 'error': 'Failed to save bank details. Try again.'}, status=500)

    return JsonResponse({'ok': True, 'message': 'Bank details saved.'})


@login_required
@require_POST
def api_submit_kyc(request):
    """
    Final submit endpoint.
    Marks the user's TestKYC as submitted/pending and sends the "thanks, wait for admin approval" email.
    The front-end will redirect the user to the dashboard after receiving {ok: True}.
    """
    user = request.user
    try:
        from .models import TestKYC
        kyc, _ = TestKYC.objects.get_or_create(user=user)

        # Optionally set a 'submitted' flag / status / timestamp if your model supports it.
        # Use defensive setattr only if field exists.
        if hasattr(kyc, 'submitted'):
            kyc.submitted = True
        if hasattr(kyc, 'submitted_at'):
            kyc.submitted_at = timezone.now()
        # generic status field fallback
        if hasattr(kyc, 'status'):
            try:
                # prefer a textual status
                kyc.status = getattr(kyc, 'status_pending_value', 'PENDING') if hasattr(kyc, 'status_pending_value') else 'PENDING'
            except Exception:
                kyc.status = 'PENDING'

        # If you have separate flags for each verification stage, you can keep them unchanged;
        # admin will later set pan_verified/bank_verified etc.
        kyc.save()

        # send email to user: "we received your KYC — wait for admin approval"
        to_email = None
        # prefer TestKYC.email then user.email
        if hasattr(kyc, 'email') and kyc.email:
            to_email = kyc.email
        elif getattr(user, 'email', None):
            to_email = user.email

        if to_email:
            subject = "KYC submitted — pending admin approval"
            message = (
                f"Hello {user.get_full_name() or user.username},\n\n"
                "Thanks for choosing VPay. We have received your KYC details in Test Mode and will review them shortly.\n\n"
                "While you wait for admin approval you can continue using test keys. Once your KYC is approved by our admin team we will notify you and enable live keys (only after further checks).\n\n"
                "Regards,\nVPay Team"
            )
            from_email = getattr(settings, "DEFAULT_FROM_EMAIL", None) or getattr(settings, "SERVER_EMAIL", None) or "noreply@vpay.local"
            try:
                send_mail(subject, message, from_email, [to_email], fail_silently=True)
            except Exception:
                # do not fail submit if email fails; admin will check record
                pass

        # Optionally notify admins (if settings.ADMINS exists) — non-blocking
        try:
            admins = getattr(settings, "ADMINS", None)
            if admins:
                admin_emails = [a[1] for a in admins if len(a) > 1]
                admin_subject = f"[KYC] New submission by {user.username}"
                admin_msg = f"User {user.username} has submitted TestKYC. Review in admin panel."
                if admin_emails:
                    send_mail(admin_subject, admin_msg, from_email, admin_emails, fail_silently=True)
        except Exception:
            pass

    except Exception as exc:
        return JsonResponse({'ok': False, 'error': 'Failed to submit KYC. Try again.'}, status=500)

    return JsonResponse({'ok': True, 'message': 'KYC submitted and pending admin approval.'})


# vpaydashbaord
# # core/views.py
# from django.shortcuts import render
# from django.contrib.auth.decorators import login_required
# from .models import TestKYC, TestKeys   # adjust if your model names differ

# @login_required
# def vpay_dashboard(request):
#     """
#     Dashboard shows:
#     - Always: overview + KYC status
#     - Only after admin approval: test keys
#     """

#     # Get KYC record for logged-in user
#     try:
#         kyc = TestKYC.objects.get(user=request.user)
#     except TestKYC.DoesNotExist:
#         kyc = None

#     # Default: hide test keys
#     test_keys = None

#     # Show test keys ONLY if admin approved
#     if kyc and kyc.is_verified:
#         # Fetch test keys from DB
#         test_keys = TestKeys.objects.filter(user=request.user).first()

#     return render(request, "vpay/vpay_dashboard.html", {
#         "user": request.user,
#         "kyc": kyc,
#         "test_keys": test_keys,  # None → template hides keys
#     })


# core/views.py
from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from .models import TestKYC, TestKeys

@login_required
def vpay_dashboard(request):
    try:
        kyc = TestKYC.objects.get(user=request.user)
    except TestKYC.DoesNotExist:
        kyc = None

    test_keys = None

    if kyc and kyc.is_verified:
        # Create keys if not found (atomic-ish)
        test_keys, created = TestKeys.objects.get_or_create(
            user=request.user,
            defaults={
                'public_key': TestKeys.generate_key('vpay_test_pub'),
                'secret_key': TestKeys.generate_key('vpay_test_secret'),
            }
        )
        # optional: do something when created
        if created:
            # e.g. log, notify user, send email, etc.
            pass

    return render(request, "vpay/vpay_dashboard.html", {
        "user": request.user,
        "kyc": kyc,
        "test_keys": test_keys,
    })


# for payment integration
# payments/views.py
import json
import hmac
import hashlib
import requests
import uuid

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import AllowAny

from .serializers import (
    CreatePaymentSerializer, CapturePaymentSerializer,
    UpiCollectSerializer, NetbankingSerializer, VerifyOtpSerializer
)
from .models import PaymentSession, IdempotencyKey, WebhookEvent

# Try to import your existing TestKeys / SandboxKey models (from core.models)
try:
    from core.models import TestKeys, SandboxKey
except Exception:
    TestKeys = None
    SandboxKey = None

# ----------------- helpers -----------------
def find_key_record(public_key=None, secret_key=None):
    pub_obj = None
    sec_obj = None
    if public_key and TestKeys:
        try:
            pub_obj = TestKeys.objects.get(public_key=public_key)
        except Exception:
            pub_obj = None
    if public_key and SandboxKey and not pub_obj:
        try:
            pub_obj = SandboxKey.objects.get(public_key=public_key)
        except Exception:
            pub_obj = None

    if secret_key and TestKeys:
        try:
            sec_obj = TestKeys.objects.get(secret_key=secret_key)
        except Exception:
            sec_obj = None
    if secret_key and SandboxKey and not sec_obj:
        try:
            sec_obj = SandboxKey.objects.get(secret_key=secret_key)
        except Exception:
            sec_obj = None

    if pub_obj and sec_obj:
        if getattr(pub_obj, 'user_id', None) == getattr(sec_obj, 'user_id', None):
            return pub_obj
        return None
    return pub_obj or sec_obj


def validate_public_key(public_key):
    rec = find_key_record(public_key=public_key)
    if not rec:
        return None
    if hasattr(rec, 'enabled') and not getattr(rec, 'enabled'):
        return None
    user = getattr(rec, 'user', None)
    if user and hasattr(user, 'is_active') and not user.is_active:
        return None
    return rec


def validate_secret_key(secret_key):
    rec = find_key_record(secret_key=secret_key)
    if not rec:
        return None
    if hasattr(rec, 'enabled') and not getattr(rec, 'enabled'):
        return None
    return rec


def sign_webhook(payload: dict, secret: str) -> str:
    body = json.dumps(payload, separators=(',', ':'), sort_keys=True)
    sig = hmac.new(secret.encode('utf-8'), body.encode('utf-8'), hashlib.sha256).hexdigest()
    return sig


def deliver_webhook(callback_url: str, payload: dict, secret: str):
    """
    Best-effort synchronous webhook delivery for sandbox demos.
    In production you MUST do this in a background worker with retry/backoff.
    """
    sig = sign_webhook(payload, secret) if secret else ""
    headers = {
        'Content-Type': 'application/json',
        'X-VPay-Signature': sig
    }
    try:
        r = requests.post(callback_url, headers=headers, data=json.dumps(payload), timeout=5)
        return (r.status_code, r.text)
    except Exception as e:
        return (None, str(e))
# views.py (revamped simple sandbox)
import uuid
import time
from django.utils import timezone
from django.views.decorators.csrf import ensure_csrf_cookie
from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status

# import your models
# from .models import TestKeys, PaymentSession, WebhookEvent
# If model names differ, change imports accordingly.

# --- Helpers (very small and explicit) -----------------------------------
def lookup_key(public_key):
    """
    Very small helper that returns TestKeys record or None.
    Adjust field names to match your TestKeys model.
    """
    try:
        return TestKeys.objects.filter(public_key=public_key).first()
    except Exception:
        return None

def create_session(amount=0, currency='INR', public_key=None, meta=None):
    """
    Create minimal PaymentSession. Adjust create logic to match your model fields.
    Expects PaymentSession to have fields: session_id (str), amount (int),
    currency (str), meta (JSON/dict), status (str), payment_id (str).
    """
    sid = uuid.uuid4().hex
    payment_id = "pay_" + uuid.uuid4().hex[:12]
    sess = PaymentSession.objects.create(
        session_id=sid,
        payment_id=payment_id,
        amount=int(amount),
        currency=currency,
        meta=meta or {},
        status='created',
    )
    # store public_key for later convenience
    if public_key:
        meta = sess.meta or {}
        meta['public_key'] = public_key
        sess.meta = meta
        sess.save(update_fields=['meta'])
    return sess

def requires_otp_response():
    return {'success': False, 'requires_otp': True, 'otp_sent': True}

def mark_success_session(session):
    # mark session as successful in a minimal way
    session.status = 'success'
    if not getattr(session, 'payment_id', None):
        session.payment_id = "pay_" + uuid.uuid4().hex[:12]
    session.meta = session.meta or {}
    session.meta.pop('otp_code', None)
    session.meta['completed_at'] = timezone.now().isoformat()
    session.save(update_fields=['status', 'meta', 'payment_id'])
    return session

# --- Views ---------------------------------------------------------------
class CreatePaymentView(APIView):
    """
    Create a simple payment session. Caller provides key (public key), amount (cents), currency.
    Returns a minimal payment_session_id and merchant info.
    """
    permission_classes = []  # AllowAny in sandbox; change in prod

    def post(self, request):
        pk = request.data.get('key') or request.query_params.get('key')
        amount = request.data.get('amount', 0)
        currency = request.data.get('currency', 'INR')

        # Basic validation
        try:
            amount = int(amount)
        except Exception:
            return Response({'success': False, 'message': 'Invalid amount'}, status=400)

        rec = lookup_key(pk)
        # If key not found, still allow demo sessions with a warning (optional)
        if not rec:
            # you can decide to fail here; for demo we'll allow and mark merchant_name as "Demo"
            merchant_name = "Demo Merchant"
            merchant_logo = ""
        else:
            merchant_name = getattr(rec, 'merchant_name', '') or getattr(getattr(rec, 'user', None), 'username', 'Merchant')
            merchant_logo = getattr(rec, 'merchant_logo', '') or getattr(rec, 'merchant_logo_url', '') or ''

        # create session (simple)
        session = create_session(amount=amount, currency=currency, public_key=pk, meta={'customer': request.data.get('customer', {})})

        return Response({
            'success': True,
            'payment_session_id': session.session_id,
            'order_id': "ord_" + session.session_id[:8],
            'merchant_name': merchant_name,
            'merchant_logo': merchant_logo,
            'amount': session.amount,
            'currency': session.currency
        })


class CapturePaymentView(APIView):
    """
    Capture attempt for any method. For sandbox:
      - if method == 'card' and last4 == '4242' => success immediate
      - otherwise => set OTP on session.meta and return requires_otp True
    For UPI / Netbanking / Wallet we trigger OTP path by default (sandbox).
    """
    permission_classes = []

    def post(self, request):
        sid = request.data.get('payment_session_id')
        method = (request.data.get('method') or '').lower()
        if not sid:
            return Response({'success': False, 'message': 'payment_session_id required'}, status=400)

        try:
            session = PaymentSession.objects.get(session_id=sid)
        except PaymentSession.DoesNotExist:
            return Response({'success': False, 'message': 'Invalid session'}, status=400)

        # Simple merchant check (optional) - ensure public_key present in session.meta
        # If you want to require secret, add header checks here.

        # CARD
        if method == 'card':
            last4 = (request.data.get('card_last4') or '')[-4:]
            # succeed instantly for test card 4242
            if last4 == '4242':
                session = mark_success_session(session)
                return Response({'success': True, 'payment_id': session.payment_id})
            # else require OTP
            otp = '1234'
            meta = session.meta or {}
            meta.update({'otp_required': True, 'otp_code': otp, 'otp_issued_at': timezone.now().isoformat(), 'method': 'card'})
            session.meta = meta
            session.status = 'pending'
            session.save(update_fields=['meta', 'status'])
            return Response(requires_otp_response())

        # UPI
        # ---------------- UPI ----------------
        if method == 'upi':
            otp = '1234'
            meta = session.meta or {}
            meta.update({
                'otp_required': True,
                'otp_code': otp,
                'otp_issued_at': timezone.now().isoformat(),
                'method': 'upi',
                'upi_id': request.data.get('upi_id')
            })
            session.meta = meta
            session.status = 'pending'
            session.save(update_fields=['meta', 'status'])

            # No redirect URL
            return Response({
                'success': False,
                'requires_otp': True,
                'otp_sent': True
            })


        # ---------------- NETBANKING ----------------
        if method == 'netbanking':
            otp = '1234'
            meta = session.meta or {}
            meta.update({
                'otp_required': True,
                'otp_code': otp,
                'otp_issued_at': timezone.now().isoformat(),
                'method': 'netbanking',
                'bank': request.data.get('bank')
            })
            session.meta = meta
            session.status = 'pending'
            session.save(update_fields=['meta', 'status'])

            # No redirect URL
            return Response({
                'success': False,
                'requires_otp': True,
                'otp_sent': True
            })


        # WALLET
        if method == 'wallet':
            otp = '1234'
            meta = session.meta or {}
            meta.update({'otp_required': True, 'otp_code': otp, 'otp_issued_at': timezone.now().isoformat(), 'method': 'wallet', 'wallet': request.data.get('wallet','')})
            session.meta = meta
            session.status = 'pending'
            session.save(update_fields=['meta', 'status'])
            return Response({'success': False, 'requires_otp': True, 'otp_sent': True})

        return Response({'success': False, 'message': 'Unsupported method'}, status=400)


class VerifyOtpView(APIView):
    """
    Verify OTP for a session - if correct, mark success and (optionally) deliver webhook.
    """
    permission_classes = []

    def post(self, request):
        sid = request.data.get('payment_session_id')
        otp = request.data.get('otp')

        if not sid or not otp:
            return Response({'success': False, 'message': 'payment_session_id and otp required'}, status=400)

        try:
            session = PaymentSession.objects.get(session_id=sid)
        except PaymentSession.DoesNotExist:
            return Response({'success': False, 'message': 'Invalid session'}, status=400)

        meta = session.meta or {}
        expected = str(meta.get('otp_code') or '')
        if expected and str(otp).strip() == expected.strip():
            session = mark_success_session(session)

            # optionally deliver webhook if callback_url exists in meta and you have a signing secret
            callback = meta.get('callback_url')
            # if callback:
            #   deliver_webhook(callback, payload, secret)

            return Response({'success': True, 'payment_id': session.payment_id})
        return Response({'success': False, 'message': 'Invalid OTP'}, status=400)


class PaymentStatusView(APIView):
    permission_classes = []

    def get(self, request):
        sid = request.GET.get('session_id')
        if not sid:
            return Response({'status': 'failed', 'message': 'session_id required'}, status=400)
        try:
            session = PaymentSession.objects.get(session_id=sid)
        except PaymentSession.DoesNotExist:
            return Response({'status': 'failed', 'message': 'Invalid session'}, status=400)

        # Provide useful, simple state
        if session.status == 'success':
            return Response({'status': 'success', 'payment_id': session.payment_id})
        elif session.status == 'pending' or (session.meta or {}).get('otp_required'):
            return Response({'status': 'pending'})
        else:
            return Response({'status': 'failed', 'message': (session.meta or {}).get('failure_reason') or 'Payment not completed'})

# Simple demo page
@ensure_csrf_cookie
def vts_pay_demo(request):
    return render(request, "test-pay.html")
# myapp/views.py
import uuid
from django.shortcuts import render
from django.views.decorators.csrf import ensure_csrf_cookie
from django.http import HttpResponseBadRequest
from django.utils import timezone

# import your PaymentSession model
# from .models import PaymentSession

@ensure_csrf_cookie
def sandbox_simulate(request):
    """
    Single simulator for bank/upi/netbanking/wallet/qr.
    GET: show page with session + method.
    POST: mark session success immediately (no OTP).
    Query params or POST fields:
      - session_id (required)
      - method (optional) e.g. card / upi / netbanking / wallet / qr
      - bank / upi / wallet (optional)
    """
    session_id = request.GET.get('session_id') or request.POST.get('session_id')
    method = (request.GET.get('method') or request.POST.get('method') or '').lower()
    bank = request.GET.get('bank') or request.POST.get('bank') or ''
    upi = request.GET.get('upi') or request.POST.get('upi') or ''
    wallet = request.GET.get('wallet') or request.POST.get('wallet') or ''

    if not session_id:
        return HttpResponseBadRequest("session_id is required")

    try:
        session = PaymentSession.objects.get(session_id=session_id)
    except PaymentSession.DoesNotExist:
        return HttpResponseBadRequest("Invalid session_id")

    if request.method == 'POST':
        # Mark session success (simple, immediate; no OTP)
        session.status = 'success'
        meta = session.meta or {}
        meta.pop('otp_code', None)     # remove sandbox OTP if any
        meta['sandbox_completed_at'] = timezone.now().isoformat()
        session.meta = meta
        # ensure payment_id exists
        if not getattr(session, 'payment_id', None):
            session.payment_id = "pay_" + uuid.uuid4().hex[:12]
        session.save(update_fields=['status', 'meta', 'payment_id'])
        return render(request, 'sandbox/sandbox_simulate.html', {
            'session': session,
            'method': method,
            'bank': bank,
            'upi': upi,
            'wallet': wallet,
            'completed': True
        })

    # GET -> show simulator (not completed yet)
    return render(request, 'sandbox/sandbox_simulate.html', {
        'session': session,
        'method': method,
        'bank': bank,
        'upi': upi,
        'wallet': wallet,
        'completed': False
    })
# CapturePaymentView — full implementation with Transaction handling
import uuid
from decimal import Decimal
from django.utils import timezone
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import AllowAny
from django.contrib.auth import get_user_model

# Import your models / helpers (adjust import paths to match your project)
# from .models import PaymentSession, TestKeys, Transaction, SandboxKey, WebhookEvent
# from .webhooks import deliver_webhook, sign_webhook

User = get_user_model()

# ---------------- small helpers (self-contained) ----------------
def _create_transaction_for_session(session, key_record=None, method='UNKNOWN', request_data=None):
    """
    Create a Transaction row for this session and return it.
    Raises ValueError if no user can be resolved for the transaction.
    """
    # Resolve user: prefer key_record.user then session.merchant_user_id
    user = None
    if key_record and getattr(key_record, 'user', None):
        user = key_record.user
    elif getattr(session, 'merchant_user_id', None):
        try:
            user = User.objects.filter(id=session.merchant_user_id).first()
        except Exception:
            user = None

    if not user:
        raise ValueError("Transaction requires a merchant user. Ensure TestKeys.user or session.merchant_user_id is set.")

    # convert amount: assume session.amount is integer paise
    try:
        amount_val = Decimal(session.amount) / Decimal(100)
    except Exception:
        amount_val = Decimal(session.amount or 0)

    txn = Transaction.objects.create(
        user=user,
        amount=amount_val,
        provider=(method or 'UNKNOWN').upper(),
        status=Transaction.STATUS_PENDING,
        notes=f"Sandbox {method} capture for session {session.session_id}",
        raw_payload=request_data or {}
    )
    return txn

def _mark_txn_success_if_present(session, payment_id=None, signature=None):
    meta = session.meta or {}
    txn_id = meta.get('txn_id')
    if not txn_id:
        return
    try:
        t = Transaction.objects.filter(id=txn_id).first()
        if t:
            t.mark_success(payment_id=payment_id, signature=signature)
    except Exception:
        pass

def _mark_txn_failed_if_present(session, reason=None):
    meta = session.meta or {}
    txn_id = meta.get('txn_id')
    if not txn_id:
        return
    try:
        t = Transaction.objects.filter(id=txn_id).first()
        if t:
            t.mark_failed(reason=reason)
    except Exception:
        pass

# ---------------- CapturePaymentView ----------------
class CapturePaymentView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        ser = CapturePaymentSerializer(data=request.data)
        ser.is_valid(raise_exception=True)
        data = ser.validated_data

        # Load session
        try:
            session = PaymentSession.objects.get(session_id=data['payment_session_id'])
        except PaymentSession.DoesNotExist:
            return Response({'success': False, 'message': 'Invalid session'}, status=400)

        # -------------------------------------------------------------------
        # STEP 1: Resolve merchant → find TestKeys record (if any)
        # -------------------------------------------------------------------
        key_record = None

        # 1) Resolve using merchant_user_id stored on session
        if getattr(session, 'merchant_user_id', None):
            key_record = TestKeys.objects.filter(user__id=session.merchant_user_id).first()

        # 2) Resolve using public_key stored in session.meta
        if not key_record:
            public_key = (session.meta or {}).get("public_key")
            if public_key:
                key_record = TestKeys.objects.filter(public_key=public_key).first()

        # 3) Fallback: client supplied public key in request
        if not key_record:
            req_pub = request.data.get('key') or request.data.get('public_key')
            if req_pub:
                key_record = TestKeys.objects.filter(public_key=req_pub).first()

        if not key_record:
            # Merchant could not be identified — return 400 (you may change to allow demo behavior)
            return Response({
                'success': False,
                'message': 'Merchant/TestKeys not found. Ensure you save merchant_user_id and meta["public_key"] during create-payment.'
            }, status=400)

        secret = getattr(key_record, 'secret_key', None)

        # -------------------------------------------------------------------
        # STEP 2: Payment method handling + Transaction creation
        # -------------------------------------------------------------------
        method = (data.get('method') or '').lower()

        # ---------- Helper: ensure a transaction exists for this session ----------
        try:
            # create txn and attach to session.meta
            txn = _create_transaction_for_session(session, key_record=key_record, method=method or 'UNKNOWN', request_data=data)
            meta = session.meta or {}
            meta['txn_id'] = txn.id
            session.meta = meta
            session.save(update_fields=['meta'])
        except ValueError as e:
            return Response({'success': False, 'message': str(e)}, status=400)
        except Exception:
            # do not hard-fail capture if txn creation fails; continue without txn mapping
            txn = None

        # ---------------- CARD PAYMENT ----------------
        if method == 'card':
            last4 = (data.get('card_last4') or '')[-4:]

            # Success path → 4242 cards auto succeed
            if last4 == '4242':
                session.mark_success()
                _mark_txn_success_if_present(session, payment_id=session.payment_id)

                payload = {
                    'event': 'payment.captured',
                    'payment_id': session.payment_id,
                    'session_id': session.session_id,
                    'amount': session.amount,
                    'currency': session.currency
                }

                callback = request.query_params.get('callback_url') or (session.meta or {}).get('callback_url')
                if callback and secret:
                    deliver_webhook(callback, payload, secret)
                    # record webhook event if you track them
                    try:
                        WebhookEvent.objects.create(
                            event_type='payment.captured',
                            payload=payload,
                            signature=sign_webhook(payload, secret)
                        )
                    except Exception:
                        pass

                return Response({'success': True, 'payment_id': session.payment_id})

            # OTP path → non-4242 trigger OTP
            else:
                meta = session.meta or {}
                meta.update({'otp_required': True, 'otp_code': '1234', 'method': 'card'})
                session.meta = meta
                session.status = 'pending'
                session.save(update_fields=['meta', 'status'])
                return Response({'success': False, 'requires_otp': True, 'otp_sent': True})

        # ---------------- UPI PAYMENT ----------------
        if method == 'upi':
            otp = '1234'
            meta = session.meta or {}
            meta.update({'otp_required': True, 'otp_code': otp, 'otp_issued_at': timezone.now().isoformat(), 'method': 'upi', 'upi_id': request.data.get('upi_id')})
            session.meta = meta
            session.status = 'pending'
            session.save(update_fields=['meta', 'status'])
            return Response({'success': False, 'requires_otp': True, 'otp_sent': True})

        # ---------------- NETBANKING PAYMENT ----------------
        if method == 'netbanking':
            otp = '1234'
            meta = session.meta or {}
            meta.update({'otp_required': True, 'otp_code': otp, 'otp_issued_at': timezone.now().isoformat(), 'method': 'netbanking', 'bank': request.data.get('bank')})
            session.meta = meta
            session.status = 'pending'
            session.save(update_fields=['meta', 'status'])
            return Response({'success': False, 'requires_otp': True, 'otp_sent': True})

        # ---------------- WALLET PAYMENT ----------------
        if method == 'wallet':
            # wallet immediate success in sandbox
            session.mark_success()
            _mark_txn_success_if_present(session, payment_id=session.payment_id)

            payload = {
                'event': 'payment.captured',
                'payment_id': session.payment_id,
                'session_id': session.session_id,
                'amount': session.amount,
                'currency': session.currency
            }

            callback = request.query_params.get('callback_url') or (session.meta or {}).get('callback_url')
            if callback and secret:
                deliver_webhook(callback, payload, secret)
                try:
                    WebhookEvent.objects.create(
                        event_type='payment.captured',
                        payload=payload,
                        signature=sign_webhook(payload, secret)
                    )
                except Exception:
                    pass

            return Response({'success': True, 'payment_id': session.payment_id})

        # Unsupported method
        _mark_txn_failed_if_present(session, reason='Unsupported method')
        return Response({'success': False, 'message': 'Unsupported method'}, status=400)
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.db.models import Count, Sum
from django.utils import timezone

@login_required
def transaction_stats(request):
    """
    Minimal stats endpoint used by templates. Returns JSON with
    total/pending/success counts and total amount. Extend as needed.
    """
    qs = Transaction.objects.all()

    success_val = getattr(Transaction, 'STATUS_SUCCESS', 'success')
    pending_val = getattr(Transaction, 'STATUS_PENDING', 'pending')
    failed_val = getattr(Transaction, 'STATUS_FAILED', 'failed')

    total_count = qs.count()
    success_count = qs.filter(status__iexact=success_val).count()
    pending_count = qs.filter(status__iexact=pending_val).count()
    failed_count = qs.filter(status__iexact=failed_val).count()
    total_amount = float(qs.aggregate(total=Sum('amount'))['total'] or 0)

    return JsonResponse({
        'ok': True,
        'total_count': total_count,
        'success_count': success_count,
        'pending_count': pending_count,
        'failed_count': failed_count,
        'total_amount': total_amount,
        'now': timezone.now().isoformat()
    })
