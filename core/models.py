from django.db import models
from django.contrib.auth.models import AbstractUser
from django.utils import timezone
import datetime
import uuid
from decimal import Decimal
from django.utils import timezone
from django.contrib.auth import get_user_model

# models
# from .models import PaymentSession, TestKeys, Transaction, SandboxKey, TestKeys
# Custom User model
class User(AbstractUser):
    email = models.EmailField(unique=True)
    phone_number = models.CharField(max_length=15, unique=True, null=True, blank=True)
    is_phone_verified = models.BooleanField(default=False)

    # Add this field for email verification
    email_verified = models.BooleanField(default=False)
    email_verified_at = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return self.username


# Model to store OTPs for registration/login
class MobileOTP(models.Model):
    PURPOSE_CHOICES = [
        ('REGISTER', 'Register'),
        ('LOGIN', 'Login'),
    ]

    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='otps')
    otp = models.CharField(max_length=6)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    used = models.BooleanField(default=False)
    purpose = models.CharField(max_length=10, choices=PURPOSE_CHOICES)
    attempts = models.IntegerField(default=0)

    def __str__(self):
        return f"{self.user.username} - {self.otp} ({self.purpose})"

    def is_expired(self):
        return timezone.now() > self.expires_at

    def mark_used(self):
        self.used = True
        self.save()

    @classmethod
    def create_otp(cls, user, otp, purpose):
        expiry = timezone.now() + datetime.timedelta(minutes=5)
        return cls.objects.create(user=user, otp=otp, expires_at=expiry, purpose=purpose)


# 
# core/models.py
from django.db import models
from django.conf import settings


User = settings.AUTH_USER_MODEL

class BankAccount(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='bank_accounts')
    bank_name = models.CharField(max_length=120)
    account_number = models.CharField(max_length=64)
    ifsc = models.CharField(max_length=32, blank=True, null=True)
    is_default = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.bank_name} ({self.account_number[-4:]})"

import uuid
from django.db import models
from django.contrib.auth.models import User
from django.utils.timezone import now

class Transaction(models.Model):
    STATUS_PENDING = 'PENDING'
    STATUS_SUCCESS = 'SUCCESS'
    STATUS_FAILED = 'FAILED'
    STATUS_CHOICES = [
        (STATUS_PENDING, 'Pending'),
        (STATUS_SUCCESS, 'Success'),
        (STATUS_FAILED, 'Failed'),
    ]

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,      # ✅ use this instead of User
        on_delete=models.CASCADE,
        related_name='transactions'
    )
    txn_num = models.CharField(max_length=32, unique=True, editable=False,null=True,      
    blank=True )   # ✅ new unique transaction number
    amount = models.DecimalField(max_digits=12, decimal_places=2)
    to_upi = models.CharField(max_length=128, blank=True, null=True)
    provider = models.CharField(max_length=32, blank=True, null=True)
    razorpay_order_id = models.CharField(max_length=128, blank=True, null=True)
    razorpay_payment_id = models.CharField(max_length=128, blank=True, null=True)
    razorpay_signature = models.CharField(max_length=256, blank=True, null=True)
    status = models.CharField(max_length=16, choices=STATUS_CHOICES, default=STATUS_PENDING)
    notes = models.TextField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    # 
    qr_generated_at = models.DateTimeField(null=True, blank=True)
    i_paid_at = models.DateTimeField(null=True, blank=True)
    razorpay_paid_at = models.DateTimeField(null=True, blank=True)
    verified_at = models.DateTimeField(null=True, blank=True)

    # UPI reference returned by UPI app (user-provided or provider)
    upi_reference = models.CharField(max_length=128, blank=True, null=True)

    # store raw payload/responses for debugging (requires Django's JSONField available)
    raw_payload = models.JSONField(null=True, blank=True)

    # --- METHODS ---

    def save(self, *args, **kwargs):
        """Auto-generate a unique transaction number on creation."""
        if not self.txn_num:
            # Format: TXN + YYYYMMDD + 8-char UUID segment
            self.txn_num = f"TXN{now().strftime('%Y%m%d')}{uuid.uuid4().hex[:8].upper()}"
        super().save(*args, **kwargs)

    def mark_success(self, payment_id=None, signature=None):
        if payment_id:
            self.razorpay_payment_id = payment_id
        if signature:
            self.razorpay_signature = signature
        self.status = self.STATUS_SUCCESS
        # set paid timestamp
        self.razorpay_paid_at = now()
        self.save(update_fields=[
            'razorpay_payment_id', 'razorpay_signature', 'status', 'razorpay_paid_at', 'updated_at'
        ])

    def mark_failed(self, reason=None):
        if reason:
            self.notes = (self.notes or '') + f"\nFailed: {reason}"
        self.status = self.STATUS_FAILED
        self.save(update_fields=['notes', 'status', 'updated_at'])

    def get_retry_url(self):
        """
        Return a URL (relative) where the user/admin can retry/resolve a pending transaction.
        Customize to match your app's URL names.
        """
        if self.status == self.STATUS_PENDING:
            # Example: retry payments for Razorpay or show recharge detail
            if (self.provider or '').lower() == 'razorpay':
                return f"/payments/retry/{self.id}/"   # change to your real path or use reverse()
            if (self.provider or '').lower() in ('gpay', 'phonepe', 'bhim', 'upi'):
                return f"/payments/manual/upi/{self.id}/"
        return ""


    def __str__(self):
        return f"{self.txn_num} — {self.user} — ₹{self.amount} — {self.status}"


class Notification(models.Model):
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,     # ✅ correct
        on_delete=models.CASCADE,
        related_name='notifications'
    )
    message = models.TextField()
    is_read = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.user} — {self.message[:40]}"


# recharge
from django.db import models
from django.utils import timezone
import uuid
from django.contrib.auth import get_user_model

User = get_user_model()

class Operator(models.Model):
    name = models.CharField(max_length=120)
    code = models.CharField(max_length=64, unique=True)
    circle = models.CharField(max_length=80, blank=True)

    def __str__(self):
        return f"{self.name} ({self.circle})" if self.circle else self.name

class RechargePlan(models.Model):
    operator = models.ForeignKey(Operator, on_delete=models.CASCADE, related_name='plans')
    plan_id = models.CharField(max_length=100)   # provider plan idKYCRevisio
    title = models.CharField(max_length=200)
    description = models.TextField(blank=True)
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    validity = models.CharField(max_length=80, blank=True)

    def __str__(self):
        return f"{self.operator.name} - {self.title} - ₹{self.amount}"

class RechargeOrder(models.Model):
    STATUS_CHOICES = [
        ('PENDING', 'Pending'),
        ('INITIATED', 'Initiated'),
        ('PAID', 'Paid'),
        ('PROCESSING', 'Processing'),
        ('SUCCESS', 'Success'),
        ('FAILED', 'Failed'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, null=True, blank=True, on_delete=models.SET_NULL)
    mobile = models.CharField(max_length=15)
    operator = models.ForeignKey(Operator, null=True, blank=True, on_delete=models.SET_NULL)
    plan = models.ForeignKey(RechargePlan, null=True, blank=True, on_delete=models.SET_NULL)
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    status = models.CharField(max_length=12, choices=STATUS_CHOICES, default='PENDING')
    created_at = models.DateTimeField(default=timezone.now)
    upi_tid = models.CharField(max_length=200, blank=True)
    provider_txn = models.CharField(max_length=200, blank=True)
    notes = models.TextField(blank=True)

    def __str__(self):
        return f"{self.mobile} | ₹{self.amount} | {self.status}"


# kyc
from django.db import models
from django.conf import settings

# Common file upload function
def upload_path(instance, filename):
    return f"kyc/{instance.user.id}/{filename}"


class TestKYC(models.Model):
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)

    # Basic Information
    full_name = models.CharField(max_length=100)
    email = models.EmailField(blank=True)         
    mobile_number = models.CharField(max_length=20)
    business_name = models.CharField(max_length=150)
    business_type = models.CharField(max_length=100)
    address = models.TextField()

    # PAN Details
    pan_number = models.CharField(max_length=20)
    pan_document = models.FileField(upload_to=upload_path, null=True, blank=True)

    # Bank Details
    bank_account_number = models.CharField(max_length=30)
    ifsc_code = models.CharField(max_length=20)
    bank_proof = models.FileField(upload_to=upload_path, null=True, blank=True)

    # ID Proof
    id_proof = models.FileField(upload_to=upload_path, null=True, blank=True)
    # Verification placeholders (NEW)
    email_verified = models.BooleanField(default=False)
    email_verified_at = models.DateTimeField(null=True, blank=True)
    email_verification_method = models.CharField(max_length=32, blank=True, null=True)

    # Verification placeholders
    is_verified = models.BooleanField(default=False)
    verification_notes = models.TextField(blank=True, null=True)

    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.user.username} - Test KYC"
    def mark_email_verified(self, method="email_link"):
        self.email_verified = True
        self.email_verification_method = method
        self.email_verified_at = timezone.now()
        self.save(update_fields=["email_verified", "email_verified_at", "email_verification_method"])


class LiveKYC(models.Model):
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)

    # Aadhaar
    aadhaar_front = models.FileField(upload_to=upload_path, null=True, blank=True)
    aadhaar_back = models.FileField(upload_to=upload_path, null=True, blank=True)

    # Address proof
    address_proof = models.FileField(upload_to=upload_path, null=True, blank=True)

    # Bank Verification (extra)
    cancelled_cheque = models.FileField(upload_to=upload_path, null=True, blank=True)

    # Business Documents
    gst_certificate = models.FileField(upload_to=upload_path, null=True, blank=True)
    business_registration_proof = models.FileField(upload_to=upload_path, null=True, blank=True)
    msme_certificate = models.FileField(upload_to=upload_path, null=True, blank=True)
    partnership_deed = models.FileField(upload_to=upload_path, null=True, blank=True)

    # Director / Owner Details
    director_name = models.CharField(max_length=120, blank=True, null=True)
    director_pan = models.CharField(max_length=20, blank=True, null=True)
    director_aadhaar = models.CharField(max_length=20, blank=True, null=True)

    # UBO
    ubo_name = models.CharField(max_length=120, blank=True, null=True)
    ubo_percentage = models.CharField(max_length=10, blank=True, null=True)
    ubo_document = models.FileField(upload_to=upload_path, null=True, blank=True)

    # Selfie / Liveness
    selfie = models.FileField(upload_to=upload_path, null=True, blank=True)
    signature = models.FileField(upload_to=upload_path, null=True, blank=True)

    # Board resolution
    board_resolution = models.FileField(upload_to=upload_path, null=True, blank=True)

    # Extra bank verification result
    bank_name_match = models.BooleanField(default=False)

    # Verification
    is_verified = models.BooleanField(default=False)
    verification_notes = models.TextField(blank=True, null=True)

    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.user.username} - Live KYC"


# core/models.py (below User or in the same models file)
import hashlib, secrets
from datetime import timedelta
from django.conf import settings

class EmailVerificationToken(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="email_tokens")
    token_hash = models.CharField(max_length=128, help_text="sha256 hex of token")
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    used_at = models.DateTimeField(null=True, blank=True)
    created_from_ip = models.CharField(max_length=45, null=True, blank=True)
    created_user_agent = models.CharField(max_length=255, null=True, blank=True)

    class Meta:
        indexes = [
            models.Index(fields=["user", "token_hash"]),
            models.Index(fields=["expires_at"]),
        ]

    def mark_used(self):
        self.used_at = timezone.now()
        self.save(update_fields=["used_at"])

    @classmethod
    def create_token_for_user(cls, user, ttl_hours=24, request=None):
        raw = secrets.token_urlsafe(32)
        h = hashlib.sha256(raw.encode()).hexdigest()
        expires = timezone.now() + timedelta(hours=ttl_hours)
        obj = cls.objects.create(
            user=user,
            token_hash=h,
            expires_at=expires,
            created_from_ip=(request.META.get("REMOTE_ADDR") if request else None),
            created_user_agent=(request.META.get("HTTP_USER_AGENT")[:255] if request else None),
        )
        return raw, obj


# test keys
# core/models.py

import secrets
from django.db import models
from django.conf import settings

class TestKeys(models.Model):
    """
    Stores sandbox test keys for each user after KYC approval.
    Only one test key pair per user.
    """
    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='test_keys'
    )

    public_key = models.CharField(max_length=150, unique=True)
    secret_key = models.CharField(max_length=150, unique=True)

    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Test Keys for {self.user.username}"

    @staticmethod
    def generate_key(prefix):
        """ Generate a random VPay-style key """
        return f"{prefix}_{secrets.token_urlsafe(24)}"

    @classmethod
    def create_for_user(cls, user):
        """ Auto-generate test keys for a user """
        return cls.objects.create(
            user=user,
            public_key=cls.generate_key("vpay_test_pub"),
            secret_key=cls.generate_key("vpay_test_secret")
        )


# core/models.py (append near your other models)
import secrets
from django.db import models
from django.conf import settings
from django.utils import timezone

User = settings.AUTH_USER_MODEL

def generate_public_key():
    # short readable public key
    return "vp_test_pub_" + secrets.token_urlsafe(12)

def generate_secret_key():
    return "vp_test_sec_" + secrets.token_urlsafe(28)


class SandboxKey(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name="sandbox_key")
    public_key = models.CharField(max_length=128, unique=True)
    secret_key = models.CharField(max_length=256, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    enabled = models.BooleanField(default=True)   # can disable keys if needed (revoke)

    def __str__(self):
        return f"SandboxKey({self.user})"

    @classmethod
    def create_for_user(cls, user):
        # ensure uniqueness loop (rare collision)
        for _ in range(5):
            pub = generate_public_key()
            sec = generate_secret_key()
            if not cls.objects.filter(public_key=pub).exists() and not cls.objects.filter(secret_key=sec).exists():
                return cls.objects.create(user=user, public_key=pub, secret_key=sec, enabled=True)
        # fallback (shouldn't happen)
        pub = generate_public_key() + "_x"
        sec = generate_secret_key() + "_x"
        return cls.objects.create(user=user, public_key=pub, secret_key=sec, enabled=True)
    
# for payment integration
# payments/models.py
from django.db import models
from django.utils import timezone
import uuid

# Top-level functions so Django migrations can serialize them
def generate_session_id():
    return uuid.uuid4().hex

def generate_event_id():
    return uuid.uuid4().hex

class PaymentSession(models.Model):
    STATUS_CHOICES = [
        ("created", "Created"),
        ("pending", "Pending"),
        ("success", "Success"),
        ("failed", "Failed"),
    ]

    session_id = models.CharField(max_length=64, unique=True, default=generate_session_id)
    order_id = models.CharField(max_length=64, blank=True, null=True)
    amount = models.BigIntegerField(help_text="Amount in smallest currency unit (e.g., paise)")
    currency = models.CharField(max_length=8, default="INR")

    # merchant info populated from key lookup
    merchant_user_id = models.IntegerField(blank=True, null=True)
    merchant_name = models.CharField(max_length=192, blank=True)
    merchant_logo = models.URLField(blank=True)

    status = models.CharField(max_length=16, choices=STATUS_CHOICES, default="created")
    payment_id = models.CharField(max_length=64, blank=True, null=True)

    meta = models.JSONField(default=dict, blank=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def mark_success(self, payment_id=None):
        self.status = "success"
        if payment_id:
            self.payment_id = payment_id
        elif not self.payment_id:
            self.payment_id = "pay_" + uuid.uuid4().hex[:12]
        self.save()

    def mark_failed(self, message=None):
        self.status = "failed"
        if message:
            self.meta["failure_reason"] = message
        self.save()

    def __str__(self):
        return f"PaymentSession({self.session_id})"


class IdempotencyKey(models.Model):
    key = models.CharField(max_length=255, unique=True)
    method = models.CharField(max_length=8, blank=True)
    path = models.CharField(max_length=255, blank=True)
    response_code = models.IntegerField(null=True, blank=True)
    response_body = models.JSONField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    last_used = models.DateTimeField(auto_now=True)

    def save_response(self, code, body_json):
        self.response_code = code
        self.response_body = body_json
        self.save()

    def __str__(self):
        return f"IdempotencyKey({self.key})"


class WebhookEvent(models.Model):
    event_id = models.CharField(max_length=64, unique=True, default=generate_event_id)
    event_type = models.CharField(max_length=64)
    payload = models.JSONField()
    delivered = models.BooleanField(default=False)
    delivered_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    signature = models.CharField(max_length=256, blank=True)

    def mark_delivered(self):
        self.delivered = True
        self.delivered_at = timezone.now()
        self.save()

    def __str__(self):
        return f"WebhookEvent({self.event_type} {self.event_id})"
