# # core/admin.py
# from django.contrib import admin
# from .models import BankAccount, Transaction, Notification

# @admin.register(BankAccount)
# class BankAccountAdmin(admin.ModelAdmin):
#     list_display = ('user', 'bank_name', 'account_number', 'is_default', 'created_at')
#     search_fields = ('user__username', 'bank_name', 'account_number')
# from django.contrib import admin
# from .models import Transaction

# from django.contrib import admin
# from .models import Transaction
# from django.utils.html import format_html
# @admin.register(Transaction)
# class TransactionAdmin(admin.ModelAdmin):
#     # Columns shown in the main list view
#     list_display = (
#         'txn_num', 'user', 'amount', 'provider', 'status', 'created_at', 'updated_at'
#     )
#     # Fields that can be searched
#     search_fields = (
#         'txn_num', 'user__username', 'provider', 'to_upi', 'razorpay_payment_id'
#     )
#     # Filters shown on the right-hand side
#     list_filter = (
#         'status', 'provider', 'created_at'
#     )
#     # Fields that cannot be edited manually in the admin form
#     readonly_fields = (
#         'txn_num', 'created_at', 'updated_at', 'razorpay_order_id',
#         'razorpay_payment_id', 'razorpay_signature'
#     )

#     # Optional: field grouping in the edit form for better layout
#     fieldsets = (
#         ("Transaction Info", {
#             "fields": (
#                 'txn_num', 'user', 'amount', 'to_upi', 'provider', 'status'
#             )
#         }),
#         ("Razorpay Details", {
#             "fields": (
#                 'razorpay_order_id', 'razorpay_payment_id', 'razorpay_signature'
#             ),
#             "classes": ("collapse",),  # collapsible section
#         }),
#         ("Notes & Timestamps", {
#             "fields": ('notes', 'created_at', 'updated_at')
#         }),
#     )

#     # Default ordering (latest first)
#     ordering = ('-created_at',)

#     # Display color-coded statuses (optional enhancement)
#     def colored_status(self, obj):
#         color_map = {
#             'PENDING': 'orange',
#             'SUCCESS': 'green',
#             'FAILED': 'red'
#         }
#         color = color_map.get(obj.status, 'black')
#         return format_html(f'<b style="color:{color}">{obj.status}</b>')
#     colored_status.short_description = 'Status'


# @admin.register(Notification)
# class NotificationAdmin(admin.ModelAdmin):
#     list_display = ('user', 'message', 'is_read', 'created_at')
#     list_filter = ('is_read','created_at')


# core/admin.py
from django.contrib import admin
from django.contrib.auth import get_user_model
from django.contrib.auth.admin import UserAdmin as DjangoUserAdmin
from django.utils.html import format_html
from django.http import HttpResponse
import csv

from .models import (
    BankAccount,
    Transaction,
    Notification,
    Operator,
    RechargePlan,
    RechargeOrder,
)

User = get_user_model()


# --- Inline for Transactions on User page ---
class TransactionInline(admin.TabularInline):
    model = Transaction
    fields = ('txn_num', 'amount', 'to_upi', 'provider', 'status', 'created_at')
    readonly_fields = ('txn_num', 'amount', 'to_upi', 'provider', 'status', 'created_at')
    extra = 0
    show_change_link = True
    can_delete = False  # typically don't delete transactions from user page


# --- Inline for BankAccount on User page ---
class BankAccountInline(admin.TabularInline):
    model = BankAccount
    fields = ('bank_name', 'account_number', 'ifsc', 'is_default', 'created_at')
    readonly_fields = ('created_at',)
    extra = 0


# --- Admin actions ---
def export_transactions_csv(modeladmin, request, queryset):
    """Admin action to export selected transactions as CSV."""
    meta = modeladmin.model._meta
    field_names = ['txn_num', 'user', 'amount', 'to_upi', 'provider', 'status', 'created_at', 'updated_at']

    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = f'attachment; filename=transactions_export.csv'
    writer = csv.writer(response)

    writer.writerow(field_names)
    for obj in queryset.select_related('user'):
        writer.writerow([
            getattr(obj, 'txn_num', ''),
            str(obj.user),
            getattr(obj, 'amount', ''),
            getattr(obj, 'to_upi', ''),
            getattr(obj, 'provider', ''),
            getattr(obj, 'status', ''),
            getattr(obj, 'created_at', ''),
            getattr(obj, 'updated_at', ''),
        ])
    return response

export_transactions_csv.short_description = "Export selected transactions to CSV"


# --- TransactionAdmin ---
# core/admin.py (TransactionAdmin portion)
from django.contrib import admin
from django.contrib.admin import DateFieldListFilter
from django.utils.html import format_html
from .models import Transaction

@admin.register(Transaction)
class TransactionAdmin(admin.ModelAdmin):
    list_display = ('txn_num', 'user', 'amount', 'provider', 'colored_status', 'created_at', 'updated_at')
    search_fields = ('txn_num', 'user__username', 'user__email', 'provider', 'to_upi', 'razorpay_payment_id')
    # Use explicit DateFieldListFilter for created_at so date ranges behave correctly
    list_filter = ('status', 'provider', ('created_at', DateFieldListFilter), 'user')
    readonly_fields = (
        'txn_num', 'created_at', 'updated_at', 'razorpay_order_id',
        'razorpay_payment_id', 'razorpay_signature'
    )
    fieldsets = (
        ("Transaction Info", {
            "fields": ('txn_num', 'user', 'amount', 'to_upi', 'provider', 'status')
        }),
        ("Razorpay Details", {
            "fields": ('razorpay_order_id', 'razorpay_payment_id', 'razorpay_signature'),
            "classes": ("collapse",),
        }),
        ("Notes & Timestamps", {
            "fields": ('notes', 'created_at', 'updated_at')
        }),
    )
    ordering = ('-created_at',)
    actions = []  # keep or add export action if you want
    date_hierarchy = 'created_at'
    list_select_related = ('user',)
    raw_id_fields = ('user',)

    def colored_status(self, obj):
        color_map = {
            Transaction.STATUS_PENDING: 'orange',
            Transaction.STATUS_SUCCESS: 'green',
            Transaction.STATUS_FAILED: 'red'
        }
        color = color_map.get(obj.status, 'black')
        return format_html(f'<b style="color:{color}">{obj.status}</b>')
    colored_status.short_description = 'Status'



# --- NotificationAdmin ---
@admin.register(Notification)
class NotificationAdmin(admin.ModelAdmin):
    list_display = ('user', 'short_message', 'is_read', 'created_at')
    list_filter = ('is_read', 'created_at')
    search_fields = ('user__username', 'message')
    readonly_fields = ('created_at',)

    def short_message(self, obj):
        return obj.message[:60]
    short_message.short_description = 'Message (first 60 chars)'


# --- BankAccount admin ---
@admin.register(BankAccount)
class BankAccountAdmin(admin.ModelAdmin):
    list_display = ('user', 'bank_name', 'account_number_masked', 'is_default', 'created_at')
    search_fields = ('user__username', 'bank_name', 'account_number')
    list_filter = ('is_default', 'created_at')
    raw_id_fields = ('user',)
    readonly_fields = ('created_at',)

    def account_number_masked(self, obj):
        if obj.account_number and len(obj.account_number) > 4:
            return f"****{obj.account_number[-4:]}"
        return obj.account_number
    account_number_masked.short_description = 'Account'


# --- Optionally register recharge models if you want them in admin ---
@admin.register(Operator)
class OperatorAdmin(admin.ModelAdmin):
    list_display = ('name', 'code', 'circle')
    search_fields = ('name', 'code', 'circle')


@admin.register(RechargePlan)
class RechargePlanAdmin(admin.ModelAdmin):
    list_display = ('title', 'operator', 'amount', 'validity')
    search_fields = ('title', 'operator__name')
    list_filter = ('operator',)


@admin.register(RechargeOrder)
class RechargeOrderAdmin(admin.ModelAdmin):
    list_display = ('id', 'user', 'mobile', 'amount', 'status', 'created_at')
    list_filter = ('status', 'created_at', 'operator')
    search_fields = ('mobile', 'user__username', 'id')
    date_hierarchy = 'created_at'
    raw_id_fields = ('user', 'operator', 'plan')


# --- Register User with inlines ---
@admin.register(User)
class UserAdmin(DjangoUserAdmin):
    # keep Django's default UserAdmin configuration but add inlines
    inlines = (BankAccountInline, TransactionInline)
    list_display = ('username', 'email', 'phone_number', 'is_staff', 'is_phone_verified', 'is_active', 'date_joined')
    search_fields = ('username', 'email', 'phone_number',)
    readonly_fields = ('date_joined',)
    # optionally add list_filter or fieldsets adjustments if needed


# analytics page
# core/admin.py
from django.contrib import admin
from django.urls import path
from django.shortcuts import render
from django.utils.translation import gettext_lazy as _
from django.conf import settings
from django.urls import reverse
# core/admin.py
from django.contrib import admin
from django.urls import path
from . import views as core_views

# register your models here as usual, e.g.
# admin.site.register(MyModel)

# Patch admin URLs once (wrap the original function)
def _get_admin_urls(original_get_urls):
    def get_urls():
        # our extra admin-only urls
        extra = [
            path('analytics/', admin.site.admin_view(core_views.admin_analytics_view), name='analytics'),
        ]
        return extra + original_get_urls()
    return get_urls

# Only patch once (defensive)
if not getattr(admin.site, '_analytics_patched', False):
    admin.site.get_urls = _get_admin_urls(admin.site.get_urls)
    admin.site._analytics_patched = True


# kyc
from django.contrib import admin
from .models import TestKYC, LiveKYC


# ------------------------
# TEST MODE KYC ADMIN
# ------------------------
# core/admin.py (excerpt)
from django.contrib import admin
from .models import TestKYC, LiveKYC

# @admin.register(TestKYC)
# class TestKYCAdmin(admin.ModelAdmin):
#     list_display = (
#         "user",
#         "full_name",
#         "email",
#         "mobile_number",
#         "business_name",
#         "pan_number",
#         "email_verified",
#         "email_verification_method",
#         "created_at",
#     )
#     search_fields = (
#         "user__username",
#         "full_name",
#         "email",
#         "mobile_number",
#         "pan_number",
#         "business_name",
#     )
#     list_filter = ("is_verified", "email_verified", "created_at")
#     readonly_fields = ("created_at", "email_verified_at")
#     fieldsets = (
#         (None, {
#             "fields": ("user", "full_name", "email", "mobile_number", "business_name", "business_type", "address")
#         }),
#         ("PAN", {"fields": ("pan_number", "pan_document")}),
#         ("Bank", {"fields": ("bank_account_number", "ifsc_code", "bank_proof")}),
#         ("Verification", {"fields": ("email_verified", "email_verified_at", "email_verification_method", "is_verified", "verification_notes")}),
#         ("Timestamps", {"fields": ("created_at",)}),
#     )



# # ------------------------
# # LIVE MODE KYC ADMIN
# # ------------------------
# @admin.register(LiveKYC)
# class LiveKYCAdmin(admin.ModelAdmin):
#     list_display = (
#         "user",
#         "director_name",
#         "director_pan",
#         "ubo_name",
#         "is_verified",
#         "created_at",
#     )
#     search_fields = (
#         "user__username",
#         "director_name",
#         "director_pan",
#         "ubo_name",
#     )
#     list_filter = ("is_verified", "created_at")
#     readonly_fields = ("created_at",)



from django.contrib import admin
from django.urls import path
from django.shortcuts import redirect
from django.template.response import TemplateResponse
from django.contrib import messages
from django.core.mail import send_mail
from django.conf import settings
from django.utils import timezone
from django.utils.html import format_html
from django.http import HttpResponseRedirect

from .models import TestKYC, LiveKYC, Notification,TestKeys

# small helper: set attribute only if model has it
def _maybe_set(instance, field, value):
    if hasattr(instance, field):
        setattr(instance, field, value)
        return True
    return False

# send email helper (non-blocking: fail_silently True)
def _send_user_email(to_email, subject, body):
    if not to_email:
        return False
    from_email = getattr(settings, "DEFAULT_FROM_EMAIL", None) or getattr(settings, "SERVER_EMAIL", None) or "noreply@vpay.local"
    try:
        send_mail(subject, body, from_email, [to_email], fail_silently=True)
        return True
    except Exception:
        return False

# create notification helper (defensive)
def _create_notification(user, message):
    try:
        Notification.objects.create(user=user, message=message)
    except Exception:
        pass


# @admin.register(TestKYC)
# class TestKYCAdmin(admin.ModelAdmin):
#     list_display = (
#         "user", "full_name", "email", "mobile_number", "business_name",
#         "pan_number", "email_verified", "is_verified", "created_at",
#     )
#     search_fields = ("user__username", "full_name", "email", "mobile_number", "pan_number", "business_name")
#     list_filter = ("is_verified", "email_verified", "created_at")
#     readonly_fields = (
#         # readonly fields so admin doesn't edit the submitted documents directly
#         "pan_number", "pan_document", "bank_account_number", "ifsc_code", "bank_proof",
#         "created_at", "email_verified_at",
#     )

#     fieldsets = (
#         (None, {"fields": ("user", "full_name", "email", "mobile_number", "business_name", "business_type", "address")}),
#         ("PAN", {"fields": ("pan_number", "pan_document")}),
#         ("Bank", {"fields": ("bank_account_number", "ifsc_code", "bank_proof")}),
#         ("Verification", {"fields": ("email_verified", "email_verified_at", "email_verification_method", "is_verified", "verification_notes")}),
#         ("Timestamps", {"fields": ("created_at", "verified_at")}) if hasattr(TestKYC, "verified_at") else ("Timestamps", {"fields": ("created_at",)}),
#     )

#     actions = ["approve_kyc", "reject_kyc"]

#     # show small colored status in list (if is_verified exists)
#     def colored_is_verified(self, obj):
#         if getattr(obj, "is_verified", False):
#             return format_html('<span style="color:green;font-weight:700">Approved</span>')
#         return format_html('<span style="color:orange;font-weight:700">Pending</span>')
#     colored_is_verified.short_description = "KYC Status"

#     # Admin action: approve selected
#     def approve_kyc(self, request, queryset):
#         count = 0
#         for kyc in queryset:
#             try:
#                 _maybe_set(kyc, "is_verified", True)
#                 _maybe_set(kyc, "verified_at", timezone.now())
#                 # store who verified if field exists
#                 if hasattr(kyc, "verified_by"):
#                     try:
#                         kyc.verified_by = request.user
#                     except Exception:
#                         pass
#                 # set status field fallback
#                 if hasattr(kyc, "status"):
#                     try:
#                         kyc.status = "APPROVED"
#                     except Exception:
#                         pass
#                 kyc.save()
#                 # send email + create notification
#                 to_email = getattr(kyc, "email", None) or getattr(kyc.user, "email", None)
#                 subj = "Your KYC has been approved"
#                 body = (
#                     f"Hello {kyc.full_name or kyc.user.get_full_name() or kyc.user.username},\n\n"
#                     "Your KYC has been reviewed and approved by our team. You will be notified if any further steps are required.\n\n"
#                     "Regards,\nVPay Team"
#                 )
#                 _send_user_email(to_email, subj, body)
#                 _create_notification(kyc.user, "Your KYC has been approved by admin.")
#                 count += 1
#             except Exception:
#                 # keep going for other records
#                 continue
#         self.message_user(request, f"{count} KYC record(s) approved.", level=messages.SUCCESS)
#     approve_kyc.short_description = "Approve selected KYC(s)"

#     # Admin action: reject selected (will ask for reason via admin action form is more complex,
#     # so we'll just mark rejected and set note from request.POST if available)
#     def reject_kyc(self, request, queryset):
#         count = 0
#         # optional reason from POST (when using action form)
#         reason = request.POST.get("reject_reason", "").strip() or None
#         for kyc in queryset:
#             try:
#                 _maybe_set(kyc, "is_verified", False)
#                 if hasattr(kyc, "status"):
#                     try:
#                         kyc.status = "REJECTED"
#                     except Exception:
#                         pass
#                 if reason:
#                     prev = getattr(kyc, "verification_notes", "") or ""
#                     kyc.verification_notes = prev + f"\n[Admin Reject {timezone.now().isoformat()} by {request.user}]: {reason}"
#                 else:
#                     prev = getattr(kyc, "verification_notes", "") or ""
#                     kyc.verification_notes = prev + f"\n[Admin Reject {timezone.now().isoformat()} by {request.user}]"
#                 kyc.save()
#                 # notify user
#                 to_email = getattr(kyc, "email", None) or getattr(kyc.user, "email", None)
#                 subj = "Your KYC has been rejected"
#                 body = (
#                     f"Hello {kyc.full_name or kyc.user.get_full_name() or kyc.user.username},\n\n"
#                     "We reviewed your KYC submission and it could not be approved. "
#                     "Please check the verification notes in your account and re-submit if applicable.\n\n"
#                     "Regards,\nVPay Team\n\n"
#                     + (f"Reason: {reason}" if reason else "")
#                 )
#                 _send_user_email(to_email, subj, body)
#                 _create_notification(kyc.user, "Your KYC submission was rejected by admin. Check notes.")
#                 count += 1
#             except Exception:
#                 continue
#         self.message_user(request, f"{count} KYC record(s) rejected.", level=messages.WARNING)
#     reject_kyc.short_description = "Reject selected KYC(s)"

#     # Add approve/reject buttons on change form (single object)
#     def change_view(self, request, object_id, form_url='', extra_context=None):
#         extra_context = extra_context or {}
#         try:
#             obj = self.get_object(request, object_id)
#         except Exception:
#             obj = None

#         if obj:
#             # provide URLs that post back to this view with ?_approve=1 or ?_reject=1
#             extra_context['show_approve_buttons'] = True
#             extra_context['approve_url'] = f"{request.path}?_approve=1"
#             extra_context['reject_url'] = f"{request.path}?_reject=1"
#         # handle immediate approve/reject triggered by those buttons
#         if request.method == "POST" and "_approve" in request.GET:
#             # perform approve
#             try:
#                 obj = self.get_object(request, object_id)
#                 if obj:
#                     _maybe_set(obj, "is_verified", True)
#                     _maybe_set(obj, "verified_at", timezone.now())
#                     if hasattr(obj, "verified_by"):
#                         try:
#                             obj.verified_by = request.user
#                         except Exception:
#                             pass
#                     if hasattr(obj, "status"):
#                         obj.status = "APPROVED"
#                     obj.save()
#                     to_email = getattr(obj, "email", None) or getattr(obj.user, "email", None)
#                     _send_user_email(to_email, "Your KYC has been approved", "Your KYC was approved by admin.")
#                     _create_notification(obj.user, "Your KYC has been approved by admin.")
#                     self.message_user(request, "KYC approved.", level=messages.SUCCESS)
#                     return HttpResponseRedirect(request.path)
#             except Exception:
#                 self.message_user(request, "Failed to approve KYC (server error).", level=messages.ERROR)

#         if request.method == "POST" and "_reject" in request.GET:
#             # admin submitted reject; check for reason in POST
#             reason = request.POST.get("admin_reject_reason", "").strip()
#             try:
#                 obj = self.get_object(request, object_id)
#                 if obj:
#                     _maybe_set(obj, "is_verified", False)
#                     if hasattr(obj, "status"):
#                         obj.status = "REJECTED"
#                     prev = getattr(obj, "verification_notes", "") or ""
#                     obj.verification_notes = prev + f"\n[Admin Reject {timezone.now().isoformat()} by {request.user}]: {reason}"
#                     obj.save()
#                     to_email = getattr(obj, "email", None) or getattr(obj.user, "email", None)
#                     _send_user_email(to_email, "Your KYC has been rejected", f"Your KYC was rejected. Reason: {reason}")
#                     _create_notification(obj.user, "Your KYC was rejected by admin. Check notes.")
#                     self.message_user(request, "KYC rejected.", level=messages.WARNING)
#                     return HttpResponseRedirect(request.path)
#             except Exception:
#                 self.message_user(request, "Failed to reject KYC (server error).", level=messages.ERROR)

#         # provide control buttons in template via extra_context
#         return super().change_view(request, object_id, form_url, extra_context=extra_context)

#     # To show our small buttons in the admin change form we can inject HTML in change_form_template,
#     # but to avoid custom templates, we'll use admin's 'object-tools' area via response change.
#     def render_change_form(self, request, context, add=False, change=False, form_url='', obj=None):
#         # If on change form for an object, add "Approve" and "Reject" buttons at top
#         if obj is not None:
#             # Build a small HTML snippet to place in the admin change form
#             approve_button = format_html(
#                 '<form style="display:inline;margin-right:8px" method="post" action="{}">{% csrf_token %}<button type="submit" class="default">Approve</button></form>',
#                 request.path + "?_approve=1"
#             )
#             # For reject we want a small prompt; we'll make a simple form with a reason text field
#             reject_form = format_html(
#                 '<form style="display:inline" method="post" action="{}">{% csrf_token %}'
#                 '<input name="admin_reject_reason" placeholder="Rejection reason (optional)" style="margin-right:8px;padding:4px"/>'
#                 '<button type="submit" class="deletelink">Reject</button></form>',
#                 request.path + "?_reject=1"
#             )
#             # Place them into context under a key the template can show; default admin templates show 'extra' keys in some places,
#             # but to be safe, we'll add to context so templates that use it can display. Many Django versions don't display it by default,
#             # but some deployments accept additional html in 'adminform'.
#             context.setdefault('admin_extra_buttons', '')
#             # NOTE: can't directly insert template tags in format_html above; keep raw HTML string pieces
#             context['admin_extra_buttons'] = approve_button + reject_form

#         return super().render_change_form(request, context, add, change, form_url, obj)
#     def save_model(self, request, obj, form, change):
#     # Check if KYC was already approved before saving
#         approved_before = False
#         if change:
#             try:
#                 old = TestKYC.objects.get(pk=obj.pk)
#                 approved_before = old.is_verified
#             except TestKYC.DoesNotExist:
#                 approved_before = False

#         super().save_model(request, obj, form, change)

#     # If newly approved → generate test keys
#         if obj.is_verified and not approved_before:
#             from .models import TestKeys

#         # Create keys only if user doesn't already have TestKeys
#         TestKeys.objects.get_or_create(
#             user=obj.user,
#             defaults={
#                 "public_key": TestKeys.generate_key("vpay_test_pub"),
#                 "secret_key": TestKeys.generate_key("vpay_test_secret"),
#             }
#         )



# core/admin.py (add / replace these imports near the top of the file)
from django.contrib import admin, messages
from django.utils.html import format_html
from django.http import HttpResponseRedirect
from django.middleware.csrf import get_token
from django.utils import timezone

# make sure your helper functions are available in this module:
# _maybe_set, _send_user_email, _create_notification
# (if they're defined elsewhere, import them)

# --- TestKYCAdmin ---
@admin.register(TestKYC)
class TestKYCAdmin(admin.ModelAdmin):
    list_display = (
        "user", "full_name", "email", "mobile_number", "business_name",
        "pan_number", "email_verified", "is_verified", "created_at",
    )
    search_fields = ("user__username", "full_name", "email", "mobile_number", "pan_number", "business_name")
    list_filter = ("is_verified", "email_verified", "created_at")
    readonly_fields = (
        # readonly fields so admin doesn't edit the submitted documents directly
        "pan_number", "pan_document", "bank_account_number", "ifsc_code", "bank_proof",
        "created_at", "email_verified_at",
    )

    fieldsets = (
        (None, {"fields": ("user", "full_name", "email", "mobile_number", "business_name", "business_type", "address")}),
        ("PAN", {"fields": ("pan_number", "pan_document")}),
        ("Bank", {"fields": ("bank_account_number", "ifsc_code", "bank_proof")}),
        ("Verification", {"fields": ("email_verified", "email_verified_at", "email_verification_method", "is_verified", "verification_notes")}),
        ("Timestamps", {"fields": ("created_at", "verified_at")}) if hasattr(TestKYC, "verified_at") else ("Timestamps", {"fields": ("created_at",)}),
    )

    actions = ["approve_kyc", "reject_kyc"]

    # show small colored status in list (if is_verified exists)
    def colored_is_verified(self, obj):
        if getattr(obj, "is_verified", False):
            return format_html('<span style="color:green;font-weight:700">Approved</span>')
        return format_html('<span style="color:orange;font-weight:700">Pending</span>')
    colored_is_verified.short_description = "KYC Status"

    # Admin action: approve selected
    def approve_kyc(self, request, queryset):
        count = 0
        for kyc in queryset:
            try:
                _maybe_set(kyc, "is_verified", True)
                _maybe_set(kyc, "verified_at", timezone.now())
                # store who verified if field exists
                if hasattr(kyc, "verified_by"):
                    try:
                        kyc.verified_by = request.user
                    except Exception:
                        pass
                # set status field fallback
                if hasattr(kyc, "status"):
                    try:
                        kyc.status = "APPROVED"
                    except Exception:
                        pass
                kyc.save()
                # send email + create notification
                to_email = getattr(kyc, "email", None) or getattr(kyc.user, "email", None)
                subj = "Your KYC has been approved"
                body = (
                    f"Hello {kyc.full_name or kyc.user.get_full_name() or kyc.user.username},\n\n"
                    "Your KYC has been reviewed and approved by our team. You will be notified if any further steps are required.\n\n"
                    "Regards,\nVPay Team"
                )
                try:
                    _send_user_email(to_email, subj, body)
                except Exception:
                    # log or ignore if mail helper not present
                    pass
                try:
                    _create_notification(kyc.user, "Your KYC has been approved by admin.")
                except Exception:
                    pass
                count += 1
            except Exception:
                # keep going for other records
                continue
        self.message_user(request, f"{count} KYC record(s) approved.", level=messages.SUCCESS)
    approve_kyc.short_description = "Approve selected KYC(s)"

    # Admin action: reject selected (will ask for reason via admin action form is more complex,
    # so we'll just mark rejected and set note from request.POST if available)
    def reject_kyc(self, request, queryset):
        count = 0
        # optional reason from POST (when using action form)
        reason = request.POST.get("reject_reason", "").strip() or None
        for kyc in queryset:
            try:
                _maybe_set(kyc, "is_verified", False)
                if hasattr(kyc, "status"):
                    try:
                        kyc.status = "REJECTED"
                    except Exception:
                        pass
                if reason:
                    prev = getattr(kyc, "verification_notes", "") or ""
                    kyc.verification_notes = prev + f"\n[Admin Reject {timezone.now().isoformat()} by {request.user}]: {reason}"
                else:
                    prev = getattr(kyc, "verification_notes", "") or ""
                    kyc.verification_notes = prev + f"\n[Admin Reject {timezone.now().isoformat()} by {request.user}]"
                kyc.save()
                # notify user
                to_email = getattr(kyc, "email", None) or getattr(kyc.user, "email", None)
                subj = "Your KYC has been rejected"
                body = (
                    f"Hello {kyc.full_name or kyc.user.get_full_name() or kyc.user.username},\n\n"
                    "We reviewed your KYC submission and it could not be approved. "
                    "Please check the verification notes in your account and re-submit if applicable.\n\n"
                    "Regards,\nVPay Team\n\n"
                    + (f"Reason: {reason}" if reason else "")
                )
                try:
                    _send_user_email(to_email, subj, body)
                except Exception:
                    pass
                try:
                    _create_notification(kyc.user, "Your KYC submission was rejected by admin. Check notes.")
                except Exception:
                    pass
                count += 1
            except Exception:
                continue
        self.message_user(request, f"{count} KYC record(s) rejected.", level=messages.WARNING)
    reject_kyc.short_description = "Reject selected KYC(s)"

    # Add approve/reject buttons on change form (single object)
    def change_view(self, request, object_id, form_url='', extra_context=None):
        extra_context = extra_context or {}
        try:
            obj = self.get_object(request, object_id)
        except Exception:
            obj = None

        if obj:
            # provide URLs that post back to this view with ?_approve=1 or ?_reject=1
            extra_context['show_approve_buttons'] = True
            extra_context['approve_url'] = f"{request.path}?_approve=1"
            extra_context['reject_url'] = f"{request.path}?_reject=1"

        # handle immediate approve/reject triggered by those buttons
        if request.method == "POST" and "_approve" in request.GET:
            # perform approve
            try:
                obj = self.get_object(request, object_id)
                if obj:
                    _maybe_set(obj, "is_verified", True)
                    _maybe_set(obj, "verified_at", timezone.now())
                    if hasattr(obj, "verified_by"):
                        try:
                            obj.verified_by = request.user
                        except Exception:
                            pass
                    if hasattr(obj, "status"):
                        obj.status = "APPROVED"
                    obj.save()
                    to_email = getattr(obj, "email", None) or getattr(obj.user, "email", None)
                    try:
                        _send_user_email(to_email, "Your KYC has been approved", "Your KYC was approved by admin.")
                    except Exception:
                        pass
                    try:
                        _create_notification(obj.user, "Your KYC has been approved by admin.")
                    except Exception:
                        pass
                    self.message_user(request, "KYC approved.", level=messages.SUCCESS)
                    return HttpResponseRedirect(request.path)
            except Exception:
                self.message_user(request, "Failed to approve KYC (server error).", level=messages.ERROR)

        if request.method == "POST" and "_reject" in request.GET:
            # admin submitted reject; check for reason in POST
            reason = request.POST.get("admin_reject_reason", "").strip()
            try:
                obj = self.get_object(request, object_id)
                if obj:
                    _maybe_set(obj, "is_verified", False)
                    if hasattr(obj, "status"):
                        obj.status = "REJECTED"
                    prev = getattr(obj, "verification_notes", "") or ""
                    obj.verification_notes = prev + f"\n[Admin Reject {timezone.now().isoformat()} by {request.user}]: {reason}"
                    obj.save()
                    to_email = getattr(obj, "email", None) or getattr(obj.user, "email", None)
                    try:
                        _send_user_email(to_email, "Your KYC has been rejected", f"Your KYC was rejected. Reason: {reason}")
                    except Exception:
                        pass
                    try:
                        _create_notification(obj.user, "Your KYC was rejected by admin. Check notes.")
                    except Exception:
                        pass
                    self.message_user(request, "KYC rejected.", level=messages.WARNING)
                    return HttpResponseRedirect(request.path)
            except Exception:
                self.message_user(request, "Failed to reject KYC (server error).", level=messages.ERROR)

        # provide control buttons in template via extra_context
        return super().change_view(request, object_id, form_url, extra_context=extra_context)

    # To show our small buttons in the admin change form we can inject HTML in change_form_template,
    # but to avoid custom templates, we'll add HTML via context safely (no template tags in Python strings).
    def render_change_form(self, request, context, add=False, change=False, form_url='', obj=None):
        # If on change form for an object, add "Approve" and "Reject" buttons at top
        if obj is not None:
            # get actual csrf token string and embed as hidden input (safe)
            csrf_value = get_token(request)

            approve_button = format_html(
                '<form style="display:inline;margin-right:8px" method="post" action="{}">'
                '<input type="hidden" name="csrfmiddlewaretoken" value="{}">'
                '<button type="submit" class="default">Approve</button>'
                '</form>',
                request.path + "?_approve=1",
                csrf_value
            )

            reject_form = format_html(
                '<form style="display:inline" method="post" action="{}">'
                '<input type="hidden" name="csrfmiddlewaretoken" value="{}">'
                '<input name="admin_reject_reason" placeholder="Rejection reason (optional)" style="margin-right:8px;padding:4px"/>'
                '<button type="submit" class="deletelink">Reject</button>'
                '</form>',
                request.path + "?_reject=1",
                csrf_value
            )

            # attach to context for use by templates (if your admin template prints this)
            context.setdefault('admin_extra_buttons', '')
            context['admin_extra_buttons'] = approve_button + reject_form

        return super().render_change_form(request, context, add, change, form_url, obj)

    def save_model(self, request, obj, form, change):
        # Determine if it was approved before saving so we can detect newly-approved
        approved_before = False
        if change:
            try:
                old = TestKYC.objects.get(pk=obj.pk)
                approved_before = bool(getattr(old, "is_verified", False))
            except TestKYC.DoesNotExist:
                approved_before = False

        super().save_model(request, obj, form, change)

        # If newly approved → generate test keys (create only if not exists)
        try:
            from .models import TestKeys  # local import to avoid circulars if any
            if getattr(obj, "is_verified", False) and not approved_before:
                TestKeys.objects.get_or_create(
                    user=obj.user,
                    defaults={
                        "public_key": TestKeys.generate_key("vpay_test_pub"),
                        "secret_key": TestKeys.generate_key("vpay_test_secret"),
                    }
                )
        except Exception:
            # avoid admin crash if TestKeys not present or generation fails; optionally log
            pass

# payment integration
# payments/admin.py
from django.contrib import admin
from .models import PaymentSession, IdempotencyKey, WebhookEvent

@admin.register(PaymentSession)
class PaymentSessionAdmin(admin.ModelAdmin):
    list_display = ('session_id','order_id','amount','currency','status','payment_id','created_at')
    search_fields = ('session_id','order_id','payment_id')

@admin.register(IdempotencyKey)
class IdempotencyAdmin(admin.ModelAdmin):
    list_display = ('key','method','path','response_code','last_used')

@admin.register(WebhookEvent)
class WebhookEventAdmin(admin.ModelAdmin):
    list_display = ('event_id','event_type','delivered','delivered_at','created_at')

