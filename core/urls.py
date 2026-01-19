from django.urls import path
from . import views
from core.views import google_login_redirect
from .views import (
    CreatePaymentView, CapturePaymentView,
    PaymentStatusView, VerifyOtpView,vts_pay_demo,
)

app_name = 'core'

urlpatterns = [
    path('', views.home_view, name='home'),                     # optional homepage
    path('register/', views.register_view, name='register'),    # registration form (GET/POST)
    path('login/', views.login_view, name='login'),             # login form (username + otp) (GET/POST)
    path('resend-otp/', views.resend_otp_view, name='resend_otp'),  # resend otp (POST)
    path('dashboard/', views.dashboard_view, name='dashboard'), # user dashboard (login required)
    path('logout/', views.logout_view, name='logout'),  
    path('resend-otp/', views.resend_otp_view, name='resend_otp'),
    path('ajax-verify-otp/', views.ajax_verify_otp, name='ajax_verify_otp'),
         path('googlelogin/', google_login_redirect, name='google_login_redirect'),
   
    path('payments/create-order/', views.create_order_razor_view, name='create_order'),
    path('payments/verify/', views.verify_payment_view, name='verify_payment'),
    path('payments/webhook/razorpay/', views.razorpay_webhook, name='razorpay_webhook'),

    path("recharge/", views.recharge_view, name="recharge"),
    path("recharge/create/", views.create_recharge, name="create_recharge"),
    path("recharge/upi/<uuid:order_id>/", views.recharge_upi_page, name="recharge_upi_page"),
    path("recharge/submit-txn/<uuid:order_id>/", views.submit_upi_tid, name="submit_upi_tid"),
    path("api/plans/<str:operator_code>/", views.api_get_plans, name="api_get_plans"),
    path('create-order/', views.create_order_view, name='create_order'),
    path('i-paid/', views.i_paid, name='i_paid'),
    path('transaction/', views.transactions_view, name='transactions_view'),
    path('transactions/<int:txn_id>/', views.transaction_detail, name='transaction_detail'),
    path('transactions/stats/', views.transaction_stats, name='txn_stats'),
    path('transactions/filter/', views.filter_transactions_api, name='api_filter_transactions'),
 # ------- TEST MODE (single page) -------
    path("test/", views.test_kyc_view, name="test_view"),
    path("kyc/submit-test/", views.test_kyc_submit, name="test_submit"),

    # ------- LIVE MODE (single page) -------
    path("live/", views.live_kyc_view, name="live_view"),
    path("api/kyc/submit-live/", views.live_kyc_submit, name="live_submit"),

    # ------- STATUS PAGE -------
    path("status/", views.kyc_status, name="status"),

    # path("send-email-verification/", views.send_email_verification, name="send_email_verification"),
    # path("verify-email/", views.verify_email_link, name="verify_email_link"),
    # path("api/email-status/", views.email_status, name="email_status"),
    path("send-email-verification/", views.send_email_verification_view, name="send_email_verification"),
path("verify-email/", views.verify_email_link, name="verify_email_link"),
path("api/email-status/", views.email_status, name="email_status"),
    path("api/kyc/personal/", views.api_get_kyc_personal, name="api_kyc_personal_get"),  # GET
path("api/kyc/personal/save/", views.api_save_kyc_personal, name="api_kyc_personal_save"),  # POST

path('api/kyc/pan/save/', views.api_save_kyc_pan, name='api_save_kyc_pan'),
    path('api/kyc/bank/save/', views.api_save_kyc_bank, name='api_save_kyc_bank'),
    path('api/kyc/submit/', views.api_submit_kyc, name='api_submit_kyc'),
    path('vpay_dashboard/', views.vpay_dashboard, name='vpay_dashboard'),

    # payment integration
    path('api/v1/create-payment/', CreatePaymentView.as_view(), name='create-payment'),
    path('api/v1/capture-payment/', CapturePaymentView.as_view(), name='capture-payment'),
    path('api/v1/payment-status/', PaymentStatusView.as_view(), name='payment-status'),
    path('api/v1/verify-otp/', VerifyOtpView.as_view(), name='verify-otp'),
    path("vts-demo/", vts_pay_demo, name="vts-demo"),
        path('sandbox/simulate/', views.sandbox_simulate, name='sandbox_simulate'),

]

