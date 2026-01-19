# payments/serializers.py
from rest_framework import serializers

class CreatePaymentSerializer(serializers.Serializer):
    key = serializers.CharField()
    amount = serializers.IntegerField()
    currency = serializers.CharField(default="INR")
    customer = serializers.DictField(child=serializers.CharField(), required=False)
    order_id = serializers.CharField(required=False, allow_blank=True)


class CapturePaymentSerializer(serializers.Serializer):
    payment_session_id = serializers.CharField()
    method = serializers.CharField()  # card, wallet, upi, netbanking
    card_last4 = serializers.CharField(required=False, allow_blank=True)


class UpiCollectSerializer(serializers.Serializer):
    payment_session_id = serializers.CharField()
    upi_id = serializers.CharField()


class NetbankingSerializer(serializers.Serializer):
    payment_session_id = serializers.CharField()
    bank = serializers.CharField()


class VerifyOtpSerializer(serializers.Serializer):
    payment_session_id = serializers.CharField()
    otp = serializers.CharField()
