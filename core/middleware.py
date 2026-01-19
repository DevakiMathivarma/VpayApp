# payments/middleware.py
from .models import IdempotencyKey
import json

class IdempotencyMiddleware:
    """
    Simple idempotency middleware: if request contains `Idempotency-Key` header and we have a stored
    response it returns that stored response early. Views should save responses using IdempotencyKey
    model (examples in views.py).
    """
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        key = request.headers.get('Idempotency-Key') or request.META.get('HTTP_IDEMPOTENCY_KEY')
        if not key or request.method not in ('POST', 'PUT'):
            return self.get_response(request)

        try:
            existing = IdempotencyKey.objects.filter(key=key).first()
            if existing and existing.response_body is not None:
                from django.http import JsonResponse
                return JsonResponse(existing.response_body, status=existing.response_code or 200, safe=False)
        except Exception:
            pass

        response = self.get_response(request)
        return response

# Utility that views may call to save idempotency response
def save_idempotency_response(request, response):
    key = request.headers.get('Idempotency-Key') or request.META.get('HTTP_IDEMPOTENCY_KEY')
    if not key:
        return
    try:
        body = None
        try:
            body = json.loads(response.content.decode('utf-8'))
        except Exception:
            body = {'detail': response.content.decode('utf-8')}
        IdempotencyKey.objects.update_or_create(
            key=key,
            defaults={'method': request.method, 'path': request.path, 'response_code': response.status_code, 'response_body': body}
        )
    except Exception:
        pass
