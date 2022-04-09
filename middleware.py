import json
import re
from time import time

from django.http import HttpRequest, HttpResponse, HttpResponseForbidden
from django.utils.deprecation import MiddlewareMixin
from django.contrib.auth import get_user_model
from django.contrib.auth.models import AnonymousUser
from django.conf import settings
from .models import Token

if getattr(settings, "USE_TZ", False):
    from django.utils.timezone import localtime as now
else:
    from django.utils.timezone import now


class TokenMiddleware(MiddlewareMixin):
    def __init__(self, get_response):
        super().__init__(get_response)

        urls = [
            re.compile(r'^(.*)/api'),
            re.compile(r'^api'),
            re.compile(r'^(.*)/admin/(.*)'),
        ]
        methods = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE']

        self.PREFIX = getattr(settings, "CUSTOM_PREFIX", '')
        if self.PREFIX:
            self.PREFIX += "_"

        self.ALLOWED_URL = getattr(
            settings, f"{self.PREFIX}ALLOWED_URL", ["/accounts/signin/"])
        self.CONTENT_TYPE = getattr(
            settings, f"{self.PREFIX}CONTENT_TYPE", "JSON")
        self.BACKEND_ONLY = getattr(
            settings, f"{self.PREFIX}BACKEND_ONLY", True)
        self.FILTERED_URLS = getattr(
            settings, f"{self.PREFIX}FILTERED_URL", urls)
        self.FILTERED_METHODS = getattr(
            settings, f"{self.PREFIX}FILTERED_METHODS", methods)
        self.USE_DJANGO_AUTH = getattr(
            settings, f"{self.PREFIX}USE_DJANGO_AUTH", True)
        self.DELIVER = getattr(settings, f"{self.PREFIX}DELIVER", "COOKIES")

    def process_request(self, request: HttpRequest):
        if self.BACKEND_ONLY and request.method in self.FILTERED_METHODS:
            token: Token | bool = self.validator(request)
            if not token:
                valid_url: list[bool] = [url.match(request.path)
                                         for url in self.FILTERED_URLS]
                if request.path in self.ALLOWED_URL:
                    pass
                elif any(valid_url):
                    pass

                else:
                    return HttpResponseForbidden(request, "미인가사용자")
            if self.USE_DJANGO_AUTH == True:
                self.authorize(request, token)

    def validator(self, request) -> Token | bool:
        """
        request에 담긴 token값을 받아서 유효한토큰 혹은 False를 반환함
        """
        try:
            value: str | None = self.get_token_from_url(request)
            token: Token = Token.objects.get(token=value)

            if token.expired_in >= now():
                token.token_refresher()
                return token
            else:
                token.delete()
                return False
        except:
            return False

    def authorize(self, request, token):
        if token:
            # from django.contrib.auth import login
            # login(request,token.user)
            request.user = token.user
        else:
            request.user = AnonymousUser()

    def get_token_from_url(self, request: HttpRequest) -> str | None:
        serial = None
        if self.DELIVER == "COOKIES":
            serial: str | None = request.COOKIES.get('token')
        if not serial:
            body: dict = json.loads(request.body)
            serial = body.get('token')
        # print(f"token  : {serial}")
        try:
            return serial
        except:
            return None

    def send_token(self, request: HttpRequest, token: Token):
        request.COOKIES.update(token=token.token)
        return token


def ResponseCheckMiddleware(get_response):
    def MiddleWare(request):
        result = get_response(request)
        return result
    return MiddleWare


class TimeChecker(MiddlewareMixin):

    def process_request(self, request: HttpRequest):
        _start_time: str = str(time())
        request.COOKIES.update(start_time=_start_time)
        print('timechecking')
        # return self.get_response(request)

    def process_response(self, request: HttpRequest, response: HttpResponse):
        start_time: str | None = request.COOKIES.get('start_time')
        if isinstance(start_time, str):
            print(f"{time()-float(start_time):0.5f}sec")
        return response


class JsonFormatter(MiddlewareMixin):
    async_capable = True
    API_URLS = [
        re.compile(r'^api/(.*)'),
    ]
    AVOID_URLS = [
        re.compile(r'^api/docs'),
        re.compile(r'^api/openapi.json'),
        re.compile(r'^api/docs(.*)'),
    ]
    METHOD = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE']

    def process_response(self, request: HttpRequest, response: HttpResponse):
        path = request.path_info.lstrip('/')
        valid_urls = (url.match(path) for url in self.API_URLS)
        avoid_urls = (url.match(path) for url in self.AVOID_URLS)
        try:
            if not any(avoid_urls):
                if request.method in self.METHOD and any(valid_urls):
                    response_format = {
                        'status': response.status_code,
                        'datas': {},
                        'message': None
                    }

                    if hasattr(response, 'content') and \
                            getattr(response, 'content') is not None:
                        data: dict = json.loads(response.content)
                        try:
                            response_format['message'] = data['message']
                            data.pop('message')
                        except:
                            pass

                        response_format['datas'] = data
                        response.content = json.dumps(response_format)
        except:
            pass
        return response
