import uuid
from datetime import timedelta
from django.db import models
from django.conf import settings
from django.http import HttpRequest
if getattr(settings, "USE_TZ", False):
    from django.utils.timezone import localtime as now
else:
    from django.utils.timezone import now


class TokenManager(models.Manager):

    def get_queryset(self):
        return super().get_queryset()


class Token(models.Model):
    token = models.TextField('token')
    user = models.ForeignKey(settings.AUTH_USER_MODEL,
                             on_delete=models.CASCADE)
    expired_in = models.DateTimeField()
    UNIT_OF_TIME = "hours"
    TIMES = 1

    class Meta:
        db_table = "token"

    def __init__(self, *args, **kwargs):

        super().__init__(*args, **kwargs)

    def expire_all(self):
        self.user.token_set.all().delete()  # type: ignore

    @classmethod
    def get_valid_token(cls, user_id: int):
        try:
            token = cls.objects.get(user_id=user_id)
            if token.expired_in <= now():
                token.delete()
                token = Token.token_factory(user_id=user_id)
            else:
                cls.token_refresher(token)
        except:
            token = Token.token_factory(user_id=user_id)

        return token

    def token_refresher(self):
        self.expired_in = self.suspended_time()
        self.save()
        return

    @classmethod
    def token_factory(cls, user_id):
        token = Token.objects.create(
            token=cls.token_generator(),
            user_id=user_id,
            expired_in=cls.suspended_time()
        )
        token.expired_in = token.suspended_time()
        token.save()
        return token

    @classmethod
    def token_generator(cls):
        return str(uuid.uuid4())

    @classmethod
    def suspended_time(cls):

        PREFIX = getattr(settings, "CUSTOM_PREFIX", '')
        if PREFIX:
            PREFIX += "_"
        TIMES = getattr(settings, f"{PREFIX}TIMES", 1)
        UNIT_OF_TIME = getattr(settings, f"{PREFIX}UNIT_OF_TIME", 'hours')
        polling_time = {UNIT_OF_TIME: TIMES}
        cur_time = now()
        ensure_time = timedelta(**polling_time)
        return cur_time+ensure_time
