# 在 users 应用下创建 signals.py 文件，用于保存信号函数，参考创建token信号的函数，用来在新建用户时加密密码
# 用户注册使用信号量实现密码加密
# https://blog.starmeow.cn/detail/4c5bde74a8f110656874902f07378009/
from django.conf import settings
from django.db.models.signals import post_save
from django.dispatch import receiver

from django.contrib.auth import get_user_model

User = get_user_model()

#sender表示接收User这个Model传递过来的信号，在传过来后，它需要确认是否是created新建数据，如果是新建数据，才进行密码加密。因为如果是update更新的时候也会传递post_save信号。使用信号，代码分离性较强
@receiver(post_save, sender=settings.AUTH_USER_MODEL)
def create_user(sender, instance=None, created=False, **kwargs):
    if created:
        password = instance.password  # instance指的就是创建的用户对象
        instance.set_password(password)
        instance.save()
