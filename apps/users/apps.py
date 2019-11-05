from django.apps import AppConfig

# 这些逻辑写完之后还需要加个配置，修改 users/apps.py 重载UsersConfig的ready方法
class UsersConfig(AppConfig):
    name = 'users'
    verbose_name = '用户'

    def ready(self):
        from users.signals import create_user