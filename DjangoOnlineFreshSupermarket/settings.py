"""
Django settings for DjangoOnlineFreshSupermarket project.

Generated by 'django-admin startproject' using Django 2.2.

For more information on this file, see
https://docs.djangoproject.com/en/2.2/topics/settings/

For the full list of settings and their values, see
https://docs.djangoproject.com/en/2.2/ref/settings/
"""

import os
import sys

# Build paths inside the project like this: os.path.join(BASE_DIR, ...)
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE_DIR)
sys.path.insert(0, os.path.join(BASE_DIR, 'apps'))
sys.path.insert(0, os.path.join(BASE_DIR, 'apps_extend'))  # 添加扩展应用路径

# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/2.2/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = '+0jtduy*crf@8%!m3plwm!x@dnna0-&%04hmy&#y$rk0*u7az5'

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True

# ALLOWED_HOSTS = []
ALLOWED_HOSTS = ["*"]

AUTH_USER_MODEL = 'users.UserProfile'  # 使用自定义的models做认证

AUTHENTICATION_BACKENDS = (
    'users.views.CustomBackend',  # 自定义认证后端
    'social_core.backends.weibo.WeiboOAuth2',  # 微博认证后端
    'social_core.backends.qq.QQOAuth2',  # QQ认证后端
    'social_core.backends.weixin.WeixinOAuth2',  # 微信认证后端
    'django.contrib.auth.backends.ModelBackend',  # 使用了`django.contrib.auth`应用程序，支持帐密认证
)  # 指定认证后台

# Application definition

INSTALLED_APPS = [
    # 'simpleui',  # 第三方后台，使用https://github.com/newpanjing/simpleui
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    # 添加drf应用
    'rest_framework',
    'rest_framework.authtoken',
    'django_filters',
    # 添加Django联合登录
    'social_django',
    # Django跨域解决
    'corsheaders',
    # 注册富文本编辑器ckeditor
    'ckeditor',
    # 注册富文本上传图片ckeditor_uploader
    'ckeditor_uploader',
    'users.apps.UsersConfig',
    'goods.apps.GoodsConfig',
    'trade.apps.TradeConfig',
    'user_operation.apps.UserOperationConfig',
]

MIDDLEWARE = [
    'corsheaders.middleware.CorsMiddleware',  # corsheaders跨域
    'django.middleware.common.CommonMiddleware',  # corsheaders跨域
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'DjangoOnlineFreshSupermarket.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [os.path.join(BASE_DIR, 'templates')]
        ,
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
                # 添加下面2条social_django上下文处理器
                'social_django.context_processors.backends',
                'social_django.context_processors.login_redirect',
            ],
        },
    },
]

WSGI_APPLICATION = 'DjangoOnlineFreshSupermarket.wsgi.application'

# Database
# https://docs.djangoproject.com/en/2.2/ref/settings/#databases

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': os.path.join(BASE_DIR, 'db.sqlite3'),
    }
}

# Password validation
# https://docs.djangoproject.com/en/2.2/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]

# Internationalization
# https://docs.djangoproject.com/en/2.2/topics/i18n/

# LANGUAGE_CODE = 'en-us'
# 语言改为中文
LANGUAGE_CODE = 'zh-hans'

# TIME_ZONE = 'UTC'
# 时区改为上海
TIME_ZONE = 'Asia/Shanghai'

USE_I18N = True

USE_L10N = True

# USE_TZ = True
# 数据库存储使用时间，True时间会被存为UTC的时间
USE_TZ = False

# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/2.2/howto/static-files/

STATIC_URL = '/static/'
# 配置静态文件
STATICFILES_DIRS = (
    os.path.join(BASE_DIR, 'static'),  # 逗号不能少
)

# 配置媒体文件
MEDIA_URL = '/media/'
MEDIA_ROOT = os.path.join(BASE_DIR, 'media')

# 配置富文本上传路径
CKEDITOR_UPLOAD_PATH = 'upload/'

# DRF配置
REST_FRAMEWORK = {
    # 'DEFAULT_PAGINATION_CLASS': 'rest_framework.pagination.PageNumberPagination',
    # 'PAGE_SIZE': 5,
    'DEFAULT_AUTHENTICATION_CLASSES': (
        'rest_framework.authentication.BasicAuthentication',
        'rest_framework.authentication.SessionAuthentication',  # 上面两个用于DRF基本验证
        # 'rest_framework.authentication.TokenAuthentication',  # TokenAuthentication，取消全局token，放在视图中进行
        # 'rest_framework_simplejwt.authentication.JWTAuthentication',  # djangorestframework_simplejwt JWT认证
    ),
    # throttle对接口访问限速
    'DEFAULT_THROTTLE_CLASSES': [
        # 'rest_framework.throttling.AnonRateThrottle',  # 用户未登录请求限速，通过IP地址判断
        # 'rest_framework.throttling.UserRateThrottle'  # 用户登陆后请求限速，通过token判断
        'rest_framework.throttling.ScopedRateThrottle',  # 限制用户对于每个视图的访问频次，使用ip或user id。
    ],
    'DEFAULT_THROTTLE_RATES': {
        # 'anon': '60/minute',  # 限制所有匿名未认证用户，使用IP区分用户。使用DEFAULT_THROTTLE_RATES['anon'] 来设置频次
        # 'user': '200/minute'  # 限制认证用户，使用User id 来区分。使用DEFAULT_THROTTLE_RATES['user'] 来设置频次
        'goods_list': '600/minute'
    }
}


# 跨域CORS设置
# CORS_ORIGIN_ALLOW_ALL = False  # 默认为False，如果为True则允许所有连接
CORS_ORIGIN_WHITELIST = (  # 配置允许访问的白名单
    'localhost:8080',
    'localhost:8000',
    '127.0.0.1:8080',
    '127.0.0.1:8000',
)

# JWT自定义配置
from datetime import timedelta

SIMPLE_JWT = {
    'ACCESS_TOKEN_LIFETIME': timedelta(days=7),  # 配置过期时间
    'REFRESH_TOKEN_LIFETIME': timedelta(days=15),
}

# 支付宝相关配置
app_id = "2016100900646609"
alipay_debug = True
app_private_key_path = os.path.join(BASE_DIR, 'apps/trade/keys/private_key_2048.txt')
alipay_public_key_path = os.path.join(BASE_DIR, "apps/trade/keys/alipay_key_2048.txt")

# drf-extensions配置
REST_FRAMEWORK_EXTENSIONS = {
    'DEFAULT_CACHE_RESPONSE_TIMEOUT': 60 * 10  # 缓存全局过期时间（60 * 10 表示10分钟）
}

# 配置 django-redis做缓存后端
CACHES = {
    "default": {
        "BACKEND": "django_redis.cache.RedisCache",
        "LOCATION": "redis://127.0.0.1:6379/1",
        "OPTIONS": {
            "CLIENT_CLASS": "django_redis.client.DefaultClient",
            # "PASSWORD": "blog.starmeow.cn"  # 如果redis服务器设置了密码，配置成自己的密码
        }
    }
}

# social_django配置OAuth keys，项目上传晚上，将涉密信息保存在配置文件中
'''
import configparser
config = configparser.ConfigParser()
config.read(os.path.join(BASE_DIR, 'ProjectConfig.ini'))
weibo_key = config['DjangoOnlineFreshSupermarket']['weibo_key']
weibo_secret = config['DjangoOnlineFreshSupermarket']['weibo_secret']
SOCIAL_AUTH_WEIBO_KEY = weibo_key
SOCIAL_AUTH_WEIBO_SECRET = weibo_secret

SOCIAL_AUTH_LOGIN_REDIRECT_URL = '/index/'  # 登录成功后跳转，一般为项目首页
'''
SOCIAL_AUTH_WEIBO_KEY = '547783069'
SOCIAL_AUTH_WEIBO_SECRET = 'ecd581e5a3ebbd08828880703a32389d'

SOCIAL_AUTH_LOGIN_REDIRECT_URL = '/index/'  # 登录成功后跳转，一般为项目首页