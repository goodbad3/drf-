import re
from django.utils.timezone import now
from datetime import timedelta
from django.contrib.auth import get_user_model
from rest_framework import serializers
from rest_framework.validators import UniqueValidator
from users.models import VerifyCode

User = get_user_model()

# 序列化类VerifyCodeSerializer验证手机号
class VerifyCodeSerializer(serializers.Serializer):
    """"
    不用ModelSerializer原因：发送验证码只需要提交手机号码
    """
    mobile = serializers.CharField(max_length=11, help_text='手机号码', label='手机号码')

    def validate_mobile(self, mobile):
        """
        验证手机号码
        :param mobile:
        :return:
        """
        # 是否已注册
        if User.objects.filter(mobile=mobile):
            raise serializers.ValidationError('用户已存在')

        # 正则验证手机号码
        regexp = "^[1][3,4,5,7,8][0-9]{9}$"
        if not re.match(regexp, mobile):
            raise serializers.ValidationError('手机号码不正确')

        # 验证发送频率
        one_minute_ago = now() - timedelta(hours=0, minutes=1, seconds=0)  # 获取一分钟以前的时间
        # print(one_minute_ago)
        if VerifyCode.objects.filter(add_time__gt=one_minute_ago, mobile=mobile):
            # 如果添加时间大于一分钟以前的时间，则在这一分钟内已经发过短信，不允许再次发送
            raise serializers.ValidationError('距离上次发送未超过60s')

        return mobile

# django-rest-framework(实战篇)——用户手机注册功能实现
# 文档
#https://www.jianshu.com/p/ff85b77f4e88
# 编写用户注册接口
# 创建用户
# 创建用户测试序列化UserSerializer
# 这个Serializer中直接继承ModelSerializer，并添加code这个字段，用于验证验证码是否正确，如果正确，则在validate(self, attrs)函数中删除该字段的键值，并把username赋值给mobile
class UserSerializer(serializers.ModelSerializer):
    code = serializers.CharField(required=True,
                                 min_length=4,
                                 max_length=4,
                                 help_text='验证码',
                                 label='验证码',
                                 write_only=True,  # 更新或创建实例时可以使用该字段，但序列化时不包含该字段
                                 error_messages={
                                     'blank': '请输入验证码',
                                     'required': '该字段必填项',
                                     'min_length': '验证码格式不正确',
                                     'max_length': '验证码格式不正确',
                                 })
    # 其中有个参数叫write_only，这个字段的意思是：将此设置为True，以确保在更新或创建实例时可以使用该字段，但在序列化表示时不包括该字段，默认为False
    username = serializers.CharField(required=True,
                                     allow_blank=False,
                                     help_text='用户名',
                                     label='用户名',
                                     validators=[UniqueValidator(queryset=User.objects.all(), message='用户已存在')])
    # validators=[UniqueValidator(queryset=User.objects.all(), message='用户已存在')]中该字段进行添加时，从User.objects.all()验证唯一性，如果已存在，则提示message中的内容
    password = serializers.CharField(required=True,
                                     help_text='密码',
                                     label='密码',
                                     write_only=True,#序列化password字段增加write_only参数 #但是上方password字段也被显示出来了，这显然是不合理的，所以也需要将password添加
                                     style={'input_type': 'password'})
    # 一个键值对字典，可用于控制呈现器应如何呈现字段。例如这些的密码想要不显示，则进行如下配置，在UserSerializer中增加password字段，并配置它的style
    # 增加password字段style参数隐藏密码显示
    def validate_code(self, code):
        # 验证code
        # self.initial_data 为用户前端传过来的所有值
        verify_codes = VerifyCode.objects.filter(mobile=self.initial_data['username']).order_by('-add_time')
        if verify_codes:
            last_record = verify_codes[0]

            # 发送验证码如果超过某个时间就提示过期
            three_minute_ago = now() - timedelta(hours=0, minutes=3, seconds=0)  # 获取三分钟以前的时间
            if last_record.add_time < three_minute_ago:
                #            3ago             now
                #      add1          add2            add1就过期
                raise serializers.ValidationError('验证码已过期')

            # 比较传入的验证码
            if last_record.code != code:
                raise serializers.ValidationError('验证码输入错误')
            # return code
            # 这没必要return，因为code这个字段只是用来验证的，不是用来保存到数据库中的

        else:
            # 没有查到该手机号对应的验证码
            raise serializers.ValidationError('验证码错误')

    def validate(self, attrs):
        """
        code 这个字段是不需要保存数据库的，不需要改字段
        validate这个函数作用于所有的字段之上
        :param attrs: 每个字段validate之后返回的一个总的dict
        :return:
        """
        attrs['mobile'] = attrs['username']  # mobile不需要前端传过来，就直接后台取username中的值填充
        # 意思是我注册的时候，只填username字段，mobile字段可以隐藏了
        del attrs['code']  # 删除不需要的code字段
        return attrs

    # def create(self, validated_data):
    #     user = super(UserRegisterSerializer, self).create(validated_data=validated_data)  # user对象是Django中继承的AbstractUser
    #     # UserProfile-->AbstractUser-->AbstractBaseUser中有个set_password(self, raw_password)方法
    #     user.set_password(validated_data['password'])  # 取出password密码，进行加密后保存
    #     user.save()
    #     # ModelSerializer有一个save()方法，save()里面会调用create()函数，这儿重载了create()函数，加入加密的逻辑
    #     return user

    class Meta:
        model = User
        fields = ('username', 'mobile', 'code', 'password')  # username是Django自带的字段，与mobile的值保持一致


class UserDetailSerializer(serializers.ModelSerializer):
    """
    用户详情序列化类
    """

    class Meta:
        model = User
        fields = ('username', 'name', 'email', 'birthday', 'mobile', 'gender')
