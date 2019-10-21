# Generated by Django 2.0.7 on 2019-09-24 17:51

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('goods', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='OrderGoods',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('goods_nums', models.IntegerField(default=0, help_text='购买数量', verbose_name='购买数量')),
                ('add_time', models.DateTimeField(auto_now_add=True, verbose_name='添加时间')),
                ('goods', models.ForeignKey(blank=True, help_text='商品', null=True, on_delete=django.db.models.deletion.SET_NULL, to='goods.Goods', verbose_name='商品')),
            ],
            options={
                'verbose_name': '订单商品',
                'verbose_name_plural': '订单商品',
            },
        ),
        migrations.CreateModel(
            name='OrderInfo',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('order_sn', models.CharField(blank=True, help_text='订单号', max_length=30, null=True, unique=True, verbose_name='订单号')),
                ('trade_no', models.CharField(blank=True, help_text='支付交易号', max_length=100, null=True, unique=True, verbose_name='支付交易号')),
                ('pay_status', models.CharField(choices=[('TRADE_FINISHED', '交易完成'), ('TRADE_SUCCESS', '支付成功'), ('WAIT_BUYER_PAY', '交易创建'), ('TRADE_CLOSE', '交易关闭')], default='WAIT_BUYER_PAY', help_text='订单状态', max_length=20, verbose_name='订单状态')),
                ('post_script', models.CharField(blank=True, help_text='订单留言', max_length=50, null=True, verbose_name='订单留言')),
                ('order_amount', models.FloatField(default=0.0, help_text='订单金额', verbose_name='订单金额')),
                ('pay_time', models.DateTimeField(blank=True, help_text='支付时间', null=True, verbose_name='支付时间')),
                ('address', models.CharField(default='', help_text='收货地址', max_length=200, verbose_name='收货地址')),
                ('signer_name', models.CharField(default='', help_text='签收人', max_length=20, verbose_name='签收人')),
                ('signer_mobile', models.CharField(help_text='联系电话', max_length=11, verbose_name='联系电话')),
                ('add_time', models.DateTimeField(auto_now_add=True, verbose_name='添加时间')),
                ('user', models.ForeignKey(help_text='用户', on_delete=django.db.models.deletion.CASCADE, related_name='order_infos', to=settings.AUTH_USER_MODEL, verbose_name='用户')),
            ],
            options={
                'verbose_name': '订单',
                'verbose_name_plural': '订单',
                'ordering': ['-add_time'],
            },
        ),
        migrations.CreateModel(
            name='ShoppingCart',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('nums', models.IntegerField(default=0, help_text='购买数量', verbose_name='购买数量')),
                ('add_time', models.DateTimeField(auto_now_add=True, verbose_name='添加时间')),
                ('goods', models.ForeignKey(help_text='商品', on_delete=django.db.models.deletion.CASCADE, to='goods.Goods', verbose_name='商品')),
                ('user', models.ForeignKey(help_text='用户', on_delete=django.db.models.deletion.CASCADE, related_name='shopping_carts', to=settings.AUTH_USER_MODEL, verbose_name='用户')),
            ],
            options={
                'verbose_name': '购物车',
                'verbose_name_plural': '购物车',
            },
        ),
        migrations.AddField(
            model_name='ordergoods',
            name='order',
            field=models.ForeignKey(help_text='订单信息', on_delete=django.db.models.deletion.CASCADE, related_name='order_goods', to='trade.OrderInfo', verbose_name='订单信息'),
        ),
        migrations.AlterUniqueTogether(
            name='shoppingcart',
            unique_together={('user', 'goods')},
        ),
    ]
