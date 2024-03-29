# Generated by Django 2.0.7 on 2019-09-24 17:51

import ckeditor_uploader.fields
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='Banner',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('image', models.ImageField(help_text='图片', upload_to='goods/banners/', verbose_name='图片')),
                ('index', models.IntegerField(default=0, help_text='轮播顺序', verbose_name='轮播顺序')),
                ('add_time', models.DateTimeField(auto_now_add=True, verbose_name='添加时间')),
            ],
            options={
                'verbose_name': '首页轮播图',
                'verbose_name_plural': '首页轮播图',
            },
        ),
        migrations.CreateModel(
            name='Goods',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('goods_sn', models.CharField(default='', help_text='商品唯一货号', max_length=100, verbose_name='商品编码')),
                ('name', models.CharField(help_text='商品名称', max_length=300, verbose_name='商品名称')),
                ('click_num', models.IntegerField(default=0, help_text='点击数', verbose_name='点击数')),
                ('sold_num', models.IntegerField(default=0, help_text='销售量', verbose_name='销售量')),
                ('fav_num', models.IntegerField(default=0, help_text='收藏数', verbose_name='收藏数')),
                ('goods_num', models.IntegerField(default=0, help_text='库存量', verbose_name='库存量')),
                ('market_price', models.FloatField(default=0, help_text='市场价格', verbose_name='市场价格')),
                ('shop_price', models.FloatField(default=0, help_text='本店价格', verbose_name='本店价格')),
                ('goods_brief', models.TextField(help_text='商品简短描述', max_length=500, verbose_name='简短描述')),
                ('goods_desc', ckeditor_uploader.fields.RichTextUploadingField(help_text='详情描述', verbose_name='详情描述')),
                ('ship_free', models.BooleanField(default=True, help_text='是否免运费', verbose_name='是否免运费')),
                ('goods_front_image', models.ImageField(blank=True, help_text='封面图', null=True, upload_to='goods/front/', verbose_name='封面图')),
                ('is_new', models.BooleanField(default=False, help_text='是否新品', verbose_name='是否新品')),
                ('is_hot', models.BooleanField(default=False, help_text='是否热销', verbose_name='是否热销')),
                ('add_time', models.DateTimeField(auto_now_add=True, verbose_name='添加时间')),
            ],
            options={
                'verbose_name': '商品',
                'verbose_name_plural': '商品',
            },
        ),
        migrations.CreateModel(
            name='GoodsCategory',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(default='', help_text='商品类别名称', max_length=30, verbose_name='类别名称')),
                ('code', models.CharField(default='', help_text='商品类别编码', max_length=30, verbose_name='类别编码')),
                ('desc', models.TextField(default='', help_text='类别描述', verbose_name='类别描述')),
                ('category_type', models.SmallIntegerField(choices=[(1, '一级类目'), (2, '二级类目'), (3, '三级类目')], default=1, help_text='商品类目的级别', verbose_name='类目级别')),
                ('is_tab', models.BooleanField(default=False, help_text='类别是否导航', verbose_name='是否导航')),
                ('add_time', models.DateTimeField(auto_now_add=True, verbose_name='添加时间')),
                ('parent_category', models.ForeignKey(blank=True, help_text='父级目录', null=True, on_delete=django.db.models.deletion.CASCADE, related_name='sub_category', to='goods.GoodsCategory', verbose_name='父级目录')),
            ],
            options={
                'verbose_name': '商品类别',
                'verbose_name_plural': '商品类别',
            },
        ),
        migrations.CreateModel(
            name='GoodsCategoryBrand',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(default='', help_text='品牌名称', max_length=30, verbose_name='品牌名称')),
                ('desc', models.TextField(default='', help_text='品牌描述', max_length=200, verbose_name='品牌描述')),
                ('image', models.ImageField(help_text='品牌图片', max_length=200, upload_to='brand/images/', verbose_name='品牌图片')),
                ('add_time', models.DateTimeField(auto_now_add=True, verbose_name='添加时间')),
                ('category', models.ForeignKey(blank=True, help_text='商品类别', null=True, on_delete=django.db.models.deletion.CASCADE, related_name='brands', to='goods.GoodsCategory', verbose_name='商品类别')),
            ],
            options={
                'verbose_name': '品牌',
                'verbose_name_plural': '品牌',
            },
        ),
        migrations.CreateModel(
            name='GoodsImage',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('image', models.ImageField(help_text='图片', upload_to='goods/images/', verbose_name='图片')),
                ('add_time', models.DateTimeField(auto_now_add=True, verbose_name='添加时间')),
                ('goods', models.ForeignKey(help_text='商品', on_delete=django.db.models.deletion.CASCADE, related_name='images', to='goods.Goods', verbose_name='商品')),
            ],
            options={
                'verbose_name': '商品图片',
                'verbose_name_plural': '商品图片',
            },
        ),
        migrations.CreateModel(
            name='IndexCategoryAd',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('add_time', models.DateTimeField(auto_now_add=True, verbose_name='添加时间')),
                ('category', models.ForeignKey(blank=True, help_text='商品类别', null=True, on_delete=django.db.models.deletion.CASCADE, related_name='ads', to='goods.GoodsCategory', verbose_name='商品类别')),
                ('goods', models.ForeignKey(help_text='商品', on_delete=django.db.models.deletion.CASCADE, related_name='ads', to='goods.Goods', verbose_name='商品')),
            ],
            options={
                'verbose_name': '首页类别广告',
                'verbose_name_plural': '首页类别广告',
            },
        ),
        migrations.AddField(
            model_name='goods',
            name='category',
            field=models.ForeignKey(help_text='商品类别', on_delete=django.db.models.deletion.CASCADE, related_name='goods', to='goods.GoodsCategory', verbose_name='商品类别'),
        ),
        migrations.AddField(
            model_name='banner',
            name='goods',
            field=models.ForeignKey(help_text='商品', on_delete=django.db.models.deletion.CASCADE, related_name='banners', to='goods.Goods', verbose_name='商品'),
        ),
    ]
