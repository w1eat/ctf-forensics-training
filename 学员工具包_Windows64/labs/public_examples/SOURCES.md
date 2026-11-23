# 公开例题来源与复现说明

这两张 *_demo.jpg 是自制教学复现，**不是 picoCTF 官方原始附件**，图像、哈希与 flag 均不同。
用于原始附件服务器不可访问时演示相同的入门方法。

## Glory of the Garden · picoCTF 2019

平台入口：https://play.picoctf.org/practice/challenge/44
历史官方附件：https://jupiter.challenges.picoctf.org/static/d0e1ffb10fc0017c6a82c57900f3ffe3/garden.jpg
方法：识别 JPEG → strings 检索 → 十六进制核对位置。不同附件版本 flag 后缀可能不同。
复现文件 garden_demo.jpg：flag{strings_see_more_than_pixels}

## information · picoCTF 2021

平台入口：https://play.picoctf.org/practice/challenge/186
历史官方附件：https://mercury.picoctf.net/static/d1375e383810d8d957c04eef9e345732/cat.jpg
方法：ExifTool 找 XMP License → 提取字段值 → Base64 解码。
复现文件 cat_demo.jpg：flag{metadata_then_base64}

核对日期：2026-10-19。当前执行环境无法解析旧附件域名及新附件域名，因此未宣称已下载或校验官方原件。
公开题的题意为课件作者转述；解题命令独立编写并在复现附件上验证。平台登录与原件获取由平台当前状态决定。
