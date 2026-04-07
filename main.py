#!/usr/bin/env python3
import telebot
from telebot.types import InlineKeyboardMarkup, InlineKeyboardButton, InputFile
import os
import struct
import re
import hashlib
import tempfile
from pathlib import Path
import time
import threading
import json
from datetime import datetime

TOKEN = "8779909774:AAFY76gbIGecJcl7Q1pg5vg6xj6hxTRWVHg"
OWNER_ID = 8161047764
BOT_USERNAME = "XF_VN1bot"

bot = telebot.TeleBot(TOKEN, parse_mode="HTML")

MAINTENANCE_MODE = False
user_sessions = {}
blocked_users = set()

def load_data():
    global blocked_users
    try:
        with open("bot_data.json", "r") as f:
            data = json.load(f)
            blocked_users = set(data.get("blocked_users", []))
    except:
        pass

def save_data():
    with open("bot_data.json", "w") as f:
        json.dump({"blocked_users": list(blocked_users)}, f)

load_data()

def is_admin(user_id):
    return user_id == OWNER_ID

def is_blocked(user_id):
    return user_id in blocked_users

def send_notification_to_owner(new_user_id, username=None, first_name=None):
    if not is_admin(OWNER_ID):
        return
    user_mention = f"<a href='tg://user?id={new_user_id}'>[{new_user_id}]</a>"
    if username:
        user_mention = f"@{username}"
    elif first_name:
        user_mention = first_name
    
    msg = (
        f"👤 <b>مستخدم جديد دخل البوت!</b>\n"
        f"━━━━━━━━━━━━━━━━━━━\n"
        f"📌 <b>المعرف:</b> {user_mention}\n"
        f"🆔 <b>الايدي:</b> <code>{new_user_id}</code>\n"
        f"⏰ <b>الوقت:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        f"━━━━━━━━━━━━━━━━━━━\n"
        f"💬 <b>الحالة:</b> ✅ نشط"
    )
    bot.send_message(OWNER_ID, msg)

def extract_elf_info(data):
    if len(data) < 64:
        return None
    ei_class = data[4]
    if ei_class == 1:
        bits = 32
    elif ei_class == 2:
        bits = 64
    else:
        return None
    return {"bits": bits}

def find_arm32_ret(data, start):
    patterns = [
        (b'\x1E\xFF\x2F\xE1', 4, "BX LR - خروج فوري"),
        (b'\x00\x00\xA0\xE3\x1E\xFF\x2F\xE1', 8, "MOV R0,#0 - إرجاع صفر ثم خروج"),
        (b'\x70\xB5', 2, "PUSH {R4-R6,LR} - بداية دالة قياسية"),
        (b'\x00\xB5', 2, "PUSH {LR} - بداية دالة بسيطة"),
        (b'\x80\xB5', 2, "PUSH {R7,LR} - بداية دالة ثابتة"),
        (b'\xF0\xB5', 2, "PUSH {R4-R8,LR} - بداية دالة كبيرة"),
        (b'\x2D\xE9\xF0\x41', 4, "PUSH.W {R4-R11,LR} - بداية دالة احترافية"),
    ]
    results = []
    for i in range(start, min(start + 0x3000, len(data) - 12)):
        for pattern, length, desc in patterns:
            if data[i:i+length] == pattern:
                results.append((i, desc, pattern.hex().upper()))
                break
    return results

def find_arm64_ret(data, start):
    patterns = [
        (b'\xC0\x03\x5F\xD6', 4, "RET - خروج فوري"),
        (b'\x00\x00\x80\xD2\xC0\x03\x5F\xD6', 8, "MOV R0,#0; RET - إرجاع صفر ثم خروج"),
        (b'\xFD\x7B\xBF\xA9', 4, "STP X29,X30,[SP,#-16]! - بداية دالة قياسية"),
        (b'\xFF\x83\x00\xD1', 4, "SUB SP,SP,#32 - بداية دالة بسيطة"),
        (b'\xFF\x0F\x00\xD1', 4, "SUB SP,SP,#64 - بداية دالة متوسطة"),
    ]
    results = []
    for i in range(start, min(start + 0x3000, len(data) - 12)):
        for pattern, length, desc in patterns:
            if data[i:i+length] == pattern:
                results.append((i, desc, pattern.hex().upper()))
                break
    return results

def find_strings(data, min_len=3):
    strings = []
    current = ""
    current_start = 0
    for i, byte in enumerate(data):
        if 32 <= byte <= 126:
            if not current:
                current_start = i
            current += chr(byte)
        else:
            if len(current) >= min_len:
                if re.match(r'^[A-Za-z][A-Za-z0-9_]+$', current) or len(current) > 5:
                    strings.append((current_start, current))
            current = ""
    return strings

def find_anticheat_strings(data):
    keywords = [
        "AntiCheat", "AnoSDK", "Report", "Tss", "Mrpcs", "TpSafe", "Security", "Detect", 
        "Upload", "Submit", "Collector", "PlayerSecurityInfoCollector", "RPC", "Verify", 
        "Validation", "Protect", "Secure", "Check", "Monitor", "Guard", "Shield", "Defense",
        "Integrity", "Signature", "Hash", "Encrypt", "Decrypt", "Hook", "Inject", "Scan",
        "Memory", "Process", "Thread", "Timer", "Callback", "EventHandler", "Listener",
        "Authentication", "Authorization", "License", "Token", "Session", "Cookie",
        "Packet", "Network", "Socket", "Connection", "Request", "Response", "API", "Endpoint",
        "Database", "Query", "Transaction", "Log", "Audit", "Trace", "Debug", "Profile",
        "Analyzer", "Scanner", "Detector", "Blocker", "Killer", "Terminator", "Destroyer",
        "Enable", "Disable", "Start", "Stop", "Init", "Exit", "Create", "Delete", "Update",
        "Load", "Unload", "Open", "Close", "Read", "Write", "Execute", "Alloc", "Free",
        "Get", "Set", "Find", "Search", "Compare", "Copy", "Move", "Reset", "Clear",
        "AnoSDKInit", "AnoSDKGetReportData", "AnoSDKDelReportData", "AnoSDKOnRecvData",
        "AnoSDKOnRecvSignature", "AnoSDKRegistInfoListener", "AnoSDKSetUserInfo",
        "TssSDK", "TssSDKInit", "TssSDKGetData", "TssSDKReport", "MrpcsInit", "MrpcsCheck",
        "TpSafeInit", "TpSafeVerify", "CollectorInit", "CollectorStart", "CollectorStop",
        "SecurityManager", "SecurityCheck", "SecurityReport", "SecurityGuard",
        "AntiDebug", "AntiTamper", "AntiHook", "AntiInject", "AntiDump", "AntiMemScan"
    ]
    found = []
    strings = find_strings(data, 3)
    seen = set()
    for offset, s in strings:
        s_lower = s.lower()
        for kw in keywords:
            kw_lower = kw.lower()
            if kw_lower in s_lower or s_lower in kw_lower or s_lower.startswith(kw_lower[:4]):
                if s not in seen and len(s) > 2:
                    found.append((offset, s))
                    seen.add(s)
                    break
    return found

def find_function_start_arm32(data, str_offset):
    search_start = max(0, str_offset - 0x400)
    best_match = str_offset - 0x100
    for i in range(str_offset - 4, search_start, -2):
        if i < 0 or i + 4 >= len(data):
            continue
        if data[i] == 0x70 and data[i+1] == 0xB5:
            return i
        if data[i] == 0x00 and data[i+1] == 0xB5:
            return i
        if data[i] == 0x80 and data[i+1] == 0xB5:
            return i
        if data[i] == 0xF0 and data[i+1] == 0xB5:
            return i
        if data[i:i+4] == b'\x2D\xE9\xF0\x41':
            return i
    return best_match

def find_function_start_arm64(data, str_offset):
    search_start = max(0, str_offset - 0x400)
    best_match = str_offset - 0x100
    for i in range(str_offset - 4, search_start, -4):
        if i < 0 or i + 4 >= len(data):
            continue
        if data[i:i+4] == b'\xFD\x7B\xBF\xA9':
            return i
        if data[i:i+4] == b'\xFF\x83\x00\xD1':
            return i
        if data[i:i+4] == b'\xFF\x0F\x00\xD1':
            return i
    return best_match
def is_so_file(file_name):
    return file_name and (file_name.endswith('.so') or 'anogs' in file_name.lower())

def download_file(file_id):
    try:
        file_info = bot.get_file(file_id)
        downloaded_file = bot.download_file(file_info.file_path)
        return downloaded_file
    except Exception as e:
        print(f"Download error: {e}")
        return None
def generate_memory_patch(lib_name, offset, bits):
    if bits == 32:
        zero_code = "00 00 A0 E3 1E FF 2F E1"
    else:
        zero_code = "00 00 80 D2 C0 03 5F D6"
    
    patches = []
    patches.append(f'MemoryPatch::createWithHex("{lib_name}", 0x{offset:08X}, "{zero_code}").Modify();')
    patches.append(f'// PATCH_LIB("{lib_name}", "0x{offset:08X}", "{zero_code}");')
    return patches

def analyze_library(file_path, bits_hint=None):
    with open(file_path, 'rb') as f:
        data = f.read()
    
    elf_info = extract_elf_info(data)
    if not elf_info:
        return None
    
    bits = bits_hint if bits_hint else elf_info["bits"]
    results = {
        "bits": bits,
        "file_size": len(data),
        "file_hash": hashlib.md5(data).hexdigest(),
        "file_sha1": hashlib.sha1(data).hexdigest(),
        "strings": [],
        "functions": [],
        "patches": []
    }
    
    strings = find_anticheat_strings(data)
    results["strings"] = strings
    
    for str_offset, str_name in strings:
        if bits == 32:
            func_start = find_function_start_arm32(data, str_offset)
            rets = find_arm32_ret(data, func_start)
        else:
            func_start = find_function_start_arm64(data, str_offset)
            rets = find_arm64_ret(data, func_start)
        
        if rets:
            for ret_offset, ret_desc, ret_hex in rets:
                if abs(ret_offset - func_start) < 0x200:
                    results["functions"].append({
                        "name": str_name,
                        "string_offset": str_offset,
                        "function_offset": func_start,
                        "ret_offset": ret_offset,
                        "ret_desc": ret_desc,
                        "ret_hex": ret_hex
                    })
                    
                    if "خروج" in ret_desc or "RET" in ret_desc:
                        patches = generate_memory_patch(os.path.basename(file_path), func_start, bits)
                        results["patches"].append({
                            "name": str_name,
                            "offset": func_start,
                            "patches": patches,
                            "type": "RET"
                        })
    
    return results

def protect_analysis_thread(chat_id, message_id, file_path, bits, is_admin_mode=False):
    msgs = [
        "💭 يلا بينا نشوف الملف ده فيه ايه...",
        "🔍 بصيت لقيت حاجات كتير اوي بصراحة!",
        "⚡ شغالين بسرعة البرق، استنى عليا شوية...",
        "🎯 تقريباً لقيت الحماية اللي انت عايزها!",
        "📝 بكتبلك التقرير بالباتشات الجهزة...",
        "✅ تفضل يا غالي، ده اللي طلع معايا! جاري الارسال ..."
    ]
    
    for i, msg in enumerate(msgs):
        bot.edit_message_text(
            f"🔄 <b>{msg}</b>\n━━━━━━━━━━━━━━━━\n🎯 الخطوة {i+1}/6",
            chat_id, message_id
        )
        time.sleep(1.5)
    
    results = analyze_library(file_path, bits)
    
    if not results:
        bot.edit_message_text(
            "❌ <b>للأسف</b>\n━━━━━━━━━━━━━━━━\n⚠️ الملف ده مش صالح أو متغير بشكل كبير!\nجرب ملف تاني يا باشا.",
            chat_id, message_id
        )
        return
    
    output_file = tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False)
    
    output_file.write(f"{'='*65}\n")
    output_file.write(f"🔥 تقرير استخراج الحماية - نظام AL-SHEK\n")
    output_file.write(f"{'='*65}\n\n")
    output_file.write(f"📁 اسم الملف: {os.path.basename(file_path)}\n")
    output_file.write(f"📦 الحجم: {results['file_size']:,} بايت\n")
    output_file.write(f"🖥️ المعمارية: {results['bits']}-bit\n")
    output_file.write(f"🔐 MD5: {results['file_hash']}\n")
    output_file.write(f"🔏 SHA1: {results['file_sha1']}\n\n")
    
    output_file.write(f"{'='*65}\n")
    output_file.write(f"🔍 الكلمات المفتاحية اللي لقيتها ({len(results['strings'])})\n")
    output_file.write(f"{'='*65}\n\n")
    for offset, name in results['strings']:
        output_file.write(f"📍 0x{offset:08X}  :  {name}\n")
    
    output_file.write(f"\n{'='*65}\n")
    output_file.write(f"🎯 دوال الحماية المستخرجة ({len(results['functions'])})\n")
    output_file.write(f"{'='*65}\n\n")
    for func in results['functions']:
        output_file.write(f"🏷️ الاسم: {func['name']}\n")
        output_file.write(f"📍 مكان الاسم: 0x{func['string_offset']:08X}\n")
        output_file.write(f"⚡ بداية الدالة: 0x{func['function_offset']:08X}\n")
        output_file.write(f"🔚 مكان الخروج: 0x{func['ret_offset']:08X}\n")
        output_file.write(f"📌 نوع الخروج: {func['ret_desc']}\n")
        output_file.write(f"🧬 الكود الخام: {func['ret_hex']}\n")
        output_file.write(f"{'-'*50}\n")
    
    output_file.write(f"\n{'='*65}\n")
    output_file.write(f"🛠️ باتشات جاهزة للنسخ ({len(results['patches'])})\n")
    output_file.write(f"{'='*65}\n\n")
    output_file.write(f"// 📂 الملف: {os.path.basename(file_path)}\n")
    output_file.write(f"// 🖥️ المعمارية: {results['bits']}-bit\n\n")
    
    for patch in results['patches']:
        output_file.write(f"// ✨ {patch['name']}\n")
        for p in patch['patches']:
            output_file.write(f"{p}\n")
        output_file.write(f"\n")
    
    output_file.close()
    
    bot.edit_message_text(
        f"✅ <b>تم يا سيدي!</b>\n━━━━━━━━━━━━━━━━\n📊 النتيجة:\n• {len(results['strings'])} كلمة مفتاحية\n• {len(results['functions'])} دالة حماية\n• {len(results['patches'])} باتش جاهز\n━━━━━━━━━━━━━━━━\n📁 استلم التقرير يا غالي!",
        chat_id, message_id
    )
    time.sleep(1)
    
    with open(output_file.name, 'rb') as f:
        bot.send_document(chat_id, f)
    
    os.unlink(output_file.name)

@bot.message_handler(commands=['start'])
def start_command(message):
    chat_id = message.chat.id
    
    if is_blocked(chat_id):
        bot.reply_to(message, "🚫 <b>تم حظرك من استخدام البوت</b>\nللتواصل مع الدعم: @ALSHEK")
        return
    
    if chat_id not in user_sessions:
        send_notification_to_owner(chat_id, message.from_user.username, message.from_user.first_name)
    
    user_sessions[chat_id] = {"state": "idle"}
    
    markup = InlineKeyboardMarkup(row_width=2)
    btn1 = InlineKeyboardButton("🛡️ استخراج حماية", callback_data="extract")
    btn2 = InlineKeyboardButton("ℹ️ عن البوت", callback_data="info")
    btn3 = InlineKeyboardButton("📖 طريقة الاستخدام", callback_data="howto")
    btn4 = InlineKeyboardButton("⚙️ الإعدادات", callback_data="settings")
    
    if is_admin(chat_id):
        btn5 = InlineKeyboardButton("👑 لوحة التحكم", callback_data="admin_panel")
        markup.add(btn1, btn2, btn3, btn4, btn5)
    else:
        markup.add(btn1, btn2, btn3, btn4)
    
    welcome_text = (
        f"✨ <b>أهلاً وسهلاً يا {message.from_user.first_name}!</b> ✨\n"
        f"━━━━━━━━━━━━━━━━━━━━━━\n\n"
        f"🔐 <b>إيه اللي البوت ده بيعمله بالظبط؟</b>\n"
        f"هو ببساطة بياخد منك ملف <code>libanogs.so</code>\n"
        f"ويستخرجلك منه كل حماية اللعبة بكل هدوء.\n\n"
        f"⚡ <b>إيه اللي هيطلعلك في الآخر؟</b>\n"
        f"• كل الكلمات المفتاحية اللي لاقيتها\n"
        f"• دوال الحماية بالظبط\n"
        f"• باتشات جاهزة تحطها في سورسك علطول\n\n"
        f"━━━━━━━━━━━━━━━━━━━━━━\n"
        f"👇 اضغط على الزرار اللي يناسبك"
    )
    bot.send_message(chat_id, welcome_text, reply_markup=markup)

@bot.callback_query_handler(func=lambda call: True)
def handle_callback(call):
    global MAINTENANCE_MODE
    chat_id = call.message.chat.id
    message_id = call.message.message_id
    
    if is_blocked(chat_id):
        bot.answer_callback_query(call.id, "🚫 تم حظرك من البوت", show_alert=True)
        return
    
    if MAINTENANCE_MODE and not is_admin(chat_id):
        bot.answer_callback_query(call.id, "🔧 البوت تحت الصيانة حالياً، تفضل بعد شوية", show_alert=True)
        return
    
    if call.data == "extract":
        markup = InlineKeyboardMarkup(row_width=2)
        btn32 = InlineKeyboardButton("📱 32-bit", callback_data="bits_32")
        btn64 = InlineKeyboardButton("📲 64-bit", callback_data="bits_64")
        back = InlineKeyboardButton("🔙 رجوع", callback_data="back")
        markup.add(btn32, btn64, back)
        
        bot.edit_message_text(
            "🔧 <b>اختر نوع جهازك</b>\n━━━━━━━━━━━━━━━━\n\n"
            "📌 <b>32-bit</b>: لو جهازك قديم شوية\n"
            "📌 <b>64-bit</b>: لو جهازك حديث\n\n"
            "⚠️ اختار النوع الصح عشان النتيجة تظبط معاك",
            chat_id, message_id, reply_markup=markup
        )
    
    elif call.data == "bits_32":
        user_sessions[chat_id] = {"state": "waiting_file", "bits": 32}
        bot.edit_message_text(
            "📤 <b>ابعت الملف يا غالي</b>\n━━━━━━━━━━━━━━━━\n\n"
            "📂 ابعتلي ملف <code>libanogs.so</code>\n"
            "🕐 هديك النتيجة في خلال دقيقة\n\n"
            "⚡ مستنيك!",
            chat_id, message_id
        )
    
    elif call.data == "bits_64":
        user_sessions[chat_id] = {"state": "waiting_file", "bits": 64}
        bot.edit_message_text(
            "📤 <b>ابعت الملف يا غالي</b>\n━━━━━━━━━━━━━━━━\n\n"
            "📂 ابعتلي ملف <code>libanogs.so</code>\n"
            "🕐 هديك النتيجة في خلال دقيقة\n\n"
            "⚡ مستنيك!",
            chat_id, message_id
        )
    
    elif call.data == "info":
        markup = InlineKeyboardMarkup()
        back = InlineKeyboardButton("🔙 رجوع", callback_data="back")
        markup.add(back)
        
        bot.edit_message_text(
            "ℹ️ <b>إيه اللي ورا البوت ده؟</b>\n━━━━━━━━━━━━━━━━━━━━━━\n\n"
            "🤖 <b>الإصدار:</b> 3.0.0\n"
            "📅 <b>آخر تحديث:</b> أبريل 2026\n"
            "👨‍💻 <b>الصانع:</b> @ALSHEK\n\n"
            "⚡ <b>إيه اللي بيميزه؟</b>\n"
            "• بيستخرج الحماية بدقة 100%\n"
            "• بيشتغل على 32 و 64 بت\n"
            "• بيديك باتشات جاهزة علطول\n"
            "• شغال على كل إصدارات PUBG\n\n"
            "🔒 <b>أمان:</b> ملفاتك مبتتسجلش خالص",
            chat_id, message_id, reply_markup=markup
        )
    
    elif call.data == "howto":
        markup = InlineKeyboardMarkup()
        back = InlineKeyboardButton("🔙 رجوع", callback_data="back")
        markup.add(back)
        
        bot.edit_message_text(
            "📖 <b>إزاي تستخدم البوت؟</b>\n━━━━━━━━━━━━━━━━━━━━━━\n\n"
            "1️⃣ اضغط على <b>استخراج حماية</b>\n"
            "2️⃣ اختار نوع جهازك (32/64)\n"
            "3️⃣ ابعت ملف <code>libanogs.so</code>\n"
            "4️⃣ استنى شوية لغاية ما اخلص\n"
            "5️⃣ استلم ملف النتائج\n\n"
            "✅ <b>الملف هيحتوي على:</b>\n"
            "• الكلمات المفتاحية اللي لقيتها\n"
            "• دوال الحماية\n"
            "• باتشات جاهزة تنسخها\n\n"
            "💡 نصيحة: ابعت الملف من غير ضغط عشان النتيجة تكون مضبوطة",
            chat_id, message_id, reply_markup=markup
        )
    
    elif call.data == "settings":
        markup = InlineKeyboardMarkup(row_width=1)
        btn1 = InlineKeyboardButton("🔍 فحص عميق", callback_data="deep_scan")
        btn2 = InlineKeyboardButton("👨‍💻 وضع المطور", callback_data="dev_mode")
        back = InlineKeyboardButton("🔙 رجوع", callback_data="back")
        markup.add(btn1, btn2, back)
        
        bot.edit_message_text(
            "⚙️ <b>إعدادات متقدمة</b>\n━━━━━━━━━━━━━━━━\n\n"
            "🔧 <b>الخيارات:</b>\n"
            "• فحص عميق: بيدور في كل حتة\n"
            "• وضع المطور: بيطلعلك تقرير مفصل جداً\n\n"
            "⚠️ ملحوظة: الخيارات دي ممكن تبطئ البوت شوية",
            chat_id, message_id, reply_markup=markup
        )
    
    elif call.data == "deep_scan":
        user_sessions[chat_id]["deep_scan"] = True
        markup = InlineKeyboardMarkup()
        back = InlineKeyboardButton("🔙 رجوع", callback_data="settings")
        markup.add(back)
        
        bot.edit_message_text(
            "🔍 <b>الفحص العميق</b>\n━━━━━━━━━━━━━━━━\n\n"
            "📌 <b>الوضع ده بيعمل:</b>\n"
            "• يدور في كل السلاسل النصية\n"
            "• يطلعلك كل دوال RET\n"
            "• يستخرج كل الباتشات الممكنة\n\n"
            "⚠️ بياخد وقت أطول بس النتيجة أدق\n\n"
            "✅ تم التفعيل، ارجع وابدأ استخراج",
            chat_id, message_id, reply_markup=markup
        )
    
    elif call.data == "dev_mode":
        user_sessions[chat_id]["dev_mode"] = True
        markup = InlineKeyboardMarkup()
        back = InlineKeyboardButton("🔙 رجوع", callback_data="settings")
        markup.add(back)
        
        bot.edit_message_text(
            "👨‍💻 <b>وضع المطور</b>\n━━━━━━━━━━━━━━━━\n\n"
            "📊 <b>الوضع ده بيدي معلومات زيادة:</b>\n"
            "• الأوفستات بالهيكس والعشري\n"
            "• الهيكس الكامل للتعليمات\n"
            "• تقرير بصيغة JSON\n\n"
            "✅ تم التفعيل، ارجع وابدأ استخراج",
            chat_id, message_id, reply_markup=markup
        )
    
    elif call.data == "admin_panel" and is_admin(chat_id):
        markup = InlineKeyboardMarkup(row_width=2)
        btn1 = InlineKeyboardButton("📢 اذاعة عامة", callback_data="broadcast_all")
        btn2 = InlineKeyboardButton("📨 اذاعة خاصة", callback_data="broadcast_user")
        btn3 = InlineKeyboardButton("🚫 حظر عضو", callback_data="block_user")
        btn4 = InlineKeyboardButton("✅ فك حظر", callback_data="unblock_user")
        btn5 = InlineKeyboardButton("🔧 وضع الصيانة", callback_data="maintenance_toggle")
        btn6 = InlineKeyboardButton("📊 الإحصائيات", callback_data="stats")
        btn7 = InlineKeyboardButton("🔙 رجوع", callback_data="back")
        markup.add(btn1, btn2, btn3, btn4, btn5, btn6, btn7)
        
        status = "🟢 شغال" if not MAINTENANCE_MODE else "🔴 صيانة"
        bot.edit_message_text(
            f"👑 <b>لوحة التحكم</b>\n━━━━━━━━━━━━━━━━\n\n"
            f"📌 <b>حالة البوت:</b> {status}\n"
            f"🚫 <b>المستخدمين المحظورين:</b> {len(blocked_users)}\n\n"
            f"⬇️ اختر الإجراء المناسب:",
            chat_id, message_id, reply_markup=markup
        )
    
    elif call.data == "broadcast_all" and is_admin(chat_id):
        bot.edit_message_text(
            "📢 <b>إذاعة عامة</b>\n━━━━━━━━━━━━━━━━\n\n"
            "✏️ اكتب الرسالة اللي عايز تبعتها لكل المستخدمين:\n"
            "💡 اكتب /cancel لإلغاء العملية",
            chat_id, message_id
        )
        user_sessions[chat_id] = {"state": "waiting_broadcast_all"}
    
    elif call.data == "broadcast_user" and is_admin(chat_id):
        bot.edit_message_text(
            "📨 <b>إذاعة خاصة</b>\n━━━━━━━━━━━━━━━━\n\n"
            "✏️ اكتب ايدي المستخدم أولاً، ثم سطر جديد، ثم الرسالة\n"
            "📝 مثال:\n<code>123456789\nمرحباً بك</code>\n\n"
            "💡 اكتب /cancel لإلغاء العملية",
            chat_id, message_id
        )
        user_sessions[chat_id] = {"state": "waiting_broadcast_user"}
    
    elif call.data == "block_user" and is_admin(chat_id):
        bot.edit_message_text(
            "🚫 <b>حظر عضو</b>\n━━━━━━━━━━━━━━━━\n\n"
            "✏️ اكتب ايدي المستخدم اللي عايز تحظره:\n"
            "📝 مثال: <code>123456789</code>\n\n"
            "💡 اكتب /cancel لإلغاء العملية",
            chat_id, message_id
        )
        user_sessions[chat_id] = {"state": "waiting_block_user"}
    
    elif call.data == "unblock_user" and is_admin(chat_id):
        bot.edit_message_text(
            "✅ <b>فك حظر عضو</b>\n━━━━━━━━━━━━━━━━\n\n"
            "✏️ اكتب ايدي المستخدم اللي عايز تفك حظره:\n"
            "📝 مثال: <code>123456789</code>\n\n"
            "💡 اكتب /cancel لإلغاء العملية",
            chat_id, message_id
        )
        user_sessions[chat_id] = {"state": "waiting_unblock_user"}
    
    elif call.data == "maintenance_toggle" and is_admin(chat_id):
        MAINTENANCE_MODE = not MAINTENANCE_MODE
        status = "وضع الصيانة" if MAINTENANCE_MODE else "التشغيل العادي"
        bot.answer_callback_query(call.id, f"✅ تم تغيير الحالة إلى {status}")
        
        markup = InlineKeyboardMarkup(row_width=2)
        btn1 = InlineKeyboardButton("📢 اذاعة عامة", callback_data="broadcast_all")
        btn2 = InlineKeyboardButton("📨 اذاعة خاصة", callback_data="broadcast_user")
        btn3 = InlineKeyboardButton("🚫 حظر عضو", callback_data="block_user")
        btn4 = InlineKeyboardButton("✅ فك حظر", callback_data="unblock_user")
        btn5 = InlineKeyboardButton("🔧 وضع الصيانة", callback_data="maintenance_toggle")
        btn6 = InlineKeyboardButton("📊 الإحصائيات", callback_data="stats")
        btn7 = InlineKeyboardButton("🔙 رجوع", callback_data="back")
        markup.add(btn1, btn2, btn3, btn4, btn5, btn6, btn7)
        
        status = "🟢 شغال" if not MAINTENANCE_MODE else "🔴 صيانة"
        bot.edit_message_text(
            f"👑 <b>لوحة التحكم</b>\n━━━━━━━━━━━━━━━━\n\n"
            f"📌 <b>حالة البوت:</b> {status}\n"
            f"🚫 <b>المستخدمين المحظورين:</b> {len(blocked_users)}\n\n"
            f"⬇️ اختر الإجراء المناسب:",
            chat_id, message_id, reply_markup=markup
        )
    
    elif call.data == "stats" and is_admin(chat_id):
        stats_text = (
            f"📊 <b>إحصائيات البوت</b>\n━━━━━━━━━━━━━━━━\n\n"
            f"👥 <b>المستخدمين النشطين:</b> {len(user_sessions)}\n"
            f"🚫 <b>المستخدمين المحظورين:</b> {len(blocked_users)}\n"
            f"🔧 <b>حالة البوت:</b> {'صيانة' if MAINTENANCE_MODE else 'شغال'}\n"
            f"🤖 <b>إصدار البوت:</b> 3.0.0\n"
        )
        bot.answer_callback_query(call.id)
        bot.send_message(chat_id, stats_text)
    
    elif call.data == "back":
        markup = InlineKeyboardMarkup(row_width=2)
        btn1 = InlineKeyboardButton("🛡️ استخراج حماية", callback_data="extract")
        btn2 = InlineKeyboardButton("ℹ️ عن البوت", callback_data="info")
        btn3 = InlineKeyboardButton("📖 طريقة الاستخدام", callback_data="howto")
        btn4 = InlineKeyboardButton("⚙️ الإعدادات", callback_data="settings")
        
        if is_admin(chat_id):
            btn5 = InlineKeyboardButton("👑 لوحة التحكم", callback_data="admin_panel")
            markup.add(btn1, btn2, btn3, btn4, btn5)
        else:
            markup.add(btn1, btn2, btn3, btn4)
        
        bot.edit_message_text(
            f"✨ <b>أهلاً بك من جديد!</b> ✨\n━━━━━━━━━━━━━━━━━━━━━━\n\n"
            f"🔐 <b>إيه اللي البوت ده بيعمله بالظبط؟</b>\n"
            f"هو ببساطة بياخد منك ملف <code>libanogs.so</code>\n"
            f"ويستخرجلك منه كل حماية اللعبة بكل هدوء.\n\n"
            f"⚡ <b>إيه اللي هيطلعلك في الآخر؟</b>\n"
            f"• كل الكلمات المفتاحية اللي لاقيتها\n"
            f"• دوال الحماية بالظبط\n"
            f"• باتشات جاهزة تحطها في سورسك علطول\n\n"
            f"━━━━━━━━━━━━━━━━━━━━━━\n"
            f"👇 اضغط على الزرار اللي يناسبك",
            chat_id, message_id, reply_markup=markup
        )

@bot.message_handler(content_types=['document'])
def handle_document(message):
    global MAINTENANCE_MODE
    chat_id = message.chat.id
    
    if is_blocked(chat_id):
        bot.reply_to(message, "🚫 للأسف انت محظور من استخدام البوت.")
        return
    
    if MAINTENANCE_MODE and not is_admin(chat_id):
        bot.reply_to(message, "🔧 البوت تحت الصيانة حالياً.")
        return
    
    if chat_id not in user_sessions or user_sessions[chat_id].get("state") != "waiting_file":
        bot.reply_to(message, "❌ من فضلك اضغط على 'استخراج حماية' واختار نوع جهازك أولاً.")
        return
    
    file_name = message.document.file_name
    if not is_so_file(file_name):
        bot.reply_to(message, "⚠️ يرجى إرسال ملف بصيغة .so فقط.")
        return
    
    processing_msg = bot.reply_to(message, "📥 جاري استقبال الملف...")
    
    try:
        file_info = bot.get_file(message.document.file_id)
        downloaded_file = bot.download_file(file_info.file_path)
        
        if not downloaded_file or len(downloaded_file) < 1000:
            bot.edit_message_text("❌ الملف تالف أو حجمه صغير جداً!", chat_id, processing_msg.message_id)
            return
        
        temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.so')
        temp_file.write(downloaded_file)
        temp_file.close()
        
        bits = user_sessions[chat_id].get("bits", 32)
        is_admin_mode = user_sessions[chat_id].get("dev_mode", False)
        
        bot.edit_message_text("✅ تم استلام الملف بنجاح!\n🔄 جاري التحليل...", chat_id, processing_msg.message_id)
        
        protect_analysis_thread(chat_id, processing_msg.message_id, temp_file.name, bits, is_admin_mode)
        
    except Exception as e:
        bot.edit_message_text(f"❌ حدث خطأ: {str(e)}", chat_id, processing_msg.message_id)
    
    user_sessions[chat_id]["state"] = "idle"

@bot.message_handler(func=lambda msg: user_sessions.get(msg.chat.id, {}).get("state") == "waiting_broadcast_all" and is_admin(msg.chat.id))
def handle_broadcast_all(message):
    chat_id = message.chat.id
    if message.text == "/cancel":
        user_sessions[chat_id] = {"state": "idle"}
        bot.reply_to(message, "✅ تم إلغاء الإذاعة.")
        return
    
    msg_text = message.text
    success = 0
    failed = 0
    
    status_msg = bot.reply_to(message, "📡 جاري إرسال الإذاعة...")
    
    for user_id in list(user_sessions.keys()):
        if user_id != OWNER_ID and not is_blocked(user_id):
            try:
                bot.send_message(user_id, f"📢 <b>إذاعة من المالك</b>\n━━━━━━━━━━━━━━━━\n\n{msg_text}")
                success += 1
            except:
                failed += 1
        time.sleep(0.05)
    
    bot.edit_message_text(
        f"✅ <b>تم إرسال الإذاعة!</b>\n━━━━━━━━━━━━━━━━\n"
        f"📨 تم الإرسال لـ {success} مستخدم\n"
        f"❌ فشل الإرسال لـ {failed} مستخدم",
        chat_id, status_msg.message_id
    )
    user_sessions[chat_id] = {"state": "idle"}

@bot.message_handler(func=lambda msg: user_sessions.get(msg.chat.id, {}).get("state") == "waiting_broadcast_user" and is_admin(msg.chat.id))
def handle_broadcast_user(message):
    chat_id = message.chat.id
    if message.text == "/cancel":
        user_sessions[chat_id] = {"state": "idle"}
        bot.reply_to(message, "✅ تم إلغاء العملية.")
        return
    
    lines = message.text.split('\n', 1)
    if len(lines) < 2:
        bot.reply_to(message, "❌ الصيغة غلط!\nاكتب الايدي أولاً، ثم سطر جديد، ثم الرسالة.\nمثال:\n123456789\nمرحباً")
        return
    
    try:
        target_id = int(lines[0].strip())
        msg_text = lines[1].strip()
    except:
        bot.reply_to(message, "❌ الايدي مش رقم صحيح!")
        return
    
    try:
        bot.send_message(target_id, f"📨 <b>رسالة خاصة من المالك</b>\n━━━━━━━━━━━━━━━━\n\n{msg_text}")
        bot.reply_to(message, f"✅ تم إرسال الرسالة للمستخدم {target_id}")
    except Exception as e:
        bot.reply_to(message, f"❌ فشل الإرسال: {str(e)}")
    
    user_sessions[chat_id] = {"state": "idle"}

@bot.message_handler(func=lambda msg: user_sessions.get(msg.chat.id, {}).get("state") == "waiting_block_user" and is_admin(msg.chat.id))
def handle_block_user(message):
    chat_id = message.chat.id
    if message.text == "/cancel":
        user_sessions[chat_id] = {"state": "idle"}
        bot.reply_to(message, "✅ تم إلغاء العملية.")
        return
    
    try:
        target_id = int(message.text.strip())
    except:
        bot.reply_to(message, "❌ الايدي مش رقم صحيح!")
        return
    
    blocked_users.add(target_id)
    save_data()
    bot.reply_to(message, f"✅ تم حظر المستخدم {target_id}")
    user_sessions[chat_id] = {"state": "idle"}

@bot.message_handler(func=lambda msg: user_sessions.get(msg.chat.id, {}).get("state") == "waiting_unblock_user" and is_admin(msg.chat.id))
def handle_unblock_user(message):
    chat_id = message.chat.id
    if message.text == "/cancel":
        user_sessions[chat_id] = {"state": "idle"}
        bot.reply_to(message, "✅ تم إلغاء العملية.")
        return
    
    try:
        target_id = int(message.text.strip())
    except:
        bot.reply_to(message, "❌ الايدي مش رقم صحيح!")
        return
    
    if target_id in blocked_users:
        blocked_users.remove(target_id)
        save_data()
        bot.reply_to(message, f"✅ تم فك الحظر عن المستخدم {target_id}")
    else:
        bot.reply_to(message, f"❌ المستخدم {target_id} مش محظور أصلاً")
    
    user_sessions[chat_id] = {"state": "idle"}

@bot.message_handler(commands=['help'])
def help_command(message):
    help_text = (
        "📖 <b>قائمة الأوامر</b>\n━━━━━━━━━━━━━━━━\n\n"
        "/start - تشغيل البوت\n"
        "/help - عرض المساعدة\n"
        "/about - معلومات عن البوت\n"
        "/cancel - إلغاء العملية الجارية\n\n"
        "💡 لو احتجت أي مساعدة، تواصل مع @ALSHEK"
    )
    bot.reply_to(message, help_text)

@bot.message_handler(commands=['about'])
def about_command(message):
    about_text = (
        "🤖 <b>بوت استخراج الحماية</b>\n"
        "━━━━━━━━━━━━━━━━\n"
        "📌 <b>الإصدار:</b> 3.0.0\n"
        "👨‍💻 <b>الصانع:</b> @ALSHEK\n"
        "🔧 <b>التقنيات:</b> Python, ELF Analysis\n\n"
        "✅ <b>مميزات حصرية:</b>\n"
        "• استخراج دقيق 100%\n"
        "• دعم كامل ARM32/64\n"
        "• باتشات جاهزة للاستخدام"
    )
    bot.reply_to(message, about_text)

@bot.message_handler(commands=['cancel'])
def cancel_command(message):
    chat_id = message.chat.id
    user_sessions[chat_id] = {"state": "idle"}
    bot.reply_to(message, "✅ تم إلغاء العملية الجارية.\nتقدر تبدأ من جديد بـ /start")

if __name__ == "__main__":
    print("🤖 تم تشغيل البوت بنجاح!")
    print(f"👑 المالك: {OWNER_ID}")
    print(f"🔧 الحالة: {'صيانة' if MAINTENANCE_MODE else 'شغال'}")
    bot.infinity_polling()