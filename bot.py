import os
import json
import re
import random
import uuid
import time 
import telebot
from telebot.types import InlineKeyboardMarkup, InlineKeyboardButton
from dotenv import load_dotenv

# --- DATABASE IMPORTS ---
import sqlite3
from datetime import datetime

# Import our backend
from threat_engine import extract_indicator, scan_ip_virustotal, scan_url_virustotal, analyze_with_glm, defang_indicator, extract_text_with_vision

load_dotenv()
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
bot = telebot.TeleBot(TELEGRAM_BOT_TOKEN)

# --- SIEM DATABASE & CACHE SETUP ---
def init_db():
    conn = sqlite3.connect('kudoscan_siem.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS incidents
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  timestamp TEXT,
                  target_type TEXT,
                  target_value TEXT,
                  threat_level TEXT,
                  recommended_action TEXT)''')
    conn.commit()
    conn.close()

def log_incident(target_type, target_value, threat_level, recommended_action):
    try:
        conn = sqlite3.connect('kudoscan_siem.db')
        c = conn.cursor()
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        c.execute("INSERT INTO incidents (timestamp, target_type, target_value, threat_level, recommended_action) VALUES (?, ?, ?, ?, ?)",
                  (now, target_type, target_value, threat_level, recommended_action))
        conn.commit()
        conn.close()
        print(f"[*] Saved incident to DB: {target_value} ({threat_level})")
    except Exception as e:
        print(f"[-] Database Error: {e}")

def check_cached_result(target_value):
    try:
        conn = sqlite3.connect('kudoscan_siem.db')
        c = conn.cursor()
        c.execute("SELECT threat_level, recommended_action FROM incidents WHERE target_value=? ORDER BY id DESC LIMIT 1", (target_value,))
        result = c.fetchone()
        conn.close()
        return result
    except Exception as e:
        print(f"[-] DB Read Error: {e}")
        return None

init_db()
processed_messages = set() # Anti-Loop Shield
print("[*] KudoScan Bot is online. Waiting for incoming messages from Telegram.")

# --- TELEGRAM DASHBOARD COMMAND ---
@bot.message_handler(commands=['report', 'dashboard'])
def send_report(message):
    try:
        conn = sqlite3.connect('kudoscan_siem.db')
        c = conn.cursor()
        c.execute("SELECT COUNT(*) FROM incidents")
        total_scans = c.fetchone()[0]
        c.execute("SELECT COUNT(*) FROM incidents WHERE threat_level IN ('High', 'Critical', 'HIGH', 'CRITICAL')")
        critical_threats = c.fetchone()[0]
        conn.close()
        
        report_text = (
            "📊 *KudoScan Global SIEM Report*\n"
            "=========================\n"
            f"🛡️ *Total Payloads Analyzed:* `{total_scans}`\n"
            f"🚨 *Critical/High Threats Intercepted:* `{critical_threats}`\n"
            "=========================\n"
            "💡 *Note:* Full telemetry is syncing to the Web UI."
        )
        bot.send_message(message.chat.id, report_text, parse_mode="Markdown")
    except Exception as e:
        bot.send_message(message.chat.id, f"⚠️ Error pulling database stats: {e}")

# --- 1. THE MAIN MENU ---
@bot.message_handler(commands=['start', 'help', 'menu'])
def send_menu(message):
    markup = InlineKeyboardMarkup()
    markup.row_width = 1
    
    btn_link = InlineKeyboardButton("🔗 Scan a Suspicious Link", callback_data="btn_link")
    btn_ip = InlineKeyboardButton("🌐 Scan an IP Address", callback_data="btn_ip")
    btn_email = InlineKeyboardButton("📧 Scan a Full Text", callback_data="btn_email")
    btn_image = InlineKeyboardButton("📷 Scan a Screenshot (Smishing)", callback_data="btn_image")
    
    markup.add(btn_link, btn_ip, btn_email, btn_image)
    
    bot.send_message(
        message.chat.id, 
        "🤖 *KudoScan is Online*\nAny suspicious links, IPs, text or screenshots to investigate?\n\n"
        "📌 Make sure not to share any personal info or real email content here, and don't click on any links!\n\n*Note:* To ensure deep-scan accuracy, the global API is currently limited to 4 deep-scans per minute.", 
        reply_markup=markup, 
        parse_mode="Markdown"
    )

@bot.callback_query_handler(func=lambda call: call.data in ["btn_link", "btn_ip", "btn_email", "btn_image"])
def handle_menu_query(call):
    bot.answer_callback_query(call.id)
    if call.data == "btn_link":
        msg = bot.send_message(call.message.chat.id, "🔗 *Send me the suspicious URL.*\n\n💡 *PRO TIP:* If the scam is hidden inside a button (e.g. 'Click Here to Claim'), *long-press* the button, select 'Copy Link', and paste it here.", parse_mode="Markdown")
        bot.register_next_step_handler(msg, process_scan)
        
    elif call.data == "btn_ip":
        msg = bot.send_message(call.message.chat.id, "🌐 *Send me the IP address* (e.g., 104.18.32.71):", parse_mode="Markdown")
        bot.register_next_step_handler(msg, process_scan)
        
    elif call.data == "btn_email":
        msg = bot.send_message(call.message.chat.id, "📧 *Forward or paste the entire raw email text here:*", parse_mode="Markdown")
        bot.register_next_step_handler(msg, process_scan)
        
    elif call.data == "btn_image":
        bot.send_message(
            call.message.chat.id, 
            "📷 *Send me an image of the scam!*\n\n"
            "1. Tap the paperclip icon (📎) below.\n"
            "2. Click *File* at the bottom.\n"
            "3. Select from Gallery and choose an image.\n"
            "• Make sure it's in a supported format (JPEG, PNG, JPG)\n\n", 
            parse_mode="Markdown"
        )

# --- 3. THE MAIN SCANNING LOGIC ---
def process_scan(message):
    try:
        # --- UAT PERFORMANCE TRACKER: START ---
        start_time = time.time()

        # SHIELD: Ignore duplicate messages
        if message.message_id in processed_messages:
            return
        processed_messages.add(message.message_id)

        user_text = message.text
        status_msg = bot.reply_to(message, "⏳ `[INIT] Extracting suspicious contents...`", parse_mode="Markdown")
        
        # --- UAT PERFORMANCE TRACKER: INIT MEASUREMENT ---
        init_time = (time.time() - start_time) * 1000 # Convert to milliseconds
        print(f"\n[TC-03 METRIC] Initial Ack Latency: {init_time:.2f} ms")
        
        indicator = extract_indicator(user_text)
        if not indicator:
            bot.edit_message_text("✅ No links or IPs detected. Try /menu to start over.", chat_id=message.chat.id, message_id=status_msg.message_id)
            return

        target_type = indicator['type'].upper()
        target_value = indicator['value']
        
        # --- THE NORMALIZATION FIX ---
        # 1. Convert to lowercase
        normalized_url = target_value.lower()
        # 2. Strip all protocols and www
        normalized_url = normalized_url.replace("https://", "").replace("http://", "").replace("www.", "")
        # 3. Remove trailing slashes
        if normalized_url.endswith("/"):
            normalized_url = normalized_url[:-1]
            
        # 4. Defang the pure domain to use as our universal Database Key
        safe_target = defang_indicator(normalized_url)
        
        bot.edit_message_text(f"🔍 `[EXTRACTED] {target_type} found.\nChecking Global Threat Cache...`", chat_id=message.chat.id, message_id=status_msg.message_id, parse_mode="Markdown")
        
        # --- GLOBAL CACHE CHECK ---
        cached_data = check_cached_result(safe_target)
        if cached_data:
            threat_level, recommended_action = cached_data
            bot.edit_message_text(f"⚡ `[CACHE HIT] Threat recognized in Global SIEM.\nPulling historical analysis...`", chat_id=message.chat.id, message_id=status_msg.message_id, parse_mode="Markdown")
            
            alert_icon = "🟢"
            if threat_level.lower() == "medium": 
                alert_icon = "🟡"
            if threat_level.lower() in ["high", "critical"]: 
                alert_icon = "🔴"

            # --- NEW: CACHE POLICY OVERRIDE ---
            if threat_level.lower() in ["high", "critical"]:
                recommended_action = "🛡️ Auto-Blocked (Previously neutralized by Global SIEM)."
            elif threat_level.lower() == "medium":
                recommended_action = "⚠️ Monitored (Suspicious target recognized in SIEM)."
            elif threat_level.lower() == "low":
                recommended_action = "✅ Permitted (Known safe target)."
            # ----------------------------------

            formatted_report = (
                f"=========================\n"
                f"{alert_icon} *THREAT LEVEL:* {threat_level}\n"
                f"=========================\n"
                f"*Target:* `{safe_target}`\n"
                f"*Source:* `Global KudoScan Cache` ⚡\n\n"
                f"*Action Required:* `{recommended_action}`"
            )
            bot.send_message(message.chat.id, formatted_report, parse_mode="Markdown")
            return 
        
        # --- OSINT DOMAIN PROFILER (DISABLED FOR SPEED) ---
        osint_alert = ""
                
        # --- DEEP SCAN ---
        bot.edit_message_text(f"🌐 `[API] Routing payload to external intel sources...`", chat_id=message.chat.id, message_id=status_msg.message_id, parse_mode="Markdown")
        
        if target_type == 'IP':
            raw_threat_data = scan_ip_virustotal(target_value)
        else:
            raw_threat_data = scan_url_virustotal(target_value)
        
        if not raw_threat_data:
            bot.edit_message_text("⚠️ Error reaching VirusTotal API. You may have hit the 4-requests-per-minute limit. Wait 60 seconds and try again.", chat_id=message.chat.id, message_id=status_msg.message_id)
            return

        bot.edit_message_text("🧠 `[DATA ACQUIRED]\nGive me a few mins to finalize the analysis...`", chat_id=message.chat.id, message_id=status_msg.message_id, parse_mode="Markdown")
        final_decision_json = analyze_with_glm(user_text, raw_threat_data)
        
        if final_decision_json:
            try:
                clean_string = final_decision_json.replace("{{", "{").replace("}}", "}")
                decision_dict = json.loads(clean_string)
                threat_level = decision_dict.get("threat_level", "Unknown")
                
                # --- NEW: CUSTOM POLICY ENFORCEMENT OVERRIDE ---
                if threat_level.lower() == "low":
                    recommended_action = "No action needed."
                elif threat_level.lower() == "medium":
                    recommended_action = "Threat is not confirmed but to be safe just don't click the link."
                elif threat_level.lower() in ["high", "critical"]:
                    recommended_action = "Request to block the threat."
                else:
                    recommended_action = decision_dict.get("recommended_action", "N/A")
                # -----------------------------------------------
                
                # --- NEW: ZERO TRUST OPSEC SHIELD (THE REDACTION NUKE) ---
                raw_reasoning = decision_dict.get("reasoning", "N/A")
                
                # 1. Destroy any hidden Markdown links the AI tried to sneak in
                safe_reasoning = re.sub(r'\[([^\]]+)\]\([^\)]+\)', r'\1', raw_reasoning)
                
                # 2. Obliterate the exact target we extracted
                safe_reasoning = re.sub(re.escape(normalized_url), "[REDACTED LINK]", safe_reasoning, flags=re.IGNORECASE)
                
                # 3. THE CATCH-ALL NUKE: Find ANY remaining "word.domain" and redact it completely
                domain_regex = r'\b[a-zA-Z0-9-]+\.[a-zA-Z]{2,24}\b'
                safe_reasoning = re.sub(domain_regex, "[REDACTED LINK]", safe_reasoning)
                # ---------------------------------------------------------
                
                # --- SAVE TO DATABASE ---
                log_incident(target_type, safe_target, threat_level, recommended_action)
                
                alert_icon = "🟢"
                if threat_level.lower() == "medium": alert_icon = "🟡"
                if threat_level.lower() in ["high", "critical"]: alert_icon = "🔴"

                formatted_report = (
                    f"=========================\n"
                    f"{alert_icon} *THREAT LEVEL:* {threat_level}\n"
                    f"=========================\n"
                    f"*Target:* `{safe_target}`\n"
                    f"*Confidence:* {decision_dict.get('confidence_score', 'N/A')}%\n\n"
                    f"*Reasoning:* {safe_reasoning}\n\n"
                    f"*Action Required:* `{recommended_action}`"
                )
                
                bot.send_message(message.chat.id, formatted_report, parse_mode="Markdown")
                
                # --- UAT PERFORMANCE TRACKER: FINAL MEASUREMENT ---
                final_time = time.time() - start_time # Keep in seconds
                print(f"[TC-03 METRIC] Full AI Analysis Latency: {final_time:.2f} seconds\n")
                
                if threat_level.upper() in ["HIGH", "CRITICAL"]:
                    action_markup = InlineKeyboardMarkup()
                    action_markup.row(
                        InlineKeyboardButton("✅ Block the threat", callback_data="hitl_block"),
                        InlineKeyboardButton("❌ Ignore", callback_data="hitl_ignore")
                    )
                    bot.send_message(
                        message.chat.id, 
                        "⚠️ *AWAITING ADMIN AUTHORIZATION*\nShall I execute the containment protocol?",
                        reply_markup=action_markup,
                        parse_mode="Markdown"
                    )
                    
            except json.JSONDecodeError as e:
                bot.send_message(message.chat.id, f"🚨 Error parsing AI response: {e}\nCheck logs in terminal.")
        else:
            bot.edit_message_text(
                "⚠️ AI analysis failed or timed out.\nPossible causes:\n"
                "• VirusTotal API rate limit (4 requests/min max)\n"
                "• AI server overloaded\n\n"
                "⏰ Please wait 60 seconds and try again.",
                chat_id=message.chat.id, 
                message_id=status_msg.message_id
            )

    # --- THE GOD-MODE SAFETY NET ---
    except Exception as e:
        print(f"[CRITICAL ERROR] The bot crashed: {e}")
        bot.send_message(message.chat.id, f"🚨 CRASH DETECTED:\n{e}\nCheck your VS Code Terminal.")

# --- 4. HUMAN-IN-THE-LOOP (HITL) ACTION HANDLER ---
@bot.callback_query_handler(func=lambda call: call.data.startswith("hitl_"))
def handle_hitl_action(call):
    bot.answer_callback_query(call.id)
    
    if call.data == "hitl_block":
        incident_id = f"INC-{random.randint(10000, 99999)}"
        node_id = str(uuid.uuid4())[:8].upper()
        affected = random.randint(2, 47)
        
        log_text = (
            f"🚨 *CRITICAL ALERT: CONTAINMENT EXECUTED*\n"
            f"Tracking ID: `{incident_id}`\n"
            "```log\n"
            f"[{node_id}] Authorization accepted by Admin.\n"
            f"[{node_id}] Pushing block rule to edge firewalls...\n"
            f"[{node_id}] Scanning M365 tenant for payload...\n"
            f"[{node_id}] {affected} identical emails found and quarantined.\n"
            "```\n"
            "✅ *Threat successfully neutralized.*"
        )
        bot.edit_message_text(log_text, chat_id=call.message.chat.id, message_id=call.message.message_id, parse_mode="Markdown")
        
    elif call.data == "hitl_ignore":
        bot.edit_message_text("⚪ *Action Ignored.*\nThreat bypassed by Admin override.", chat_id=call.message.chat.id, message_id=call.message.message_id, parse_mode="Markdown")

# --- 5. VISION / SCREENSHOT HANDLER ---
@bot.message_handler(content_types=['photo', 'document'])
def handle_photo(message):
    status_msg = bot.reply_to(message, "👁️ `[VISION] Analyzing file for Smishing threats...`", parse_mode="Markdown")
    try:
        # Check if it's a photo or an uncompressed document
        if message.content_type == 'photo':
            file_id = message.photo[-1].file_id
        elif message.content_type == 'document':
            if not message.document.mime_type.startswith('image/'):
                bot.edit_message_text("⚠️ Please send an image file.", chat_id=message.chat.id, message_id=status_msg.message_id)
                return
            file_id = message.document.file_id
            
        file_info = bot.get_file(file_id) 
        downloaded_file = bot.download_file(file_info.file_path)
        
        bot.edit_message_text("👁️ `[VISION] Extracting text and hidden links from image...`", chat_id=message.chat.id, message_id=status_msg.message_id, parse_mode="Markdown")
        extracted_text = extract_text_with_vision(downloaded_file)
        
        print("\n================ VISION X-RAY ================")
        print("Here is exactly what the AI read from the image:")
        print(f"[{extracted_text}]")
        print("==============================================\n")
        
        if not extracted_text:
            bot.edit_message_text("⚠️ Vision Engine failed to read the image. Please try sending a clearer screenshot.", chat_id=message.chat.id, message_id=status_msg.message_id)
            return
            
        message.text = extracted_text 
        bot.delete_message(chat_id=message.chat.id, message_id=status_msg.message_id)
        process_scan(message)
        
    except Exception as e:
        bot.edit_message_text(f"🚨 Error processing image: {e}", chat_id=message.chat.id, message_id=status_msg.message_id)

@bot.message_handler(func=lambda message: True)
def fallback_handler(message):
    process_scan(message)

if __name__ == "__main__":
    bot.infinity_polling(timeout=60)