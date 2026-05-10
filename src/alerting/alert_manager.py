"""
Alert Manager - Sends notifications for security events
"""

import logging
import smtplib
import json
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
from typing import Dict, Any, List, Optional
import requests

from ..config.settings import config

logger = logging.getLogger(__name__)

class AlertManager:
    """Manages alerts for security events"""
    
    def __init__(self):
        self.slack_webhook = config.alert.slack_webhook_url
        self.email_enabled = config.alert.email_enabled
        self.smtp_server = config.alert.smtp_server
        self.recipients = config.alert.alert_recipients
        
        # Alert thresholds
        self.critical_threshold = 90
        self.high_threshold = 70
        self.medium_threshold = 40
        
        # Rate limiting for alerts (prevent flooding)
        self.last_alert_cache = {}
        self.min_interval_seconds = 300  # 5 minutes between same indicator alerts
    
    def _should_send_alert(self, indicator: str, severity: str) -> bool:
        """Rate limit alerts to prevent flooding"""
        cache_key = f"{indicator}:{severity}"
        last_sent = self.last_alert_cache.get(cache_key)
        
        if last_sent:
            elapsed = (datetime.utcnow() - last_sent).total_seconds()
            if elapsed < self.min_interval_seconds:
                return False
        
        self.last_alert_cache[cache_key] = datetime.utcnow()
        return True
    
    def send_slack_alert(self, title: str, message: str, color: str = "danger") -> bool:
        """Send alert to Slack channel"""
        if not self.slack_webhook:
            logger.debug("Slack webhook not configured")
            return False
        
        color_map = {
            "critical": "#ff0000",
            "high": "#ff6600",
            "medium": "#ffcc00",
            "low": "#00ff00"
        }
        
        payload = {
            "attachments": [{
                "color": color_map.get(color, color),
                "title": title,
                "text": message,
                "footer": "Threat Intelligence Platform",
                "ts": int(datetime.utcnow().timestamp())
            }]
        }
        
        try:
            response = requests.post(
                self.slack_webhook,
                data=json.dumps(payload),
                headers={"Content-Type": "application/json"},
                timeout=10
            )
            
            if response.status_code == 200:
                logger.info(f"Slack alert sent: {title}")
                return True
            else:
                logger.error(f"Slack alert failed: {response.status_code}")
                return False
                
        except Exception as e:
            logger.error(f"Failed to send Slack alert: {e}")
            return False
    
    def send_email_alert(self, subject: str, body: str, recipients: List[str] = None) -> bool:
        """Send email alert"""
        if not self.email_enabled or not self.smtp_server:
            logger.debug("Email alerts not configured")
            return False
        
        recipients = recipients or self.recipients
        if not recipients:
            return False
        
        try:
            msg = MIMEMultipart()
            msg["From"] = "threat-intel@financial-bank.com"
            msg["To"] = ", ".join(recipients)
            msg["Subject"] = f"[TIP Alert] {subject}"
            
            msg.attach(MIMEText(body, "plain"))
            
            # Connect to SMTP server
            server = smtplib.SMTP(self.smtp_server, 587)
            server.starttls()
            # server.login(username, password)  # Add if authentication needed
            server.send_message(msg)
            server.quit()
            
            logger.info(f"Email alert sent: {subject}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to send email alert: {e}")
            return False
    
    def alert_threat_detected(self, threat: Dict[str, Any]) -> bool:
        """Send alert for detected threat"""
        indicator = threat.get('indicator', 'unknown')
        risk_score = threat.get('risk_score', 0)
        
        if risk_score >= self.critical_threshold:
            severity = "critical"
            emoji = "🔴 CRITICAL"
        elif risk_score >= self.high_threshold:
            severity = "high"
            emoji = "🟠 HIGH"
        elif risk_score >= self.medium_threshold:
            severity = "medium"
            emoji = "🟡 MEDIUM"
        else:
            return False  # Don't alert for low severity
        
        if not self._should_send_alert(indicator, severity):
            return False
        
        title = f"{emoji} Threat Alert: {indicator}"
        message = (
            f"**Indicator:** `{indicator}`\n"
            f"**Risk Score:** {risk_score}/100\n"
            f"**Severity:** {severity.upper()}\n"
            f"**Type:** {threat.get('threat_type', 'unknown')}\n"
            f"**Sources:** {', '.join(threat.get('source_feeds', []))}\n"
            f"**Tags:** {', '.join(threat.get('tags', []))}\n\n"
            f"*Action: Automated block has been applied.*"
        )
        
        # Send to Slack
        slack_sent = self.send_slack_alert(title, message, severity)
        
        # Send to email for critical threats only
        email_sent = False
        if severity == "critical":
            email_body = f"Critical threat detected:\n\n{message}"
            email_sent = self.send_email_alert(f"CRITICAL: {indicator}", email_body)
        
        # Log alert
        logger.warning(f"Alert sent for {indicator} (risk: {risk_score})")
        
        return slack_sent or email_sent
    
    def alert_block_removed(self, indicator: str, reason: str) -> bool:
        """Alert when a block is removed"""
        title = f"🟢 Block Removed: {indicator}"
        message = (
            f"**Indicator:** `{indicator}`\n"
            f"**Reason:** {reason}\n"
            f"*The block rule has been removed from the firewall.*"
        )
        
        return self.send_slack_alert(title, message, "good")
    
    def alert_system_health(self, status: str, details: Dict[str, Any]) -> bool:
        """Send system health alert"""
        if status == "degraded":
            title = "⚠️ System Health: Degraded"
            color = "warning"
        elif status == "failed":
            title = "🔴 System Health: Failed"
            color = "danger"
        else:
            title = "🟢 System Health: Operational"
            color = "good"
        
        message = f"**Status:** {status}\n"
        for key, value in details.items():
            message += f"**{key}:** {value}\n"
        
        return self.send_slack_alert(title, message, color)
    
    def send_daily_summary(self, summary: Dict[str, Any]) -> bool:
        """Send daily summary report"""
        title = "📊 Daily Threat Intelligence Summary"
        message = (
            f"**Period:** {summary.get('date', 'today')}\n\n"
            f"**Threats Detected:** {summary.get('total_threats', 0)}\n"
            f"**High Risk:** {summary.get('high_risk_count', 0)}\n"
            f"**Critical Risk:** {summary.get('critical_risk_count', 0)}\n"
            f"**Blocks Applied:** {summary.get('blocks_applied', 0)}\n"
            f"**Blocks Removed:** {summary.get('blocks_removed', 0)}\n"
            f"**False Positives:** {summary.get('false_positives', 0)}\n\n"
            f"**Top Threat Sources:**\n"
        )
        
        for feed, count in summary.get('top_feeds', {}).items():
            message += f"- {feed}: {count}\n"
        
        return self.send_slack_alert(title, message, "info")
