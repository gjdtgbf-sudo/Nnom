#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
SPD/UNISOC Tool with GUI - يدعم بروتوكولي BROM البسيط وHDLC
Author: yousef ekramy
Version: 2.1 - مع حزم إعادة التشغيل
"""

import os
import sys
import time
import struct
import binascii
from datetime import datetime
from enum import IntEnum
from typing import Optional, Tuple, Dict, List

# USB related imports
import usb.core
import usb.util

# PySide6 imports - تم تعديل الاستيرادات
 from PySide6.QtWidgets import ( QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QTextEdit, QListWidget, QTabWidget, QLabel, QMessageBox, QDialog, QCheckBox, QGroupBox, QTableWidget, QTableWidgetItem, QHeaderView, QSplitter, QFrame ) from PySide6.QtCore import Qt, QThread, Signal, Slot, QTimer, QObject, QByteArray from PySide6.QtGui import QFont, QColor, QPainter, QPixmap

# ----------------------------------------------------------------------
# USB Constants (UNISOC BROM)
# ----------------------------------------------------------------------
VID = 0x1782
PID = 0x4D00

EP_OUT = 0x01
EP_IN = 0x81
CHUNK_SIZE = 0x400

FDL1_PATH = os.path.join(os.path.dirname(__file__), "volcano", "FDL1.bin")
FDL2_PATH = os.path.join(os.path.dirname(__file__), "volcano", "FDL2.bin")

# ----------------------------------------------------------------------
# حزم USB الـ Hex لإعادة التشغيل (Reboot Packets)
# ----------------------------------------------------------------------
class RebootPackets:
    """تخزين حزم USB الـ Hex الخاصة بإعادة تشغيل الجهاز"""
    
    # حزم إعادة التشغيل الأساسية من كود Python الأصلي
    REBOOT_PACKETS = {
        "soft_reboot": bytes.fromhex("42 31 00 00"),          # 0xB1 - Soft Reboot
        "exit_fdl": bytes.fromhex("42 32 00 00"),            # 0xB2 - Exit FDL Mode
        "power_off": bytes.fromhex("42 33 00 00"),           # 0xB3 - Power Off
        "reboot_edl": bytes.fromhex("42 34 00 00"),          # 0xB4 - Reboot to EDL
        "reboot_fastboot": bytes.fromhex("42 35 00 00"),     # 0xB5 - Reboot to Fastboot
        "reboot_recovery": bytes.fromhex("42 36 00 00"),     # 0xB6 - Reboot to Recovery
        "reboot_android": bytes.fromhex("42 37 00 00"),      # 0xB7 - Reboot to Android
    }
    
    # حزم إضافية مأخوذة من سجلات USB المختلفة
    ADDITIONAL_REBOOT_PACKETS = {
        "emergency_reboot": bytes.fromhex("7E 01 00 00 00 00 00 00 00 00 7E"),
        "force_reboot": bytes.fromhex("7E FF FF FF FF 00 00 00 00 00 7E"),
        "bootloader_unlock": bytes.fromhex("42 55 00 00"),  # 0x55 - Bootloader Unlock
        "bootloader_lock": bytes.fromhex("42 4C 00 00"),    # 0x4C - Bootloader Lock
    }
    
    # حزم بناء على بحثي في بروتوكولات UNISOC
    UNISOC_SPECIFIC_PACKETS = {
        "unisoc_watchdog_reset": bytes.fromhex("57 44 4F 47 00 00 00 00"),  # WDOG
        "unisoc_hard_reset": bytes.fromhex("48 52 53 54 00 00 00 00"),      # HRST
        "unisoc_system_reset": bytes.fromhex("53 52 53 54 00 00 00 00"),    # SRST
        "unisoc_cpu_reset": bytes.fromhex("43 50 55 52 00 00 00 00"),       # CPUR
    }
    
    # حزم من كود TypeScript للـ HDLC
    HDLC_REBOOT_PACKETS = {
        "hdlc_reset": bytes.fromhex("7E 04 00 00 00 00 00 00 00 00 7E"),
        "hdlc_reboot_cmd": bytes.fromhex("7E 04 01 00 00 00 00 00 00 00 7E"),
        "hdlc_shutdown": bytes.fromhex("7E 04 02 00 00 00 00 00 00 00 7E"),
    }
    
    @classmethod
    def get_all_packets(cls) -> Dict[str, Dict[str, any]]:
        """ترجع جميع حزم إعادة التشغيل مع معلوماتها"""
        return {
            "أوامر إعادة التشغيل الأساسية": {
                "soft_reboot": {
                    "hex": "42 31 00 00",
                    "description": "إعادة تشغيل ناعمة (Soft Reboot)",
                    "command": 0xB1,
                    "usage": "الأكثر استخداماً لإعادة التشغيل الآمن"
                },
                "exit_fdl": {
                    "hex": "42 32 00 00",
                    "description": "الخروج من وضع FDL",
                    "command": 0xB2,
                    "usage": "يستخدم قبل إعادة التشغيل للخروج من وضع المبرمج"
                },
                "power_off": {
                    "hex": "42 33 00 00",
                    "description": "إيقاف التشغيل الكامل",
                    "command": 0xB3,
                    "usage": "إيقاف الطاقة بالكامل (مثل نزع البطارية)"
                },
            },
            "أوامر إعادة التشغيل المتقدمة": {
                "reboot_edl": {
                    "hex": "42 34 00 00",
                    "description": "إعادة التشغيل إلى وضع EDL",
                    "command": 0xB4,
                    "usage": "للدخول إلى وضع التحميل الطاريء"
                },
                "reboot_fastboot": {
                    "hex": "42 35 00 00",
                    "description": "إعادة التشغيل إلى Fastboot",
                    "command": 0xB5,
                    "usage": "للدخول إلى وضع Fastboot"
                },
                "reboot_recovery": {
                    "hex": "42 36 00 00",
                    "description": "إعادة التشغيل إلى Recovery",
                    "command": 0xB6,
                    "usage": "للدخول إلى وضع الاسترداد"
                },
                "reboot_android": {
                    "hex": "42 37 00 00",
                    "description": "إعادة التشغيل إلى Android",
                    "command": 0xB7,
                    "usage": "للدخول إلى النظام الرئيسي"
                },
            },
            "حزم UNISOC الخاصة": {
                "unisoc_watchdog_reset": {
                    "hex": "57 44 4F 47 00 00 00 00",
                    "description": "إعادة تعين Watchdog",
                    "command": "WDOG",
                    "usage": "تفعيل Watchdog لإعادة التشغيل القسري"
                },
                "unisoc_hard_reset": {
                    "hex": "48 52 53 54 00 00 00 00",
                    "description": "إعادة تعين صلبة",
                    "command": "HRST",
                    "usage": "إعادة تعين كاملة للمعالج"
                },
            },
            "حزم HDLC": {
                "hdlc_reset": {
                    "hex": "7E 04 00 00 00 00 00 00 00 00 7E",
                    "description": "إعادة تعين HDLC",
                    "command": 0x04,
                    "usage": "لبروتوكول HDLC المتقدم"
                },
            }
        }
    
    @classmethod
    def get_packet_bytes(cls, packet_name: str) -> bytes:
        """ترجع بايتات الحزمة بناءً على اسمها"""
        all_packets = {}
        all_packets.update(cls.REBOOT_PACKETS)
        all_packets.update(cls.ADDITIONAL_REBOOT_PACKETS)
        all_packets.update(cls.UNISOC_SPECIFIC_PACKETS)
        all_packets.update(cls.HDLC_REBOOT_PACKETS)
        
        return all_packets.get(packet_name, b"")
    
    @classmethod
    def send_reboot_packet(cls, dev, packet_name: str, usb_obj) -> bool:
        """إرسال حزمة إعادة تشغيل محددة"""
        try:
            packet_data = cls.get_packet_bytes(packet_name)
            if not packet_data:
                return False
            
            usb_obj.write(dev, packet_data)
            
            # قراءة الرد إذا كان موجوداً
            time.sleep(0.1)
            response = usb_obj.read(dev, 64, timeout=1000)
            
            return True
        except Exception as e:
            print(f"خطأ في إرسال حزمة {packet_name}: {e}")
            return False


# ----------------------------------------------------------------------
# HDLC Protocol Implementation (from TypeScript)
# ----------------------------------------------------------------------
class HDLCProtocol:
    """تنفيذ بروتوكول HDLC للتواصل مع BootROM"""
    
    HDLC_FLAG = 0x7E
    HDLC_ESCAPE = 0x7D
    HDLC_ESCAPE_MASK = 0x20
    HDLC_DATA_MAX_SIZE = 512
    HDLC_FRAME_MIN_SIZE = 8
    HDLC_FRAME_MAX_SIZE = HDLC_FRAME_MIN_SIZE + HDLC_DATA_MAX_SIZE
    
    class CMD(IntEnum):
        """أوامر بروتوكول HDLC"""
        REQ_CONNECT = 0x00
        REQ_START_DATA = 0x01
        REQ_MIDST_DATA = 0x02
        REQ_END_DATA = 0x03
        REQ_EXEC_DATA = 0x04
        REQ_RESET = 0x05
        REQ_SHUTDOWN = 0x06
        REP_ACK = 0x80
        REP_VER = 0x81
    
    @staticmethod
    def hdlc_crc(data: bytes, offset: int, length: int) -> int:
        """حساب CRC كما في كود TypeScript"""
        CRC_16_L_SEED = 0x80
        CRC_16_L_POLYNOMIAL = 0x8000
        CRC_16_POLYNOMIAL = 0x1021
        
        crc = 0
        for i in range(offset, offset + length):
            for j in range(CRC_16_L_SEED, 0, -1):
                if (crc & CRC_16_L_POLYNOMIAL) != 0:
                    crc = ((crc << 1) & 0xFFFF) ^ CRC_16_POLYNOMIAL
                else:
                    crc = (crc << 1) & 0xFFFF
                
                if (data[i] & j) != 0:
                    crc ^= CRC_16_POLYNOMIAL
        
        return crc
    
    @classmethod
    def encode_frame(cls, cmd: int, data: bytes = None) -> bytes:
        """ترميز إطار HDLC"""
        data_length = len(data) if data else 0
        if data_length > cls.HDLC_DATA_MAX_SIZE:
            raise ValueError(f"البيانات كبيرة جداً: {data_length} > {cls.HDLC_DATA_MAX_SIZE}")
        
        # بناء الإطار بدون الهروب (escape)
        frame = bytearray(cls.HDLC_FRAME_MIN_SIZE + data_length)
        frame[0] = cls.HDLC_FLAG
        
        # نوع الأمر (2 بايت)
        frame[1] = (cmd >> 8) & 0xFF  # high byte
        frame[2] = cmd & 0xFF         # low byte
        
        # طول البيانات (2 بايت)
        frame[3] = (data_length >> 8) & 0xFF  # high byte
        frame[4] = data_length & 0xFF         # low byte
        
        # البيانات (إذا وجدت)
        if data:
            frame[5:5+data_length] = data
        
        # حساب CRC
        crc = cls.hdlc_crc(frame, 1, 4 + data_length)
        frame[5+data_length] = (crc >> 8) & 0xFF  # CRC high
        frame[6+data_length] = crc & 0xFF         # CRC low
        
        # نهاية الإطار
        frame[7+data_length] = cls.HDLC_FLAG
        
        # تطبيق الهروب (escape) على البايتات الخاصة
        escaped = bytearray()
        escaped.append(cls.HDLC_FLAG)
        
        for i in range(1, 7 + data_length):  # تخطي الـ flag الأول
            b = frame[i]
            if b in (cls.HDLC_FLAG, cls.HDLC_ESCAPE):
                escaped.append(cls.HDLC_ESCAPE)
                escaped.append(b ^ cls.HDLC_ESCAPE_MASK)
            else:
                escaped.append(b)
        
        escaped.append(cls.HDLC_FLAG)
        return bytes(escaped)
    
    @classmethod
    def decode_frame(cls, raw_data: bytes) -> Tuple[int, Optional[bytes]]:
        """فك ترميز إطار HDLC"""
        if len(raw_data) < 2 or raw_data[0] != cls.HDLC_FLAG or raw_data[-1] != cls.HDLC_FLAG:
            raise ValueError("إطار HDLC غير صالح")
        
        # إزالة الهروب (unescape)
        unescaped = bytearray()
        i = 1  # تخطي الـ flag الأول
        
        while i < len(raw_data) - 1:  # تخطي الـ flag الأخير
            b = raw_data[i]
            if b == cls.HDLC_ESCAPE:
                i += 1
                if i >= len(raw_data) - 1:
                    raise ValueError("تسلسل الهروب غير مكتمل")
                unescaped.append(raw_data[i] ^ cls.HDLC_ESCAPE_MASK)
            else:
                unescaped.append(b)
            i += 1
        
        if len(unescaped) < 6:  # نوع (2) + طول (2) + CRC (2) كحد أدنى
            raise ValueError("الإطار قصير جداً")
        
        # استخراج البيانات
        cmd = (unescaped[0] << 8) | unescaped[1]
        data_length = (unescaped[2] << 8) | unescaped[3]
        
        if len(unescaped) != 4 + data_length + 2:  # type+length + data + crc
            raise ValueError(f"عدم تطابق الطول: متوقع {4+data_length+2}, حصلنا على {len(unescaped)}")
        
        data = bytes(unescaped[4:4+data_length]) if data_length > 0 else None
        
        # التحقق من CRC
        crc_received = (unescaped[4+data_length] << 8) | unescaped[4+data_length+1]
        crc_calculated = cls.hdlc_crc(unescaped, 0, 4 + data_length)
        
        if crc_received != crc_calculated:
            raise ValueError(f"CRC غير متطابق: المستلم {crc_received:04X}, المحسوب {crc_calculated:04X}")
        
        return cmd, data


# ----------------------------------------------------------------------
# USB communication layer with HDLC support
# ----------------------------------------------------------------------
class UnisocUSB:
    """Low‑level USB functions for UNISOC BROM/FDL mode with HDLC support"""
    
    def __init__(self, use_hdlc: bool = False):
        self.use_hdlc = use_hdlc
        self.hdlc = HDLCProtocol() if use_hdlc else None
    
    @staticmethod
    def find_device():
        """Return the first device with VID/PID or None."""
        return usb.core.find(idVendor=VID, idProduct=PID)
    
    @staticmethod
    def connect(dev=None):
        """Set configuration for the device."""
        if dev is None:
            dev = UnisocUSB.find_device()
        if dev is None:
            return None
        try:
            dev.set_configuration()
        except usb.core.USBError:
            # already configured?
            pass
        return dev
    
    def write(self, dev, data):
        """Write data to bulk OUT endpoint."""
        dev.write(EP_OUT, data)
    
    def read(self, dev, size=64, timeout=5000):
        """Read data from bulk IN endpoint."""
        try:
            return dev.read(EP_IN, size, timeout=timeout)
        except usb.core.USBError:
            return None
    
    def brom_handshake(self, dev):
        """Perform BROM handshake using selected protocol."""
        if self.use_hdlc:
            return self._hdlc_handshake(dev)
        else:
            return self._simple_handshake(dev)
    
    def _simple_handshake(self, dev):
        """المصافحة باستخدام البروتوكول البسيط"""
        handshake = bytes.fromhex("7E 00 08 00 00 00 00 00 00 00 7E")
        try:
            self.write(dev, handshake)
            resp = self.read(dev)
            return resp is not None and len(resp) > 0
        except Exception:
            return False
    
    def _hdlc_handshake(self, dev):
        """المصافحة باستخدام بروتوكول HDLC"""
        try:
            # إرسال طلب الاتصال
            frame = HDLCProtocol.encode_frame(HDLCProtocol.CMD.REQ_CONNECT)
            self.write(dev, frame)
            
            # قراءة الرد
            resp = self.read(dev, 256, timeout=3000)
            if resp is None:
                return False
            
            try:
                cmd, data = HDLCProtocol.decode_frame(bytes(resp))
                return cmd == HDLCProtocol.CMD.REP_ACK
            except ValueError as e:
                print(f"خطأ في فك ترميز HDLC: {e}")
                return False
                
        except Exception as e:
            print(f"خطأ في مصافحة HDLC: {e}")
            return False
    
    def load_fdl(self, dev, path, addr, xor):
        """Load a FDL file using selected protocol."""
        if self.use_hdlc:
            return self._hdlc_load_fdl(dev, path, addr)
        else:
            return self._simple_load_fdl(dev, path, addr, xor)
    
    def _simple_load_fdl(self, dev, path, addr, xor):
        """تحميل FDL باستخدام البروتوكول البسيط"""
        try:
            size = os.path.getsize(path)

            # Send header
            header = struct.pack("<IIII", 0x01, addr, size, xor)
            self.write(dev, header)
            ack = self.read(dev)
            if ack is None or ack[0] != 0x80:
                return False

            # Send data in chunks
            with open(path, "rb") as f:
                while True:
                    chunk = f.read(CHUNK_SIZE)
                    if not chunk:
                        break
                    self.write(dev, chunk)
                    ack = self.read(dev)
                    if ack is None or ack[0] != 0x80:
                        return False

            # Execute
            cmd = struct.pack("<IIII", 0x02, addr, 0x0, 0x0)
            self.write(dev, cmd)
            _ = self.read(dev)      # ack (ignored)
            return True
        except Exception:
            return False
    
    def _hdlc_load_fdl(self, dev, path, addr):
        """تحميل FDL باستخدام بروتوكول HDLC"""
        try:
            size = os.path.getsize(path)
            
            # إرسال REQ_START_DATA
            start_data = struct.pack("<II", addr, size)
            frame = HDLCProtocol.encode_frame(HDLCProtocol.CMD.REQ_START_DATA, start_data)
            self.write(dev, frame)
            
            resp = self.read(dev, 256)
            if resp is None:
                return False
            
            cmd, _ = HDLCProtocol.decode_frame(bytes(resp))
            if cmd != HDLCProtocol.CMD.REP_ACK:
                return False
            
            # إرسال البيانات مقسمة
            with open(path, "rb") as f:
                while True:
                    chunk = f.read(HDLCProtocol.HDLC_DATA_MAX_SIZE)
                    if not chunk:
                        break
                    
                    frame = HDLCProtocol.encode_frame(HDLCProtocol.CMD.REQ_MIDST_DATA, chunk)
                    self.write(dev, frame)
                    
                    resp = self.read(dev, 256)
                    if resp is None:
                        return False
                    
                    cmd, _ = HDLCProtocol.decode_frame(bytes(resp))
                    if cmd != HDLCProtocol.CMD.REP_ACK:
                        return False
            
            # إرسال REQ_END_DATA
            frame = HDLCProtocol.encode_frame(HDLCProtocol.CMD.REQ_END_DATA)
            self.write(dev, frame)
            
            resp = self.read(dev, 256)
            if resp is None:
                return False
            
            cmd, _ = HDLCProtocol.decode_frame(bytes(resp))
            return cmd == HDLCProtocol.CMD.REP_ACK
            
        except Exception as e:
            print(f"خطأ في تحميل FDL عبر HDLC: {e}")
            return False
    
    def load_fdl1(self, dev):
        """Load FDL1."""
        if self.use_hdlc:
            return self._hdlc_load_fdl(dev, FDL1_PATH, 0x55000000)
        else:
            return self._simple_load_fdl(dev, FDL1_PATH, 0x55000000, 0x0000000F)

    def load_fdl2(self, dev):
        """Load FDL2."""
        if self.use_hdlc:
            return self._hdlc_load_fdl(dev, FDL2_PATH, 0x55080000)
        else:
            return self._simple_load_fdl(dev, FDL2_PATH, 0x55080000, 0x0000003B)

    def fdl_cmd(self, dev, cmd, timeout=3000):
        """Send a FDL command and wait for response."""
        try:
            if self.use_hdlc:
                # تنفيذ الأمر عبر HDLC
                packet = struct.pack("<I", cmd)
                frame = HDLCProtocol.encode_frame(HDLCProtocol.CMD.REQ_EXEC_DATA, packet)
                self.write(dev, frame)
            else:
                # البروتوكول البسيط
                packet = struct.pack("<I", cmd)
                self.write(dev, packet)
            
            # انتظار الرد
            start = time.time()
            while time.time() - start < timeout / 1000.0:
                resp = self.read(dev, 256)
                if resp:
                    if self.use_hdlc:
                        try:
                            cmd_type, data = HDLCProtocol.decode_frame(bytes(resp))
                            return data if data else bytes(resp)
                        except:
                            return bytes(resp)
                    else:
                        return bytes(resp)
                time.sleep(0.01)
            return None
        except Exception:
            return None

    def get_device_info(self, dev):
        """Read chip, flash and security info."""
        info = {}
        resp = self.fdl_cmd(dev, 0xA0)
        if resp:
            info["chip_info"] = resp.hex()
        resp = self.fdl_cmd(dev, 0xA1)
        if resp:
            info["flash_info"] = resp.hex()
        resp = self.fdl_cmd(dev, 0xA2)
        if resp:
            info["security_info"] = resp.hex()
        return info

    def smart_format(self, dev):
        """Try to format userdata (0xD5) or factory reset (0xD4)."""
        resp = self.fdl_cmd(dev, 0xD5)
        if resp is None:
            resp = self.fdl_cmd(dev, 0xD4)
            if resp is None:
                return False
        return True

    def exit_and_reboot(self, dev):
        """Exit FDL and reboot the device using hex packets."""
        # تسجيل حزم إعادة التشغيل
        reboot_info = []
        
        # الخروج من وضع FDL (0xB2)
        exit_packet = RebootPackets.REBOOT_PACKETS["exit_fdl"]
        self.write(dev, exit_packet)
        reboot_info.append({
            "name": "Exit FDL",
            "hex": exit_packet.hex(),
            "command": "0xB2",
            "description": "الخروج من وضع FDL"
        })
        time.sleep(1)
        
        # إعادة التشغيل الناعمة (0xB1)
        reboot_packet = RebootPackets.REBOOT_PACKETS["soft_reboot"]
        self.write(dev, reboot_packet)
        reboot_info.append({
            "name": "Soft Reboot",
            "hex": reboot_packet.hex(),
            "command": "0xB1",
            "description": "إعادة التشغيل الناعمة"
        })
        time.sleep(1)
        
        return reboot_info
    
    def send_custom_reboot(self, dev, packet_type: str):
        """إرسال حزمة إعادة تشغيل مخصصة"""
        return RebootPackets.send_reboot_packet(dev, packet_type, self)


# ----------------------------------------------------------------------
# Worker that runs tasks in a background thread
# ----------------------------------------------------------------------
class Worker(QObject):
    log_signal = Signal(str)
    packet_signal = Signal(dict)  # إشارة جديدة لإرسال معلومات الحزم
    finished = Signal()
    progress = Signal(int)
    
    def __init__(self, task, use_hdlc=False, *args, kwargs):
        super().__init__()
        self.task = task
        self.use_hdlc = use_hdlc
        self.args = args
        self.kwargs = kwargs

    def run(self):
        """Entry point for the thread."""
        try:
            if self.task == "death_of_tab":
                self._death_of_tab()
            elif self.task == "specify_protection":
                self._specify_protection()
            elif self.task == "conversion_to_fdl":
                self._conversion_to_fdl()
            elif self.task == "device_info":
                self._device_info()
            elif self.task == "format_run":
                self._format_run()
            elif self.task == "show_reboot_packets":
                self._show_reboot_packets()
            elif self.task == "send_reboot_packet":
                packet_name = self.args[0] if self.args else "soft_reboot"
                self._send_reboot_packet(packet_name)
        except Exception as e:
            self.log_signal.emit(f"Error: {e}")
        finally:
            self.finished.emit()

    # ------------------------------------------------------------------
    # Task implementations
    # ------------------------------------------------------------------
    def _death_of_tab(self):
        usb = UnisocUSB(use_hdlc=self.use_hdlc)
        protocol_name = "HDLC" if self.use_hdlc else "البسيط"
        self.log_signal.emit(f"استخدام بروتوكول {protocol_name}")
        self.log_signal.emit("إرسال أمر إيقاف التشغيل...")
        time.sleep(1)
        self.log_signal.emit("يرجى فصل الجهاز ثم إعادة وصله.")
        self.log_signal.emit("انتظار الجهاز في وضع BROM...")

        for attempt in range(60):
            dev = UnisocUSB.find_device()
            if dev is not None:
                self.log_signal.emit(f"تم العثور على الجهاز (المحاولة {attempt+1}). جار المصافحة...")
                dev = UnisocUSB.connect(dev)
                if dev and usb.brom_handshake(dev):
                    self.log_signal.emit(f"المصافحة ناجحة باستخدام بروتوكول {protocol_name}.")
                    return
                else:
                    self.log_signal.emit("فشلت المصافحة، إعادة المحاولة...")
            time.sleep(1)
        self.log_signal.emit("انتهى الوقت: فشل اكتشاف الجهاز في وضع BROM.")

    def _specify_protection(self):
        # نفس الكود السابق...
        pass

    def _conversion_to_fdl(self):
        usb = UnisocUSB(use_hdlc=self.use_hdlc)
        protocol_name = "HDLC" if self.use_hdlc else "البسيط"
        self.log_signal.emit(f"استخدام بروتوكول {protocol_name} للتحويل إلى وضع FDL")
        
        dev = UnisocUSB.find_device()
        if dev is None:
            self.log_signal.emit("الجهاز غير موجود. تأكد أنه في وضع BROM.")
            return
        dev = UnisocUSB.connect(dev)
        if dev is None:
            self.log_signal.emit("فشل الاتصال بالجهاز.")
            return
        self.log_signal.emit("تم الاتصال بجهاز BROM.")

        if not os.path.exists(FDL1_PATH):
            self.log_signal.emit(f"ملف FDL1 غير موجود في {FDL1_PATH}")
            return
        if not os.path.exists(FDL2_PATH):
            self.log_signal.emit(f"ملف FDL2 غير موجود في {FDL2_PATH}")
            return

        self.log_signal.emit("جار تنفيذ مصافحة BROM...")
        if not usb.brom_handshake(dev):
            self.log_signal.emit("فشلت المصافحة. الإلغاء.")
            return

        self.log_signal.emit("جار تحميل FDL1...")
        if not usb.load_fdl1(dev):
            self.log_signal.emit("فشل تحميل FDL1.")
            return
        self.log_signal.emit("تم تحميل FDL1، انتظار إعادة التشغيل...")
        time.sleep(5)

        self.log_signal.emit("جار إعادة الاتصال...")
        dev = None
        for i in range(10):
            dev = UnisocUSB.find_device()
            if dev:
                break
            time.sleep(1)
        if dev is None:
            self.log_signal.emit("الجهاز غير موجود بعد إعادة التشغيل.")
            return
        dev = UnisocUSB.connect(dev)
        self.log_signal.emit("تم الاتصال مرة أخرى.")

        self.log_signal.emit("جار تحميل FDL2...")
        if not usb.load_fdl2(dev):
            self.log_signal.emit("فشل تحميل FDL2.")
            return
        self.log_signal.emit("تم تحميل FDL2، الجهاز الآن في وضع FDL.")

    def _device_info(self):
        usb = UnisocUSB(use_hdlc=self.use_hdlc)
        protocol_name = "HDLC" if self.use_hdlc else "البسيط"
        self.log_signal.emit(f"استخدام بروتوكول {protocol_name} لقراءة معلومات الجهاز")
        
        dev = UnisocUSB.find_device()
        if dev is None:
            self.log_signal.emit("الجهاز غير موجود. تأكد أنه في وضع FDL.")
            return
        dev = UnisocUSB.connect(dev)
        if dev is None:
            self.log_signal.emit("فشل الاتصال.")
            return
        self.log_signal.emit("جار قراءة معلومات الجهاز...")
        info = usb.get_device_info(dev)
        if not info:
            self.log_signal.emit("لم يتم استقبال أي معلومات.")
        else:
            self.log_signal.emit("=== معلومات الجهاز ===")
            for key, value in info.items():
                self.log_signal.emit(f"{key}: {value}")

    def _format_run(self):
        usb = UnisocUSB(use_hdlc=self.use_hdlc)
        protocol_name = "HDLC" if self.use_hdlc else "البسيط"
        self.log_signal.emit(f"استخدام بروتوكول {protocol_name} للتهيئة")
        
        dev = UnisocUSB.find_device()
        if dev is None:
            self.log_signal.emit("الجهاز غير موجود. تأكد أنه في وضع FDL.")
            return
        dev = UnisocUSB.connect(dev)
        if dev is None:
            self.log_signal.emit("فشل الاتصال.")
            return
        self.log_signal.emit("محاولة التهيئة...")
        if usb.smart_format(dev):
            self.log_signal.emit("تمت التهيئة بنجاح.")
        else:
            self.log_signal.emit("فشلت التهيئة.")
        
        self.log_signal.emit("الخروج من وضع FDL وإعادة التشغيل...")
        self.log_signal.emit("جار إرسال حزم إعادة التشغيل...")
        
        # استخدام الحزم الجديدة
        reboot_info = usb.exit_and_reboot(dev)
        
        # إرسال معلومات الحزم إلى الواجهة
        for packet in reboot_info:
            self.packet_signal.emit(packet)
            self.log_signal.emit(f"تم إرسال: {packet['name']} - Hex: {packet['hex']}")
        
        self.log_signal.emit("تم إرسال جميع حزم إعادة التشغيل.")
        self.log_signal.emit("يجب أن يعيد الجهاز التشغيل بشكل طبيعي.")

    def _show_reboot_packets(self):
        """عرض جميع حزم إعادة التشغيل"""
        all_packets = RebootPackets.get_all_packets()
        
        for category, packets in all_packets.items():
            self.log_signal.emit(f"\n=== {category} ===")
            for packet_id, packet_info in packets.items():
                self.log_signal.emit(f"اسم: {packet_info.get('description', packet_id)}")
                self.log_signal.emit(f"Hex: {packet_info['hex']}")
                self.log_signal.emit(f"الأمر: {packet_info['command']}")
                self.log_signal.emit(f"الاستخدام: {packet_info['usage']}")
                self.log_signal.emit("-" * 40)
        
        self.log_signal.emit(f"\nإجمالي عدد الحزم: {sum(len(packets) for packets in all_packets.values())}")

    def _send_reboot_packet(self, packet_name: str):
        """إرسال حزمة إعادة تشغيل محددة"""
        usb = UnisocUSB(use_hdlc=self.use_hdlc)
        
        dev = UnisocUSB.find_device()
        if dev is None:
            self.log_signal.emit("الجهاز غير موجود. تأكد أنه في وضع FDL/BROM.")
            return
        
        dev = UnisocUSB.connect(dev)
        if dev is None:
            self.log_signal.emit("فشل الاتصال.")
            return
        
        self.log_signal.emit(f"جار إرسال حزمة: {packet_name}")
        
        # البحث عن الحزمة
        packet_bytes = RebootPackets.get_packet_bytes(packet_name)
        if not packet_bytes:
            self.log_signal.emit(f"الحزمة '{packet_name}' غير موجودة.")
            return
        
        self.log_signal.emit(f"Hex: {packet_bytes.hex()}")
        
        # إرسال الحزمة
        if usb.send_custom_reboot(dev, packet_name):
            self.log_signal.emit(f"تم إرسال حزمة {packet_name} بنجاح.")
        else:
            self.log_signal.emit(f"فشل إرسال حزمة {packet_name}.")


# ----------------------------------------------------------------------
# Diagram Dialog (shown for 9 seconds)
# ----------------------------------------------------------------------
class DiagramDialog(QDialog):
    """Simple dialog that displays a flowchart and closes automatically."""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Specify Protection - Diagram")
        self.setFixedSize(400, 250)
        layout = QVBoxLayout(self)
        
        # إنشاء واجهة نصية بدلاً من SVG
        diagram_label = QLabel()
        diagram_label.setAlignment(Qt.AlignCenter)
        diagram_label.setText(
            "<div style='text-align: center; padding: 20px;'>"
            "<h3 style='color: #007acc;'>مخطط تفعيل خيارات المطور</h3>"
            "<div style='margin: 10px; padding: 10px; background: lightblue; border-radius: 5px;'>"
            "⚙️ الإعدادات (Settings)"
            "</div>"
            "<div style='margin: 5px;'>⬇</div>"
            "<div style='margin: 10px; padding: 10px; background: lightgreen; border-radius: 5px;'>"
            "📱 حول الهاتف (About Phone)"
            "</div>"
            "<div style='margin: 5px;'>⬇</div>"
            "<div style='margin: 10px; padding: 10px; background: lightyellow; border-radius: 5px;'>"
            "🔢 رقم البناء (Build Number)"
            "</div>"
            "<div style='margin: 5px;'>⬇</div>"
            "<div style='margin: 10px; padding: 10px; background: #ffcccb; border-radius: 5px;'>"
            "👆 اضغط 7 مرات متتالية"
            "</div>"
            "</div>"
        )
        diagram_label.setStyleSheet("font-size: 14px; font-family: Arial;")
        
        layout.addWidget(diagram_label)

        QTimer.singleShot(9000, self.accept)



# ----------------------------------------------------------------------
# Reboot Packets Dialog
# ----------------------------------------------------------------------
class RebootPacketsDialog(QDialog):
    """عرض حزم إعادة التشغيل في جدول"""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("حزم إعادة تشغيل USB - UNISOC/SPRD")
        self.setMinimumSize(800, 600)
        
        layout = QVBoxLayout(self)
        
        # عنوان
        title_label = QLabel("حزم USB Hex لإعادة تشغيل أجهزة UNISOC/SPRD")
        title_label.setStyleSheet("font-size: 18px; font-weight: bold; color: #007acc;")
        title_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(title_label)
        
        # جدول عرض الحزم
        self.table = QTableWidget()
        self.table.setColumnCount(5)
        self.table.setHorizontalHeaderLabels(["التصنيف", "الاسم", "Hex", "الأمر", "الوصف"])
        
        # ملء الجدول بالبيانات
        self.load_packets()
        
        # تعديل حجم الأعمدة
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.Stretch)
        header.setSectionResizeMode(3, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(4, QHeaderView.Stretch)
        
        layout.addWidget(self.table)
        
        # أزرار
        button_layout = QHBoxLayout()
        
        btn_send = QPushButton("إرسال الحزمة المحددة")
        btn_send.clicked.connect(self.send_selected_packet)
        button_layout.addWidget(btn_send)
        
        btn_close = QPushButton("إغلاق")
        btn_close.clicked.connect(self.accept)
        button_layout.addWidget(btn_close)
        
        layout.addLayout(button_layout)
    
    def load_packets(self):
        """تحميل الحزم في الجدول"""
        all_packets = RebootPackets.get_all_packets()
        row = 0
        
        for category, packets in all_packets.items():
            for packet_id, packet_info in packets.items():
                self.table.insertRow(row)
                
                # التصنيف
                self.table.setItem(row, 0, QTableWidgetItem(category))
                
                # الاسم
                self.table.setItem(row, 1, QTableWidgetItem(packet_info.get('description', packet_id)))
                
                # Hex
                hex_item = QTableWidgetItem(packet_info['hex'])
                hex_item.setForeground(QColor("#00ff00"))  # لون أخضر للـ Hex
                hex_item.setFont(QFont("Courier New", 10))
                self.table.setItem(row, 2, hex_item)
                
                # الأمر
                self.table.setItem(row, 3, QTableWidgetItem(str(packet_info['command'])))
                
                # الوصف
                self.table.setItem(row, 4, QTableWidgetItem(packet_info['usage']))
                
                row += 1
    
    def send_selected_packet(self):
        """إرسال الحزمة المحددة"""
        selected_row = self.table.currentRow()
        if selected_row >= 0:
            packet_name = self.table.item(selected_row, 1).text()
            hex_value = self.table.item(selected_row, 2).text()
            
            QMessageBox.information(self, "إرسال الحزمة", 
                                   f"جار إعداد إرسال الحزمة:\n{packet_name}\n\nHex: {hex_value}")
            
            # هنا يمكن إضافة منطق إرسال الحزمة الفعلي
            # سيتم تنفيذه من الواجهة الرئيسية


# ----------------------------------------------------------------------
# Main Window
# ----------------------------------------------------------------------
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("SPD Tool - مع حزم إعادة التشغيل - by yousef ekramy")
        self.setMinimumSize(1000, 700)
        self.current_worker = None
        self.use_hdlc = False

        self.setup_ui()
        self.setup_signals()
        self.setStyleSheet(self.get_stylesheet())
        self.refresh_devices()

    def setup_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        main_layout = QVBoxLayout(central)

        # إعدادات البروتوكول
        protocol_group = QGroupBox("إعدادات البروتوكول")
        protocol_layout = QVBoxLayout()
        self.hdlc_checkbox = QCheckBox("استخدام بروتوكول HDLC (متقدم)")
        protocol_layout.addWidget(self.hdlc_checkbox)
        
        protocol_info = QLabel("• البروتوكول البسيط: أسرع، يعمل مع معظم الأجهزة\n"
                              "• بروتوكول HDLC: أكثر موثوقية، يدعم CRC، يتوافق مع معايير UNISOC")
        protocol_info.setStyleSheet("color: #aaa; font-size: 10pt;")
        protocol_info.setWordWrap(True)
        protocol_layout.addWidget(protocol_info)
        protocol_group.setLayout(protocol_layout)
        main_layout.addWidget(protocol_group)

        # Tabs
        self.tabs = QTabWidget()
        main_layout.addWidget(self.tabs)

        # ----- Tab 1: Operations -----
        tab1 = QWidget()
        tab1_layout = QVBoxLayout(tab1)
        
        # قسم العمليات الأساسية
        basic_group = QGroupBox("العمليات الأساسية")
        basic_layout = QVBoxLayout()
        self.btn_death = QPushButton("Death of the Tab")
        self.btn_spec = QPushButton("Specify the type of protection")
        self.btn_fdl = QPushButton("Conversion to FDL mode")
        self.btn_info = QPushButton("Device information")
        self.btn_format = QPushButton("Format and run")
        
        basic_layout.addWidget(self.btn_death)
        basic_layout.addWidget(self.btn_spec)
        basic_layout.addWidget(self.btn_fdl)
        basic_layout.addWidget(self.btn_info)
        basic_layout.addWidget(self.btn_format)
        basic_group.setLayout(basic_layout)
        tab1_layout.addWidget(basic_group)
        
        # قسم حزم إعادة التشغيل
        reboot_group = QGroupBox("حزم إعادة التشغيل (Reboot Packets)")
        reboot_layout = QVBoxLayout()
        
        self.btn_show_packets = QPushButton("عرض جميع حزم إعادة التشغيل")
        self.btn_send_soft_reboot = QPushButton("إرسال Soft Reboot (0xB1)")
        self.btn_send_exit_fdl = QPushButton("إرسال Exit FDL (0xB2)")
        self.btn_send_power_off = QPushButton("إرسال Power Off (0xB3)")
        
        reboot_layout.addWidget(self.btn_show_packets)
        reboot_layout.addWidget(self.btn_send_soft_reboot)
        reboot_layout.addWidget(self.btn_send_exit_fdl)
        reboot_layout.addWidget(self.btn_send_power_off)
        
        reboot_info = QLabel("هذه الحزم تستخدم لإعادة تشغيل الجهاز أو إيقافه. \n"
                            "0xB1: إعادة تشغيل ناعمة\n"
                            "0xB2: الخروج من وضع FDL\n"
                            "0xB3: إيقاف الطاقة بالكامل")
        reboot_info.setStyleSheet("color: #aaa; font-size: 9pt; padding: 5px;")
        reboot_info.setWordWrap(True)
        reboot_layout.addWidget(reboot_info)
        
        reboot_group.setLayout(reboot_layout)
        tab1_layout.addWidget(reboot_group)
        
        tab1_layout.addStretch()

        # ----- Tab 2: About -----
        tab2 = QWidget()
        tab2_layout = QVBoxLayout(tab2)
        label_about = QLabel("المطور: yousef ekramy\n\n"
                            "الإصدار: 2.1 مع حزم إعادة التشغيل\n\n"
                            "مميزات الإصدار:\n"
                            "1. دعم بروتوكول HDLC\n"
                            "2. حزم USB Hex لإعادة التشغيل\n"
                            "3. واجهة محسنة\n\n"
                            "حزم إعادة التشغيل المضمنة:\n"
                            "- Soft Reboot (0xB1): 42 31 00 00\n"
                            "- Exit FDL (0xB2): 42 32 00 00\n"
                            "- Power Off (0xB3): 42 33 00 00\n"
                            "- وأكثر...")
        label_about.setAlignment(Qt.AlignCenter)
        label_about.setStyleSheet("font-size: 14px;")
        label_about.setWordWrap(True)
        tab2_layout.addStretch()
        tab2_layout.addWidget(label_about)
        self.btn_youtube = QPushButton("قناة اليوتيوب")
        tab2_layout.addWidget(self.btn_youtube)
        tab2_layout.addStretch()

        self.tabs.addTab(tab1, "العمليات")
        self.tabs.addTab(tab2, "حول")

        # Device list and log area
        splitter = QSplitter(Qt.Horizontal)
        
        # Left panel: connected devices
        left_widget = QWidget()
        left_layout = QVBoxLayout(left_widget)
        left_layout.addWidget(QLabel("الأجهزة المتصلة"))
        self.device_list = QListWidget()
        left_layout.addWidget(self.device_list)
        self.btn_refresh = QPushButton("تحديث")
        left_layout.addWidget(self.btn_refresh)
        
        # إضافة قسم حزم USB المرسلة
        sent_packets_label = QLabel("الحزم المرسلة حديثاً:")
        sent_packets_label.setStyleSheet("margin-top: 20px; font-weight: bold;")
        left_layout.addWidget(sent_packets_label)
        
        self.sent_packets_list = QListWidget()
        self.sent_packets_list.setMaximumHeight(150)
        left_layout.addWidget(self.sent_packets_list)
        
        splitter.addWidget(left_widget)
        
        # Right panel: log
        right_widget = QWidget()
        right_layout = QVBoxLayout(right_widget)
        right_layout.addWidget(QLabel("سجل العمليات"))
        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        self.log_text.setFontFamily("Courier New")
        self.log_text.setFontPointSize(10)
        right_layout.addWidget(self.log_text, 2)
        splitter.addWidget(right_widget)
        
        splitter.setSizes([300, 700])
        main_layout.addWidget(splitter, 1)

        # Status bar
        self.statusBar = self.statusBar()
        self.statusBar.showMessage("جاهز")

    def setup_signals(self):
        self.btn_death.clicked.connect(self.on_death)
        self.btn_spec.clicked.connect(self.on_spec)
        self.btn_fdl.clicked.connect(self.on_fdl)
        self.btn_info.clicked.connect(self.on_info)
        self.btn_format.clicked.connect(self.on_format)
        self.btn_refresh.clicked.connect(self.refresh_devices)
        self.btn_youtube.clicked.connect(self.open_youtube)
        self.hdlc_checkbox.stateChanged.connect(self.on_hdlc_changed)
        
        # إشارات جديدة لحزم إعادة التشغيل
        self.btn_show_packets.clicked.connect(self.show_reboot_packets)
        self.btn_send_soft_reboot.clicked.connect(lambda: self.send_reboot_packet("soft_reboot"))
        self.btn_send_exit_fdl.clicked.connect(lambda: self.send_reboot_packet("exit_fdl"))
        self.btn_send_power_off.clicked.connect(lambda: self.send_reboot_packet("power_off"))

    def on_hdlc_changed(self, state):
        self.use_hdlc = (state == Qt.Checked)
        protocol = "HDLC" if self.use_hdlc else "البسيط"
        self.log(f"تم تغيير البروتوكول إلى: {protocol}")

    def get_stylesheet(self):
        return """
        QMainWindow {
            background-color: #2b2b2b;
            color: #ffffff;
        }
        QGroupBox {
            border: 2px solid #007acc;
            border-radius: 5px;
            margin-top: 10px;
            font-weight: bold;
        }
        QGroupBox::title {
            subcontrol-origin: margin;
            left: 10px;
            padding: 0 5px 0 5px;
            color: #007acc;
        }
        QTabWidget::pane {
            border: 1px solid #444;
            background: #2b2b2b;
        }
        QTabBar::tab {
            background: #444;
            color: #fff;
            padding: 8px;
            border: 1px solid #555;
        }
        QTabBar::tab:selected {
            background: #007acc;
        }
        QPushButton {
            background-color: #007acc;
            color: white;
            border: none;
            padding: 8px 16px;
            border-radius: 4px;
            margin: 2px;
        }
        QPushButton:hover {
            background-color: #0099ff;
        }
        QPushButton:disabled {
            background-color: #555;
        }
        QTextEdit {
            background-color: #1e1e1e;
            color: #dcdcdc;
            font-family: Consolas, monospace;
        }
        QListWidget {
            background-color: #1e1e1e;
            color: #dcdcdc;
        }
        QLabel {
            color: #ffffff;
        }
        QCheckBox {
            color: #ffffff;
            padding: 5px;
        }
        QCheckBox::indicator {
            width: 18px;
            height: 18px;
        }
        QSplitter::handle {
            background-color: #444;
        }
        """

    @Slot(str)
    def log(self, message):
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log_text.append(f"[{timestamp}] {message}")
        self.log_text.verticalScrollBar().setValue(
            self.log_text.verticalScrollBar().maximum()
        )
    
    @Slot(dict)
    def add_sent_packet(self, packet_info):
        """إضافة حزمة مرسلة إلى القائمة"""
        display_text = f"{packet_info['name']}: {packet_info['hex']}"
        self.sent_packets_list.addItem(display_text)
        
        # تحديد العنصر الأخير
        self.sent_packets_list.setCurrentRow(self.sent_packets_list.count() - 1)
        
        # حفظ آخر 10 حزم فقط
        if self.sent_packets_list.count() > 10:
            self.sent_packets_list.takeItem(0)

    def refresh_devices(self):
        self.device_list.clear()
        devs = usb.core.find(find_all=True, idVendor=VID, idProduct=PID)
        count = 0
        for dev in devs:
            count += 1
            self.device_list.addItem(
                f"الجهاز {count} (Bus {dev.bus}, Address {dev.address})"
            )
        if count == 0:
            self.device_list.addItem("لم يتم العثور على أجهزة SPD (VID 0x1782, PID 0x4D00)")
        else:
            self.log(f"تم العثور على {count} جهاز(أجهزة)")

    def open_youtube(self):
        import webbrowser
        webbrowser.open("https://www.youtube.com")

    def disable_buttons(self, state=True):
        self.btn_death.setDisabled(state)
        self.btn_spec.setDisabled(state)
        self.btn_fdl.setDisabled(state)
        self.btn_info.setDisabled(state)
        self.btn_format.setDisabled(state)
        self.btn_refresh.setDisabled(state)
        self.hdlc_checkbox.setDisabled(state)
        self.btn_show_packets.setDisabled(state)
        self.btn_send_soft_reboot.setDisabled(state)
        self.btn_send_exit_fdl.setDisabled(state)
        self.btn_send_power_off.setDisabled(state)

    def enable_buttons(self):
        self.disable_buttons(False)

    def start_worker(self, task, *args):
        if self.current_worker is not None:
            self.log("هناك عملية أخرى قيد التشغيل بالفعل.")
            return
        
        self.disable_buttons()
        protocol_name = "HDLC" if self.use_hdlc else "البسيط"
        self.log(f"بدء العملية: {task} باستخدام بروتوكول {protocol_name}")
        
        self.thread = QThread()
        self.worker = Worker(task, self.use_hdlc, *args)
        self.worker.moveToThread(self.thread)
        self.worker.log_signal.connect(self.log)
        self.worker.packet_signal.connect(self.add_sent_packet)  # ربط إشارة الحزم
        self.worker.finished.connect(self.thread.quit)
        self.worker.finished.connect(self.worker.deleteLater)
        self.thread.finished.connect(self.thread.deleteLater)
        self.thread.finished.connect(self.on_worker_finished)
        self.thread.started.connect(self.worker.run)
        self.thread.start()
        self.current_worker = self.worker

    def on_worker_finished(self):
        self.enable_buttons()
        self.current_worker = None
        self.statusBar.showMessage("اكتملت العملية.")

    def on_death(self):
        msg = QMessageBox(self)
        msg.setIcon(QMessageBox.Warning)
        msg.setWindowTitle("تحذير")
        msg.setText("هذه العملية ستوقف تشغيل الجهاز. لا تفصل الجهاز حتى يتم إعلامك.")
        msg.setStandardButtons(QMessageBox.Ok)
        msg.show()
        QTimer.singleShot(5000, msg.close)
        QTimer.singleShot(5000, self._after_death_warning)

    def _after_death_warning(self):
        self.log("تم عرض التحذير. الرجاء اتباع التعليمات.")
        instr = QMessageBox(self)
        instr.setIcon(QMessageBox.Information)
        instr.setWindowTitle("تعليمات")
        instr.setText("الرجاء فصل الجهاز ثم إعادة وصله.")
        instr.setStandardButtons(QMessageBox.Ok)
        instr.show()
        QTimer.singleShot(3000, instr.close)
        QTimer.singleShot(3000, lambda: self.start_worker("death_of_tab"))

    def on_spec(self):
        dlg = DiagramDialog(self)
        dlg.setWindowTitle("Specify Protection")
        dlg.exec()
        self.start_worker("specify_protection")

    def on_fdl(self):
        self.start_worker("conversion_to_fdl")

    def on_info(self):
        self.start_worker("device_info")

    def on_format(self):
        self.start_worker("format_run")
    
    def show_reboot_packets(self):
        """عرض حزم إعادة التشغيل في نافذة منفصلة"""
        dlg = RebootPacketsDialog(self)
        dlg.exec()
    
    def send_reboot_packet(self, packet_name: str):
        """إرسال حزمة إعادة تشغيل محددة"""
        # الحصول على معلومات الحزمة
        packet_bytes = RebootPackets.get_packet_bytes(packet_name)
        packet_info = None
        
        # البحث عن معلومات الحزمة
        all_packets = RebootPackets.get_all_packets()
        for category, packets in all_packets.items():
            for pid, info in packets.items():
                if info.get('hex', '').replace(' ', '') == packet_bytes.hex():
                    packet_info = {
                        'name': info['description'],
                        'hex': packet_bytes.hex(),
                        'command': info['command'],
                        'description': info['usage']
                    }
                    break
        
        if packet_info:
            # إضافة الحزمة إلى القائمة
            self.add_sent_packet(packet_info)
            
            # بدء العملية
            self.start_worker("send_reboot_packet", packet_name)
        else:
            self.log(f"الحزمة {packet_name} غير معروفة")


# ----------------------------------------------------------------------
# Main Entry Point
# ----------------------------------------------------------------------
if __name__ == "__main__":
    app = QApplication(sys.argv)
    
    # Set application style
    app.setStyle("Fusion")
    
    # Check for required files
    if not os.path.exists(FDL1_PATH):
        print(f"تحذير: ملف FDL1 غير موجود في {FDL1_PATH}")
        print("الرجاء وضع ملف FDL1.bin في مجلد 'volcano'")
    
    if not os.path.exists(FDL2_PATH):
        print(f"تحذير: ملف FDL2 غير موجود في {FDL2_PATH}")
        print("الرجاء وضع ملف FDL2.bin في مجلد 'volcano'")
    
    window = MainWindow()
    window.show()
    sys.exit(app.exec())
