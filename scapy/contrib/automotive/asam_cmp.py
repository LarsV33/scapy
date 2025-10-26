# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Dr. Lars Völker

# scapy.contrib.description = Capture Module Protocol (CMP)
# scapy.contrib.status = loads

import struct

from scapy.layers.l2 import Ether
from scapy.layers.inet import UDP

from scapy.packet import (Packet, Raw, bind_top_down, bind_bottom_up,
                          bind_layers)
from scapy.fields import (ByteField, XByteField, ByteEnumField, XByteEnumField,
                          ShortField, XShortField,
                          IntField, XIntField,
                          LongField, XLongField,
                          FlagsField,

                          ConditionalField,
                          BitField, XBitField,
                          X3BytesField, StrLenField, IPField,
                          FieldLenField, PacketListField, XIntField,
                          MultipleTypeField,
                          BitScalingField, LenField)


class CMP(Packet):
    """ CMP Packet """

    PROTOCOL_VERSION = 0x01

    MSG_TYPE_CAP_DATA_MSG = 0x01
    MSG_TYPE_CTRL_MSG = 0x02
    MSG_TYPE_STATUS_MSG = 0x03
    MSG_TYPE_TX_DATA_MSG = 0x04
    MSG_TYPE_VENDOR_MSG = 0xFF

    name = "CMP"

    fields_desc = [
        ByteField("CmpVersion", PROTOCOL_VERSION),
        XByteField("Reserved", 0),
        XShortField("DeviceId", 0),
        XByteEnumField("MessageType", 1, {
            MSG_TYPE_CAP_DATA_MSG: "CAP_DATA_MSG",
            MSG_TYPE_CTRL_MSG: "CTRL_MSG",
            MSG_TYPE_STATUS_MSG: "STATUS_MSG",
            MSG_TYPE_TX_DATA_MSG: "TX_DATA_MSG",
            MSG_TYPE_VENDOR_MSG: "VENDOR_MSG",
        }),
        XByteField("StreamId", 0),
        ShortField("StreamSequenceCounter", 0)
    ]

class CMP_DATA_MESSAGE(Packet):
    """ CMP Data Message """

    PAYLOAD_TYPE_INVALID = 0x00
    PAYLOAD_TYPE_CAN = 0x01
    PAYLOAD_TYPE_CAN_FD = 0x02
    PAYLOAD_TYPE_LIN = 0x03
    PAYLOAD_TYPE_FLEXRAY = 0x04
    PAYLOAD_TYPE_DIGITAL = 0x05
    PAYLOAD_TYPE_UART_RS232 = 0x06
    PAYLOAD_TYPE_ANALOG = 0x07
    PAYLOAD_TYPE_ETHERNET = 0x08
    PAYLOAD_TYPE_SPI = 0x09
    PAYLOAD_TYPE_I2C = 0x0A
    PAYLOAD_TYPE_GIGE_VISION = 0x0B
    PAYLOAD_TYPE_MIPI_CSI2_DPHY = 0x0C
    PAYLOAD_TYPE_RAW_ETHERNET = 0x0D
    PAYLOAD_TYPE_10BASET1S_SYMBOL = 0x0E
    PAYLOAD_TYPE_A2B = 0x0F
    PAYLOAD_TYPE_LINK_STATE = 0xFE
    PAYLOAD_TYPE_RESERVED = 0xFF

    name = "CMP Data Message"

    fields_desc = [
        LongField("Timestamp", 0),
        XIntField("InterfaceId", 0),
        FlagsField("CommonFlags", 0, 8, [
            "RECALC", "INSYNC", "SEG0", "SEG1",
            "DIR_ON_IF", "OVERFLOW", "ERROR_IN_PAYLOAD", "RESERVED"
        ]),
        XByteEnumField("PayloadType", 0, {
            PAYLOAD_TYPE_INVALID: "PAYLOAD_TYPE_INVALID",
            PAYLOAD_TYPE_CAN: "PAYLOAD_TYPE_CAN",
            PAYLOAD_TYPE_CAN_FD: "PAYLOAD_TYPE_CAN_FD",
            PAYLOAD_TYPE_LIN: "PAYLOAD_TYPE_LIN",
            PAYLOAD_TYPE_FLEXRAY: "PAYLOAD_TYPE_FLEXRAY",
            PAYLOAD_TYPE_DIGITAL: "PAYLOAD_TYPE_DIGITAL",
            PAYLOAD_TYPE_UART_RS232: "PAYLOAD_TYPE_UART_RS232",
            PAYLOAD_TYPE_ANALOG: "PAYLOAD_TYPE_ANALOG",
            PAYLOAD_TYPE_ETHERNET: "PAYLOAD_TYPE_ETHERNET",
            PAYLOAD_TYPE_SPI: "PAYLOAD_TYPE_SPI",
            PAYLOAD_TYPE_I2C: "PAYLOAD_TYPE_I2C",
            PAYLOAD_TYPE_GIGE_VISION: "PAYLOAD_TYPE_GIGE_VISION",
            PAYLOAD_TYPE_MIPI_CSI2_DPHY: "PAYLOAD_TYPE_MIPI_CSI2_DPHY",
            PAYLOAD_TYPE_RAW_ETHERNET: "PAYLOAD_TYPE_RAW_ETHERNET",
            PAYLOAD_TYPE_10BASET1S_SYMBOL: "PAYLOAD_TYPE_10BASET1S_SYMBOL",
            PAYLOAD_TYPE_A2B: "PAYLOAD_TYPE_A2B",
            PAYLOAD_TYPE_LINK_STATE: "PAYLOAD_TYPE_LINK_STATE",
            PAYLOAD_TYPE_RESERVED: "PAYLOAD_TYPE_RESERVED",
        }),
        ShortField("PayloadLength", 0),
    ]


def _bind_cmp_layers():
    bind_layers(Ether, CMP, type=0x99FE)

_bind_cmp_layers()
bind_layers(CMP, CMP)
