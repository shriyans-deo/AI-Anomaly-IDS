from datetime import datetime
from ipaddress import IPv4Address, IPv6Address
from typing import Union

from pydantic import BaseModel, Field


class TrafficFlow(BaseModel):
    timestamp: datetime = Field(
        ...,
        description="Timestamp of the network flow event.",
    )
    src_ip: Union[IPv4Address, IPv6Address] = Field(
        ...,
        description="Source IP address of the traffic flow (IPv4 or IPv6).",
    )
    num_connections: int = Field(
        ...,
        ge=0,
        description="Number of connections observed in the flow.",
    )
    unique_dst_ports: int = Field(
        ...,
        ge=0,
        le=65535,
        description="Number of unique destination ports contacted.",
    )
    bytes_sent: float = Field(
        ...,
        ge=0,
        description="Total bytes sent during the flow.",
    )
    bytes_recv: float = Field(
        ...,
        ge=0,
        description="Total bytes received during the flow.",
    )
    failed_logins: int = Field(
        ...,
        ge=0,
        description="Number of failed login attempts observed.",
    )
    syn_ratio: float = Field(
        ...,
        ge=0,
        le=1,
        description="Ratio of SYN packets to total packets (0-1).",
    )
    avg_conn_duration: float = Field(
        ...,
        ge=0,
        description="Average connection duration in seconds.",
    )
    label: str = Field(
        ...,
        pattern="^(normal|attack)$",
        description="Traffic label, either 'normal' or 'attack'.",
    )