import argparse
import ctypes
import select
import socket
import struct
import sys
import time


def _error_result(message):
    return [{"hop": 1, "ip": f"Error: {message}", "time": "-"}]


def _run_windows_traceroute(destination_ip, max_hops, timeout):
    class IpOptionInformation(ctypes.Structure):
        _fields_ = [
            ("ttl", ctypes.c_ubyte),
            ("tos", ctypes.c_ubyte),
            ("flags", ctypes.c_ubyte),
            ("options_size", ctypes.c_ubyte),
            ("options_data", ctypes.POINTER(ctypes.c_ubyte)),
        ]

    class IcmpEchoReply(ctypes.Structure):
        _fields_ = [
            ("address", ctypes.c_uint32),
            ("status", ctypes.c_uint32),
            ("round_trip_time", ctypes.c_uint32),
            ("data", ctypes.c_void_p),
            ("data_size", ctypes.c_ushort),
            ("reserved", ctypes.c_ushort),
            ("options", IpOptionInformation),
        ]

    try:
        iphlpapi = ctypes.WinDLL("iphlpapi", use_last_error=True)
        iphlpapi.IcmpCreateFile.restype = ctypes.c_void_p
        iphlpapi.IcmpCloseHandle.argtypes = [ctypes.c_void_p]
        iphlpapi.IcmpSendEcho.argtypes = [
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.c_void_p,
            ctypes.c_ushort,
            ctypes.POINTER(IpOptionInformation),
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.c_uint32,
        ]
        iphlpapi.IcmpSendEcho.restype = ctypes.c_uint32
        handle = iphlpapi.IcmpCreateFile()
    except (AttributeError, OSError) as exc:
        return _error_result(f"Cannot initialize Windows ICMP support ({exc}).")

    if handle == ctypes.c_void_p(-1).value:
        return _error_result(
            f"Cannot open a Windows ICMP handle ({ctypes.WinError(ctypes.get_last_error())})."
        )

    destination_address = int.from_bytes(socket.inet_aton(destination_ip), sys.byteorder)
    timeout_ms = max(1, int(timeout * 1000))
    hops = []
    try:
        for ttl in range(1, max_hops + 1):
            options = IpOptionInformation(ttl=ttl)
            reply = IcmpEchoReply()
            started_at = time.perf_counter()
            reply_count = iphlpapi.IcmpSendEcho(
                handle,
                destination_address,
                None,
                0,
                ctypes.byref(options),
                ctypes.byref(reply),
                ctypes.sizeof(reply),
                timeout_ms,
            )

            if not reply_count and reply.status == 11010:
                hops.append({"hop": ttl, "ip": "* (Request timed out)", "time": "-"})
                continue
            if not reply_count:
                return _error_result(f"Windows ICMP request failed (status {reply.status}).")

            current_ip = socket.inet_ntoa(struct.pack("=I", reply.address))
            hops.append({
                "hop": ttl,
                "ip": current_ip,
                "time": f"{reply.round_trip_time}ms",
            })
            if reply.status == 0 or current_ip == destination_ip:
                break
            if reply.status != 11013:
                break
    finally:
        iphlpapi.IcmpCloseHandle(handle)

    return hops


def _parse_icmp_response(packet):
    outer_ip_offset = 0
    if len(packet) >= 20 and packet[0] >> 4 == 4:
        outer_header_length = (packet[0] & 0x0F) * 4
        if outer_header_length < 20 or len(packet) < outer_header_length + 2:
            return None
        outer_ip_offset = outer_header_length

    if len(packet) < outer_ip_offset + 2:
        return None

    icmp_type, icmp_code = packet[outer_ip_offset:outer_ip_offset + 2]
    original_destination = None
    original_port = None

    if icmp_type in (3, 11):
        original_ip_offset = outer_ip_offset + 8
        if len(packet) >= original_ip_offset + 20 and packet[original_ip_offset] >> 4 == 4:
            original_header_length = (packet[original_ip_offset] & 0x0F) * 4
            udp_offset = original_ip_offset + original_header_length
            if original_header_length >= 20 and len(packet) >= udp_offset + 4:
                original_destination = socket.inet_ntoa(
                    packet[original_ip_offset + 16:original_ip_offset + 20]
                )
                original_port = int.from_bytes(packet[udp_offset + 2:udp_offset + 4], "big")

    return icmp_type, icmp_code, original_destination, original_port


def run_manual_traceroute(destination_name, max_hops=20, timeout=2.0):
    destination_name = destination_name.strip()
    if not destination_name:
        return _error_result("Enter a host name or IP address.")
    if not 1 <= max_hops <= 64:
        return _error_result("Maximum hops must be between 1 and 64.")
    if timeout <= 0:
        return _error_result("Timeout must be greater than zero.")

    try:
        destination_ip = socket.gethostbyname(destination_name)
    except socket.gaierror:
        return _error_result("Invalid or unreachable host name.")

    if sys.platform == "win32":
        return _run_windows_traceroute(destination_ip, max_hops, timeout)

    try:
        recv_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    except OSError as exc:
        return _error_result(
            f"Cannot open a raw ICMP socket ({exc}). On Windows, run the terminal as Administrator."
        )

    try:
        send_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    except OSError as exc:
        recv_socket.close()
        return _error_result(f"Cannot open the UDP socket ({exc}).")

    hops = []
    try:
        for ttl in range(1, max_hops + 1):
            destination_port = 33434 + ttl
            try:
                send_socket.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
                started_at = time.perf_counter()
                send_socket.sendto(b"RouteTrace", (destination_ip, destination_port))
                deadline = started_at + timeout

                while True:
                    remaining = deadline - time.perf_counter()
                    if remaining <= 0:
                        hops.append({"hop": ttl, "ip": "* (Request timed out)", "time": "-"})
                        break

                    readable, _, _ = select.select([recv_socket], [], [], remaining)
                    if not readable:
                        hops.append({"hop": ttl, "ip": "* (Request timed out)", "time": "-"})
                        break

                    packet, current_address = recv_socket.recvfrom(512)
                    response = _parse_icmp_response(packet)
                    if response is None:
                        continue

                    icmp_type, _, original_destination, original_port = response
                    if icmp_type not in (3, 11):
                        continue
                    if original_destination is not None and (
                        original_destination != destination_ip or original_port != destination_port
                    ):
                        continue

                    elapsed_ms = (time.perf_counter() - started_at) * 1000
                    current_ip = current_address[0]
                    hops.append({"hop": ttl, "ip": current_ip, "time": f"{elapsed_ms:.2f}ms"})
                    if current_ip == destination_ip or icmp_type == 3:
                        return hops
                    break
            except OSError as exc:
                hops.append({"hop": ttl, "ip": f"Error: {exc}", "time": "-"})
                break
    finally:
        send_socket.close()
        recv_socket.close()

    return hops


def main():
    parser = argparse.ArgumentParser(
        description="Trace an IPv4 route using Python UDP and ICMP sockets."
    )
    parser.add_argument("host", help="host name or IPv4 address to trace")
    parser.add_argument("--max-hops", type=int, default=20, help="maximum hops (1-64, default: 20)")
    parser.add_argument("--timeout", type=float, default=2.0, help="seconds to wait per hop (default: 2)")
    args = parser.parse_args()

    print(f"Tracing route to {args.host} (maximum {args.max_hops} hops):")
    results = run_manual_traceroute(args.host, args.max_hops, args.timeout)
    for hop in results:
        print(f"{hop['hop']:>2}  {hop['ip']:<45} {hop['time']}")

    if results[0]["ip"].startswith("Error:"):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
