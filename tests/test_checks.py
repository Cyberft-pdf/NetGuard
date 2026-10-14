import ipaddress
import unittest

from netguard.checks import BAD, GOOD, INFO, WARN, Result, decode_av_state, overall_status, parse_arp, parse_wifi

NETSH_WPA2 = """
There is 1 interface on the system:

    Name                   : Wi-Fi
    State                  : connected
    SSID                   : Home Net
    BSSID                  : aa:bb:cc:dd:ee:ff
    Authentication         : WPA2-Personal
    Cipher                 : CCMP
"""

# Czech Windows translates the labels but not the values.
NETSH_CZ_OPEN = """
    Název                  : Wi-Fi
    Stav                   : připojeno
    SSID                   : Kavarna
    BSSID                  : aa:bb:cc:dd:ee:ff
    Ověřování              : Otevřené
    Šifra                  : Žádné
"""


class ParseWifiTest(unittest.TestCase):
    def test_wpa2(self):
        self.assertEqual(parse_wifi(NETSH_WPA2), ("Home Net", "wpa2"))

    def test_wpa3_and_wep(self):
        self.assertEqual(parse_wifi(NETSH_WPA2.replace("WPA2-Personal", "WPA3-Personal"))[1], "wpa3")
        self.assertEqual(parse_wifi(NETSH_WPA2.replace("WPA2-Personal", "WEP"))[1], "wep")

    def test_open_network_in_other_language(self):
        self.assertEqual(parse_wifi(NETSH_CZ_OPEN), ("Kavarna", "open"))

    def test_not_connected(self):
        self.assertEqual(parse_wifi("    State : disconnected\n"), (None, None))


class ParseArpTest(unittest.TestCase):
    net = ipaddress.ip_network("192.168.1.0/24")

    def test_windows(self):
        out = """
Interface: 192.168.1.10 --- 0x7
  Internet Address      Physical Address      Type
  192.168.1.1           a4-2b-b0-01-02-03     dynamic
  192.168.1.255         ff-ff-ff-ff-ff-ff     static
  224.0.0.22            01-00-5e-00-00-16     static
  10.0.0.5              a4-2b-b0-01-02-04     dynamic
"""
        self.assertEqual(parse_arp(out, self.net), {"A4:2B:B0:01:02:03": "192.168.1.1"})

    def test_macos_unpadded(self):
        out = "? (192.168.1.20) at 0:1b:63:a:b:c on en0 ifscope [ethernet]\n"
        self.assertEqual(parse_arp(out, self.net), {"00:1B:63:0A:0B:0C": "192.168.1.20"})


class HelpersTest(unittest.TestCase):
    def test_defender_on_and_up_to_date(self):
        self.assertEqual(decode_av_state(397568), (True, True))  # 0x061100

    def test_av_off_and_out_of_date(self):
        self.assertEqual(decode_av_state(393488), (False, False))  # 0x060110

    def test_overall_takes_worst(self):
        self.assertEqual(overall_status([Result(GOOD, ""), Result(INFO, "")]), GOOD)
        self.assertEqual(overall_status([Result(GOOD, ""), Result(WARN, "")]), WARN)
        self.assertEqual(overall_status([Result(WARN, ""), Result(BAD, "")]), BAD)


if __name__ == "__main__":
    unittest.main()
