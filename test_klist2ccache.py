import io
import unittest
from unittest import mock

import klist2ccache


KLIST_SESSIONS = r"""
Current LogonId is 0:0x3e7
[0] Session 0 0:0x39261aa6 SEVERKINGS\Administrator NTLM:Network
[1] Session 0 0:0x39261a74 SEVERKINGS\Administrator NTLM:Network
[2] Session 1 0:0x2d4be5cf Window Manager\DWM-1 Negotiate:Interactive
[3] Session 2 0:0x670f8ba SEVERKINGS\administrator Kerberos:RemoteInteractive
[4] Session 0 0:0x3e4 SEVERKINGS\BASTION$ Negotiate:Service
[5] Session 0 0:0x3e5 NT AUTHORITY\LOCAL SERVICE Negotiate:Service
[6] Session 0 0:0xe072 \ NTLM:(0)
[7] Session 0 0:0x3e7 SEVERKINGS\BASTION$ Negotiate:(0)
"""

TGT = """
ClientName       : BASTION$
DomainName       : SEVERKINGS.LOCAL
ServiceName      : krbtgt
TargetDomainName : SEVERKINGS.LOCAL
Ticket Flags     : 0x40e10000
KeyType          0x12
0000  61 82 01 00 30 82 00 fc
"""

SINGLE_SESSION = r"""
[0] Session 2 0:0x670f8ba SEVERKINGS\administrator Kerberos:RemoteInteractive
"""


class KlistSessionTests(unittest.TestCase):
    def test_parses_candidates_from_every_authentication_package(self):
        sessions = klist2ccache.parse_klist_sessions(KLIST_SESSIONS)

        self.assertIn(("0x670f8ba", r"SEVERKINGS\administrator"), sessions)
        self.assertIn(("0x3e4", r"SEVERKINGS\BASTION$"), sessions)
        self.assertIn(("0x3e7", r"SEVERKINGS\BASTION$"), sessions)
        self.assertIn(("0x39261aa6", r"SEVERKINGS\Administrator"), sessions)

    def test_users_only_excludes_machine_accounts(self):
        sessions = klist2ccache.parse_klist_sessions(
            KLIST_SESSIONS,
            include_computer=False,
        )

        self.assertFalse(any(account.endswith("$") for _, account in sessions))

    def test_combined_output_keeps_empty_results_aligned(self):
        combined = "first\n%s\n\n%s\nthird" % (
            klist2ccache.OUTPUT_SEP,
            klist2ccache.OUTPUT_SEP,
        )

        self.assertEqual(
            ["first", "", "third"],
            klist2ccache._split_tgt_output(combined, 3),
        )

    def test_only_sessions_with_ticket_data_survive_probe(self):
        sessions = [
            ("0x1", r"SEVERKINGS\administrator"),
            ("0x2", r"SEVERKINGS\BASTION$"),
            ("0x3", r"NT AUTHORITY\LOCAL SERVICE"),
        ]
        outputs = [TGT.replace("BASTION$", "administrator"), TGT, "Cached Tickets: (0)"]

        found = klist2ccache._sessions_with_tgts(sessions, outputs)

        self.assertEqual(["0x1", "0x2"], [entry[0] for entry in found])
        self.assertEqual(
            ["0x1"],
            [
                entry[0]
                for entry in klist2ccache._sessions_with_tgts(
                    sessions,
                    outputs,
                    include_computer=False,
                )
            ],
        )

    def test_remote_method_defaults_to_smb(self):
        args = klist2ccache.build_parser().parse_args(
            ["list", "DOMAIN/user:pass@host"]
        )

        self.assertEqual("smb", args.method)

    def test_remote_method_accepts_winrm(self):
        args = klist2ccache.build_parser().parse_args(
            ["list", "DOMAIN/user:pass@host", "-M", "winrm"]
        )

        self.assertEqual("winrm", args.method)

    def test_remote_method_is_also_accepted_before_subcommand(self):
        args = klist2ccache.build_parser().parse_args(
            ["-M", "winrm", "list", "DOMAIN/user:pass@host"]
        )

        self.assertEqual("winrm", args.method)

    def test_legacy_converter_options_select_convert_command(self):
        with mock.patch.object(klist2ccache, "cmd_convert", return_value=0) as convert:
            result = klist2ccache.main(["-i", "ticket.txt"])

        self.assertEqual(0, result)
        self.assertEqual("ticket.txt", convert.call_args.args[0].input)

    def test_named_pipes_are_rejected_for_winrm(self):
        with mock.patch("sys.stderr", new=io.StringIO()):
            with self.assertRaises(SystemExit) as raised:
                klist2ccache.main(
                    [
                        "list",
                        "DOMAIN/user:pass@host",
                        "-M",
                        "winrm",
                        "-named-pipes",
                    ]
                )

        self.assertEqual(2, raised.exception.code)

    def test_smb_transport_collects_and_filters_tgts(self):
        args = klist2ccache.build_parser().parse_args(
            ["list", "SEVERKINGS/administrator:pass@bastion"]
        )
        dce = mock.Mock()
        smb = mock.Mock()
        credentials = (
            "SEVERKINGS",
            "administrator",
            "pass",
            "bastion",
            "",
            "",
        )

        with mock.patch.object(
            klist2ccache,
            "_resolve_creds",
            return_value=credentials,
        ), mock.patch.object(
            klist2ccache,
            "_connect_smb",
            return_value=(dce, smb),
        ), mock.patch.object(
            klist2ccache,
            "run_remote_cmd_and_read_output",
            return_value=SINGLE_SESSION,
        ), mock.patch.object(
            klist2ccache,
            "_get_tgts_via_file",
            return_value=[TGT.replace("BASTION$", "administrator")],
        ):
            address, sessions = klist2ccache._collect_remote_tgts(args)

        self.assertEqual("bastion", address)
        self.assertEqual(["0x670f8ba"], [entry[0] for entry in sessions])
        dce.disconnect.assert_called_once_with()

    def test_winrm_transport_collects_and_filters_tgts(self):
        args = klist2ccache.build_parser().parse_args(
            ["list", "SEVERKINGS/administrator:pass@bastion", "-M", "winrm"]
        )
        credentials = (
            "SEVERKINGS",
            "administrator",
            "pass",
            "bastion",
            "",
            "",
        )

        with mock.patch.object(
            klist2ccache,
            "_resolve_creds",
            return_value=credentials,
        ), mock.patch.object(
            klist2ccache,
            "_connect_winrm",
            return_value=mock.Mock(),
        ), mock.patch.object(
            klist2ccache,
            "_run_winrm_cmd",
            side_effect=[
                SINGLE_SESSION,
                TGT.replace("BASTION$", "administrator"),
            ],
        ):
            address, sessions = klist2ccache._collect_remote_tgts(args)

        self.assertEqual("bastion", address)
        self.assertEqual(["0x670f8ba"], [entry[0] for entry in sessions])


if __name__ == "__main__":
    unittest.main()
