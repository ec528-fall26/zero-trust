from __future__ import annotations

import os
import stat
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class DeploymentConfigTests(unittest.TestCase):
    def test_every_shell_entry_point_is_executable(self) -> None:
        scripts = [
            *ROOT.glob("experiments/*.sh"),
            *ROOT.glob("infra/**/*.sh"),
        ]
        self.assertTrue(scripts)
        for script in scripts:
            with self.subTest(script=script.relative_to(ROOT)):
                self.assertNotEqual(script.stat().st_mode & stat.S_IXUSR, 0)

    def test_aws_installer_rejects_an_ambiguous_freshness_flag(self) -> None:
        completed = subprocess.run(
            [
                "bash",
                str(ROOT / "infra/aws/install-mcp.sh"),
                "d432fbb3-d2f1-4a97-9ef7-75bd81c00000",
                "yes",
            ],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(completed.returncode, 64)
        self.assertIn("must be 0 or 1", completed.stderr)

    def test_aws_deploy_rejects_an_ambiguous_freshness_flag_before_aws(self) -> None:
        environment = os.environ.copy()
        environment["KEYLIME_REQUIRE_FRESH_ATTESTATION"] = "yes"
        completed = subprocess.run(
            ["bash", str(ROOT / "infra/aws/deploy.sh")],
            cwd=ROOT,
            env=environment,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(completed.returncode, 64)
        self.assertIn("must be 0 or 1", completed.stderr)

    def test_deployments_ship_every_server_module_and_avoid_sudo_in_mcp(self) -> None:
        aws = (ROOT / "infra/aws/install-mcp.sh").read_text(encoding="utf-8")
        aws_deploy = (ROOT / "infra/aws/deploy.sh").read_text(encoding="utf-8")
        azure = (ROOT / "infra/azure/configure-mcp.sh").read_text(encoding="utf-8")
        self.assertIn("KEYLIME_REQUIRE_FRESH_ATTESTATION=$require_fresh_attestation", aws)
        self.assertIn("config.mjs", azure)
        self.assertIn("policy_digest.mjs", azure)
        self.assertIn("security_parameters.mjs", azure)
        self.assertIn("security-parameters.json", azure)
        self.assertIn("src/security_parameters.mjs", aws_deploy)
        self.assertIn("config/security-parameters.json", aws_deploy)
        self.assertIn("chown -R root:ec528-mcp /opt/ec528-zero-trust", aws)
        self.assertIn("chmod -R u=rwX,g=rX,o= /opt/ec528-zero-trust", aws)
        self.assertNotIn("KEYLIME_MAX_ATTESTATION_AGE_SECONDS=30", aws)
        self.assertNotIn("KEYLIME_FRESH_ATTESTATION_TIMEOUT_SECONDS=15", aws)
        self.assertNotIn("KEYLIME_MAX_ATTESTATION_AGE_SECONDS=30", azure)
        self.assertNotIn("KEYLIME_FRESH_ATTESTATION_TIMEOUT_SECONDS=15", azure)
        self.assertIn("KEYLIME_STATUS_SOCKET=/run/ec528/keylime-status.sock", azure)
        self.assertNotIn("KEYLIME_STATUS_COMMAND=/usr/local/bin/ec528-keylime-status-sudo", azure)

    def test_aws_stages_bootstrap_instead_of_enrolling_during_cloud_init(self) -> None:
        template = (ROOT / "infra/aws/main.yaml").read_text(encoding="utf-8")
        installer = (ROOT / "infra/aws/install-mcp.sh").read_text(encoding="utf-8")
        self.assertIn("keylime-bootstrap-pending", template)
        self.assertIn("ec528-keylime-bootstrap.socket", installer)
        self.assertIn('"-f", str(PAYLOAD)', template)
        self.assertNotIn('"--include", str(PAYLOAD.parent)', template)
        self.assertIn("capture_output=True", template)
        helper_end = template.index("chmod 0755 /usr/local/libexec/ec528-keylime-bootstrap")
        final_policy = template.index("keylime-policy create runtime", helper_end)
        pending_marker = template.index("keylime-bootstrap-pending", final_policy)
        self.assertLess(helper_end, final_policy)
        self.assertLess(final_policy, pending_marker)
        cloud_init_tail = template.split("ec528-keylime-bootstrap <<'BOOTSTRAP'", 1)[-1]
        self.assertNotIn('keylime_tenant -c add -u "$agent_uuid"', cloud_init_tail)

    def test_end_to_end_recovery_does_not_bypass_quorum_bootstrap(self) -> None:
        experiment = (ROOT / "experiments/demo2_end_to_end.mjs").read_text(encoding="utf-8")
        self.assertIn("keylime_tenant -c reactivate", experiment)
        self.assertNotIn("keylime_tenant -c delete", experiment)


class NodeEnforcementDeploymentTests(unittest.TestCase):
    def test_aws_installer_requires_a_permit_public_key(self) -> None:
        for key in ("", "not base64!"):
            with self.subTest(key=key):
                completed = subprocess.run(
                    [
                        "bash",
                        str(ROOT / "infra/aws/install-mcp.sh"),
                        "d432fbb3-d2f1-4a97-9ef7-75bd81c00000",
                        "0",
                        key,
                    ],
                    cwd=ROOT,
                    check=False,
                    capture_output=True,
                    text=True,
                )
                self.assertEqual(completed.returncode, 64)
                self.assertIn("launch-permit public key", completed.stderr)

    def test_aws_node_is_configured_for_permits_and_a_durable_ledger(self) -> None:
        installer = (ROOT / "infra/aws/install-mcp.sh").read_text(encoding="utf-8")
        self.assertIn(
            "KEYLIME_PERMIT_PUBLIC_KEY_FILE=/etc/ec528-permit-public-key.pem", installer
        )
        self.assertIn("KEYLIME_LAUNCH_LEDGER_DIR=/var/lib/ec528-launch-ledger", installer)
        # ProtectSystem=strict makes /var read-only unless the unit declares this.
        self.assertIn("StateDirectory=ec528-launch-ledger", installer)

    def test_private_permit_key_never_ships_to_the_node(self) -> None:
        deploy = (ROOT / "infra/aws/deploy.sh").read_text(encoding="utf-8")
        bundle = deploy.split('tar -C "$repository" -czf "$bundle"', 1)[1].split("bundle_base64", 1)[0]
        self.assertIn("src/keylime_mcp", bundle)
        self.assertNotIn("src/controller", bundle)
        self.assertNotIn("build/", bundle)
        self.assertIn("${permitPublicKey}", deploy)

    def test_node_modules_import_nothing_from_the_controller(self) -> None:
        for module in (ROOT / "src/keylime_mcp").glob("*.mjs"):
            with self.subTest(module=module.name):
                self.assertNotIn("../controller/", module.read_text(encoding="utf-8"))

    def test_status_helper_reports_the_enrollment_epoch(self) -> None:
        template = (ROOT / "infra/aws/main.yaml").read_text(encoding="utf-8")
        self.assertIn('"enrollment_epoch": enrollment_epoch', template)
        helper = template.index('"enrollment_epoch": enrollment_epoch')
        final_policy = template.index("keylime-policy create runtime", helper)
        self.assertLess(helper, final_policy)

    def test_azure_ships_every_node_module(self) -> None:
        azure = (ROOT / "infra/azure/configure-mcp.sh").read_text(encoding="utf-8")
        for module in (ROOT / "src/keylime_mcp").glob("*.mjs"):
            with self.subTest(module=module.name):
                self.assertIn(f"src/keylime_mcp/{module.name}", azure)


if __name__ == "__main__":
    unittest.main()
